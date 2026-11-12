"""Unit tests for the mobile sync client (fasting reads).

Pure — no network, no keychain, no real MyFitnessPal session. A fake session
routes requests by (method, URL) so the OAuth flow and the paginated import can
be exercised deterministically. The protocol shapes mirror live iOS traffic
captured 2026-11-12.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import mobile_sync as ms  # noqa: E402


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class FakeResp:
    def __init__(self, status=200, json_body=None, headers=None, text=""):
        self.status_code = status
        self._json = json_body
        self.headers = dict(headers or {})
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


class FakeSession:
    """Routes by a handler keyed on an (method, url-substring) match."""

    def __init__(self):
        self.routes = []  # list of (method, substring, handler)
        self.calls = []   # (method, url, kwargs)

    def on(self, method, substring, handler):
        self.routes.append((method.upper(), substring, handler))
        return self

    def _dispatch(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for m, sub, handler in self.routes:
            if m == method and sub in url:
                return handler(url, kwargs) if callable(handler) else handler
        raise AssertionError(f"no route for {method} {url}")

    def get(self, url, **kwargs):
        return self._dispatch("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._dispatch("POST", url, **kwargs)


CLIENT_KEYS_BODY = {
    "_embedded": {
        "clientKeys": [
            {"key": {"kty": "oct", "use": "sig", "kid": "sig-kid-1",
                     "k": base64.urlsafe_b64encode(b"super-secret-signing-key").rstrip(b"=").decode(),
                     "alg": "HS512"}},
            {"key": {"kty": "oct", "use": "enc", "kid": "enc-kid-1",
                     "k": base64.urlsafe_b64encode(b"enc").rstrip(b"=").decode(), "alg": "dir"}},
        ]
    }
}


def _fast_item(fid, started, ended, action="created"):
    return {"type": "fasting_entry", "id": fid, "action": action,
            "data": {"id": fid, "fast_started": started, "fast_ended": ended,
                     "user_id": "u", "created_at": started, "updated_at": ended or started}}


@pytest.fixture(autouse=True)
def _reset_cache():
    ms._access_cache["token"] = None
    ms._access_cache["expires_at"] = 0.0
    yield


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
class TestCredentialsJwt:
    def test_signs_and_verifies_hs512(self):
        k_raw = b"super-secret-signing-key"
        k = base64.urlsafe_b64encode(k_raw).rstrip(b"=").decode()
        jwt = ms.build_credentials_jwt("alice", "pw", k, "sig-kid-1")
        h, p, sig = jwt.split(".")
        expected = base64.urlsafe_b64encode(
            hmac.new(k_raw, f"{h}.{p}".encode(), hashlib.sha512).digest()
        ).rstrip(b"=").decode()
        assert sig == expected

    def test_header_and_payload_contents(self):
        k = base64.urlsafe_b64encode(b"x").rstrip(b"=").decode()
        jwt = ms.build_credentials_jwt("alice", "pw", k, "the-kid")
        h, p, _ = jwt.split(".")
        def dec(s):
            return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        assert dec(h) == {"alg": "HS512", "kid": "the-kid", "typ": "JWT"}
        assert dec(p) == {"username": "alice", "password": "pw"}

    def test_requires_username_and_password(self):
        k = base64.urlsafe_b64encode(b"x").rstrip(b"=").decode()
        with pytest.raises(ms.MobileAuthError):
            ms.build_credentials_jwt("", "pw", k, "kid")


# --------------------------------------------------------------------------- #
# OAuth steps
# --------------------------------------------------------------------------- #
class TestOAuthSteps:
    def test_fetch_signing_key_picks_sig(self):
        s = FakeSession().on("GET", "/clientKeys", FakeResp(200, CLIENT_KEYS_BODY))
        k, kid = ms.fetch_signing_key(s, "cid", "csec")
        assert kid == "sig-kid-1"
        assert ms._b64u_decode(k) == b"super-secret-signing-key"

    def test_fetch_signing_key_errors_without_sig(self):
        body = {"_embedded": {"clientKeys": [
            {"key": {"use": "enc", "kid": "e", "k": "AA"}}]}}
        s = FakeSession().on("GET", "/clientKeys", FakeResp(200, body))
        with pytest.raises(ms.MobileAuthError):
            ms.fetch_signing_key(s, "cid", "csec")

    def test_authorize_extracts_code(self):
        resp = FakeResp(302, headers={"Location": "mfp://identity/callback?code=THE_CODE"})
        s = FakeSession().on("POST", "/oauth/authorize", resp)
        assert ms.authorize(s, "cid", "csec", "jwt") == "THE_CODE"

    def test_authorize_wrong_password_raises(self):
        # No redirect — the real server returns 200 with no Location here.
        s = FakeSession().on("POST", "/oauth/authorize", FakeResp(200, {"error": "nope"}))
        with pytest.raises(ms.MobileAuthError, match="authorize failed"):
            ms.authorize(s, "cid", "csec", "jwt")

    def test_exchange_code_returns_tokens(self):
        body = {"access_token": "NL.M.acc", "refresh_token": "NL.O.ref", "expires_in": 900}
        s = FakeSession().on("POST", "/oauth/token", FakeResp(200, body))
        access, refresh, ttl = ms.exchange_code(s, "cid", "csec", "app", "code")
        assert (access, refresh, ttl) == ("NL.M.acc", "NL.O.ref", 900)

    def test_refresh_keeps_old_refresh_when_not_rotated(self):
        body = {"access_token": "NL.M.new", "expires_in": 900}  # no new refresh
        s = FakeSession().on("POST", "/oauth/token", FakeResp(200, body))
        access, refresh, ttl = ms.refresh_access_token(s, "cid", "csec", "OLD_REFRESH")
        assert access == "NL.M.new"
        assert refresh == "OLD_REFRESH"

    def test_refresh_failure_raises(self):
        s = FakeSession().on("POST", "/oauth/token", FakeResp(401, {"error": "invalid_grant"}))
        with pytest.raises(ms.MobileAuthError):
            ms.refresh_access_token(s, "cid", "csec", "ref")

    def test_login_with_password_full_flow(self):
        s = FakeSession()
        s.on("GET", "/clientKeys", FakeResp(200, CLIENT_KEYS_BODY))
        # both grants hit /oauth/token; route by form 'grant_type'
        def token(url, kw):
            gt = kw["data"]["grant_type"]
            if gt == "client_credentials":
                return FakeResp(200, {"access_token": "APP", "expires_in": 900})
            return FakeResp(200, {"access_token": "NL.M.acc", "refresh_token": "NL.O.ref",
                                  "expires_in": 900})
        s.on("POST", "/oauth/token", token)
        s.on("POST", "/oauth/authorize",
             FakeResp(302, headers={"Location": "mfp://identity/callback?code=C"}))
        access, refresh, ttl = ms.login_with_password(s, "cid", "csec", "alice", "pw")
        assert (access, refresh) == ("NL.M.acc", "NL.O.ref")
        # the code exchange is authed with the app token as a Bearer
        exchange = [c for c in s.calls if c[0] == "POST" and "/oauth/token" in c[1]
                    and c[2]["data"]["grant_type"] == "authorization_code"][0]
        assert exchange[2]["headers"]["Authorization"] == "Bearer APP"


# --------------------------------------------------------------------------- #
# token manager
# --------------------------------------------------------------------------- #
class TestAccessTokenManager:
    def test_cache_hit_skips_network(self, monkeypatch):
        ms._cache_access("CACHED", 900)
        # No session needed; should return without touching config/network.
        assert ms.get_mobile_access_token(session=FakeSession()) == "CACHED"

    def test_refresh_path(self, monkeypatch):
        monkeypatch.setenv("MFP_MOBILE_CLIENT_ID", "cid")
        monkeypatch.setenv("MFP_MOBILE_CLIENT_SECRET", "csec")
        monkeypatch.setattr(ms, "_load_refresh_token", lambda: "STORED_REFRESH")
        stored = {}
        monkeypatch.setattr(ms, "_store_refresh_token", lambda t: stored.update(tok=t))
        s = FakeSession().on("POST", "/oauth/token",
                             FakeResp(200, {"access_token": "NL.M.r", "refresh_token": "ROT",
                                            "expires_in": 900}))
        assert ms.get_mobile_access_token(session=s) == "NL.M.r"
        assert stored["tok"] == "ROT"  # rotated refresh persisted

    def test_bootstrap_when_no_refresh(self, monkeypatch):
        monkeypatch.setenv("MFP_MOBILE_CLIENT_ID", "cid")
        monkeypatch.setenv("MFP_MOBILE_CLIENT_SECRET", "csec")
        monkeypatch.setattr(ms, "_load_refresh_token", lambda: None)
        monkeypatch.setattr(ms, "_resolve_user_credential",
                            lambda name: {"MFP_USERNAME": "alice", "MFP_PASSWORD": "pw"}[name])
        saved = {}
        monkeypatch.setattr(ms, "_store_refresh_token", lambda t: saved.update(tok=t))
        s = FakeSession()
        s.on("GET", "/clientKeys", FakeResp(200, CLIENT_KEYS_BODY))
        s.on("POST", "/oauth/authorize",
             FakeResp(302, headers={"Location": "mfp://identity/callback?code=C"}))
        def token(url, kw):
            if kw["data"]["grant_type"] == "client_credentials":
                return FakeResp(200, {"access_token": "APP", "expires_in": 900})
            return FakeResp(200, {"access_token": "NL.M.boot", "refresh_token": "NL.O.boot",
                                  "expires_in": 900})
        s.on("POST", "/oauth/token", token)
        assert ms.get_mobile_access_token(session=s) == "NL.M.boot"
        assert saved["tok"] == "NL.O.boot"

    def test_missing_password_raises_clear_error(self, monkeypatch):
        monkeypatch.setenv("MFP_MOBILE_CLIENT_ID", "cid")
        monkeypatch.setenv("MFP_MOBILE_CLIENT_SECRET", "csec")
        monkeypatch.setattr(ms, "_load_refresh_token", lambda: None)
        monkeypatch.setattr(ms, "_resolve_user_credential", lambda name: None)
        with pytest.raises(ms.MobileAuthError, match="MFP_USERNAME"):
            ms.get_mobile_access_token(session=FakeSession())

    def test_missing_client_creds_raises(self, monkeypatch):
        monkeypatch.delenv("MFP_MOBILE_CLIENT_ID", raising=False)
        monkeypatch.delenv("MFP_MOBILE_CLIENT_SECRET", raising=False)
        monkeypatch.setattr(ms, "_config", lambda env, acct: None)
        with pytest.raises(ms.MobileAuthError, match="client credentials"):
            ms.get_mobile_access_token(session=FakeSession())


# --------------------------------------------------------------------------- #
# import pagination
# --------------------------------------------------------------------------- #
class TestFetchAllFasts:
    def test_paginates_until_sync_token(self):
        pages = [
            FakeResp(200, {"items": [_fast_item("a", "2026-01-01T10:00:00Z", "2026-01-01T18:00:00Z")]},
                     headers={"next-import-token": "tok1"}),
            FakeResp(200, {"items": [_fast_item("b", "2026-01-02T10:00:00Z", "2026-01-02T18:00:00Z")]},
                     headers={"next-import-token": "tok2"}),
            FakeResp(200, {"items": [_fast_item("c", "2026-01-03T10:00:00Z", None)]},
                     headers={"next-import-token": "last", "next-sync-token": "SYNC"}),
        ]
        seq = iter(pages)
        s = FakeSession().on("GET", "/v2.1/import", lambda url, kw: next(seq))
        fasts, sync_token = ms.fetch_all_fasts("tok", session=s)
        assert [f["id"] for f in fasts] == ["a", "b", "c"]
        assert sync_token == "SYNC"
        # import_token fed back on later pages
        assert s.calls[1][2]["params"]["import_token"] == "tok1"
        assert s.calls[2][2]["params"]["import_token"] == "tok2"

    def test_dedupes_and_skips_deleted_and_other_types(self):
        body = {"items": [
            _fast_item("dup", "2026-01-01T10:00:00Z", "2026-01-01T18:00:00Z"),
            _fast_item("dup", "2026-01-01T10:00:00Z", "2026-01-01T19:00:00Z"),  # later wins
            _fast_item("gone", "2026-01-02T10:00:00Z", None, action="deleted"),
            {"type": "nutrient_goal", "id": "x", "action": "created", "data": {"id": "x"}},
        ]}
        s = FakeSession().on("GET", "/v2.1/import", FakeResp(200, body, headers={"next-sync-token": "S"}))
        fasts, _ = ms.fetch_all_fasts("tok", session=s)
        assert [f["id"] for f in fasts] == ["dup"]
        assert fasts[0]["fast_ended"] == "2026-01-01T19:00:00Z"

    def test_stops_when_no_import_token(self):
        s = FakeSession().on("GET", "/v2.1/import",
                             FakeResp(200, {"items": []}))  # no import token, no sync token
        fasts, sync_token = ms.fetch_all_fasts("tok", session=s)
        assert fasts == [] and sync_token is None
        assert len(s.calls) == 1

    def test_401_raises_unauthorized(self):
        s = FakeSession().on("GET", "/v2.1/import", FakeResp(401, {"error_description": "expired"}))
        with pytest.raises(ms.Unauthorized):
            ms.fetch_all_fasts("tok", session=s)


# --------------------------------------------------------------------------- #
# shaping / rendering
# --------------------------------------------------------------------------- #
class TestShaping:
    def test_summarize_completed_fast(self):
        out = ms.summarize_fast({"id": "a", "fast_started": "2026-01-01T10:00:00Z",
                                 "fast_ended": "2026-01-02T02:00:00Z",
                                 "created_at": "c", "updated_at": "u"})
        assert out["duration_hours"] == 16.0
        assert out["ongoing"] is False

    def test_summarize_ongoing_fast(self):
        out = ms.summarize_fast({"id": "a", "fast_started": "2026-01-01T10:00:00Z",
                                 "fast_ended": None})
        assert out["ongoing"] is True
        assert out["duration_hours"] is None

    def test_filter_by_utc_start_date_and_sort_newest_first(self):
        fasts = [ms.summarize_fast(_fast_item(str(i), f"2026-01-0{i}T10:00:00Z",
                                              f"2026-01-0{i}T18:00:00Z")["data"])
                 for i in (1, 2, 3)]
        got = ms.filter_and_sort(fasts, start=date(2026, 1, 2), end=date(2026, 1, 2))
        assert [f["id"] for f in got] == ["2"]
        allsorted = ms.filter_and_sort(fasts)
        assert [f["id"] for f in allsorted] == ["3", "2", "1"]

    def test_markdown_ongoing_and_total_line(self):
        fasts = [
            ms.summarize_fast({"id": "a", "fast_started": "2026-01-03T10:00:00Z", "fast_ended": None}),
            ms.summarize_fast({"id": "b", "fast_started": "2026-01-02T10:00:00Z",
                               "fast_ended": "2026-01-02T22:00:00Z"}),
        ]
        md = ms.fasts_markdown(fasts, total=10)
        assert "- **count**: 2" in md
        assert "- **total on account**: 10" in md
        assert "→ (ongoing)" in md
        assert "(12.0h)" in md
