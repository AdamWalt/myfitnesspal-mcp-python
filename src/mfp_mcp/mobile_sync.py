"""MyFitnessPal mobile sync client — the read path the web/cookie session can't reach.

MyFitnessPal's web v2 API has no fasting read endpoint; the iOS app loads its
Fasting History from a separate sync service
(``mobile-sync-api.myfitnesspal.com``) that only accepts a token minted for the
*mobile* OAuth client. The web-session bearer this server normally uses is
rejected there (HTTP 401).

This module reproduces the mobile app's standard OAuth2 authorization-code flow
to obtain that token, then reads the full fasting history from the sync
service's ``/v2.1/import`` snapshot endpoint. The protocol was mapped from live
traffic of the iOS app (captured 2026-11-12); there is no device attestation,
so the flow is fully reproducible headlessly.

Auth inputs:
- Mobile client credentials (client_id / client_secret) baked into the iOS app.
  Resolved from env (``MFP_MOBILE_CLIENT_ID`` / ``MFP_MOBILE_CLIENT_SECRET``) or
  the OS keychain (service ``mfp-mcp``). Not hardcoded here.
- The user's MyFitnessPal username + password (``MFP_USERNAME`` / ``MFP_PASSWORD``),
  needed ONCE to bootstrap. The resulting refresh token is stored in the keychain
  and reused; the password is never persisted by this module.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, date, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import keyring

logger = logging.getLogger("mfp_mcp.mobile")

IDENTITY_BASE = "https://identity-api.myfitnesspal.com"
SYNC_BASE = "https://mobile-sync-api.myfitnesspal.com"
REDIRECT_URI = "mfp://identity/callback"
# Matches the iOS app's User-Agent at capture time. Kept stable so requests
# look like the client the server expects; bump alongside the app if needed.
MOBILE_USER_AGENT = "IDM/26.44.0 MYFITNESSPAL/26.44.0.83006 iOS/26.7.2"

KEYRING_SERVICE = "mfp-mcp"
ACCT_CLIENT_ID = "MFP_MOBILE_CLIENT_ID"
ACCT_CLIENT_SECRET = "MFP_MOBILE_CLIENT_SECRET"
ACCT_REFRESH = "MFP_MOBILE_REFRESH_TOKEN"

# Access tokens are short-lived and the response may omit expires_in; fall back
# to a conservative lifetime and lean on the 401 retry in fetch_all_fasts.
_DEFAULT_TTL = 3600


class MobileAuthError(RuntimeError):
    """Auth could not be completed (missing config/credentials or a rejected grant)."""


class Unauthorized(RuntimeError):
    """A sync request was rejected with HTTP 401 (token expired/invalid)."""


# --------------------------------------------------------------------------- #
# base64url + JWT (pure)
# --------------------------------------------------------------------------- #
def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_decode(data: str) -> bytes:
    b = data.encode() if isinstance(data, str) else data
    return base64.urlsafe_b64decode(b + b"=" * (-len(b) % 4))


def build_credentials_jwt(username: str, password: str, key_b64url: str, kid: str) -> str:
    """Build the signed ``credentials`` JWT the authorize endpoint expects.

    The iOS app wraps the plaintext username/password in a compact JWS signed
    HS512 with the client's signing key (a JWK ``oct`` key whose ``k`` is the
    base64url-encoded secret), keyed by ``kid``. The signature protects
    integrity only — it is not encryption.
    """
    if not username or not password:
        raise MobileAuthError("username and password are required to build the credentials JWT")
    header = {"alg": "HS512", "kid": kid, "typ": "JWT"}
    payload = {"username": username, "password": password}
    seg = lambda obj: _b64u_encode(json.dumps(obj, separators=(",", ":")).encode())
    signing_input = f"{seg(header)}.{seg(payload)}".encode()
    sig = hmac.new(_b64u_decode(key_b64url), signing_input, hashlib.sha512).digest()
    return f"{signing_input.decode()}.{_b64u_encode(sig)}"


# --------------------------------------------------------------------------- #
# config / token storage
# --------------------------------------------------------------------------- #
def _config(env_name: str, keyring_account: str) -> Optional[str]:
    """env var first, then OS keychain (service ``mfp-mcp``)."""
    val = os.environ.get(env_name)
    if val:
        return val
    try:
        return keyring.get_password(KEYRING_SERVICE, keyring_account)
    except Exception as e:  # keychain locked / unavailable
        logger.warning("Keychain lookup for %s failed: %s", keyring_account, e)
        return None


def get_client_credentials() -> Tuple[str, str]:
    client_id = _config("MFP_MOBILE_CLIENT_ID", ACCT_CLIENT_ID)
    client_secret = _config("MFP_MOBILE_CLIENT_SECRET", ACCT_CLIENT_SECRET)
    if not client_id or not client_secret:
        raise MobileAuthError(
            "Mobile client credentials are not configured. Set MFP_MOBILE_CLIENT_ID "
            "and MFP_MOBILE_CLIENT_SECRET (environment or the 'mfp-mcp' keychain) to "
            "enable fasting reads."
        )
    return client_id, client_secret


def _store_refresh_token(token: str) -> None:
    try:
        keyring.set_password(KEYRING_SERVICE, ACCT_REFRESH, token)
    except Exception as e:
        logger.warning("Could not persist mobile refresh token to keychain: %s", e)


def _load_refresh_token() -> Optional[str]:
    try:
        return keyring.get_password(KEYRING_SERVICE, ACCT_REFRESH)
    except Exception as e:
        logger.warning("Could not read mobile refresh token from keychain: %s", e)
        return None


def _resolve_user_credential(name: str) -> Optional[str]:
    """Reuse the server's credential resolver (env + Fernet), lazily to avoid
    a circular import."""
    try:
        from mfp_mcp.server import get_decrypted_credential

        return get_decrypted_credential(name)
    except Exception:  # pragma: no cover - fallback if server import changes
        return os.environ.get(name)


# --------------------------------------------------------------------------- #
# HTTP (session-injectable for tests)
# --------------------------------------------------------------------------- #
def _new_session():
    import requests

    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": MOBILE_USER_AGENT,
            "Accept": "*/*",
            # Avoid brotli (`br`): plain requests can't decode it without the
            # optional dependency, and gzip/deflate are handled natively.
            "Accept-Encoding": "gzip, deflate",
        }
    )
    return s


def _basic_auth(client_id: str, client_secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()


def _detail(resp) -> str:
    try:
        body = resp.json()
    except Exception:
        return (getattr(resp, "text", "") or "")[:200]
    if isinstance(body, dict):
        return str(body.get("error_description") or body.get("error") or "")
    return ""


# --- OAuth steps ----------------------------------------------------------- #
def fetch_signing_key(session, client_id: str, client_secret: str) -> Tuple[str, str]:
    """GET /clientKeys -> (k, kid) for the signing (``use == "sig"``) key."""
    r = session.get(
        f"{IDENTITY_BASE}/clientKeys",
        headers={"Authorization": _basic_auth(client_id, client_secret),
                 "Content-Type": "application/json"},
        timeout=30,
    )
    if r.status_code != 200:
        raise MobileAuthError(f"clientKeys failed: HTTP {r.status_code} {_detail(r)}")
    for ck in r.json().get("_embedded", {}).get("clientKeys", []):
        key = ck.get("key", {})
        if key.get("use") == "sig" and key.get("k") and key.get("kid"):
            return key["k"], key["kid"]
    raise MobileAuthError("No signing key found in clientKeys response")


def client_credentials_token(session, client_id: str, client_secret: str) -> str:
    """POST /oauth/token grant_type=client_credentials -> short-lived app token.

    Used as the bearer for the authorization-code exchange, mirroring the app.
    """
    r = session.post(
        f"{IDENTITY_BASE}/oauth/token",
        headers={"Authorization": _basic_auth(client_id, client_secret),
                 "Content-Type": "application/x-www-form-urlencoded"},
        data={"client_id": client_id, "client_secret": client_secret,
              "grant_type": "client_credentials"},
        timeout=30,
    )
    if r.status_code != 200:
        raise MobileAuthError(f"client_credentials grant failed: HTTP {r.status_code} {_detail(r)}")
    token = r.json().get("access_token")
    if not token:
        raise MobileAuthError("client_credentials response did not include an access_token")
    return token


def authorize(session, client_id: str, client_secret: str, credentials_jwt: str) -> str:
    """POST /oauth/authorize with the credentials JWT -> authorization code.

    Responds 302 to ``mfp://identity/callback?code=...``; the redirect is NOT
    followed (custom scheme), the code is pulled from the Location header.
    """
    r = session.post(
        f"{IDENTITY_BASE}/oauth/authorize",
        params={"client_id": client_id, "response_type": "code",
                "redirect_uri": REDIRECT_URI, "scope": "openid"},
        headers={"Authorization": _basic_auth(client_id, client_secret),
                 "Content-Type": "application/x-www-form-urlencoded"},
        data={"credentials": credentials_jwt},
        allow_redirects=False,
        timeout=30,
    )
    location = r.headers.get("Location", "") if hasattr(r, "headers") else ""
    if r.status_code not in (301, 302, 303, 307, 308) or "code=" not in location:
        # A wrong password comes back here (no redirect) rather than as a 401.
        raise MobileAuthError(
            f"authorize failed: HTTP {r.status_code} {_detail(r)} "
            "(check MFP_USERNAME / MFP_PASSWORD)"
        )
    code = parse_qs(urlparse(location).query).get("code", [None])[0]
    if not code:
        raise MobileAuthError("authorize redirect contained no code")
    return code


def exchange_code(session, client_id: str, client_secret: str, app_token: str, code: str
                  ) -> Tuple[str, Optional[str], Optional[int]]:
    """POST /oauth/token grant_type=authorization_code -> (access, refresh, ttl)."""
    r = session.post(
        f"{IDENTITY_BASE}/oauth/token",
        headers={"Authorization": f"Bearer {app_token}",
                 "Content-Type": "application/x-www-form-urlencoded"},
        data={"client_id": client_id, "client_secret": client_secret, "code": code,
              "grant_type": "authorization_code", "redirect_uri": REDIRECT_URI},
        timeout=30,
    )
    if r.status_code != 200:
        raise MobileAuthError(f"code exchange failed: HTTP {r.status_code} {_detail(r)}")
    j = r.json()
    if not j.get("access_token"):
        raise MobileAuthError("code exchange response did not include an access_token")
    return j["access_token"], j.get("refresh_token"), j.get("expires_in")


def refresh_access_token(session, client_id: str, client_secret: str, refresh_token: str
                         ) -> Tuple[str, Optional[str], Optional[int]]:
    """POST /oauth/token grant_type=refresh_token -> (access, refresh, ttl)."""
    r = session.post(
        f"{IDENTITY_BASE}/oauth/token",
        headers={"Authorization": _basic_auth(client_id, client_secret),
                 "Content-Type": "application/x-www-form-urlencoded"},
        data={"client_id": client_id, "client_secret": client_secret,
              "grant_type": "refresh_token", "refresh_token": refresh_token},
        timeout=30,
    )
    if r.status_code != 200:
        raise MobileAuthError(f"token refresh failed: HTTP {r.status_code} {_detail(r)}")
    j = r.json()
    if not j.get("access_token"):
        raise MobileAuthError("token refresh response did not include an access_token")
    # Refresh tokens may rotate; keep the new one if provided.
    return j["access_token"], j.get("refresh_token") or refresh_token, j.get("expires_in")


def login_with_password(session, client_id: str, client_secret: str,
                        username: str, password: str
                        ) -> Tuple[str, Optional[str], Optional[int]]:
    """Full authorization-code bootstrap -> (access, refresh, ttl)."""
    k, kid = fetch_signing_key(session, client_id, client_secret)
    app_token = client_credentials_token(session, client_id, client_secret)
    creds_jwt = build_credentials_jwt(username, password, k, kid)
    code = authorize(session, client_id, client_secret, creds_jwt)
    return exchange_code(session, client_id, client_secret, app_token, code)


# --------------------------------------------------------------------------- #
# access-token manager (module-level cache)
# --------------------------------------------------------------------------- #
_access_cache: Dict[str, Any] = {"token": None, "expires_at": 0.0}


def _cache_access(token: str, ttl: Optional[int]) -> None:
    _access_cache["token"] = token
    _access_cache["expires_at"] = time.time() + (ttl or _DEFAULT_TTL)


def get_mobile_access_token(force_refresh: bool = False, session=None) -> str:
    """Return a valid mobile access token, minting or refreshing as needed.

    Order: in-memory cache -> stored refresh token -> password bootstrap.
    The password (MFP_USERNAME/MFP_PASSWORD) is only read when there is no
    usable refresh token; the resulting refresh token is persisted and reused.
    """
    now = time.time()
    if not force_refresh and _access_cache["token"] and _access_cache["expires_at"] - 60 > now:
        return _access_cache["token"]

    client_id, client_secret = get_client_credentials()
    session = session or _new_session()

    refresh = _load_refresh_token()
    if refresh:
        try:
            access, new_refresh, ttl = refresh_access_token(session, client_id, client_secret, refresh)
            if new_refresh and new_refresh != refresh:
                _store_refresh_token(new_refresh)
            _cache_access(access, ttl)
            return access
        except MobileAuthError as e:
            logger.warning("Mobile refresh token rejected (%s); re-bootstrapping from password.", e)

    username = _resolve_user_credential("MFP_USERNAME")
    password = _resolve_user_credential("MFP_PASSWORD")
    if not username or not password:
        raise MobileAuthError(
            "No stored mobile session yet, and MFP_USERNAME / MFP_PASSWORD are not "
            "available to bootstrap one. Set them once (environment or Claude Desktop "
            "config) to enable fasting reads; the password is not stored afterwards."
        )
    access, refresh, ttl = login_with_password(session, client_id, client_secret, username, password)
    if refresh:
        _store_refresh_token(refresh)
    _cache_access(access, ttl)
    return access


# --------------------------------------------------------------------------- #
# fasting read via the /v2.1/import snapshot (full history, paginated)
# --------------------------------------------------------------------------- #
def fetch_all_fasts(access_token: str, session=None, max_pages: int = 500
                    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Page the full ``fasting_entry`` snapshot. Returns (raw_data_dicts, sync_token).

    ``/v2.1/import?filter[]=fasting_entry`` returns the complete current set,
    100 per page. Each response carries a ``next-import-token`` header fed back
    as the ``import_token`` query param; the final page also carries a
    ``next-sync-token`` (the delta cursor) — that header is the end signal.

    Raises Unauthorized on HTTP 401 so the caller can refresh and retry.
    """
    session = session or _new_session()
    by_id: Dict[str, Dict[str, Any]] = {}
    import_token: Optional[str] = None
    sync_token: Optional[str] = None
    pages = 0

    while pages < max_pages:
        params = {"application": "MYFITNESSPAL", "filter[]": "fasting_entry"}
        if import_token:
            params["import_token"] = import_token
        r = session.get(
            f"{SYNC_BASE}/v2.1/import",
            params=params,
            headers={"Authorization": f"Bearer {access_token}",
                     "Content-Type": "application/json"},
            timeout=40,
        )
        if r.status_code == 401:
            raise Unauthorized(_detail(r) or "mobile token rejected (401)")
        if r.status_code != 200:
            raise RuntimeError(f"Fasting import failed: HTTP {r.status_code} {_detail(r)}")

        for item in r.json().get("items") or []:
            if item.get("type") != "fasting_entry":
                continue
            data = item.get("data") or {}
            fid = data.get("id") or item.get("id")
            if item.get("action") == "deleted":
                # A tombstone removes a previously-accumulated entry. The import
                # snapshot shouldn't mix states, but the endpoint is cursor-paged
                # like the delta stream, so honour deletes rather than skip them.
                if fid:
                    by_id.pop(fid, None)
                continue
            if fid:
                by_id[fid] = data
        pages += 1

        headers = r.headers
        sync_token = headers.get("next-sync-token")
        import_token = headers.get("next-import-token")
        if sync_token or not import_token:
            break
    else:
        # Exhausted max_pages without a terminating next-sync-token.
        logger.warning(
            "Fasting import stopped at max_pages=%d without completing; "
            "returned data may be incomplete.", max_pages
        )

    return list(by_id.values()), sync_token


# --------------------------------------------------------------------------- #
# shaping / rendering (pure)
# --------------------------------------------------------------------------- #
def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    # A timestamp with no offset is treated as UTC, so date bucketing and
    # duration math never silently depend on the host's local timezone.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def summarize_fast(data: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten one raw ``fasting_entry`` ``data`` object for output. Pure."""
    started = data.get("fast_started")
    ended = data.get("fast_ended")
    s, e = _parse_iso(started), _parse_iso(ended)
    duration = round((e - s).total_seconds() / 3600, 2) if (s and e) else None
    return {
        "id": data.get("id"),
        "fast_started": started,
        "fast_ended": ended,
        "ongoing": ended is None,
        "duration_hours": duration,
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
    }


_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def filter_and_sort(fasts: List[Dict[str, Any]],
                    start: Optional[date] = None,
                    end: Optional[date] = None) -> List[Dict[str, Any]]:
    """Filter by the UTC date of ``fast_started`` (inclusive) and sort newest first.

    An entry with a missing/unparseable ``fast_started`` is kept when no date
    filter is requested (and sorted last), so the returned count never silently
    disagrees with the total; it is excluded only when a start/end bound is
    given, since it cannot be placed on the timeline.
    """
    def keep(f: Dict[str, Any]) -> bool:
        dt = _parse_iso(f.get("fast_started"))
        if dt is None:
            return start is None and end is None
        d = dt.astimezone(timezone.utc).date()
        if start and d < start:
            return False
        if end and d > end:
            return False
        return True

    out = [f for f in fasts if keep(f)]
    out.sort(key=lambda f: _parse_iso(f.get("fast_started")) or _EPOCH, reverse=True)
    return out


def fasts_markdown(fasts: List[Dict[str, Any]], total: Optional[int] = None) -> str:
    """One line per fast, newest first. Pure."""
    lines = ["## Fasting Entries", f"- **count**: {len(fasts)}"]
    if total is not None and total != len(fasts):
        lines.append(f"- **total on account**: {total}")
    for f in fasts:
        started = f.get("fast_started") or "?"
        if f.get("ongoing"):
            lines.append(f"- {started} → (ongoing) (id: {f['id']})")
        else:
            dur = f["duration_hours"]
            dur_label = f"{dur}h" if dur is not None else "?"
            lines.append(f"- {started} → {f['fast_ended']} ({dur_label}) (id: {f['id']})")
    return "\n".join(lines)
