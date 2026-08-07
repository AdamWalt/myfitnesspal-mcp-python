"""Unit tests for the fasting CRUD tools.

Pure — no live MFP session required. All tests exercise the payload builders
and helpers via a small fake `client` where needed. Live smoke tests live
outside this file (documented in the PR).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import server  # noqa: E402


# --- Timestamp normalization -----------------------------------------------


class TestNormalizeTimestamp:
    """`_normalize_fasting_timestamp` must produce MFP's exact wire format:
    `YYYY-MM-DDTHH:MM:SSZ` in UTC. That's the shape captured from the iOS
    app (2026-08-07); deviations get rejected by the endpoint."""

    def test_utc_z_suffix_is_preserved(self):
        assert (
            server._normalize_fasting_timestamp("2026-08-06T13:00:00Z")
            == "2026-08-06T13:00:00Z"
        )

    def test_naive_timestamp_is_assumed_utc(self):
        """A naive string with no offset is treated as UTC and gets the Z
        suffix — silent local-time interpretation would be a footgun."""
        assert (
            server._normalize_fasting_timestamp("2026-08-06T13:00:00")
            == "2026-08-06T13:00:00Z"
        )

    def test_offset_is_converted_to_utc(self):
        """`+02:00` in Amsterdam summer must become `Z` at the -2h offset."""
        assert (
            server._normalize_fasting_timestamp("2026-08-06T15:00:00+02:00")
            == "2026-08-06T13:00:00Z"
        )

    def test_negative_offset_is_converted_to_utc(self):
        assert (
            server._normalize_fasting_timestamp("2026-08-06T08:00:00-05:00")
            == "2026-08-06T13:00:00Z"
        )

    def test_microseconds_are_dropped(self):
        """MFP's timestamps have second resolution — extra precision from
        client-side would be silently truncated by the API, so normalize
        it up-front for predictable equality."""
        assert (
            server._normalize_fasting_timestamp("2026-08-06T13:00:00.123456Z")
            == "2026-08-06T13:00:00Z"
        )

    def test_garbage_raises_value_error(self):
        with pytest.raises(ValueError, match="ISO 8601"):
            server._normalize_fasting_timestamp("not-a-timestamp")


# --- UUID generation --------------------------------------------------------


class TestGenerateFastingId:
    """The iOS app self-assigns ids in UPPERCASE UUIDv4 form (captured
    example: `4B7E2D9F-B7C0-4A31-9E5A-D0C10E2F3B45`). Matching that avoids
    downstream normalization surprises."""

    _uuid_v4 = re.compile(
        r"^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$"
    )

    def test_shape_matches_ios_convention(self):
        for _ in range(10):
            assert self._uuid_v4.match(server._generate_fasting_id())

    def test_ids_are_unique(self):
        ids = {server._generate_fasting_id() for _ in range(50)}
        assert len(ids) == 50


# --- Payload construction ---------------------------------------------------


class TestBuildFastingPayload:
    def test_matches_wire_format_verbatim(self):
        """Shape captured from the iOS app: `type` first, then `id`, then
        both timestamps in the ISO8601-Z form. If the shape drifts the
        endpoint 400s."""
        payload = server._build_fasting_payload(
            "4B7E2D9F-B7C0-4A31-9E5A-D0C10E2F3B45",
            "2026-08-06T13:00:00Z",
            "2026-08-07T05:00:00Z",
        )
        assert payload == {
            "items": [
                {
                    "type": "fasting_entry",
                    "id": "4B7E2D9F-B7C0-4A31-9E5A-D0C10E2F3B45",
                    "fast_started": "2026-08-06T13:00:00Z",
                    "fast_ended": "2026-08-07T05:00:00Z",
                }
            ]
        }

    def test_timestamps_are_normalized_to_utc(self):
        payload = server._build_fasting_payload(
            "AAAA0000-1111-4222-8333-444455556666",
            "2026-08-06T15:00:00+02:00",
            "2026-08-07T07:00:00+02:00",
        )
        item = payload["items"][0]
        assert item["fast_started"] == "2026-08-06T13:00:00Z"
        assert item["fast_ended"] == "2026-08-07T05:00:00Z"

    def test_end_before_start_raises(self):
        with pytest.raises(ValueError, match="strictly after"):
            server._build_fasting_payload(
                "AAAA0000-1111-4222-8333-444455556666",
                "2026-08-06T13:00:00Z",
                "2026-08-06T12:00:00Z",  # ends 1h before start
            )

    def test_end_equal_to_start_raises(self):
        """Zero-duration fasts are meaningless — reject rather than let MFP
        accept and confuse the fasting-average chart."""
        with pytest.raises(ValueError, match="strictly after"):
            server._build_fasting_payload(
                "AAAA0000-1111-4222-8333-444455556666",
                "2026-08-06T13:00:00Z",
                "2026-08-06T13:00:00Z",
            )

    def test_empty_id_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            server._build_fasting_payload(
                "", "2026-08-06T13:00:00Z", "2026-08-07T05:00:00Z"
            )

    def test_garbage_timestamp_raises(self):
        with pytest.raises(ValueError, match="ISO 8601"):
            server._build_fasting_payload(
                "AAAA0000-1111-4222-8333-444455556666",
                "yesterday",
                "2026-08-07T05:00:00Z",
            )


# --- HTTP behaviour via a fake client --------------------------------------


class _FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body or {}
        self.text = json.dumps(self._body) if isinstance(self._body, dict) else str(self._body)

    def json(self):
        if isinstance(self._body, dict):
            return self._body
        raise ValueError("Not JSON")


class _FakeSession:
    """Records the last request so tests can assert on URL / headers / body."""

    def __init__(self, responses):
        # responses: dict of {(method, url_suffix): _FakeResponse}
        self._responses = responses
        self.calls = []

    def _match(self, method, url):
        for (m, suffix), resp in self._responses.items():
            if m == method and url.endswith(suffix):
                return resp
        raise AssertionError(f"No fake response registered for {method} {url}")

    def post(self, url, headers=None, data=None, timeout=None):
        self.calls.append(("POST", url, headers, data))
        return self._match("POST", url)

    def patch(self, url, headers=None, data=None, timeout=None):
        self.calls.append(("PATCH", url, headers, data))
        return self._match("PATCH", url)

    def delete(self, url, headers=None, timeout=None):
        self.calls.append(("DELETE", url, headers, None))
        return self._match("DELETE", url)


class _FakeClient:
    """Minimum surface `_mfp_api_headers` needs."""

    def __init__(self, session):
        self.session = session
        self.access_token = "fake-token"
        self.user_id = "999888777"


class TestCreateFastingEntry:
    def test_posts_expected_url_and_body_and_returns_parsed_entry(self):
        entry_id = "AAAA0000-1111-4222-8333-444455556666"
        session = _FakeSession({
            ("POST", "/v2/diary/fasting_entry"): _FakeResponse(
                201, {"items": [{
                    "id": entry_id,
                    "fast_started": "2026-08-06T13:00:00Z",
                    "fast_ended": "2026-08-07T05:00:00Z",
                    "created_at": "2026-08-06T13:00:01Z",
                    "type": "fasting_entry",
                }]}
            )
        })
        client = _FakeClient(session)
        result = server.create_fasting_entry(
            client, "2026-08-06T13:00:00Z", "2026-08-07T05:00:00Z", entry_id
        )
        assert result == {
            "id": entry_id,
            "fast_started": "2026-08-06T13:00:00Z",
            "fast_ended": "2026-08-07T05:00:00Z",
            "created_at": "2026-08-06T13:00:01Z",
            "status": 201,
        }
        # URL sent to MFP
        assert session.calls[0][1].endswith("/v2/diary/fasting_entry")
        # Body sent as JSON string, matches the captured schema
        assert json.loads(session.calls[0][3]) == {
            "items": [{
                "type": "fasting_entry",
                "id": entry_id,
                "fast_started": "2026-08-06T13:00:00Z",
                "fast_ended": "2026-08-07T05:00:00Z",
            }]
        }

    def test_missing_id_auto_generates_uppercase_uuid(self):
        session = _FakeSession({
            ("POST", "/v2/diary/fasting_entry"): _FakeResponse(
                201, {"items": [{
                    "id": "PLACEHOLDER",
                    "fast_started": "2026-08-06T13:00:00Z",
                    "fast_ended": "2026-08-07T05:00:00Z",
                }]}
            )
        })
        client = _FakeClient(session)
        server.create_fasting_entry(
            client, "2026-08-06T13:00:00Z", "2026-08-07T05:00:00Z", entry_id=None
        )
        sent = json.loads(session.calls[0][3])
        sent_id = sent["items"][0]["id"]
        assert sent_id == sent_id.upper()
        assert len(sent_id) == 36  # standard UUID string length

    def test_non_201_raises_with_status_and_detail(self):
        session = _FakeSession({
            ("POST", "/v2/diary/fasting_entry"): _FakeResponse(
                400, {"error": "Bad Request", "error_description": "malformed"}
            )
        })
        client = _FakeClient(session)
        with pytest.raises(RuntimeError, match="HTTP 400"):
            server.create_fasting_entry(
                client, "2026-08-06T13:00:00Z", "2026-08-07T05:00:00Z"
            )


class TestUpdateFastingEntry:
    def test_patches_id_scoped_url_and_sends_full_replacement_body(self):
        entry_id = "AAAA0000-1111-4222-8333-444455556666"
        session = _FakeSession({
            ("PATCH", f"/v2/diary/fasting_entry/{entry_id}"): _FakeResponse(204)
        })
        client = _FakeClient(session)
        result = server.update_fasting_entry(
            client, entry_id, "2026-08-06T13:00:00Z", "2026-08-07T06:30:00Z"
        )
        assert result == {
            "id": entry_id,
            "fast_started": "2026-08-06T13:00:00Z",
            "fast_ended": "2026-08-07T06:30:00Z",
            "status": 204,
        }
        # MFP's PATCH is a full replacement — body must include both times + id + type
        sent = json.loads(session.calls[0][3])
        assert sent["items"][0]["type"] == "fasting_entry"
        assert sent["items"][0]["id"] == entry_id
        assert sent["items"][0]["fast_started"] == "2026-08-06T13:00:00Z"
        assert sent["items"][0]["fast_ended"] == "2026-08-07T06:30:00Z"

    def test_non_204_raises(self):
        entry_id = "AAAA0000-1111-4222-8333-444455556666"
        session = _FakeSession({
            ("PATCH", f"/v2/diary/fasting_entry/{entry_id}"): _FakeResponse(
                404, {"error": "not-found"}
            )
        })
        client = _FakeClient(session)
        with pytest.raises(RuntimeError, match="HTTP 404"):
            server.update_fasting_entry(
                client, entry_id, "2026-08-06T13:00:00Z", "2026-08-07T05:00:00Z"
            )


class TestDeleteFastingEntry:
    def test_deletes_id_scoped_url(self):
        entry_id = "AAAA0000-1111-4222-8333-444455556666"
        session = _FakeSession({
            ("DELETE", f"/v2/diary/fasting_entry/{entry_id}"): _FakeResponse(204)
        })
        client = _FakeClient(session)
        result = server.delete_fasting_entry(client, entry_id)
        assert result == {"id": entry_id, "deleted": True, "status": 204}

    def test_empty_id_raises_before_hitting_network(self):
        client = _FakeClient(_FakeSession({}))
        with pytest.raises(ValueError, match="non-empty"):
            server.delete_fasting_entry(client, "")

    def test_non_204_raises(self):
        entry_id = "AAAA0000-1111-4222-8333-444455556666"
        session = _FakeSession({
            ("DELETE", f"/v2/diary/fasting_entry/{entry_id}"): _FakeResponse(
                404, {"error": "not-found"}
            )
        })
        client = _FakeClient(session)
        with pytest.raises(RuntimeError, match="HTTP 404"):
            server.delete_fasting_entry(client, entry_id)
