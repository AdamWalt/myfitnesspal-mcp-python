"""Unit tests for the mfp_get_steps tool.

Pure — no live MFP session required. A small fake `client` stands in for
the v2 diary API, using the response shape captured live on 2026-10-17.
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import server  # noqa: E402


def _aggregate(date_str, steps, primary=True):
    return {
        "type": "steps_aggregate",
        "date": date_str,
        "steps": steps,
        "energy": {"unit": "kilojoules", "value": 48},
        "primary": primary,
    }


class _FakeResponse:
    def __init__(self, items, status_code=200):
        self.status_code = status_code
        self._items = items

    def json(self):
        return {"items": self._items}


class _FakeSession:
    def __init__(self, items_by_date, status_code=200):
        self.items_by_date = items_by_date
        self.status_code = status_code
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params))
        return _FakeResponse(
            self.items_by_date.get(params["entry_date"], []), self.status_code
        )


class _FakeClient:
    access_token = "token"
    user_id = "123"

    def __init__(self, items_by_date, status_code=200):
        self.session = _FakeSession(items_by_date, status_code)


class TestPrimarySteps:
    def test_returns_steps_from_aggregate(self):
        assert server._primary_steps([_aggregate("2026-10-16", 3241)]) == 3241

    def test_empty_items_is_none(self):
        assert server._primary_steps([]) is None

    def test_prefers_primary_source(self):
        items = [
            _aggregate("2026-10-16", 100, primary=False),
            _aggregate("2026-10-16", 3241, primary=True),
        ]
        assert server._primary_steps(items) == 3241

    def test_falls_back_to_first_aggregate_without_primary(self):
        items = [
            _aggregate("2026-10-16", 100, primary=False),
            _aggregate("2026-10-16", 200, primary=False),
        ]
        assert server._primary_steps(items) == 100

    def test_ignores_other_entry_types(self):
        items = [{"type": "exercise_entry", "date": "2026-10-16"}]
        assert server._primary_steps(items) is None


class TestGetStepsRange:
    def test_one_request_per_day_with_null_for_missing(self):
        client = _FakeClient({
            "2026-10-10": [_aggregate("2026-10-10", 4936)],
            "2026-10-12": [_aggregate("2026-10-12", 9766)],
        })
        days = server.get_steps_range(client, date(2026, 10, 10), date(2026, 10, 12))
        assert days == [
            {"date": "2026-10-10", "steps": 4936},
            {"date": "2026-10-11", "steps": None},
            {"date": "2026-10-12", "steps": 9766},
        ]
        assert [p["entry_date"] for _, p in client.session.calls] == [
            "2026-10-10", "2026-10-11", "2026-10-12",
        ]
        assert all(p["types"] == "steps_aggregate" for _, p in client.session.calls)

    def test_http_error_raises(self):
        client = _FakeClient({}, status_code=500)
        with pytest.raises(RuntimeError, match="HTTP 500"):
            server.get_steps_range(client, date(2026, 10, 10), date(2026, 10, 10))


class TestGetStepsTool:
    def _run(self, monkeypatch, client, **kwargs):
        monkeypatch.setattr(server, "get_mfp_client", lambda: client)
        params = server.GetStepsInput(response_format="json", **kwargs)
        return asyncio.run(server.mfp_get_steps(params))

    def test_defaults_to_last_seven_days(self, monkeypatch):
        client = _FakeClient({})
        result = json.loads(self._run(monkeypatch, client))
        assert len(result["days"]) == 7
        assert result["end_date"] == str(date.today())

    def test_explicit_range_with_summary(self, monkeypatch):
        client = _FakeClient({
            "2026-10-10": [_aggregate("2026-10-10", 4000)],
            "2026-10-11": [_aggregate("2026-10-11", 6000)],
        })
        result = json.loads(self._run(
            monkeypatch, client, start_date="2026-10-10", end_date="2026-10-12",
        ))
        assert result["start_date"] == "2026-10-10"
        assert result["end_date"] == "2026-10-12"
        assert [d["steps"] for d in result["days"]] == [4000, 6000, None]
        assert result["summary"] == {
            "days_with_data": 2, "total": 10000, "average": 5000,
        }

    def test_rejects_start_after_end(self, monkeypatch):
        result = self._run(
            monkeypatch, _FakeClient({}),
            start_date="2026-10-12", end_date="2026-10-10",
        )
        assert result.startswith("Error")

    def test_rejects_range_over_31_days(self, monkeypatch):
        client = _FakeClient({})
        result = self._run(
            monkeypatch, client, start_date="2026-01-01", end_date="2026-03-01",
        )
        assert result.startswith("Error")
        assert "31" in result
        assert client.session.calls == []
