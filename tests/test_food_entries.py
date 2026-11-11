"""Unit tests for the mfp_get_food_entries tool.

Pure — no live MFP session required. A small fake `client` stands in for
the v2 diary API, using the `food_entry` shape captured live on 2026-11-11.
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


def _entry(**overrides):
    """A timed entry: 76.1 g of banana, logged from a device at UTC+1."""
    item = {
        "id": "11111111-2222-4333-8444-555555555555",
        "type": "food_entry",
        "date": "2026-01-15",
        "meal_name": "Snacks",
        "meal_position": 3,
        "food": {"id": "1", "description": "Banana", "brand_name": "Generic"},
        "serving_size": {"value": 1.0, "unit": "g", "nutrition_multiplier": 0.01},
        "servings": 76.0999984741211,
        "nutritional_contents": {
            "energy": {"unit": "calories", "value": 73.81699851989747},
            "carbohydrates": 17.274699653625486,
            "fat": 0.21307999572753908,
            "protein": 0.5631399887084961,
            "sodium": 0.761,
            "sugar": 9.3,
        },
        "consumed_at": "15:45:00",
        "logged_at": "2026-01-15T14:45:28+00:00",
        "logged_at_offset": "+01:00",
        "created_at": "2026-01-15T14:45:29Z",
        "deleted": False,
    }
    item.update(overrides)
    return item


def _untimed(**overrides):
    """An entry MyFitnessPal holds no time for: all three log fields null."""
    return _entry(
        consumed_at=None, logged_at=None, logged_at_offset=None, **overrides
    )


class _FakeResponse:
    def __init__(self, body, status_code=200):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class _FakeSession:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params))
        return _FakeResponse(self.body, self.status_code)


class _FakeClient:
    access_token = "token"
    user_id = "123"

    def __init__(self, items=None, status_code=200, body=None):
        self.session = _FakeSession(
            body if body is not None else {"items": items or []}, status_code
        )


class TestFoodEntrySummary:
    def test_time_fields_pass_through_verbatim(self):
        summary = server._food_entry_summary(_entry())
        assert summary["consumed_at"] == "15:45:00"
        assert summary["logged_at"] == "2026-01-15T14:45:28+00:00"
        assert summary["logged_at_offset"] == "+01:00"
        assert summary["created_at"] == "2026-01-15T14:45:29Z"

    def test_untimed_entry_keeps_nulls_and_does_not_borrow_created_at(self):
        """created_at is not the eating time: live, it matched the app for one
        untimed entry and was over two hours late for another."""
        summary = server._food_entry_summary(_untimed())
        assert summary["consumed_at"] is None
        assert summary["logged_at"] is None
        assert summary["logged_at_offset"] is None
        assert summary["created_at"] == "2026-01-15T14:45:29Z"

    def test_identity_and_food_fields(self):
        summary = server._food_entry_summary(_entry())
        assert summary["id"] == "11111111-2222-4333-8444-555555555555"
        assert summary["meal"] == "Snacks"
        assert summary["name"] == "Banana"
        assert summary["brand"] == "Generic"

    def test_quantity_is_servings_times_serving_value(self):
        """76.1 servings of a "1 g" serving is the 76.1 g the app shows."""
        summary = server._food_entry_summary(_entry())
        assert summary["quantity"] == 76.1
        assert summary["unit"] == "g"

        summary = server._food_entry_summary(
            _entry(servings=1.5, serving_size={"value": 100.0, "unit": "g"})
        )
        assert summary["quantity"] == 150.0

    def test_quantity_falls_back_to_servings_without_a_serving_value(self):
        summary = server._food_entry_summary(
            _entry(servings=2.0, serving_size={"unit": "cup"})
        )
        assert summary["quantity"] == 2.0
        assert summary["unit"] == "cup"

    def test_nutrition_is_the_entry_total_rounded(self):
        summary = server._food_entry_summary(_entry())
        assert summary["energy"] == 73.8
        assert summary["carbohydrates"] == 17.3
        assert summary["fat"] == 0.2
        assert summary["protein"] == 0.6

    def test_energy_unit_is_reported_not_assumed(self):
        """The v2 diary also emits kilojoules (see steps_aggregate), so the
        unit travels with the value instead of being labelled calories."""
        summary = server._food_entry_summary(_entry(
            nutritional_contents={"energy": {"unit": "kilojoules", "value": 309.0}}
        ))
        assert summary["energy"] == 309.0
        assert summary["energy_unit"] == "kilojoules"

    def test_missing_nutrients_are_none_not_zero(self):
        summary = server._food_entry_summary(_entry(nutritional_contents={}))
        assert summary["energy"] is None
        assert summary["energy_unit"] is None
        assert summary["protein"] is None


class TestGetFoodEntries:
    def test_requests_food_entries_for_the_date(self):
        client = _FakeClient([_entry()])
        entries = server.get_food_entries(client, date(2026, 1, 15))

        url, params = client.session.calls[0]
        assert url.endswith("/v2/diary")
        assert params == {"entry_date": "2026-01-15", "types": "food_entry"}
        assert [e["name"] for e in entries] == ["Banana"]

    def test_keeps_api_order(self):
        client = _FakeClient([
            _entry(id="a", consumed_at="21:00:00"),
            _entry(id="b", consumed_at="07:00:00"),
        ])
        entries = server.get_food_entries(client, date(2026, 1, 15))
        assert [e["id"] for e in entries] == ["a", "b"]

    def test_skips_other_types_and_deleted_entries(self):
        client = _FakeClient([
            _entry(id="kept"),
            _entry(id="gone", deleted=True),
            {"type": "diary_meal", "diary_meal": "Breakfast"},
        ])
        entries = server.get_food_entries(client, date(2026, 1, 15))
        assert [e["id"] for e in entries] == ["kept"]

    def test_empty_day_is_an_empty_list(self):
        assert server.get_food_entries(_FakeClient([]), date(2019, 1, 1)) == []

    def test_http_error_raises_with_mfp_detail(self):
        client = _FakeClient(
            status_code=400,
            body={"error": "entry_date", "error_description": "is invalid"},
        )
        with pytest.raises(RuntimeError, match="HTTP 400 - is invalid"):
            server.get_food_entries(client, date(2026, 1, 15))


class TestGetFoodEntriesTool:
    def _run(self, monkeypatch, client, **kwargs):
        monkeypatch.setattr(server, "get_mfp_client", lambda: client)
        params = server.GetFoodEntriesInput(**kwargs)
        return asyncio.run(server.mfp_get_food_entries(params))

    def test_json_shape(self, monkeypatch):
        client = _FakeClient([_entry(), _untimed(id="untimed")])
        result = json.loads(self._run(
            monkeypatch, client, date="2026-01-15", response_format="json",
        ))
        assert result["date"] == "2026-01-15"
        assert result["count"] == 2
        assert result["entries"][0]["consumed_at"] == "15:45:00"
        assert result["entries"][1]["consumed_at"] is None

    def test_defaults_to_today(self, monkeypatch):
        client = _FakeClient([])
        result = json.loads(self._run(monkeypatch, client, response_format="json"))
        assert result["date"] == str(date.today())
        assert client.session.calls[0][1]["entry_date"] == str(date.today())

    def test_markdown_groups_by_meal_with_time_first(self, monkeypatch):
        client = _FakeClient([
            _entry(meal_name="Breakfast", consumed_at="09:00:00"),
            _entry(),
            _untimed(id="untimed"),
        ])
        lines = self._run(monkeypatch, client, date="2026-01-15").splitlines()

        assert lines[0] == "## Food Entries for 2026-01-15"
        assert "- **count**: 3" in lines
        assert lines.index("### Breakfast") < lines.index("### Snacks")
        snacks = lines[lines.index("### Snacks") + 1:]
        assert snacks[0] == (
            "- 15:45 - Banana, 76.1 g - 73.8 calories"
            " (id: 11111111-2222-4333-8444-555555555555)"
        )
        assert snacks[1].startswith("- no time - Banana")

    def test_markdown_handles_null_name_and_null_quantity(self, monkeypatch):
        """A food with no description shows a placeholder, not literal None;
        a null quantity drops the amount clause rather than printing ', g'."""
        client = _FakeClient([
            _entry(
                food={"description": None, "brand_name": None},
                servings=None,
            ),
        ])
        line = self._run(monkeypatch, client, date="2026-01-15").splitlines()[-1]
        assert "Unknown food" in line
        assert "None" not in line
        assert ", g" not in line

    def test_http_failure_is_reported_as_an_error_string(self, monkeypatch):
        result = self._run(monkeypatch, _FakeClient(status_code=500, body={}))
        assert result.startswith("Error getting food entries")
        assert "500" in result
