"""Tests for account-aware meal resolution (issue #12).

Pure — no network. A fake client's get_date returns the account's meals. The
real risk this guards: MFP silently files an unrecognized meal_name under a
default meal instead of erroring, so entries get mis-logged on accounts with
renamed/localized/custom meals.
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


class _FakeMeal:
    def __init__(self, name):
        self.name = name


class _FakeDay:
    def __init__(self, names):
        self.meals = [_FakeMeal(n) for n in names]


class _FakeClient:
    def __init__(self, names):
        self._names = names

    def get_date(self, target_date):
        return _FakeDay(self._names)


NAMES = ["breakfast", "lunch", "dinner", "snacks", "supplements", "during ride"]


class TestResolveMeal:
    def test_matches_case_insensitively_and_returns_account_spelling(self):
        assert server._resolve_meal("Breakfast", NAMES) == "breakfast"
        assert server._resolve_meal("SUPPLEMENTS", NAMES) == "supplements"
        assert server._resolve_meal("  during ride  ", NAMES) == "during ride"

    def test_no_match_raises_and_names_the_options(self):
        # The localized case from the issue: "Breakfast" matches nothing.
        with pytest.raises(RuntimeError) as ei:
            server._resolve_meal("Breakfast", ["café da manhã", "almoço", "jantar"])
        msg = str(ei.value)
        assert "café da manhã" in msg
        assert "mfp_list_meals" in msg

    def test_empty_meal_raises(self):
        with pytest.raises(RuntimeError):
            server._resolve_meal("", NAMES)

    def test_singular_plural_slip_is_tolerated(self):
        # LLMs/users often say "snack" (singular) for the "snacks" meal.
        assert server._resolve_meal("snack", ["breakfast", "snacks"]) == "snacks"
        assert server._resolve_meal("snacks", ["breakfast", "snack"]) == "snack"

    def test_empty_meal_names_gives_a_clear_error(self):
        with pytest.raises(RuntimeError, match="Could not read this account's meals"):
            server._resolve_meal("breakfast", [])

    def test_matching_is_robust_to_stored_whitespace(self):
        assert server._resolve_meal("snacks", ["  snacks  "]) == "  snacks  "


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _AddClient:
    """Fake client for add_food_to_diary: get_date for meals + session.post capture."""
    access_token = "t"
    user_id = "add-test"

    def __init__(self, names):
        self._names = names
        self.posted = None
        outer = self

        class _Session:
            def post(self, url, headers=None, data=None, timeout=None):
                outer.posted = json.loads(data)
                return _Resp(201, {"items": [{"id": "entry-1"}]})

        self.session = _Session()

    def get_date(self, target_date):
        return _FakeDay(self._names)


class TestAddFoodResolution:
    """The actual #12 fix: resolution is wired into the diary POST."""

    def _patch_food(self, monkeypatch):
        monkeypatch.setattr(server, "get_food_v2", lambda client, mfp_id: {"id": "1", "version": "2"})
        monkeypatch.setattr(server, "select_serving_size", lambda food, unit: {"value": 1.0, "unit": "g"})
        server._MEAL_NAMES_CACHE.clear()

    def test_posts_the_resolved_meal_name(self, monkeypatch):
        self._patch_food(monkeypatch)
        client = _AddClient(["breakfast", "supplements"])
        entry_id, resolved = server.add_food_to_diary(client, "1", "SUPPLEMENTS", date(2026, 1, 1), 1.0)
        assert entry_id == "entry-1"
        assert resolved == "supplements"
        assert client.posted["items"][0]["meal_name"] == "supplements"

    def test_unknown_meal_raises_before_any_post(self, monkeypatch):
        self._patch_food(monkeypatch)
        client = _AddClient(["breakfast", "lunch"])
        with pytest.raises(RuntimeError, match="not one of this account"):
            server.add_food_to_diary(client, "1", "NotAMeal", date(2026, 1, 1), 1.0)
        assert client.posted is None  # refused, nothing logged


class TestMealNamesCache:
    def test_second_call_uses_cache_and_skips_the_scrape(self):
        server._MEAL_NAMES_CACHE.clear()
        calls = {"n": 0}

        class _C:
            user_id = "cache-test"
            def get_date(self, d):
                calls["n"] += 1
                return _FakeDay(["breakfast", "lunch"])

        c = _C()
        assert server.get_meal_names(c) == ["breakfast", "lunch"]
        assert server.get_meal_names(c) == ["breakfast", "lunch"]
        assert calls["n"] == 1  # scraped once, served from cache the second time


class TestGetMealNames:
    def test_reads_names_from_day_meals_in_order(self):
        client = _FakeClient(["breakfast", "lunch", "during ride"])
        assert server.get_meal_names(client) == ["breakfast", "lunch", "during ride"]


class TestListMealsTool:
    def _patch(self, monkeypatch, names):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(server, "get_meal_names", lambda client, target_date=None: names)

    def test_markdown_lists_custom_meals(self, monkeypatch):
        self._patch(monkeypatch, ["breakfast", "during ride"])
        out = asyncio.run(server.mfp_list_meals(server.ListMealsInput()))
        assert out.startswith("## Meals")
        assert "- during ride" in out

    def test_json(self, monkeypatch):
        self._patch(monkeypatch, ["breakfast", "lunch"])
        out = json.loads(asyncio.run(
            server.mfp_list_meals(server.ListMealsInput(response_format="json"))
        ))
        assert out["meals"] == ["breakfast", "lunch"]

    def test_error_is_surfaced(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        def boom(client, target_date=None):
            raise RuntimeError("no session")
        monkeypatch.setattr(server, "get_meal_names", boom)
        out = asyncio.run(server.mfp_list_meals(server.ListMealsInput()))
        assert out.startswith("Error listing meals") and "no session" in out
