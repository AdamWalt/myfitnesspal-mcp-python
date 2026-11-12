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
