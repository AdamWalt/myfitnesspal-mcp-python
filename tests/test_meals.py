"""Tests for account-aware meal resolution (issue #12).

Pure — no network. A fake client's session serves a diary page whose
`tr.meal_header` rows are the account's meals. The real risk this guards: MFP
silently files an unrecognized meal_name under a default meal instead of
erroring, so entries get mis-logged on accounts with renamed/localized/custom
meals. The name that is posted must be the account's own spelling.
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


def _diary_html(names):
    """A diary page reduced to what the scrape reads: one header row per meal."""
    rows = "".join(
        f'<tr class="meal_header"><td class="first alt">{n}</td><td class="alt">Calories</td></tr>'
        f'<tr><td class="first alt">some food</td></tr>'
        for n in names
    )
    return f"<html><body><table>{rows}</table></body></html>".encode()


class _Page:
    def __init__(self, status, content=b""):
        self.status_code = status
        self.content = content


class _FakeClient:
    """Serves the diary page; counts how often it is fetched."""

    user_id = "meals-test"

    def __init__(self, names, status=200):
        self.gets = []
        outer = self

        class _Session:
            def get(self, url, params=None, timeout=None):
                outer.gets.append((url, params))
                return _Page(status, _diary_html(names))

        self.session = _Session()


NAMES = ["Breakfast", "Lunch", "Dinner", "Snacks", "Supplements", "During Ride"]


class TestResolveMeal:
    def test_matches_case_insensitively_and_returns_account_spelling(self):
        assert server._resolve_meal("breakfast", NAMES) == "Breakfast"
        assert server._resolve_meal("SUPPLEMENTS", NAMES) == "Supplements"
        assert server._resolve_meal("  during ride  ", NAMES) == "During Ride"

    def test_returns_whatever_spelling_the_account_uses(self):
        # An account that really does name its meals in lower case keeps them so.
        assert server._resolve_meal("Lunch", ["breakfast", "lunch"]) == "lunch"

    def test_no_match_raises_and_names_the_options(self):
        # The localized case from the issue: "Breakfast" matches nothing.
        with pytest.raises(RuntimeError) as ei:
            server._resolve_meal("Breakfast", ["Café da manhã", "Almoço", "Jantar"])
        msg = str(ei.value)
        assert "Café da manhã" in msg
        assert "mfp_list_meals" in msg

    def test_non_ascii_names_match_case_insensitively(self):
        assert server._resolve_meal("café da manhã", ["Café da manhã", "Almoço"]) == "Café da manhã"
        assert server._resolve_meal("ALMOÇO", ["Café da manhã", "Almoço"]) == "Almoço"

    def test_empty_meal_raises(self):
        with pytest.raises(RuntimeError):
            server._resolve_meal("", NAMES)

    def test_singular_plural_slip_is_tolerated(self):
        # LLMs/users often say "snack" (singular) for the "Snacks" meal.
        assert server._resolve_meal("snack", ["Breakfast", "Snacks"]) == "Snacks"
        assert server._resolve_meal("snacks", ["Breakfast", "Snack"]) == "Snack"

    def test_empty_meal_names_gives_a_clear_error(self):
        with pytest.raises(RuntimeError, match="Could not read this account's meals"):
            server._resolve_meal("breakfast", [])

    def test_matching_is_robust_to_stored_whitespace(self):
        assert server._resolve_meal("snacks", ["  Snacks  "]) == "  Snacks  "


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _AddClient:
    """Fake client for add_food_to_diary: diary page for meals + POST capture."""

    access_token = "t"
    user_id = "add-test"

    def __init__(self, names):
        self.posted = None
        outer = self

        class _Session:
            def get(self, url, params=None, timeout=None):
                return _Page(200, _diary_html(names))

            def post(self, url, headers=None, data=None, timeout=None):
                outer.posted = json.loads(data)
                return _Resp(201, {"items": [{"id": "entry-1"}]})

        self.session = _Session()


class TestAddFoodResolution:
    """The actual #12 fix: resolution is wired into the diary POST."""

    def _patch_food(self, monkeypatch):
        monkeypatch.setattr(server, "get_food_v2", lambda client, mfp_id: {"id": "1", "version": "2"})
        monkeypatch.setattr(server, "select_serving_size", lambda food, unit: {"value": 1.0, "unit": "g"})
        server._MEAL_NAMES_CACHE.clear()

    def test_posts_the_accounts_own_spelling(self, monkeypatch):
        self._patch_food(monkeypatch)
        client = _AddClient(["Breakfast", "Supplements"])
        entry_id, resolved = server.add_food_to_diary(client, "1", "SUPPLEMENTS", date(2026, 1, 1), 1.0)
        assert entry_id == "entry-1"
        assert resolved == "Supplements"
        # Exactly as the account defines it — not the caller's or a lowercased form.
        assert client.posted["items"][0]["meal_name"] == "Supplements"

    def test_non_first_default_meal_is_posted_by_name(self, monkeypatch):
        # A misfile lands in the FIRST meal, so the check that matters is a later one.
        self._patch_food(monkeypatch)
        client = _AddClient(["Breakfast", "Lunch", "Dinner", "Snacks"])
        _, resolved = server.add_food_to_diary(client, "1", "dinner", date(2026, 1, 1), 1.0)
        assert resolved == "Dinner"
        assert client.posted["items"][0]["meal_name"] == "Dinner"

    def test_unknown_meal_raises_before_any_post(self, monkeypatch):
        self._patch_food(monkeypatch)
        client = _AddClient(["Breakfast", "Lunch"])
        with pytest.raises(RuntimeError, match="not one of this account"):
            server.add_food_to_diary(client, "1", "NotAMeal", date(2026, 1, 1), 1.0)
        assert client.posted is None  # refused, nothing logged


class TestGetMealNames:
    def setup_method(self):
        server._MEAL_NAMES_CACHE.clear()

    def test_reads_headers_in_order_with_the_accounts_spelling(self):
        client = _FakeClient(["Breakfast", "Lunch", "During Ride"])
        assert server.get_meal_names(client) == ["Breakfast", "Lunch", "During Ride"]

    def test_requests_the_diary_page_for_the_date(self):
        client = _FakeClient(["Breakfast"])
        server.get_meal_names(client, date(2026, 3, 9))
        url, params = client.gets[0]
        assert url.endswith("/food/diary")
        assert params == {"date": "2026-03-09"}

    def test_html_entities_are_decoded(self):
        client = _FakeClient(["Pre &amp; Post"])
        assert server.get_meal_names(client) == ["Pre & Post"]

    def test_second_call_uses_cache_and_skips_the_fetch(self):
        client = _FakeClient(["Breakfast", "Lunch"])
        assert server.get_meal_names(client) == ["Breakfast", "Lunch"]
        assert server.get_meal_names(client) == ["Breakfast", "Lunch"]
        assert len(client.gets) == 1  # fetched once, served from cache after

    def test_empty_result_is_not_cached(self):
        # e.g. an expired session returning a login page: no meal headers.
        client = _FakeClient([])
        assert server.get_meal_names(client) == []
        assert server.get_meal_names(client) == []
        assert len(client.gets) == 2  # retried, not pinned to [] for the TTL

    def test_http_error_raises(self):
        client = _FakeClient(["Breakfast"], status=500)
        with pytest.raises(RuntimeError, match="Could not load the diary page"):
            server.get_meal_names(client)


class TestListMealsTool:
    def _patch(self, monkeypatch, names):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(server, "get_meal_names", lambda client, target_date=None: names)

    def test_markdown_lists_custom_meals(self, monkeypatch):
        self._patch(monkeypatch, ["Breakfast", "During Ride"])
        out = asyncio.run(server.mfp_list_meals(server.ListMealsInput()))
        assert out.startswith("## Meals")
        assert "- During Ride" in out

    def test_json(self, monkeypatch):
        self._patch(monkeypatch, ["Breakfast", "Lunch"])
        out = json.loads(asyncio.run(
            server.mfp_list_meals(server.ListMealsInput(response_format="json"))
        ))
        assert out["meals"] == ["Breakfast", "Lunch"]

    def test_empty_list_says_so_instead_of_a_bare_heading(self, monkeypatch):
        self._patch(monkeypatch, [])
        out = asyncio.run(server.mfp_list_meals(server.ListMealsInput()))
        assert "No meals found" in out
        as_json = json.loads(asyncio.run(
            server.mfp_list_meals(server.ListMealsInput(response_format="json"))
        ))
        assert as_json["meals"] == [] and "No meals found" in as_json["message"]

    def test_error_is_surfaced(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        def boom(client, target_date=None):
            raise RuntimeError("no session")
        monkeypatch.setattr(server, "get_meal_names", boom)
        out = asyncio.run(server.mfp_list_meals(server.ListMealsInput()))
        assert out.startswith("Error listing meals") and "no session" in out
