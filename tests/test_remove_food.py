"""Tests for mfp_remove_food_from_diary.

Pure: the network is faked. The tool has two modes that use two different id
spaces, and its documentation describes both. These pin what the docs say:
which id `entry_id` takes and what an unknown one returns, how name matching
and the meal filter behave, the max_matches cap, and what a caller sees when
nothing matches or a removal fails part-way through.

DIARY_PAGE and CSRF_PAGE are written by hand to the shape the parsers expect.
They are not captured MyFitnessPal markup, so they pin the parsers' contract,
not the live page.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import server  # noqa: E402

BASE = "https://www.myfitnesspal.com/"

ENTRIES = [
    {"entry_id": "101", "name": "Generic - Banana, 100 g", "meal": "Breakfast"},
    {"entry_id": "102", "name": "Banana bread, 1 slice", "meal": "Snacks"},
    {"entry_id": "103", "name": "Energy gel, 1 sachet", "meal": "During Ride"},
    {"entry_id": "104", "name": "BANANA chips, 30 g", "meal": "Snacks"},
]

DIARY_PAGE = """
<table>
  <tr class="meal_header"><td class="first alt">Breakfast</td></tr>
  <tr><td class="first alt">
    <a href="#" data-food-entry-id="101" class="js-show-edit-food">Generic - Banana, 100 g</a>
  </td></tr>
  <tr class="meal_header"><td class="first alt">During Ride</td></tr>
  <tr><td class="first alt">
    <a href="#" data-food-entry-id="103" class="js-show-edit-food">Energy gel, 1 sachet</a>
  </td></tr>
</table>
"""

CSRF_PAGE = '<html><head><meta name="csrf-token" content="tok-123"></head></html>'


class _Response:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _Session:
    """Records every request; answers DELETEs with `delete_status`."""

    def __init__(self, *, delete_status=204, page=""):
        self.delete_status = delete_status
        self.page = page
        self.calls = []
        self.headers_sent = []

    def delete(self, url, **kwargs):
        self.calls.append(("DELETE", url))
        return _Response(self.delete_status)

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return _Response(200, self.page)

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        self.headers_sent.append(kwargs.get("headers") or {})
        return _Response(self.delete_status)


class _Client:
    BASE_URL_SECURE = BASE

    def __init__(self, session):
        self.session = session


def _run(**fields):
    return asyncio.run(server.mfp_remove_food_from_diary(server.RemoveFoodFromDiaryInput(**fields)))


@pytest.fixture
def by_id(monkeypatch):
    """Tool wired to a fake v2 API. Any use of the by-name path is recorded in
    `calls`, so a test that asserts the exact calls also proves it stayed out."""
    session = _Session()
    monkeypatch.setattr(server, "get_mfp_client", lambda: _Client(session))
    monkeypatch.setattr(server, "_mfp_api_headers", lambda client: {})
    monkeypatch.setattr(
        server,
        "list_diary_entries",
        lambda client, day: session.calls.append(("SEARCH", str(day))) or [],
    )
    monkeypatch.setattr(
        server,
        "remove_food_entry",
        lambda client, entry_id: session.calls.append(("PAGE-DELETE", entry_id)),
    )
    return session


@pytest.fixture
def by_name(monkeypatch):
    """Tool wired to a fixed day of entries. Records the days searched, the page
    ids removed, and any (unexpected) v2 delete."""
    rec = {"entries": [dict(e) for e in ENTRIES], "searched": [], "removed": [], "v2": []}
    rec["fail_on"] = None

    def fake_list(client, target_date):
        rec["searched"].append(target_date)
        return [dict(e) for e in rec["entries"]]

    def fake_remove(client, entry_id):
        if entry_id == rec["fail_on"]:
            raise RuntimeError(f"Remove failed for entry {entry_id}: HTTP 500")
        rec["removed"].append(entry_id)

    monkeypatch.setattr(server, "get_mfp_client", lambda: object())
    monkeypatch.setattr(server, "list_diary_entries", fake_list)
    monkeypatch.setattr(server, "remove_food_entry", fake_remove)
    monkeypatch.setattr(
        server, "remove_diary_entry_v2", lambda client, entry_id: rec["v2"].append(entry_id)
    )
    return rec


class TestByEntryId:
    V2_URL = f"{server.MFP_API_BASE}/v2/diary/0a1b-uuid"

    def test_deletes_exactly_that_v2_entry(self, by_id):
        out = json.loads(_run(entry_id="0a1b-uuid"))
        assert by_id.calls == [("DELETE", self.V2_URL)]
        assert out["success"] is True
        assert out["removed"] == [{"entry_id": "0a1b-uuid"}]

    def test_entry_id_wins_over_the_name_fields(self, by_id):
        out = json.loads(_run(entry_id="0a1b-uuid", name_contains="banana", meal="Snacks"))
        assert out["removed"] == [{"entry_id": "0a1b-uuid"}]
        # No diary search and no page-id delete: only the one v2 call.
        assert by_id.calls == [("DELETE", self.V2_URL)]

    def test_an_id_the_server_rejects_reports_its_http_status(self, by_id):
        # 404 is what MyFitnessPal answered live for an id it no longer had.
        by_id.delete_status = 404
        assert _run(entry_id="gone-id") == (
            "Error removing food: Remove failed for entry gone-id: HTTP 404"
        )

    def test_date_is_echoed_but_not_used_to_find_the_entry(self, by_id):
        out = json.loads(_run(entry_id="0a1b-uuid", date="2026-01-02"))
        assert out["date"] == "2026-01-02"
        assert by_id.calls == [("DELETE", self.V2_URL)]

    def test_an_impossible_date_is_refused_before_anything_is_deleted(self, by_id):
        out = _run(entry_id="0a1b-uuid", date="2026-02-30")
        assert out.startswith("Error removing food:")
        assert by_id.calls == []


class TestByName:
    def test_removes_the_first_match_only_by_default(self, by_name):
        out = json.loads(_run(name_contains="banana"))
        assert by_name["removed"] == ["101"]
        assert by_name["v2"] == []
        assert out["removed"] == [
            {"entry_id": "101", "name": "Generic - Banana, 100 g", "meal": "Breakfast"}
        ]
        assert out["matched_count"] == 3
        assert out["remaining_matches_skipped"] == 2

    def test_name_match_ignores_case_on_both_sides(self, by_name):
        # Upper-case text against a mixed-case line, lower-case text against an
        # upper-case line.
        _run(name_contains="BANANA BREAD")
        _run(name_contains="banana chips")
        assert by_name["removed"] == ["102", "104"]

    def test_max_matches_takes_entries_in_diary_order(self, by_name):
        out = json.loads(_run(name_contains="banana", max_matches=2))
        assert by_name["removed"] == ["101", "102"]
        assert out["remaining_matches_skipped"] == 1

    def test_the_whole_line_is_matched_including_the_serving(self, by_name):
        _run(name_contains="1 slice")
        assert by_name["removed"] == ["102"]

    def test_meal_filter_is_a_case_insensitive_partial_match(self, by_name):
        _run(name_contains="banana", meal="snack", max_matches=5)
        assert by_name["removed"] == ["102", "104"]
        by_name["removed"].clear()
        _run(name_contains="banana", meal="SNACKS", max_matches=5)
        assert by_name["removed"] == ["102", "104"]

    def test_meal_filter_accepts_a_custom_meal(self, by_name):
        _run(name_contains="gel", meal="during ride")
        assert by_name["removed"] == ["103"]

    def test_partial_meal_name_also_matches_a_longer_meal_name(self, by_name):
        by_name["entries"] = [
            {"entry_id": "201", "name": "Soup, 1 bowl", "meal": "Second Lunch"},
            {"entry_id": "202", "name": "Soup, 1 bowl", "meal": "Lunch"},
        ]
        out = json.loads(_run(name_contains="soup", meal="lunch"))
        assert by_name["removed"] == ["201"]
        assert out["matched_count"] == 2

    def test_no_match_deletes_nothing(self, by_name):
        out = json.loads(_run(name_contains="pizza", meal="Snacks"))
        assert by_name["removed"] == []
        assert out["success"] is False
        assert out["removed"] == []
        assert "pizza" in out["message"] and "Snacks" in out["message"]

    def test_an_unreadable_page_looks_like_no_match(self, by_name):
        # list_diary_entries returns nothing for a page it cannot parse (a login
        # page, for instance), and the tool cannot tell that from an empty day.
        by_name["entries"] = []
        out = json.loads(_run(name_contains="banana"))
        assert out["success"] is False and out["removed"] == []

    def test_a_failure_part_way_reports_only_the_error(self, by_name):
        by_name["fail_on"] = "102"
        out = _run(name_contains="banana", max_matches=3)
        assert out == "Error removing food: Remove failed for entry 102: HTTP 500"
        # 101 was already removed and stays removed; 104 was never attempted.
        assert by_name["removed"] == ["101"]

    def test_searches_the_given_day(self, by_name):
        _run(name_contains="banana", date="2026-01-02")
        assert by_name["searched"] == [date(2026, 1, 2)]

    def test_searches_today_when_no_date_is_given(self, by_name):
        before = date.today()
        _run(name_contains="banana")
        assert by_name["searched"][0] in (before, date.today())


class TestInput:
    def test_neither_id_nor_name_is_an_error(self, by_name):
        assert _run(meal="Snacks") == (
            "Error removing food: provide either entry_id or name_contains"
        )
        assert by_name["searched"] == [] and by_name["removed"] == [] and by_name["v2"] == []

    def test_max_matches_defaults_to_one_and_stops_at_fifty(self):
        assert server.RemoveFoodFromDiaryInput().max_matches == 1
        assert server.RemoveFoodFromDiaryInput(max_matches=50).max_matches == 50
        for bad in (0, 51):
            with pytest.raises(ValidationError):
                server.RemoveFoodFromDiaryInput(max_matches=bad)


class TestListDiaryEntries:
    def test_reads_each_entry_line_with_its_meal_and_page_id(self):
        session = _Session(page=DIARY_PAGE)
        entries = server.list_diary_entries(_Client(session), date(2026, 1, 2))
        assert session.calls == [("GET", f"{BASE}food/diary?date=2026-01-02")]
        assert entries == [
            {"entry_id": "101", "name": "Generic - Banana, 100 g", "meal": "Breakfast"},
            {"entry_id": "103", "name": "Energy gel, 1 sachet", "meal": "During Ride"},
        ]

    def test_a_page_without_entries_gives_an_empty_list(self):
        session = _Session(page="<html><body>Log in</body></html>")
        assert server.list_diary_entries(_Client(session), date(2026, 1, 2)) == []


class TestRemoveFoodEntry:
    """The by-name path deletes through the diary page's own endpoint."""

    def test_deletes_by_page_id_with_the_page_csrf_token(self):
        session = _Session(delete_status=302, page=CSRF_PAGE)
        server.remove_food_entry(_Client(session), "101")
        assert session.calls == [
            ("GET", f"{BASE}food/diary"),
            ("DELETE", f"{BASE}food/remove/101"),
        ]
        assert session.headers_sent[0]["X-CSRF-Token"] == "tok-123"

    def test_a_server_error_is_raised(self):
        session = _Session(delete_status=500, page=CSRF_PAGE)
        with pytest.raises(RuntimeError, match="Remove failed for entry 101: HTTP 500"):
            server.remove_food_entry(_Client(session), "101")

    def test_no_csrf_token_means_no_delete(self):
        session = _Session(page="<html></html>")
        with pytest.raises(RuntimeError, match="csrf-token"):
            server.remove_food_entry(_Client(session), "101")
        assert [verb for verb, _ in session.calls] == ["GET"]


class TestDiaryReadHasNoIds:
    def test_mfp_get_diary_entries_carry_no_id(self):
        # The docs send callers to mfp_get_food_entries for ids because the
        # diary read has none. If this starts failing, update those docs.
        entry = SimpleNamespace(
            name="Banana", short_name="Banana", quantity=1, unit="g", totals={"calories": 89}
        )
        assert not {"id", "entry_id"} & set(server.format_meal_entry(entry))
