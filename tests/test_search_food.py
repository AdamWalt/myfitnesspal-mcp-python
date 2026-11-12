"""Unit tests for mfp_search_food's unit-aware search (issue #25).

Pure — no network. A fake client's session returns canned HTML for the search
form (CSRF token) and the results page. The results fixture includes a
kilojoules item, which is exactly what crashed the old library parser
(`float("649 kilojoules")`).
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import server  # noqa: E402


FORM_HTML = (
    b'<html><body><form>'
    b'<input type="hidden" name="authenticity_token" value="TOK123">'
    b'</form></body></html>'
)

RESULTS_HTML = (
    "<html><body>Matching Foods:<ul>"
    '<li class="matched-food">'
    '  <div class="search-title-container"><a data-external-id="111">Banana</a></div>'
    '  <p class="search-nutritional-info">Generic, 1 medium, 105 calories</p>'
    "</li>"
    '<li class="matched-food">'
    '  <div class="search-title-container"><a data-external-id="222">Weet-Bix</a></div>'
    '  <div class="verified verified-list-icon"></div>'
    '  <p class="search-nutritional-info">Sanitarium, 2 biscuits, 649 kilojoules</p>'
    "</li>"
    '<li class="matched-food">'
    '  <div class="search-title-container"><a data-external-id="333">Apple</a></div>'
    '  <p class="search-nutritional-info">1 medium, 95 calories</p>'
    "</li>"
    "</ul></body></html>"
).encode()


class _FakeResp:
    def __init__(self, status=200, content=b""):
        self.status_code = status
        self.content = content


class _FakeSession:
    def __init__(self, get_resp, post_resp):
        self._get, self._post = get_resp, post_resp
        self.posted = None

    def get(self, url, timeout=None):
        return self._get

    def post(self, url, data=None, timeout=None):
        self.posted = data
        return self._post


class _FakeClient:
    def __init__(self, get_resp, post_resp):
        self.session = _FakeSession(get_resp, post_resp)


def _client(results_html=RESULTS_HTML, form_html=FORM_HTML, results_status=200, form_status=200):
    return _FakeClient(_FakeResp(form_status, form_html), _FakeResp(results_status, results_html))


class TestParseEnergy:
    @pytest.mark.parametrize("text,expected", [
        ("105 calories", (105.0, "calories")),
        ("649 kilojoules", (649.0, "kilojoules")),
        ("649 kJ", (649.0, "kilojoules")),
        ("105 kcal", (105.0, "calories")),
        # full info line: energy is the last unit-tagged number, not the serving
        ("Generic, 1 medium, 95 calories", (95.0, "calories")),
        # thousands separator must not truncate (4-digit kJ is routine)
        ("Brand, 1 serving, 1,380 calories", (1380.0, "calories")),
        ("Sanitarium, 2 biscuits, 3,500 kilojoules", (3500.0, "kilojoules")),
        ("88", (None, None)),          # no unit -> not an energy value (e.g. a serving number)
        ("", (None, None)),
        (None, (None, None)),
        ("no numbers here", (None, None)),
    ])
    def test_cases(self, text, expected):
        assert server._parse_search_energy(text) == expected


class TestSearchFood:
    def test_parses_both_units_without_crashing(self):
        results = server.search_food(_client(), "x", limit=10)
        assert [r["mfp_id"] for r in results] == ["111", "222", "333"]
        banana, weetbix, apple = results
        assert (banana["name"], banana["brand"]) == ("Banana", "Generic")
        assert (banana["energy"], banana["energy_unit"]) == (105.0, "calories")
        # the kilojoules row — the one that used to raise
        assert (weetbix["energy"], weetbix["energy_unit"]) == (649.0, "kilojoules")
        assert weetbix["verified"] is True
        assert banana["verified"] is False
        # two-part info line -> no brand, energy still parsed
        assert apple["brand"] == "" and apple["energy"] == 95.0

    def test_limit_is_respected(self):
        results = server.search_food(_client(), "x", limit=2)
        assert [r["mfp_id"] for r in results] == ["111", "222"]

    def test_post_sends_token_and_query(self):
        client = _client()
        server.search_food(client, "banana", limit=10)
        posted = client.session.posted
        assert posted["authenticity_token"] == "TOK123"
        assert posted["search"] == "banana"
        assert posted["meal"] == "0"
        assert posted["date"]  # today's date, non-empty

    def test_missing_csrf_token_raises(self):
        client = _client(form_html=b"<html><body>no token here</body></html>")
        with pytest.raises(RuntimeError, match="CSRF token"):
            server.search_food(client, "x", limit=10)

    def test_no_results_returns_empty_list(self):
        # A 200 with no matched-food items is an empty search, not an error.
        client = _client(results_html=b"<html><body>No matches found</body></html>")
        assert server.search_food(client, "x", limit=10) == []

    def test_post_non_200_raises(self):
        client = _client(results_status=500)
        with pytest.raises(RuntimeError, match="search request failed"):
            server.search_food(client, "x", limit=10)

    def test_form_page_error_raises(self):
        client = _client(form_status=500)
        with pytest.raises(RuntimeError, match="food-search page"):
            server.search_food(client, "x", limit=10)

    def test_four_digit_kilojoules_not_truncated(self):
        html = (
            "<html><body>Matching Foods:<ul>"
            '<li class="matched-food">'
            '  <div class="search-title-container"><a data-external-id="999">Lamington</a></div>'
            '  <p class="search-nutritional-info">Sara Lee, 1 serving, 3,500 kilojoules</p>'
            "</li></ul></body></html>"
        ).encode()
        results = server.search_food(_client(results_html=html), "x", limit=10)
        assert results[0]["energy"] == 3500.0  # not 500
        assert results[0]["energy_unit"] == "kilojoules"
        assert results[0]["brand"] == "Sara Lee"


class TestSearchTool:
    def _run(self, monkeypatch, results, **kwargs):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(server, "search_food", lambda client, query, limit: results[:limit])
        params = server.SearchFoodInput(query="banana", **kwargs)
        return asyncio.run(server.mfp_search_food(params))

    def test_json_shape(self, monkeypatch):
        rows = [
            {"mfp_id": "1", "name": "Banana", "brand": "", "energy": 105.0,
             "energy_unit": "calories", "verified": False},
            {"mfp_id": "2", "name": "Weet-Bix", "brand": "Sanitarium", "energy": 649.0,
             "energy_unit": "kilojoules", "verified": True},
        ]
        out = json.loads(self._run(monkeypatch, rows, response_format="json"))
        assert out["count"] == 2 and out["query"] == "banana"
        assert out["results"][1]["energy_unit"] == "kilojoules"

    def test_error_is_surfaced(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        def boom(client, query, limit):
            raise RuntimeError("boom")
        monkeypatch.setattr(server, "search_food", boom)
        out = asyncio.run(server.mfp_search_food(server.SearchFoodInput(query="x")))
        assert out.startswith("Error searching foods") and "boom" in out
