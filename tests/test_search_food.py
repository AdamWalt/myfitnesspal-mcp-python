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


SEARCH_URL = "https://www.myfitnesspal.com/food/search"
LOGIN_URL = (
    "https://www.myfitnesspal.com/account/login"
    "?callbackUrl=https%3A%2F%2Fwww.myfitnesspal.com%2Ffood%2Fsearch"
)

# What a logged-out request really gets back (observed live): HTTP 200 on the
# login page, whose translation bundle contains the literal "Matching Foods:".
LOGIN_HTML = (
    b"<html><body><div id='__next'>Log in</div>"
    b'<script>{"food.matchingFoods":"Matching Foods:","login.title":"Log In"}</script>'
    b"</body></html>"
)

# A real search with no matches still renders the results scaffold.
EMPTY_RESULTS_HTML = (
    b"<html><body><div class='col-1' id='sort-block'>"
    b"<h4 class='secondary-title search_'>Matching Foods:</h4></div>"
    b"<p>No results found.</p></body></html>"
)


class _FakeResp:
    def __init__(self, status=200, content=b"", url=SEARCH_URL):
        self.status_code = status
        self.content = content
        self.url = url


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


def _client(results_html=RESULTS_HTML, form_html=FORM_HTML, results_status=200, form_status=200,
            results_url=SEARCH_URL, form_url=SEARCH_URL):
    return _FakeClient(
        _FakeResp(form_status, form_html, form_url),
        _FakeResp(results_status, results_html, results_url),
    )


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

    def test_calories_is_always_kcal_for_callers_of_the_old_schema(self):
        banana, weetbix, _ = server.search_food(_client(), "x", limit=10)
        assert banana["calories"] == 105.0  # kcal account value passes through
        # 649 kJ -> kcal; energy/energy_unit still carry the displayed kJ value
        assert weetbix["calories"] == round(649 / 4.184, 1) == 155.1
        assert (weetbix["energy"], weetbix["energy_unit"]) == (649.0, "kilojoules")

    def test_brand_with_a_comma_keeps_it(self):
        html = (
            "<html><body>Matching Foods:<ul>"
            '<li class="matched-food">'
            '  <div class="search-title-container"><a data-external-id="7">Soup</a></div>'
            '  <p class="search-nutritional-info">Foo, Inc., 1 cup, 120 calories</p>'
            "</li></ul></body></html>"
        ).encode()
        assert server.search_food(_client(results_html=html), "x", limit=10)[0]["brand"] == "Foo, Inc."

    def test_thousands_separator_in_the_serving_is_not_a_field_break(self):
        line = "Ben & Jerry's, 0.5 cup (1,000 g), 2,500 kilojoules"
        assert server._parse_search_brand(line) == "Ben & Jerry's"

    def test_brand_parsing_edge_cases(self):
        assert server._parse_search_brand("1 medium, 95 calories") == ""
        assert server._parse_search_brand("Generic, 1 medium, 105 calories") == "Generic"
        assert server._parse_search_brand("") == ""
        # Known limit: a comma inside the serving can't be told from one in the
        # brand, so the serving's first half lands in the brand.
        assert server._parse_search_brand("Generic, 1 cup, chopped, 120 calories") == "Generic, 1 cup"

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
        # A results page with no matched-food items is an empty search, not an error.
        client = _client(results_html=EMPTY_RESULTS_HTML)
        assert server.search_food(client, "x", limit=10) == []

    def test_login_page_on_search_raises_instead_of_zero_results(self):
        # An expired session is redirected to the login page, which is still a
        # 200 and even contains "Matching Foods:" (in its translation bundle).
        client = _client(results_html=LOGIN_HTML, results_url=LOGIN_URL)
        with pytest.raises(RuntimeError, match="login page"):
            server.search_food(client, "x", limit=10)

    def test_login_redirect_on_form_fetch_raises_auth_error(self):
        client = _client(form_html=LOGIN_HTML, form_url=LOGIN_URL)
        with pytest.raises(RuntimeError, match="login page"):
            server.search_food(client, "x", limit=10)
        assert client.session.posted is None  # never posted the query

    def test_200_without_a_results_section_raises(self):
        # Not a login redirect, but not a results page either: don't report 0 foods.
        client = _client(results_html=b"<html><body><h1>Something else</h1></body></html>")
        with pytest.raises(RuntimeError, match="search-results page"):
            server.search_food(client, "x", limit=10)

    def test_marker_text_inside_a_script_does_not_count_as_results(self):
        client = _client(results_html=LOGIN_HTML)  # same body, but no login URL
        with pytest.raises(RuntimeError, match="search-results page"):
            server.search_food(client, "x", limit=10)

    @pytest.mark.parametrize(
        "body",
        [
            # the id alone (e.g. an account whose heading is localized)
            b"<div id='sort-block'><h4>Alimentos encontrados:</h4></div>",
            # the heading alone (the id renamed)
            b"<div><h4>Matching Foods:</h4></div>",
            # the heading after a child element, i.e. not the first text node
            b"<h4>\n<b>3</b> Matching Foods:</h4>",
        ],
    )
    def test_either_results_marker_is_enough_for_an_empty_result(self, body):
        html = b"<html><body>" + body + b"<p>No results found.</p></body></html>"
        assert server.search_food(_client(results_html=html), "x", limit=10) == []

    @pytest.mark.parametrize("tag", ["script", "style", "noscript", "template", "textarea"])
    def test_marker_text_in_unrendered_elements_does_not_count(self, tag):
        html = f"<html><body><{tag}>Matching Foods:</{tag}><p>hi</p></body></html>".encode()
        with pytest.raises(RuntimeError, match="search-results page"):
            server.search_food(_client(results_html=html), "x", limit=10)

    def test_marker_text_in_the_page_title_does_not_count(self):
        html = b"<html><head><title>Matching Foods:</title></head><body><p>hi</p></body></html>"
        with pytest.raises(RuntimeError, match="search-results page"):
            server.search_food(_client(results_html=html), "x", limit=10)

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
