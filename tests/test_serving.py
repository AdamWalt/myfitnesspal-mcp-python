"""
Tests for the pure logic behind diary writes.

Serving-size selection needs no network access or MyFitnessPal credentials,
so these run anywhere.
"""

import pytest

from mfp_mcp import server


@pytest.fixture
def food():
    """A food with several serving sizes, shaped like the v2 API returns them."""
    return {
        "id": "167417344692029",
        "version": "198470069641213",
        "description": "Grilled Chicken Breast",
        "serving_sizes": [
            {
                "id": "65976937717733",
                "value": 4.0,
                "unit": "oz",
                "nutrition_multiplier": 1.13,
                "gram_weight": 113.0,
                "index": 0,
            },
            {
                "id": "65979076779877",
                "value": 1.0,
                "unit": "medium breast",
                "nutrition_multiplier": 1.2,
                "gram_weight": 120.0,
                "index": 1,
            },
            {
                "id": "66528832593765",
                "value": 1.0,
                "unit": "cup, cooked, diced",
                "nutrition_multiplier": 1.35,
                "gram_weight": 135.0,
                "index": 2,
            },
        ],
    }


class TestSelectServingSize:
    def test_defaults_to_first_serving_when_no_unit_given(self, food):
        assert server.select_serving_size(food)["unit"] == "oz"

    def test_matches_unit_exactly(self, food):
        assert server.select_serving_size(food, "medium breast")["unit"] == "medium breast"

    def test_matching_is_case_insensitive(self, food):
        assert server.select_serving_size(food, "MEDIUM BREAST")["unit"] == "medium breast"

    def test_matching_ignores_surrounding_whitespace(self, food):
        assert server.select_serving_size(food, "  oz  ")["unit"] == "oz"

    def test_matches_on_substring(self, food):
        # "cup" should find "cup, cooked, diced"
        assert server.select_serving_size(food, "cup")["unit"] == "cup, cooked, diced"

    def test_falls_back_to_default_when_unit_unknown(self, food):
        # An unmatched unit must not raise - logging the food matters more than
        # the exact serving, and the caller is warned in the logs.
        assert server.select_serving_size(food, "furlong")["unit"] == "oz"

    def test_returns_only_fields_the_diary_api_permits(self, food):
        # MFP rejects the whole request if id/gram_weight/index are included.
        assert set(server.select_serving_size(food)) == {
            "value",
            "unit",
            "nutrition_multiplier",
        }

    def test_carries_through_the_nutrition_multiplier(self, food):
        assert server.select_serving_size(food, "medium breast")["nutrition_multiplier"] == 1.2

    def test_raises_when_food_has_no_serving_sizes(self):
        with pytest.raises(RuntimeError, match="no serving sizes"):
            server.select_serving_size({"id": "123", "serving_sizes": []})

    def test_raises_when_serving_sizes_key_is_absent(self):
        with pytest.raises(RuntimeError, match="no serving sizes"):
            server.select_serving_size({"id": "123"})
