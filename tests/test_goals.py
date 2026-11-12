"""Tests for per-day nutrient goals (issue #14).

Mostly pure — a captured weekly goal item is fed to the payload builder and the
read-modify-write is exercised with a fake client/session. The real risk these
guard: the write is a full-replace POST, so a careless edit would wipe the
untouched days, the micronutrient targets, or the exercise split. Setting one
weekday must leave the other six and the default goal exactly as they were.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import server  # noqa: E402

TODAY = datetime.date.today().strftime("%Y-%m-%d")


def _goal(day, energy, carbs, protein, fat, group_id=0):
    """One weekday goal shaped like the live v2 payload."""
    return {
        "day_of_week": day,
        "group_id": group_id,
        "energy": {"value": energy, "unit": "calories"},
        "carbohydrates": carbs,
        "protein": protein,
        "fat": fat,
        "saturated_fat": 26,
        "sodium": 2300,
        "potassium": 3500,
        "fiber": 38,
        "sugar": 88,
        "cholesterol": 300,
        "vitamin_a": 100,
        "vitamin_c": 100,
        "calcium": 100,
        "iron": 100,
        "assign_exercise_energy": "nutrient_goal",
        "exercise_carbohydrates_percentage": 43,
        "exercise_fat_percentage": 26,
        "exercise_protein_percentage": 31,
    }


def current_item():
    """A full weekly goal item as GET /v2/nutrient-goals returns it."""
    days = [
        _goal(d, 2359, 257, 182, 67)
        for d in ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday")
    ]
    days.append(_goal("sunday", 2799, 322, 200, 79, group_id=1))
    default = {
        "energy": {"value": 2359, "unit": "calories"},
        "carbohydrates": 257,
        "protein": 182,
        "fat": 67,
        "saturated_fat": 26,
        "sodium": 2300,
        "potassium": 3500,
        "fiber": 38,
        "sugar": 88,
        "cholesterol": 300,
        "vitamin_a": 100,
        "vitamin_c": 100,
        "calcium": 100,
        "iron": 100,
        "assign_exercise_energy": "nutrient_goal",
    }
    return {
        "valid_from": "2026-11-01",
        "valid_to": "2100-01-01",
        "daily_goals": days,
        "default_group_id": 0,
        "default_goal": default,
        "updated_at": "2026-11-01T00:00:00+0000",
    }


def _day(item, name):
    return next(g for g in item["daily_goals"] if g["day_of_week"] == name)


class TestApplyOneGoal:
    def test_calories_sets_energy_value_and_default_unit(self):
        g = {}
        server._apply_one_goal(g, {"calories": 2000})
        assert g["energy"] == {"value": 2000, "unit": "calories"}

    def test_calories_preserves_existing_unit(self):
        g = {"energy": {"value": 1, "unit": "kilojoules"}}
        server._apply_one_goal(g, {"calories": 9872})
        assert g["energy"] == {"value": 9872, "unit": "kilojoules"}

    def test_only_provided_macros_change(self):
        g = {"carbohydrates": 100, "protein": 100, "fat": 100}
        server._apply_one_goal(g, {"protein": 200})
        assert g == {"carbohydrates": 100, "protein": 200, "fat": 100}


class TestBuildPayload:
    def test_flat_sets_default_and_every_day(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day=None, overrides={"calories": 2500}
        )["item"]
        assert item["default_goal"]["energy"]["value"] == 2500
        assert all(g["energy"]["value"] == 2500 for g in item["daily_goals"])

    def test_flat_only_calories_preserves_macros_and_micros(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day=None, overrides={"calories": 2500}
        )["item"]
        mon = _day(item, "monday")
        assert (mon["carbohydrates"], mon["protein"], mon["fat"]) == (257, 182, 67)
        assert mon["sodium"] == 2300 and mon["potassium"] == 3500
        assert mon["exercise_carbohydrates_percentage"] == 43

    def test_per_day_changes_only_that_day(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day="monday", overrides={"calories": 3000, "carbohydrates": 350}
        )["item"]
        mon, tue = _day(item, "monday"), _day(item, "tuesday")
        assert mon["energy"]["value"] == 3000 and mon["carbohydrates"] == 350
        assert tue["energy"]["value"] == 2359 and tue["carbohydrates"] == 257
        assert item["default_goal"]["energy"]["value"] == 2359  # default untouched

    def test_strips_server_fields_and_sets_valid_from(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day=None, overrides={"protein": 200}
        )["item"]
        assert "valid_to" not in item
        assert "default_group_id" not in item
        assert "updated_at" not in item
        assert all("group_id" not in g for g in item["daily_goals"])
        assert item["valid_from"] == TODAY

    def test_does_not_mutate_input(self):
        cur = current_item()
        server.build_nutrient_goals_payload(cur, day=None, overrides={"calories": 9999})
        assert _day(cur, "monday")["energy"]["value"] == 2359
        assert "valid_to" in cur and cur["valid_from"] == "2026-11-01"

    def test_missing_day_raises(self):
        item = current_item()
        item["daily_goals"] = [g for g in item["daily_goals"] if g["day_of_week"] != "monday"]
        with pytest.raises(RuntimeError, match="No monday entry"):
            server.build_nutrient_goals_payload(item, day="monday", overrides={"calories": 2500})


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _GoalsClient:
    """Fake client: GET returns a canned goals body, POST captures the payload."""

    access_token = "t"
    user_id = "u"

    def __init__(self, get_body, get_status=200, post_status=200, post_body=None):
        self.posted = None
        outer = self

        class _Session:
            def get(self, url, params=None, headers=None, timeout=None):
                return _Resp(get_status, get_body)

            def post(self, url, headers=None, data=None, timeout=None):
                outer.posted = json.loads(data)
                body = post_body
                if body is None:
                    body = {"item": json.loads(data)["item"]}
                return _Resp(post_status, body)

        self.session = _Session()


class TestFetchNutrientGoals:
    def test_returns_first_item(self):
        c = _GoalsClient({"items": [current_item()]})
        assert server.fetch_nutrient_goals(c)["valid_from"] == "2026-11-01"

    def test_empty_items_raises(self):
        c = _GoalsClient({"items": []})
        with pytest.raises(RuntimeError, match="no nutrient goal"):
            server.fetch_nutrient_goals(c)

    def test_http_error_raises(self):
        c = _GoalsClient({}, get_status=500)
        with pytest.raises(RuntimeError, match="Could not fetch nutrient goals"):
            server.fetch_nutrient_goals(c)


class TestSetNutrientGoals:
    def test_reads_modifies_and_posts(self):
        c = _GoalsClient({"items": [current_item()]})
        saved = server.set_nutrient_goals(c, day="monday", overrides={"calories": 3000})
        mon = _day(c.posted["item"], "monday")
        tue = _day(c.posted["item"], "tuesday")
        assert mon["energy"]["value"] == 3000
        assert tue["energy"]["value"] == 2359  # untouched day preserved
        assert c.posted["item"]["valid_from"] == TODAY
        assert "valid_to" not in c.posted["item"]
        assert saved["default_goal"]["energy"]["value"] == 2359

    def test_post_failure_raises(self):
        c = _GoalsClient(
            {"items": [current_item()]},
            post_status=422,
            post_body={"error_description": "bad"},
        )
        with pytest.raises(RuntimeError, match="Failed to update nutrition goals"):
            server.set_nutrient_goals(c, day=None, overrides={"calories": 2500})


class TestGoalWeekSummary:
    def test_monday_first_with_default_and_micros(self):
        s = server.goal_week_summary(current_item())
        assert list(s["days"].keys()) == list(server._WEEKDAYS)
        assert s["days"]["sunday"]["calories"] == 2799
        assert s["default"]["calories"] == 2359
        assert s["days"]["monday"]["sodium"] == 2300


class TestSetGoalsTool:
    def test_requires_at_least_one_field(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        out = asyncio.run(server.mfp_set_goals(server.SetGoalsInput()))
        assert out.startswith("Error: Please provide at least one goal")

    def test_success_reports_scope_and_applied(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(
            server, "set_nutrient_goals", lambda client, day, overrides: current_item()
        )
        out = json.loads(
            asyncio.run(server.mfp_set_goals(server.SetGoalsInput(calories=2500, day="monday")))
        )
        assert out["success"] is True
        assert out["scope"] == "monday"
        assert out["applied"] == {"calories": 2500}
        assert "monday" in out["goals"]["days"]

    def test_whole_week_scope_label(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(
            server, "set_nutrient_goals", lambda client, day, overrides: current_item()
        )
        out = json.loads(asyncio.run(server.mfp_set_goals(server.SetGoalsInput(protein=0))))
        # protein=0 is a real goal (ge=0), so it must be applied, not dropped.
        assert out["scope"] == "all_days"
        assert out["applied"] == {"protein": 0}

    def test_invalid_day_rejected(self):
        with pytest.raises(ValidationError):
            server.SetGoalsInput(calories=2500, day="funday")

    def test_day_is_normalized(self):
        assert server.SetGoalsInput(calories=2500, day="  Monday ").day == "monday"


class TestGetGoalsTool:
    def test_all_days_uses_full_week(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(
            server, "fetch_nutrient_goals", lambda client, on_date=None: current_item()
        )
        out = json.loads(
            asyncio.run(
                server.mfp_get_goals(server.GetGoalsInput(all_days=True, response_format="json"))
            )
        )
        assert out["default"]["calories"] == 2359
        assert out["days"]["sunday"]["calories"] == 2799
