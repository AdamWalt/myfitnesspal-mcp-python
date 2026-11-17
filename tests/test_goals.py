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

    def test_calories_on_a_goal_whose_energy_is_null(self):
        g = {"energy": None, "protein": 100}
        server._apply_one_goal(g, {"calories": 2000})
        assert g["energy"] == {"value": 2000, "unit": "calories"}
        assert g["protein"] == 100  # no old energy to scale from

    def test_calories_converted_when_goal_is_kilojoules(self):
        # `calories` is always kcal; a kJ account keeps its unit, value converted.
        g = {"energy": {"value": 1, "unit": "kilojoules"}}
        server._apply_one_goal(g, {"calories": 2000})
        assert g["energy"] == {"value": round(2000 * 4.184), "unit": "kilojoules"}

    def test_only_provided_macros_change(self):
        g = {"carbohydrates": 100, "protein": 100, "fat": 100}
        server._apply_one_goal(g, {"protein": 200})
        assert g == {"carbohydrates": 100, "protein": 200, "fat": 100}

    def test_zero_is_written_not_skipped(self):
        g = {"protein": 150}
        server._apply_one_goal(g, {"protein": 0})
        assert g == {"protein": 0}

    def test_calories_only_rescales_macros_proportionally(self):
        # What main did via set_new_goal: keep the macro split when only energy moves.
        g = {"energy": {"value": 2000, "unit": "calories"},
             "carbohydrates": 250, "protein": 150, "fat": 60, "sodium": 2300}
        server._apply_one_goal(g, {"calories": 1800})
        assert g["energy"]["value"] == 1800
        assert (g["carbohydrates"], g["protein"], g["fat"]) == (225, 135, 54)
        assert g["sodium"] == 2300  # micronutrients are never rescaled

    def test_calories_with_any_macro_does_not_rescale(self):
        g = {"energy": {"value": 2000, "unit": "calories"},
             "carbohydrates": 250, "protein": 150, "fat": 60}
        server._apply_one_goal(g, {"calories": 1800, "protein": 180})
        assert (g["carbohydrates"], g["protein"], g["fat"]) == (250, 180, 60)

    def test_calories_only_rescale_uses_the_stored_unit(self):
        # 2000 kcal -> 8368 kJ; the ratio is taken in kJ against the stored kJ value.
        g = {"energy": {"value": 10460, "unit": "kilojoules"},  # 2500 kcal
             "carbohydrates": 300, "protein": 150, "fat": 80}
        server._apply_one_goal(g, {"calories": 2000})
        assert g["energy"] == {"value": 8368, "unit": "kilojoules"}
        assert (g["carbohydrates"], g["protein"], g["fat"]) == (240, 120, 64)

    def test_calories_only_without_a_previous_energy_leaves_macros(self):
        for prior in ({}, {"energy": {"value": 0, "unit": "calories"}}):
            g = {**prior, "carbohydrates": 250, "protein": 150, "fat": 60}
            server._apply_one_goal(g, {"calories": 1800})
            assert (g["carbohydrates"], g["protein"], g["fat"]) == (250, 150, 60)


class TestBuildPayload:
    def test_flat_sets_default_and_every_day(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day=None, overrides={"calories": 2500}
        )["item"]
        assert item["default_goal"]["energy"]["value"] == 2500
        assert all(g["energy"]["value"] == 2500 for g in item["daily_goals"])

    def test_flat_only_calories_rescales_macros_and_keeps_micros(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day=None, overrides={"calories": 2500}
        )["item"]
        mon = _day(item, "monday")
        ratio = 2500 / 2359
        assert (mon["carbohydrates"], mon["protein"], mon["fat"]) == (
            round(257 * ratio), round(182 * ratio), round(67 * ratio)
        ) == (272, 193, 71)
        assert mon["sodium"] == 2300 and mon["potassium"] == 3500
        assert mon["exercise_carbohydrates_percentage"] == 43
        # The default goal is rescaled with the days, not left at the old split.
        default = item["default_goal"]
        assert (default["carbohydrates"], default["protein"], default["fat"]) == (272, 193, 71)

    def test_per_day_calories_only_rescales_just_that_day(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day="monday", overrides={"calories": 2500}
        )["item"]
        mon, tue = _day(item, "monday"), _day(item, "tuesday")
        assert (mon["carbohydrates"], mon["protein"], mon["fat"]) == (272, 193, 71)
        assert (tue["carbohydrates"], tue["protein"], tue["fat"]) == (257, 182, 67)
        assert item["default_goal"]["carbohydrates"] == 257

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

    def test_flat_preserves_default_micros(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day=None, overrides={"calories": 2500}
        )["item"]
        assert item["default_goal"]["sodium"] == 2300
        assert item["default_goal"]["fiber"] == 38
        assert item["default_goal"]["energy"]["value"] == 2500

    def test_per_day_zero_is_written(self):
        item = server.build_nutrient_goals_payload(
            current_item(), day="monday", overrides={"protein": 0}
        )["item"]
        assert _day(item, "monday")["protein"] == 0
        assert _day(item, "tuesday")["protein"] == 182  # other days untouched

    def test_empty_goal_set_refused(self):
        with pytest.raises(RuntimeError, match="refusing to write"):
            server.build_nutrient_goals_payload(
                {"daily_goals": []}, day=None, overrides={"calories": 2500}
            )

    @pytest.mark.parametrize("day", ["monday", None])
    @pytest.mark.parametrize(
        "overrides",
        [{"calories": 3000}, {"protein": 200}, {"calories": 3000, "fat": 90}],
        ids=["calories-only", "macro-only", "calories-and-macro"],
    )
    def test_meal_goals_are_carried_through_untouched(self, day, overrides):
        """Per-meal goals ride along as they are on every goal — not cleared the
        way python-myfitnesspal's set_new_goal clears them, and not rescaled by
        a calories-only update. Their inner shape is opaque to this tool; the
        entries here are placeholders."""
        current = _with_meal_goals(current_item())
        before = _meal_goals_by_goal(current)

        item = server.build_nutrient_goals_payload(current, day=day, overrides=overrides)["item"]

        assert _meal_goals_by_goal(item) == before
        assert len(before) == 8  # seven days and the default goal
        assert _meal_goals_by_goal(current) == before  # and the input is left alone


def _with_meal_goals(item):
    """Give every goal in `item` its own, distinct per-meal goals."""
    for index, goal in enumerate(item["daily_goals"] + [item["default_goal"]]):
        goal["meal_goals"] = [
            {"meal_name": "Breakfast", "energy": {"value": 600 + index, "unit": "calories"}},
            {"meal_name": "Dinner", "energy": {"value": 900 + index, "unit": "calories"}},
        ]
    return item


def _meal_goals_by_goal(item):
    """Each goal's meal_goals as canonical JSON text: an exact, independent
    snapshot (a later mutation can't change it, and 600 != 600.0)."""
    return {
        goal.get("day_of_week", "default"): json.dumps(goal.get("meal_goals"), sort_keys=True)
        for goal in item["daily_goals"] + [item["default_goal"]]
    }


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
        self.get_params = None
        outer = self

        class _Session:
            def get(self, url, params=None, headers=None, timeout=None):
                outer.get_params = params
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

    def test_sends_date_param(self):
        c = _GoalsClient({"items": [current_item()]})
        server.fetch_nutrient_goals(c, datetime.date(2026, 3, 9))
        assert c.get_params == {"date": "2026-03-09"}


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

    @pytest.mark.parametrize("day", ["monday", None])
    def test_meal_goals_reach_the_post_body_unchanged(self, day):
        # The whole path, not just the builder: what was fetched is what is sent.
        fetched = _with_meal_goals(current_item())
        before = _meal_goals_by_goal(fetched)
        c = _GoalsClient({"items": [fetched]})
        server.set_nutrient_goals(c, day=day, overrides={"calories": 3000})
        assert _meal_goals_by_goal(c.posted["item"]) == before

    def test_post_failure_raises(self):
        c = _GoalsClient(
            {"items": [current_item()]},
            post_status=422,
            post_body={"error_description": "bad"},
        )
        with pytest.raises(RuntimeError, match="Failed to update nutrition goals"):
            server.set_nutrient_goals(c, day=None, overrides={"calories": 2500})

    def test_reread_fallback_when_post_omits_item(self):
        # If the POST response has no "item", fall back to a fresh GET.
        c = _GoalsClient({"items": [current_item()]}, post_body={})
        saved = server.set_nutrient_goals(c, day=None, overrides={"calories": 3000})
        assert saved["valid_from"] == "2026-11-01"  # came from the re-read GET

    def test_per_day_write_that_did_not_stick_raises(self):
        # e.g. a free account: the POST succeeds but the weekday comes back unchanged.
        c = _GoalsClient({"items": [current_item()]}, post_body={"item": current_item()})
        with pytest.raises(RuntimeError) as ei:
            server.set_nutrient_goals(c, day="monday", overrides={"calories": 3000})
        msg = str(ei.value)
        assert "did not keep the monday goal" in msg
        assert "monday energy: sent 3000, saved 2359" in msg and "Premium" in msg
        # The write was accepted, so the message must not imply nothing happened.
        assert "accepted the write" in msg and "mfp_get_goals" in msg

    def _saved_matching(self, **monday):
        """What MFP echoes for monday=3000 kcal, with optional deviations."""
        saved = current_item()
        mon = _day(saved, "monday")
        mon["energy"]["value"] = 3000.0
        mon["carbohydrates"], mon["protein"], mon["fat"] = 327.0, 231.0, 85.0
        mon.update(monday)
        return saved

    def _set_monday(self, saved):
        c = _GoalsClient({"items": [current_item()]}, post_body={"item": saved})
        return server.set_nutrient_goals(c, day="monday", overrides={"calories": 3000})

    def test_per_day_check_catches_a_macro_only_mismatch(self):
        # Energy kept, a macro not: comparing energy alone would miss this.
        with pytest.raises(RuntimeError, match="monday protein: sent 231, saved 200"):
            self._set_monday(self._saved_matching(protein=200.0))

    def test_per_day_check_tolerates_only_rounding(self):
        self._set_monday(self._saved_matching(protein=231.4))  # within 0.5 g
        with pytest.raises(RuntimeError, match="monday protein"):
            self._set_monday(self._saved_matching(protein=232.0))  # a real difference

    def test_per_day_check_catches_a_missing_saved_value(self):
        with pytest.raises(RuntimeError, match="monday fat: sent 85"):
            self._set_monday(self._saved_matching(fat=None))

    def test_per_day_check_catches_the_week_being_flattened(self):
        # A free account might apply the one value to every day: monday then
        # matches, and only the other days give it away.
        saved = self._saved_matching()
        tue = _day(saved, "tuesday")
        tue["energy"]["value"] = 3000.0
        with pytest.raises(RuntimeError) as ei:
            self._set_monday(saved)
        assert "tuesday energy: sent 2359, saved 3000" in str(ei.value)

    def test_per_day_check_catches_an_energy_unit_change(self):
        saved = self._saved_matching()
        _day(saved, "monday")["energy"]["unit"] = "kilojoules"
        with pytest.raises(RuntimeError, match="monday energy unit"):
            self._set_monday(saved)

    def test_per_day_write_passes_when_saved_matches_as_floats(self):
        # Live, MyFitnessPal echoes what was sent as floats (3000 -> 3000.0).
        saved = current_item()
        mon = _day(saved, "monday")
        mon["energy"]["value"] = 3000.0
        mon["carbohydrates"], mon["protein"], mon["fat"] = 327.0, 231.0, 85.0
        c = _GoalsClient({"items": [current_item()]}, post_body={"item": saved})
        out = server.set_nutrient_goals(c, day="monday", overrides={"calories": 3000})
        assert _day(out, "monday")["energy"]["value"] == 3000.0

    def test_whole_week_write_is_not_subject_to_the_per_day_check(self):
        # Flat writes work on free accounts (MFP may round them); never block those.
        c = _GoalsClient({"items": [current_item()]}, post_body={"item": current_item()})
        server.set_nutrient_goals(c, day=None, overrides={"calories": 3000})  # no raise


class TestGoalWeekSummary:
    def test_monday_first_with_default_and_micros(self):
        s = server.goal_week_summary(current_item())
        assert list(s["days"].keys()) == list(server._WEEKDAYS)
        assert s["days"]["sunday"]["energy"] == 2799
        assert s["default"]["energy"] == 2359
        assert s["days"]["monday"]["sodium"] == 2300

    def test_energy_is_labelled_with_its_unit_not_as_calories(self):
        item = current_item()
        for g in item["daily_goals"] + [item["default_goal"]]:
            g["energy"] = {"value": 9870, "unit": "kilojoules"}
        s = server.goal_week_summary(item)
        row = s["days"]["monday"]
        assert (row["energy"], row["energy_unit"]) == (9870, "kilojoules")
        assert "calories" not in row  # a kJ value must not sit under "calories"
        assert "9870 kilojoules" in server._goals_week_markdown("2026-11-15", s)


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
        assert out["default"]["energy"] == 2359
        assert out["default"]["energy_unit"] == "calories"
        assert out["days"]["sunday"]["energy"] == 2799

    def test_single_day_read_runs_off_the_event_loop(self, monkeypatch):
        import threading

        seen = {}

        class _Day:
            goals = {"calories": 2359}

        class _Client:
            def get_date(self, d):
                seen["thread"] = threading.current_thread()
                return _Day()

        monkeypatch.setattr(server, "get_mfp_client", lambda: _Client())
        out = json.loads(
            asyncio.run(server.mfp_get_goals(server.GetGoalsInput(response_format="json")))
        )
        assert out["goals"] == {"calories": 2359}
        assert seen["thread"] is not threading.main_thread()  # not on the loop thread

    def test_all_days_markdown_is_readable(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(
            server, "fetch_nutrient_goals", lambda client, on_date=None: current_item()
        )
        out = asyncio.run(server.mfp_get_goals(server.GetGoalsInput(all_days=True)))
        assert out.startswith("## Weekly Nutrition Goals")
        assert "- **monday**:" in out and "- **sunday**:" in out
        assert "{" not in out  # no raw Python dict repr leaks through
        assert "2799" in out  # sunday's calories rendered
