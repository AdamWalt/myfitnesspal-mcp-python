"""Tests for Quick Add (issue #24).

Pure — the three network helpers (create_custom_food, add_food_to_diary,
delete_custom_food) are monkeypatched. The risks these guard: building the
wrong food spec, logging more/less than one serving, and — most important —
leaving an orphan "Quick Add" food behind in the user's food list when logging
fails, or failing the whole call because the throwaway cleanup failed.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import server  # noqa: E402


def _patch(
    monkeypatch, *, food_id="F1", add_result=("E1", "during ride"), add_exc=None, delete_exc=None
):
    """Wire fakes for the three network helpers; return recorders."""
    rec = {"spec": {}, "deleted": [], "add": None}

    def fake_create(client, spec):
        rec["spec"] = dict(spec)
        return {"id": food_id, "status": 200, "description": spec["description"]}

    def fake_add(client, mfp_id, meal, target_date, quantity=1.0, unit=None):
        # Enforce create -> log -> delete ordering: the backing food must still
        # exist when we log against it (a live read-back would 404 otherwise).
        assert rec["deleted"] == [], "backing food deleted before the entry was logged"
        if add_exc:
            raise add_exc
        rec["add"] = {"mfp_id": mfp_id, "meal": meal, "quantity": quantity}
        return add_result

    def fake_delete(client, fid):
        rec["deleted"].append(fid)
        if delete_exc:
            raise delete_exc
        return 204

    monkeypatch.setattr(server, "create_custom_food", fake_create)
    monkeypatch.setattr(server, "add_food_to_diary", fake_add)
    monkeypatch.setattr(server, "delete_custom_food", fake_delete)
    return rec


class TestQuickAddToDiary:
    def test_happy_path_builds_spec_logs_one_serving_and_cleans_up(self, monkeypatch):
        rec = _patch(monkeypatch)
        eid, meal = server.quick_add_to_diary(
            object(),
            calories=337,
            meal="during ride",
            target_date=date(2026, 11, 12),
            carbohydrates=41,
            protein=23,
            fat=9,
            name="Quick Add",
        )
        assert (eid, meal) == ("E1", "during ride")
        s = rec["spec"]
        assert s["calories"] == 337 and s["carbs"] == 41 and s["protein"] == 23 and s["fat"] == 9
        assert s["serving_amount"] == 1 and s["serving_unit"] == "serving"
        assert s["country_code"] == "NL" and s["description"] == "Quick Add"
        assert rec["add"] == {"mfp_id": "F1", "meal": "during ride", "quantity": 1.0}
        assert rec["deleted"] == ["F1"]  # backing food made a throwaway

    def test_custom_name_flows_to_description(self, monkeypatch):
        rec = _patch(monkeypatch)
        server.quick_add_to_diary(
            object(), calories=150, meal="snacks", target_date=date(2026, 1, 1), name="Ride gel"
        )
        assert rec["spec"]["description"] == "Ride gel"

    def test_only_calories_omits_macro_keys(self, monkeypatch):
        rec = _patch(monkeypatch)
        server.quick_add_to_diary(
            object(), calories=200, meal="snacks", target_date=date(2026, 1, 1)
        )
        assert "carbs" not in rec["spec"]
        assert "protein" not in rec["spec"]
        assert "fat" not in rec["spec"]

    def test_no_food_id_raises_before_logging(self, monkeypatch):
        rec = _patch(monkeypatch, food_id=None)
        with pytest.raises(RuntimeError, match="returned no id"):
            server.quick_add_to_diary(
                object(), calories=100, meal="snacks", target_date=date(2026, 1, 1)
            )
        assert rec["add"] is None and rec["deleted"] == []

    def test_log_failure_cleans_up_orphan_food(self, monkeypatch):
        rec = _patch(monkeypatch, add_exc=RuntimeError("meal not found"))
        with pytest.raises(RuntimeError, match="meal not found"):
            server.quick_add_to_diary(
                object(), calories=100, meal="nope", target_date=date(2026, 1, 1)
            )
        assert rec["deleted"] == ["F1"]  # no orphan left behind

    def test_cleanup_failure_after_success_is_nonfatal(self, monkeypatch):
        rec = _patch(monkeypatch, delete_exc=RuntimeError("delete failed"))
        eid, meal = server.quick_add_to_diary(
            object(), calories=100, meal="snacks", target_date=date(2026, 1, 1)
        )
        assert eid == "E1"  # the logged entry is returned despite cleanup failing
        assert rec["deleted"] == ["F1"]


class TestQuickAddTool:
    def test_success_reports_entry_and_logged(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        monkeypatch.setattr(server, "quick_add_to_diary", lambda client, **kw: ("E9", kw["meal"]))
        out = json.loads(
            asyncio.run(
                server.mfp_quick_add(
                    server.QuickAddInput(
                        calories=337, carbohydrates=41, protein=23, fat=9, meal="during ride"
                    )
                )
            )
        )
        assert out["success"] is True
        assert out["entry_id"] == "E9" and out["meal"] == "during ride"
        assert out["logged"] == {"calories": 337, "carbohydrates": 41, "protein": 23, "fat": 9}

    def test_date_flows_through_to_helper_and_response(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())
        seen = {}

        def capture(client, **kw):
            seen.update(kw)
            return ("E2", kw["meal"])

        monkeypatch.setattr(server, "quick_add_to_diary", capture)
        out = json.loads(
            asyncio.run(
                server.mfp_quick_add(
                    server.QuickAddInput(calories=100, meal="snacks", date="2026-03-09")
                )
            )
        )
        assert out["date"] == "2026-03-09"
        assert seen["target_date"] == date(2026, 3, 9)

    def test_calories_is_required(self):
        with pytest.raises(ValidationError):
            server.QuickAddInput(carbohydrates=10)

    def test_error_is_surfaced(self, monkeypatch):
        monkeypatch.setattr(server, "get_mfp_client", lambda: object())

        def boom(client, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(server, "quick_add_to_diary", boom)
        out = asyncio.run(server.mfp_quick_add(server.QuickAddInput(calories=100)))
        assert out.startswith("Error quick-adding") and "nope" in out
