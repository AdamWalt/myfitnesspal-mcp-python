"""
Tests for the pure logic behind custom-food creation.

Payload construction needs no network access or MyFitnessPal credentials,
so these run anywhere. The HTTP round-trip is covered manually against a
live account (see the PR description).
"""

import json

import pytest

from mfp_mcp import server


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _FakeSession:
    """Captures the POST body instead of sending it."""

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else [{"id": "123456789"}]
        self.posted = None

    def get(self, url, **kwargs):
        if "csrf" in url:
            return _FakeResponse(200, {"csrfToken": "tok"})
        # own-foods lookup, used to resolve user_id
        return _FakeResponse(200, [{"user_id": "999", "description": "existing"}])

    def post(self, url, headers=None, data=None, timeout=None):
        self.posted = json.loads(data)
        return _FakeResponse(self.status_code, self.payload)

    def delete(self, url, headers=None, timeout=None):
        return _FakeResponse(204, {})


class _FakeClient:
    def __init__(self, session):
        self.session = session
        self.access_token = "t"
        self.user_id = "999"


def _spec(**overrides):
    spec = {
        "description": "Test Food",
        "brand_name": "Generic",
        "serving_amount": 1,
        "serving_unit": "piece",
        "calories": 100,
        "carbs": 42,
        "fiber": 8,
        "protein": 7,
        "fat": 26,
        "public": False,
    }
    spec.update(overrides)
    return spec


def test_serving_sizes_include_container_wrapper():
    """MFP's own client sends a primary serving plus a container wrapper."""
    sizes = server._serving_sizes(100, "g")
    assert len(sizes) == 2
    assert sizes[0]["value"] == 100
    assert sizes[0]["unit"] == "g"
    assert sizes[0]["index"] == 0
    assert sizes[1]["unit"] == "container (100 g ea.)"
    assert sizes[1]["index"] == 1


def test_country_code_defaults_to_nl():
    """country_code decides whether `carbs` means NET or TOTAL, so it must be sent.

    Omitting it makes MFP read the value as TOTAL and derive net = total - fiber,
    silently shifting every carb value by the fibre amount.
    """
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec())
    assert session.posted["item"]["country_code"] == "NL"


def test_country_code_is_overridable():
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec(country_code="US"))
    assert session.posted["item"]["country_code"] == "US"


def test_nutrients_map_to_mfp_keys():
    """Canonical arg names are translated to MFP's nutritional_contents keys."""
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec())
    nutrition = session.posted["item"]["nutritional_contents"]

    assert nutrition["energy"] == {"unit": "calories", "value": 100}
    assert nutrition["carbohydrates"] == 42  # `carbs` -> `carbohydrates`
    assert nutrition["fiber"] == 8
    assert nutrition["protein"] == 7
    assert nutrition["fat"] == 26
    assert nutrition["grams"] == 1


def test_omitted_nutrients_are_not_sent():
    """Unset optional nutrients are omitted rather than sent as 0.

    Sending 0 would assert 'this food genuinely contains none', which is a
    different claim from 'unknown'.
    """
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec())
    nutrition = session.posted["item"]["nutritional_contents"]
    for absent in ("sodium", "cholesterol", "potassium", "vitamin_a", "iron"):
        assert absent not in nutrition


def test_explicit_zero_is_sent():
    """An explicit 0 is a real value and must survive."""
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec(trans_fat=0, sodium=0))
    nutrition = session.posted["item"]["nutritional_contents"]
    assert nutrition["trans_fat"] == 0
    assert nutrition["sodium"] == 0


def test_defaults_to_private():
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec())
    assert session.posted["item"]["public"] is False


def test_id_parsed_from_bare_list_response():
    """MFP returns a bare list of created foods, not {"item": {...}}."""
    session = _FakeSession(payload=[{"id": "999888777666555"}])
    result = server.create_custom_food(_FakeClient(session), _spec())
    assert result["id"] == "999888777666555"
    assert result["status"] == 200


def test_id_parsed_from_wrapped_response():
    """Older/alternate shape still accepted."""
    session = _FakeSession(payload={"item": {"id": "42"}})
    result = server.create_custom_food(_FakeClient(session), _spec())
    assert result["id"] == "42"


def test_create_failure_raises_with_status():
    session = _FakeSession(status_code=403, payload={"error": "forbidden"})
    with pytest.raises(RuntimeError, match="403"):
        server.create_custom_food(_FakeClient(session), _spec())


def test_csrf_token_is_sent_as_header():
    """The web endpoints reject writes without x-csrf-token."""
    headers = server._web_headers("tok", json_body=True)
    assert headers["x-csrf-token"] == "tok"
    assert headers["Content-Type"] == "application/json"


def test_delete_returns_status():
    session = _FakeSession()
    assert server.delete_custom_food(_FakeClient(session), "123") == 204

def test_public_flag_is_transmitted():
    """`public=True` reaches the payload.

    Only the outbound field is asserted. Creating a genuinely public food would
    publish into MyFitnessPal's shared database for other users, so that is
    deliberately not exercised against a live account.
    """
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec(public=True))
    assert session.posted["item"]["public"] is True


def test_country_code_is_load_bearing_for_eu_and_us():
    """Both conventions are transmitted verbatim.

    Live behaviour (verified 2026-07-26, carbohydrates=42 + fiber=8):
      NL/DE/GB/IT -> stored 50/42  (sent value read as NET)
      US/CA/absent -> stored 42/34 (sent value read as TOTAL)
    """
    for code in ("NL", "DE", "GB", "IT", "US", "CA"):
        session = _FakeSession()
        server.create_custom_food(_FakeClient(session), _spec(country_code=code))
        assert session.posted["item"]["country_code"] == code


def test_user_id_is_not_sent():
    """Ownership comes from the session, so user_id is deliberately omitted.

    Posting without it returns 200 with the correct owner (verified against the
    live API). Sending it would cost an extra request to discover the value and
    would degrade for an account that has no custom foods yet.
    """
    session = _FakeSession()
    server.create_custom_food(_FakeClient(session), _spec())
    assert "user_id" not in session.posted["item"]


def test_error_detail_prefers_structured_fields():
    """Failures report MFP's own message rather than a slice of the raw body."""
    resp = _FakeResponse(400, {"error_description": "Request payload does not contain any food objects"})
    assert server._api_error_detail(resp) == "Request payload does not contain any food objects"
    assert server._api_error_detail(_FakeResponse(400, {"error": "bad-request"})) == "bad-request"
    assert server._api_error_detail(_FakeResponse(500, "not json at all")) == ""


# --- water passthrough + markdown ordering (regression, 2026-07-30) --------

class _FakeDay:
    def __init__(self, water):
        self.water = water


def test_water_returns_raw_ml_from_mfp():
    """day.water is already millilitres — the /food/water endpoint's field is
    literally named `milliliters` (python-myfitnesspal client.py:769).

    The old code did `water_ml = day.water * 236.588` unconditionally,
    turning an 8,737 ml day into 2,067 litres. This test would have caught
    that: water_ml must equal the raw value with no scaling.
    """
    data = server._water_payload(_FakeDay(8737.0), "2026-07-30")
    assert data == {"date": "2026-07-30", "water_ml": 8737.0}


def test_water_payload_has_no_extra_fields():
    """Response schema is strictly {date, water_ml}.

    No `water_cups` (that was the mislabel bug). No `water_goal` — MFP's
    `day.goals` carries only calories, carbohydrates, fat, protein, sodium
    and sugar (verified against a live account), so the field would be
    permanently null.
    """
    data = server._water_payload(_FakeDay(3000.0), "2026-07-30")
    assert set(data.keys()) == {"date", "water_ml"}


def test_markdown_puts_scalars_before_nested_sections():
    """A top-level scalar after a '### section' reads as part of that section.

    The diary's top-level `water` rendered under `### daily_goals`, which
    is how the water ACTUAL got misread as the water GOAL. This test
    pins the ordering so a scalar cannot be visually absorbed into a
    preceding section header.
    """
    out = server.format_response(
        {"date": "2026-07-30", "daily_goals": {"water": 3000.0}, "water": 2500.0},
        server.ResponseFormat.MARKDOWN,
    )
    lines = [l for l in out.splitlines() if l.strip()]
    assert lines.index("- **water**: 2500.0") < lines.index("### daily_goals")
