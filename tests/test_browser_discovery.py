"""Invariants for the Chromium browser cookie auto-discovery (macOS).

Pure — no keychain, no filesystem, no network. These lock the data tables that
drive discovery so a typo (e.g. an alias pointing at a browser with no cookie
path) can't silently make a browser undiscoverable.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import server  # noqa: E402


def test_dia_is_mapped_with_expected_paths():
    paths = server._CHROMIUM_COOKIES_PATHS_MACOS["Dia"]
    # New Chromium layout (Network/) is tried before the legacy location.
    assert paths[0].endswith("Network/Cookies")
    assert "Dia/User Data/Default/Cookies" in paths


def test_dia_alias_resolves():
    assert server._CHROMIUM_BROWSER_ALIASES["dia"] == "Dia"


def test_every_alias_maps_to_a_known_cookie_path():
    for alias, canonical in server._CHROMIUM_BROWSER_ALIASES.items():
        assert canonical in server._CHROMIUM_COOKIES_PATHS_MACOS, (
            f"alias {alias!r} -> {canonical!r} has no cookies-path mapping"
        )


def test_safe_storage_service_name_round_trips_to_a_mapped_browser():
    # The discovery loop derives the browser name via
    # `service.replace(" Safe Storage", "")`; every mapped browser's implied
    # service name must strip back to its own key.
    for browser in server._CHROMIUM_COOKIES_PATHS_MACOS:
        service = f"{browser} Safe Storage"
        assert service.replace(" Safe Storage", "").strip() == browser


def test_has_real_mfp_session_distinguishes_session_from_csrf():
    assert server._has_real_mfp_session({"__Secure-next-auth.session-token": "x"})
    assert server._has_real_mfp_session({"_mfp_session": "x"})
    # A pre-auth response carries a csrf-token but no session — not a session.
    assert not server._has_real_mfp_session({"__Host-next-auth.csrf-token": "x"})
