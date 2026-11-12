#!/usr/bin/env python3
"""One-time bootstrap for MyFitnessPal mobile (fasting) reads.

Performs the mobile OAuth login once and stores the resulting *refresh token*
in the OS keychain (service 'mfp-mcp'). Your password is read from a hidden
prompt (or MFP_PASSWORD if already set), used once, and NEVER stored. After
this, `mfp_get_fasts` works without the password — the server refreshes the
token on its own.

Prerequisite: the mobile client credentials must be configured first, via the
environment (MFP_MOBILE_CLIENT_ID / MFP_MOBILE_CLIENT_SECRET) or the 'mfp-mcp'
keychain.

Usage:
    python scripts/mfp_mobile_login.py
"""
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import mobile_sync as ms  # noqa: E402


def main() -> int:
    username = os.environ.get("MFP_USERNAME") or input("MyFitnessPal username/email: ").strip()
    password = os.environ.get("MFP_PASSWORD") or getpass.getpass("MyFitnessPal password (hidden): ")
    if not username or not password:
        print("username and password are both required", file=sys.stderr)
        return 2

    try:
        client_id, client_secret = ms.get_client_credentials()
    except ms.MobileAuthError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    session = ms._new_session()
    try:
        access, refresh, _ttl = ms.login_with_password(
            session, client_id, client_secret, username, password
        )
    except ms.MobileAuthError as e:
        print(f"Login failed: {e}", file=sys.stderr)
        return 1

    if not refresh:
        print("Login succeeded but no refresh token was returned; cannot persist a "
              "session.", file=sys.stderr)
        return 1

    ms._store_refresh_token(refresh)

    # Verify the stored session can actually read fasting data.
    fasts, _sync = ms.fetch_all_fasts(access, session=session)
    print(f"✓ Mobile session stored in the keychain. Fasting read works: "
          f"{len(fasts)} entries found.")
    if fasts:
        newest = max(fasts, key=lambda d: d.get("fast_started") or "")
        print(f"  Newest fast started {newest.get('fast_started')} "
              f"ended {newest.get('fast_ended') or '(ongoing)'}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
