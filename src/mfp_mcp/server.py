"""
MyFitnessPal MCP Server

A Model Context Protocol (MCP) server that provides tools for interacting
with MyFitnessPal data including food diary, exercises, measurements, goals,
water intake, and food search.

Authentication Methods (in order of priority):
1. Environment variables: MFP_USERNAME and MFP_PASSWORD
2. Stored session cookies: ~/.mfp_mcp/cookies.json
3. Chromium-based browser cookies (macOS): Arc, Chrome, Edge, Brave, Vivaldi,
   Opera, and any other installed Chromium browser detected via the keychain
   "Safe Storage" entry.
4. browser_cookie3 fallback (legacy Chrome/Firefox paths on any OS)
"""

import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from datetime import date, datetime, timedelta, timezone
from http.cookiejar import CookieJar, Cookie
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from collections import OrderedDict
import time
from cryptography.fernet import Fernet
import keyring

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict, field_validator

# Configure logging to stderr (required for stdio transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("mfp_mcp")

# Initialize MCP server
mcp = FastMCP("myfitnesspal_mcp")

# Configuration paths
CONFIG_DIR = Path.home() / ".mfp_mcp"
COOKIES_FILE = CONFIG_DIR / "cookies.json"

# MyFitnessPal's v2 JSON API, used for diary writes. The legacy HTML form
# endpoint (/food/diary/{user}/add) was removed by MFP and now returns 404.
MFP_API_BASE = "https://api.myfitnesspal.com"
MFP_CLIENT_ID = "mfp-main-js"
VALID_MEALS = ("Breakfast", "Lunch", "Dinner", "Snacks")


# ============================================================================
# Authentication Helper Functions
# ============================================================================


def ensure_config_dir():
    """Ensure the config directory exists."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.chmod(0o700)


def save_cookies(cookies: Dict[str, str]):
    """
    Save session cookies to file for persistence.
    
    Args:
        cookies: Dictionary of cookie name -> value
    """
    ensure_config_dir()
    cookie_data = {
        "cookies": cookies,
        "saved_at": datetime.now().isoformat(),
    }
    with open(COOKIES_FILE, "w") as f:
        json.dump(cookie_data, f, indent=2)
    # Session cookies grant full account access - restrict to owner only
    COOKIES_FILE.chmod(0o600)
    logger.info(f"Saved session cookies to {COOKIES_FILE}")


def load_cookies() -> Optional[Dict[str, str]]:
    """
    Load session cookies from file.
    
    Returns:
        Dictionary of cookies if file exists and is valid, None otherwise
    """
    if not COOKIES_FILE.exists():
        return None
    
    try:
        with open(COOKIES_FILE, "r") as f:
            cookie_data = json.load(f)
        
        # Check if cookies are less than 30 days old
        saved_at = datetime.fromisoformat(cookie_data.get("saved_at", "2000-01-01"))
        if datetime.now() - saved_at > timedelta(days=30):
            logger.info("Stored cookies are expired (>30 days old)")
            return None
        
        return cookie_data.get("cookies")
    except Exception as e:
        logger.warning(f"Failed to load cookies: {e}")
        return None


def dict_to_cookiejar(cookies_dict: Dict[str, str], domain: str = ".myfitnesspal.com") -> CookieJar:
    """
    Convert a dictionary of cookies to a CookieJar that can be used by myfitnesspal.Client.
    
    Args:
        cookies_dict: Dictionary of cookie name -> value
        domain: Domain for the cookies (default: .myfitnesspal.com)
    
    Returns:
        CookieJar: A CookieJar object populated with the cookies
    """
    jar = CookieJar()
    
    for name, value in cookies_dict.items():
        cookie = Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=True,
            domain_initial_dot=domain.startswith('.'),
            path="/",
            path_specified=True,
            secure=True,
            expires=int(time.time()) + 86400 * 30,  # 30 days from now
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        )
        jar.set_cookie(cookie)
    
    return jar

# ============================================================================
# Chromium Browser Cookie Extraction (macOS)
# ============================================================================
#
# Chromium-based browsers (Arc, Chrome, Edge, Brave, Vivaldi, Opera, ...)
# store cookies in a SQLite database with each value encrypted using
# AES-128-CBC. The encryption key is derived from a per-browser password
# stored in the macOS Keychain under a service name like
# "<Browser> Safe Storage".
#
# We discover installed Chromium browsers by listing keychain "Safe Storage"
# entries and try each one until we find a valid MyFitnessPal session token.
# This is what lets the MCP "just work" when the user logs in via any modern
# browser — including Arc, which `browser_cookie3` does not support.

# Cookies DB locations relative to ~/Library/Application Support/.
# Newer Chromium versions moved the cookies DB into a "Network/" subdir;
# we try the new path first, falling back to the legacy location.
_CHROMIUM_COOKIES_PATHS_MACOS: Dict[str, List[str]] = {
    "Arc":            ["Arc/User Data/Default/Network/Cookies",
                       "Arc/User Data/Default/Cookies"],
    "Chrome":         ["Google/Chrome/Default/Network/Cookies",
                       "Google/Chrome/Default/Cookies"],
    "Chromium":       ["Chromium/Default/Network/Cookies",
                       "Chromium/Default/Cookies"],
    "Microsoft Edge": ["Microsoft Edge/Default/Network/Cookies",
                       "Microsoft Edge/Default/Cookies"],
    "Brave":          ["BraveSoftware/Brave-Browser/Default/Network/Cookies",
                       "BraveSoftware/Brave-Browser/Default/Cookies"],
    "Vivaldi":        ["Vivaldi/Default/Network/Cookies",
                       "Vivaldi/Default/Cookies"],
    "Opera":          ["com.operasoftware.Opera/Network/Cookies",
                       "com.operasoftware.Opera/Cookies"],
}

# Friendly browser names accepted by `refresh_browser_cookies("<name>")`
# mapped to the canonical "Safe Storage" service prefix.
_CHROMIUM_BROWSER_ALIASES: Dict[str, str] = {
    "arc": "Arc",
    "chrome": "Chrome",
    "chromium": "Chromium",
    "edge": "Microsoft Edge",
    "brave": "Brave",
    "vivaldi": "Vivaldi",
    "opera": "Opera",
}


def _safe_storage_keychain_password(service_name: str) -> Optional[bytes]:
    """Look up `service_name` in the macOS Keychain and return the raw bytes.

    Returns None if the entry doesn't exist or access is denied.

    NOTE: on a fresh install the first read of another app's Safe Storage
    entry triggers a macOS keychain authorization dialog ("<app> wants to
    use information stored in your keychain"). If this MCP is running
    headless (e.g. spawned by Claude Desktop with no UI focus), the prompt
    is silently denied and this call returns None after the 5s timeout.
    The user only needs to click "Always Allow" once, but they need to
    know to look for the prompt — the README troubleshooting section
    documents this.
    """
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service_name, "-w"],
            capture_output=True, check=True, timeout=5,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError):
        return None


def _list_chromium_safe_storage_services_macos() -> List[str]:
    """Return all keychain service names ending in 'Safe Storage'.

    These identify installed Chromium-based browsers. We don't hard-code
    the list — anything matching the pattern is fair game.
    """
    keychain_path = os.path.expanduser("~/Library/Keychains/login.keychain-db")
    try:
        result = subprocess.run(
            ["security", "dump-keychain", keychain_path],
            capture_output=True, check=True, timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError):
        return []
    services = set()
    text = result.stdout.decode("utf-8", errors="replace")
    for line in text.splitlines():
        # The `svce` attribute appears as: "svce"<blob>="Arc Safe Storage"
        if '"svce"<blob>=' not in line or "Safe Storage" not in line:
            continue
        try:
            value = line.split('"svce"<blob>=', 1)[1].strip()
            value = value.strip('"')
            if value.endswith("Safe Storage"):
                services.add(value)
        except IndexError:
            continue
    return sorted(services)


def _derive_chromium_aes_key_macos(safe_storage_password: bytes) -> bytes:
    """Derive the AES-128 cookie key Chromium uses on macOS.

    Per Chromium's `os_crypt_mac.mm`: PBKDF2-HMAC-SHA1 with salt='saltysalt',
    1003 iterations, 16-byte key.
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=16,
        salt=b"saltysalt",
        iterations=1003,
        backend=default_backend(),
    )
    return kdf.derive(safe_storage_password)


def _decrypt_chromium_value_macos(encrypted_value: bytes,
                                   aes_key: bytes,
                                   host_key: str = "") -> Optional[str]:
    """Decrypt a single Chromium cookie `encrypted_value`. Returns None on
    failure or for unsupported schemes (e.g. v20 app-bound encryption).

    `host_key` is the cookie's host column from SQLite; modern Chromium
    prepends `SHA-256(host_key)` to the plaintext as an integrity tag, so
    we strip exactly that 32-byte prefix when it's present. Without this
    check, long ASCII cookie values from legacy rows would be silently
    truncated by 32 bytes (the shortened plaintext still decodes as UTF-8).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    if not encrypted_value or len(encrypted_value) < 3:
        return None
    prefix = encrypted_value[:3]
    if prefix not in (b"v10", b"v11"):
        # v20 needs app-bound decryption via the browser process and is not
        # supported here. Caller should fall back to a different source.
        return None
    try:
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(b" " * 16),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_value[3:]) + decryptor.finalize()
    except Exception:
        return None
    # Strip PKCS#7 padding.
    if not plaintext:
        return None
    pad_len = plaintext[-1]
    if pad_len < 1 or pad_len > 16:
        return None
    plaintext = plaintext[:-pad_len]
    # Strip the SHA-256(host_key) integrity prefix only when it actually
    # matches — never blindly. Legacy rows without the prefix have shorter
    # but otherwise normal plaintexts.
    if host_key and len(plaintext) >= 32:
        expected_prefix = hashlib.sha256(host_key.encode("utf-8")).digest()
        if plaintext[:32] == expected_prefix:
            plaintext = plaintext[32:]
    try:
        return plaintext.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _snapshot_sqlite_db(src: Path, dst: str) -> None:
    """Copy a live SQLite DB into `dst` using the backup API.

    The browser's cookies DB may be open in WAL mode with active writers;
    a plain `shutil.copy` misses committed rows that still live in the
    `-wal` sidecar. The backup API handles WAL/SHM correctly, takes a
    consistent snapshot, and doesn't require taking a write lock — opening
    the source read-only is enough.
    """
    src_con = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    try:
        dst_con = sqlite3.connect(dst)
        try:
            src_con.backup(dst_con)
        finally:
            dst_con.close()
    finally:
        src_con.close()


def _extract_chromium_cookies_macos(
    cookies_db_path: Path,
    aes_key: bytes,
    domain: str = "myfitnesspal.com",
) -> Dict[str, str]:
    """Read cookies for `domain` (and its subdomains) from a Chromium DB.

    The DB is snapshotted via the SQLite backup API so rows pending in the
    `-wal` file are included. Cookies whose decrypted value isn't clean
    UTF-8 are skipped — those can't go into HTTP headers anyway.
    """
    # `mkstemp` gives us a uniquely-named file we own, immune to the
    # time-of-check/time-of-use race that `mktemp` would create.
    fd, tmp_path = tempfile.mkstemp(suffix=".cookies.db")
    os.close(fd)
    try:
        _snapshot_sqlite_db(cookies_db_path, tmp_path)
        con = sqlite3.connect(tmp_path)
        try:
            # `host_key = 'myfitnesspal.com' OR host_key LIKE '%.myfitnesspal.com'`
            # — exact match + any subdomain. Avoids matching unrelated hosts
            # like `notmyfitnesspal.com` that the loose LIKE pattern would.
            rows = con.execute(
                "SELECT name, value, encrypted_value, host_key FROM cookies "
                "WHERE host_key = ? OR host_key LIKE ?",
                (domain, f"%.{domain}"),
            ).fetchall()
        finally:
            con.close()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    cookies: Dict[str, str] = {}
    for name, plain, enc, host_key in rows:
        value = (
            plain if plain
            else _decrypt_chromium_value_macos(enc, aes_key, host_key)
        )
        if value is None or "�" in value:
            continue
        cookies[name] = value
    return cookies


def _has_real_mfp_session(cookies: Dict[str, str]) -> bool:
    """True if the cookie set looks like an authenticated MFP session.

    A pre-auth response can include cookies with 'auth' in the name
    (e.g. `__Host-next-auth.csrf-token`), so we look for the specific
    session-token markers MFP actually uses.
    """
    return any(
        "session-token" in name or name == "_mfp_session"
        for name in cookies
    )


def _try_extract_from_chromium_browser(
    service: str,
) -> Optional[Dict[str, str]]:
    """Extract cookies from one specific Chromium browser by Safe Storage
    service name (e.g. 'Arc Safe Storage'). Returns None on any failure."""
    browser_name = service.replace(" Safe Storage", "").strip()
    relative_paths = _CHROMIUM_COOKIES_PATHS_MACOS.get(browser_name)
    if not relative_paths:
        logger.debug(f"No cookies DB path mapping for '{browser_name}'")
        return None
    appsup = Path.home() / "Library" / "Application Support"
    db_path = next(
        (appsup / p for p in relative_paths if (appsup / p).exists()),
        None,
    )
    if not db_path:
        logger.debug(f"No cookies DB found for '{browser_name}'")
        return None
    password = _safe_storage_keychain_password(service)
    if not password:
        logger.debug(f"Keychain lookup failed for '{service}'")
        return None
    try:
        aes_key = _derive_chromium_aes_key_macos(password)
        return _extract_chromium_cookies_macos(db_path, aes_key)
    except Exception as e:
        logger.debug(f"Cookie extraction failed for '{browser_name}': {e}")
        return None


def try_chromium_browsers_for_session_cookies(
) -> Optional[Tuple[str, Dict[str, str]]]:
    """Discover installed Chromium browsers (macOS only) and return the first
    one that has a valid MyFitnessPal session token.

    Returns a (browser_name, cookies) tuple, or None if no browser yielded
    a usable session.
    """
    if sys.platform != "darwin":
        return None
    services = _list_chromium_safe_storage_services_macos()
    if not services:
        logger.debug("No Chromium Safe Storage entries found in keychain")
        return None
    for service in services:
        cookies = _try_extract_from_chromium_browser(service)
        if not cookies:
            continue
        browser_name = service.replace(" Safe Storage", "").strip()
        if _has_real_mfp_session(cookies):
            logger.info(
                f"Found valid MyFitnessPal session in {browser_name} "
                f"({len(cookies)} cookies)"
            )
            return browser_name, cookies
        logger.debug(
            f"{browser_name} had {len(cookies)} cookies but no session token"
        )
    return None


def looks_like_fernet_token(value: str) -> bool:
    """Return True if the value appears to be a Fernet token."""
    if not value:
        return False
    # Fernet tokens are URL-safe base64-encoded and typically begin with "gAAAAA".
    # Use a lightweight prefix check so plaintext credentials continue to work
    # even when MFP_SECRET_KEY is configured.
    #
    # Edge case: a genuine plaintext password that starts with "gAAAAA" is
    # misclassified as a ciphertext, fails Fernet decryption, and
    # `get_decrypted_credential` returns None — credential auth is silently
    # skipped and the caller falls through to cookie-based auth. Extremely
    # unlikely for a real password, and the fallback is graceful, so we
    # accept this heuristic rather than adding a length/base64 check.
    return value.startswith("gAAAAA")


KEYRING_SERVICE = "mfp-mcp"
KEYRING_SECRET_KEY_ACCOUNT = "MFP_SECRET_KEY"


def get_secret_key() -> Optional[str]:
    """Resolves MFP_SECRET_KEY from, in order:
    1. The MFP_SECRET_KEY environment variable.
    2. The OS keychain (service: 'mfp-mcp', account: 'MFP_SECRET_KEY').

    Returns the key string, or None if not found in either location.
    """
    key = os.environ.get("MFP_SECRET_KEY")
    if key:
        logger.info("MFP_SECRET_KEY loaded from environment variable.")
        return key

    try:
        key = keyring.get_password(KEYRING_SERVICE, KEYRING_SECRET_KEY_ACCOUNT)
        if key:
            logger.info("MFP_SECRET_KEY loaded from OS keychain.")
            return key
    except Exception as e:
        logger.warning(f"Keychain lookup failed: {e}")

    return None


def get_decrypted_credential(env_var_name: str) -> Optional[str]:
    """Retrieves credentials from environment variables, decrypting Fernet tokens when needed.

    The decryption key (MFP_SECRET_KEY) is resolved from the environment variable first,
    then from the OS keychain as a fallback.

    Returns the decrypted string on success, the raw value when no decryption is needed,
    or None if the env var is missing, decryption fails, or the value looks encrypted but
    no key is available (to avoid passing ciphertext to the auth flow).
    """
    encrypted_value = os.environ.get(env_var_name)

    if not encrypted_value:
        logger.warning(f"Missing {env_var_name}.")
        return None

    if not looks_like_fernet_token(encrypted_value):
        # Plain-text credential — no key lookup needed.
        return encrypted_value

    # Value looks like a Fernet token; resolve the secret key only now.
    secret_key = get_secret_key()

    if not secret_key:
        logger.warning(
            f"{env_var_name} appears to be encrypted but MFP_SECRET_KEY is not set. "
            "Credential auth will be skipped to avoid passing ciphertext to the auth flow."
        )
        return None

    try:
        f = Fernet(secret_key.encode())
        return f.decrypt(encrypted_value.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed for {env_var_name}: {e}")
        return None

def authenticate_with_credentials(username: str, password: str) -> Dict[str, str]:
    """
    Authenticate with MyFitnessPal using username/password.
    
    Args:
        username: MyFitnessPal username or email
        password: MyFitnessPal password
    
    Returns:
        Dictionary of session cookies
        
    Raises:
        RuntimeError: If authentication fails
    """
    # Log authentication attempt without exposing the username
    logger.info("Authenticating with credentials")
    
    # MyFitnessPal login URL and endpoints
    LOGIN_URL = "https://www.myfitnesspal.com/account/login"
    
    try:
        with httpx.Client(follow_redirects=True, timeout=30.0) as client:
            # First, get the login page to obtain CSRF token
            response = client.get(LOGIN_URL)
            response.raise_for_status()
            
            # Extract CSRF token from cookies or page
            cookies = dict(response.cookies)
            
            # Attempt login
            login_data = {
                "username": username,
                "password": password,
            }
            
            # Try the standard form login
            login_response = client.post(
                LOGIN_URL,
                data=login_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": LOGIN_URL,
                },
            )
            
            # MyFitnessPal moved to a NextAuth backend, so the legacy form
            # POST flow this function uses no longer actually logs the user
            # in — the endpoint just returns HTTP 200 with a fresh CSRF
            # cookie. The old success check matched any cookie containing
            # 'auth' (which `__Host-next-auth.csrf-token` does), reporting
            # success and overwriting cookies.json with useless pre-auth
            # cookies. Require a real session token before claiming success.
            all_cookies = dict(client.cookies)
            if _has_real_mfp_session(all_cookies):
                logger.info("Successfully authenticated with credentials")
                return all_cookies
            raise RuntimeError(
                "Login appeared to fail — response contained no session token. "
                "MyFitnessPal's form login flow does not work against the "
                "current NextAuth backend. Log into myfitnesspal.com in any "
                "Chromium-based browser (Arc, Chrome, Edge, Brave, ...) and "
                "the MCP will pick up the session automatically."
            )
                
    except httpx.HTTPError as e:
        raise RuntimeError(f"HTTP error during authentication: {e}")
    except Exception as e:
        raise RuntimeError(f"Authentication failed: {e}")


def get_mfp_client():
    """
    Get an authenticated MyFitnessPal client.

    Authentication is attempted in this order:
    1. Environment variables (MFP_USERNAME, MFP_PASSWORD)
       a. First tries previously-cached cookies for this user.
       b. Then falls back to form login (only useful on legacy accounts).
    2. Stored session cookies (~/.mfp_mcp/cookies.json)
    3. Chromium-based browser cookies (macOS): auto-discovers Arc, Chrome,
       Edge, Brave, Vivaldi, Opera, or any other installed Chromium browser
       via the keychain's "Safe Storage" entries.
    4. `browser_cookie3` default fallback (legacy Chrome/Firefox paths).

    Returns:
        myfitnesspal.Client: Authenticated client instance

    Raises:
        RuntimeError: If all authentication methods fail
    """
    import myfitnesspal

    last_error = None

    # Method 1: Try environment variable credentials
    username = get_decrypted_credential("MFP_USERNAME")
    password = get_decrypted_credential("MFP_PASSWORD")

    if username and password:
        logger.info("Attempting authentication with environment credentials")

        # First check if we have valid stored cookies from a previous credential auth
        stored_cookies = load_cookies()
        if stored_cookies:
            logger.info("Found stored session cookies, testing validity...")
            try:
                cookiejar = dict_to_cookiejar(stored_cookies)
                client = myfitnesspal.Client(cookiejar=cookiejar)
                # Test the connection
                _ = client.get_date(date.today())
                logger.info("Stored cookies are valid")
                return client
            except Exception as e:
                logger.info(f"Stored cookies invalid: {e}, re-authenticating...")

        # Authenticate with credentials and save cookies
        try:
            cookies = authenticate_with_credentials(username, password)
            save_cookies(cookies)

            # Create client with the new cookies
            cookiejar = dict_to_cookiejar(cookies)
            client = myfitnesspal.Client(cookiejar=cookiejar)
            # Test the connection
            _ = client.get_date(date.today())
            logger.info("Successfully authenticated with credentials")
            return client

        except Exception as e:
            last_error = e
            logger.warning(f"Credential authentication failed: {e}")
            # Fall through to other methods

    # Method 2: Try stored session cookies (without credential auth)
    stored_cookies = load_cookies()
    if stored_cookies:
        logger.info("Attempting authentication with stored cookies")
        try:
            cookiejar = dict_to_cookiejar(stored_cookies)
            client = myfitnesspal.Client(cookiejar=cookiejar)
            # Test the connection
            _ = client.get_date(date.today())
            logger.info("Successfully authenticated with stored cookies")
            return client
        except Exception as e:
            last_error = e
            logger.warning(f"Stored cookie authentication failed: {e}")

    # Method 3: Auto-discover Chromium-based browsers (macOS) and pull a live
    # session from whichever one is logged into MFP. This works for Arc,
    # Chrome, Edge, Brave, Vivaldi, Opera, etc. — anything that registers a
    # "<Browser> Safe Storage" entry in the macOS keychain.
    logger.info("Attempting authentication via Chromium browser auto-discovery")
    try:
        result = try_chromium_browsers_for_session_cookies()
        if result:
            browser_name, chromium_cookies = result
            cookiejar = dict_to_cookiejar(chromium_cookies)
            client = myfitnesspal.Client(cookiejar=cookiejar)
            _ = client.get_date(date.today())
            # Only persist after we've verified it works, so a transient
            # failure can't poison cookies.json.
            save_cookies(chromium_cookies)
            logger.info(
                f"Successfully authenticated via Chromium auto-discovery "
                f"({browser_name})"
            )
            return client
        logger.info("No Chromium browser had a usable MFP session")
    except Exception as e:
        last_error = e
        logger.warning(f"Chromium auto-discovery authentication failed: {e}")

    # Method 4: Try browser cookies via browser_cookie3 (legacy fallback)
    logger.info("Attempting authentication with browser_cookie3 fallback")
    try:
        client = myfitnesspal.Client()
        # Test the connection
        _ = client.get_date(date.today())
        logger.info("Successfully authenticated with browser cookies")
        return client
    except Exception as e:
        last_error = e
        raise RuntimeError(
            f"All authentication methods failed. Last error: {str(last_error)}\n\n"
            "Please try one of these solutions:\n"
            "1. Log into myfitnesspal.com in any Chromium-based browser "
            "(Arc, Chrome, Edge, Brave, Vivaldi, Opera, ...) — the MCP will "
            "auto-discover the session on macOS.\n"
            "2. Set MFP_USERNAME and MFP_PASSWORD in Claude Desktop config "
            "(legacy form-login flow; rarely works against the current "
            "NextAuth backend).\n"
            "3. Manually populate ~/.mfp_mcp/cookies.json with a valid "
            "session token."
        )


# ============================================================================
# Data Formatting Helper Functions
# ============================================================================


def parse_date(date_str: Optional[str] = None) -> date:
    """
    Parse a date string or return today's date.

    Args:
        date_str: Date in YYYY-MM-DD format, or None for today

    Returns:
        date: Parsed date object
    """
    if date_str is None:
        return date.today()
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def format_nutrition_dict(nutrition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format nutrition dictionary for consistent output.

    Args:
        nutrition: Raw nutrition dictionary

    Returns:
        dict: Formatted nutrition data
    """
    formatted = {}
    for key, value in nutrition.items():
        if hasattr(value, "magnitude"):
            # Handle pint quantities
            formatted[key] = float(value.magnitude)
        else:
            formatted[key] = value
    return formatted


def format_meal_entry(entry) -> Dict[str, Any]:
    """
    Format a meal entry for output.

    Args:
        entry: MFP Entry object

    Returns:
        dict: Formatted entry data
    """
    return {
        "name": entry.name,
        "short_name": getattr(entry, "short_name", None),
        "quantity": getattr(entry, "quantity", None),
        "unit": getattr(entry, "unit", None),
        "nutrition": format_nutrition_dict(entry.totals),
    }


def format_exercise(exercise) -> Dict[str, Any]:
    """
    Format an exercise object for output.

    Args:
        exercise: MFP Exercise object

    Returns:
        dict: Formatted exercise data
    """
    entries = exercise.get_as_list()
    return {"name": exercise.name, "entries": entries}


def ordered_dict_to_dict(od: OrderedDict) -> Dict[str, Any]:
    """
    Convert OrderedDict with date keys to regular dict with string keys.

    Args:
        od: OrderedDict with date keys

    Returns:
        dict: Regular dict with string keys
    """
    return {str(k): v for k, v in od.items()}


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def format_response(data: Any, format_type: ResponseFormat, title: str = "") -> str:
    """
    Format response data based on requested format.

    Args:
        data: Data to format
        format_type: Output format (markdown or json)
        title: Optional title for markdown format

    Returns:
        str: Formatted response string
    """
    if format_type == ResponseFormat.JSON:
        return json.dumps(data, indent=2, default=str)

    # Markdown format
    lines = []
    if title:
        lines.append(f"## {title}\n")

    if isinstance(data, dict):
        # Scalars FIRST, then nested sections. A top-level scalar emitted after
        # a "### section" is visually absorbed into that section: the diary's
        # top-level `water` rendered directly below `### daily_goals`, which
        # reads as the water GOAL rather than the amount actually logged.
        # (Real misread, 2026-07-30.) Ordering keeps every scalar unambiguous.
        for key, value in data.items():
            if not isinstance(value, (dict, list)):
                lines.append(f"- **{key}**: {value}")
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"### {key}")
                for k, v in value.items():
                    lines.append(f"- **{k}**: {v}")
            elif isinstance(value, list):
                lines.append(f"### {key}")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"- {item.get('name', str(item))}")
                        for k, v in item.items():
                            if k != "name":
                                lines.append(f"  - {k}: {v}")
                    else:
                        lines.append(f"- {item}")
    else:
        lines.append(str(data))

    return "\n".join(lines)


# ============================================================================
# Pydantic Input Models
# ============================================================================


class GetDiaryInput(BaseModel):
    """Input model for getting food diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SearchFoodInput(BaseModel):
    """Input model for searching foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ...,
        description="Search query for food items (e.g., 'chicken breast', 'apple')",
        min_length=1,
        max_length=200,
    )
    limit: int = Field(
        default=10,
        description="Maximum number of results to return",
        ge=1,
        le=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetFoodDetailsInput(BaseModel):
    """Input model for getting food item details."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from search results)",
        min_length=1,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetMeasurementsInput(BaseModel):
    """Input model for getting measurements."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to retrieve (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 30 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetMeasurementInput(BaseModel):
    """Input model for setting a measurement."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to set (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    value: float = Field(
        ...,
        description="Measurement value (e.g., 185.5 for weight in lbs)",
        gt=0,
    )


class GetExercisesInput(BaseModel):
    """Input model for getting exercises."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetGoalsInput(BaseModel):
    """Input model for getting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetGoalsInput(BaseModel):
    """Input model for setting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    calories: Optional[int] = Field(
        default=None,
        description="Daily calorie goal (e.g., 2000)",
        ge=500,
        le=10000,
    )
    protein: Optional[int] = Field(
        default=None,
        description="Daily protein goal in grams (e.g., 150)",
        ge=0,
        le=1000,
    )
    carbohydrates: Optional[int] = Field(
        default=None,
        description="Daily carbohydrate goal in grams (e.g., 200)",
        ge=0,
        le=2000,
    )
    fat: Optional[int] = Field(
        default=None,
        description="Daily fat goal in grams (e.g., 65)",
        ge=0,
        le=500,
    )


class GetWaterInput(BaseModel):
    """Input model for getting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )

class GetReportInput(BaseModel):
    """Input model for getting nutrition reports."""

    model_config = ConfigDict(str_strip_whitespace=True)

    report_name: str = Field(
        default="Net Calories",
        description="Report name (e.g., 'Net Calories', 'Total Calories', 'Protein', 'Fat', 'Carbs')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 7 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class AddFoodToDiaryInput(BaseModel):
    """Input model for adding food to diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from mfp_search_food)",
        min_length=1,
    )
    meal: str = Field(
        default="Breakfast",
        description="Meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks')",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    quantity: float = Field(
        default=1.0,
        description="Quantity/servings (e.g., 1.5 for 1.5 servings)",
        gt=0,
        le=100,
    )
    unit: Optional[str] = Field(
        default=None,
        description="Unit/serving size description (e.g., '1 cup', '100g'). If not provided, uses default serving size from food item.",
    )


class CreateCustomFoodInput(BaseModel):
    """Input model for creating a private custom food."""

    model_config = ConfigDict(str_strip_whitespace=True)

    description: str = Field(
        ..., description="Food name as it appears in MFP", min_length=1, max_length=200
    )
    brand_name: str = Field(
        default="Generic",
        description="Brand. Packaged food = label brand; restaurant = venue name; homemade = 'Generic'.",
        max_length=200,
    )
    serving_amount: float = Field(
        default=100, description="Serving size number (e.g. 100 for '100 g')", gt=0
    )
    serving_unit: str = Field(
        default="g", description="Serving unit (e.g. 'g', 'ml', 'piece', 'box (100 g)')"
    )
    calories: float = Field(..., description="Calories per serving", ge=0)

    carbs: Optional[float] = Field(
        default=None,
        description="NET carbs in g (MFP adds fiber itself to report total; never pre-add fiber)",
        ge=0,
    )
    fiber: Optional[float] = Field(default=None, description="Fiber, g", ge=0)
    sugar: Optional[float] = Field(default=None, description="Sugars, g", ge=0)
    protein: Optional[float] = Field(default=None, description="Protein, g", ge=0)
    fat: Optional[float] = Field(default=None, description="Total fat, g", ge=0)
    saturated_fat: Optional[float] = Field(default=None, description="Saturated fat, g", ge=0)
    polyunsaturated_fat: Optional[float] = Field(default=None, description="Polyunsaturated fat, g", ge=0)
    monounsaturated_fat: Optional[float] = Field(default=None, description="Monounsaturated fat, g", ge=0)
    trans_fat: Optional[float] = Field(default=None, description="Trans fat, g", ge=0)
    cholesterol: Optional[float] = Field(default=None, description="Cholesterol, mg", ge=0)
    sodium: Optional[float] = Field(default=None, description="Sodium, mg", ge=0)
    potassium: Optional[float] = Field(default=None, description="Potassium, mg", ge=0)
    vitamin_a: Optional[float] = Field(default=None, description="Vitamin A, %DV", ge=0)
    vitamin_c: Optional[float] = Field(default=None, description="Vitamin C, %DV", ge=0)
    calcium: Optional[float] = Field(default=None, description="Calcium, %DV", ge=0)
    iron: Optional[float] = Field(default=None, description="Iron, %DV", ge=0)

    country_code: str = Field(
        default="NL",
        description=(
            "Label convention, and it changes carb meaning. 'NL'/EU: `carbs` is read as NET "
            "(MFP reports total = carbs + fiber). Omitting/US: `carbs` is read as TOTAL. "
            "Keep 'NL' unless deliberately entering a US-style total-carb label."
        ),
        min_length=2, max_length=2,
    )
    public: bool = Field(
        default=False, description="Share publicly. Keep False for personal entries."
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class DeleteCustomFoodInput(BaseModel):
    """Input model for deleting a custom food."""

    model_config = ConfigDict(str_strip_whitespace=True)

    food_id: str = Field(..., description="Food id (from mfp_create_custom_food or mfp_list_own_foods)", min_length=1)
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class ListOwnFoodsInput(BaseModel):
    """Input model for listing the user's own custom foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    search: str = Field(default="", description="Optional substring filter on the food name")
    limit: int = Field(default=25, description="Max foods to return", gt=0, le=200)
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class RemoveFoodFromDiaryInput(BaseModel):
    """Input model for removing food entries from diary."""

    model_config = ConfigDict(extra="forbid")

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    entry_id: Optional[str] = Field(
        default=None,
        description=(
            "Specific food_entry_id to remove. If omitted, name_contains is "
            "used to match by name."
        ),
    )
    name_contains: Optional[str] = Field(
        default=None,
        description=(
            "Case-insensitive substring to match against entry names "
            "(e.g. 'banana' or '0.5 cup rice'). Ignored if entry_id is set."
        ),
    )
    meal: Optional[str] = Field(
        default=None,
        description=(
            "Restrict matching to a meal: Breakfast, Lunch, Dinner, Snacks."
        ),
    )
    max_matches: int = Field(
        default=1,
        gt=0,
        le=50,
        description=(
            "Safety cap on how many matching entries to delete in one call."
        ),
    )


class SetWaterInput(BaseModel):
    """Input model for setting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cups: float = Field(
        ...,
        description="Number of cups of water (e.g., 2.5 for 2.5 cups). Note: MyFitnessPal uses cups as the unit.",
        ge=0,
        le=50,
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


# ============================================================================
# Diary Entry Creation Helper Functions
# ============================================================================


def _mfp_api_headers(client, json_body: bool = False) -> Dict[str, str]:
    """
    Build auth headers for MyFitnessPal's v2 JSON API.

    The v2 API backs the current MFP web client. It requires the session's
    OAuth bearer token plus an mfp-client-id identifying the calling client.
    """
    headers = {
        "Authorization": f"Bearer {client.access_token}",
        "mfp-client-id": MFP_CLIENT_ID,
        "mfp-user-id": str(client.user_id),
        "Accept": "application/json",
    }
    if json_body:
        headers["Content-Type"] = "application/json"
    return headers


def get_food_v2(client, mfp_id: str) -> Dict[str, Any]:
    """
    Fetch a food's full v2 record, including its version and serving sizes.

    The diary API rejects entries whose food version does not match the
    current stored version, so this must be read fresh rather than cached.

    Args:
        client: Authenticated myfitnesspal.Client instance
        mfp_id: MyFitnessPal food item ID

    Returns:
        The food object as returned by the v2 API

    Raises:
        RuntimeError: If the food cannot be retrieved
    """
    response = client.session.get(
        f"{MFP_API_BASE}/v2/foods",
        params={"ids": str(mfp_id)},
        headers=_mfp_api_headers(client),
        timeout=30,
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"Could not look up food {mfp_id}: HTTP {response.status_code}"
        )

    items = response.json().get("items") or []
    if not items:
        raise RuntimeError(f"No food found with ID {mfp_id}")
    return items[0]


def select_serving_size(food: Dict[str, Any], unit: Optional[str] = None) -> Dict[str, Any]:
    """
    Choose which of a food's serving sizes to log against.

    Args:
        food: Food object from get_food_v2
        unit: Optional unit to match (e.g. "oz", "medium breast"). Matching is
            case-insensitive and accepts a substring. Falls back to the food's
            default (first) serving size when omitted or unmatched.

    Returns:
        The serving size dict, trimmed to the fields the diary API permits

    Raises:
        RuntimeError: If the food declares no serving sizes
    """
    serving_sizes = food.get("serving_sizes") or []
    if not serving_sizes:
        raise RuntimeError(f"Food {food.get('id')} has no serving sizes")

    chosen = serving_sizes[0]
    if unit:
        wanted = unit.strip().lower()
        exact = [s for s in serving_sizes if str(s.get("unit", "")).lower() == wanted]
        substring = [
            s for s in serving_sizes if wanted in str(s.get("unit", "")).lower()
        ]
        candidates = exact or substring
        if candidates:
            # Some foods list the same unit twice (e.g. a "100 g" pack
            # alongside a per-gram entry) - prefer value=1.0 so quantity
            # means a literal count of `unit`, not a count of packs.
            chosen = next((c for c in candidates if c.get("value") == 1.0), candidates[0])
        else:
            logger.warning(
                f"Unit {unit!r} not found for food {food.get('id')}; "
                f"using default serving {chosen.get('unit')!r}"
            )

    # The diary endpoint rejects any serving_size field beyond these three.
    return {
        "value": chosen["value"],
        "unit": chosen["unit"],
        "nutrition_multiplier": chosen["nutrition_multiplier"],
    }



# ============================================================================
# Custom-food creation (web BFF /api/services/foods)
#
# MFP exposes no custom-food create on the v2 OAuth API, but its own web client
# does it with three plain HTTP calls, all cookie-authenticated. Since this
# server already holds a logged-in cookie jar, it can call them directly — no
# browser automation, no Chrome running.
#
#   GET  /api/auth/csrf                  -> { csrfToken }
#   GET  /api/services/users/foods/mine  -> [ ...foods ]   (source of user_id)
#   POST /api/services/foods             -> { item: {...} } (201/200)
#   DELETE /api/services/foods/{id}      -> 204
#
# CARBS + COUNTRY_CODE (verified 2026-07-26, both directions):
# `country_code` decides how MFP reads nutritional_contents.carbohydrates.
#   country_code="NL" (EU labels exclude fibre):
#       sent value = NET  -> stores net_carbs=sent, carbohydrates=sent+fiber
#   country_code omitted (US default, labels include fibre):
#       sent value = TOTAL -> stores carbohydrates=sent, net_carbs=sent-fiber
# Sending carbohydrates=42, fiber=8 gives 50/42 with "NL" and 42/34 without.
# So country_code is NOT cosmetic: omitting it silently shifts every carb value
# by the fibre amount. Default "NL" and pass NET carbs.
# ============================================================================

MFP_WEB_BASE = "https://www.myfitnesspal.com"

# canonical arg -> MFP nutritional_contents key
_NUTRIENT_KEYS = {
    "fat": "fat",
    "saturated_fat": "saturated_fat",
    "polyunsaturated_fat": "polyunsaturated_fat",
    "monounsaturated_fat": "monounsaturated_fat",
    "trans_fat": "trans_fat",
    "cholesterol": "cholesterol",
    "sodium": "sodium",
    "potassium": "potassium",
    "carbs": "carbohydrates",
    "fiber": "fiber",
    "sugar": "sugar",
    "protein": "protein",
    "vitamin_a": "vitamin_a",
    "vitamin_c": "vitamin_c",
    "calcium": "calcium",
    "iron": "iron",
}


def _web_headers(csrf: Optional[str] = None, json_body: bool = False) -> Dict[str, str]:
    """Headers for the cookie-authenticated web BFF."""
    headers = {"Accept": "application/json"}
    if json_body:
        headers["Content-Type"] = "application/json"
    if csrf:
        headers["x-csrf-token"] = csrf
    return headers


def _api_error_detail(response) -> str:
    """Pull MFP's structured error text out of a failed response.

    Mirrors how add_food_to_diary surfaces v2 errors, so we report the API's own
    message rather than echoing an arbitrary slice of the response body.
    """
    try:
        body = response.json()
    except Exception:
        return ""
    if not isinstance(body, dict):
        return ""
    return str(
        body.get("error_description")
        or body.get("error_details", {}).get("item_error")
        or body.get("error")
        or ""
    )


def _get_csrf_token(client) -> Optional[str]:
    """Fetch a CSRF token. Returns None if unavailable; POST will then 403."""
    try:
        r = client.session.get(
            f"{MFP_WEB_BASE}/api/auth/csrf", headers=_web_headers(), timeout=30
        )
        if r.status_code == 200:
            return r.json().get("csrfToken")
    except Exception as e:
        logger.warning(f"Could not fetch CSRF token: {e}")
    return None


def list_own_foods(client, search: str = "") -> List[Dict[str, Any]]:
    """List the user's own custom foods (newest first), optionally filtered."""
    r = client.session.get(
        f"{MFP_WEB_BASE}/api/services/users/foods/mine",
        params={"search": search},
        headers=_web_headers(),
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(
            f"Could not list own foods: HTTP {r.status_code}. "
            "The stored session may have expired — run refresh_browser_cookies."
        )
    return r.json() or []


def _serving_sizes(amount: float, unit: str) -> List[Dict[str, Any]]:
    """Primary serving plus the container wrapper MFP's own client sends."""
    return [
        {
            "value": amount,
            "unit": unit,
            "nutrition_multiplier": 1,
            "gram_weight": 1,
            "fraction": False,
            "index": 0,
        },
        {
            "value": 1,
            "unit": f"container ({amount} {unit} ea.)",
            "nutrition_multiplier": 1,
            "gram_weight": 1,
            "fraction": False,
            "index": 1,
        },
    ]


def create_custom_food(client, spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a private custom food via the web BFF.

    Args:
        client: authenticated myfitnesspal.Client
        spec: validated CreateCustomFoodInput as a dict

    Returns:
        {"id": str|None, "status": int, "description": str}
    """
    csrf = _get_csrf_token(client)

    nutrition: Dict[str, Any] = {
        "energy": {"unit": "calories", "value": spec["calories"]},
        "grams": 1,
    }
    for arg, api_key in _NUTRIENT_KEYS.items():
        value = spec.get(arg)
        if value is not None:
            nutrition[api_key] = value

    item = {
        "description": spec["description"],
        "brand_name": spec.get("brand_name") or "Generic",
        "public": bool(spec.get("public", False)),
        "type": "food",
        "nutritional_contents": nutrition,
        "serving_sizes": _serving_sizes(
            spec.get("serving_amount", 100), spec.get("serving_unit", "g")
        ),
    }
    item["country_code"] = spec.get("country_code") or "NL"
    # Ownership is assigned by MyFitnessPal from the session, so user_id is not
    # sent: posting without it returns 200 with the correct owner. Sending it
    # would also mean an extra request, and would fail for an account that has
    # no custom foods yet.

    r = client.session.post(
        f"{MFP_WEB_BASE}/api/services/foods",
        headers=_web_headers(csrf, json_body=True),
        data=json.dumps({"item": item}),
        timeout=30,
    )

    if r.status_code not in (200, 201):
        hint = "" if csrf else " (no CSRF token acquired)"
        detail = _api_error_detail(r)
        raise RuntimeError(
            f"Failed to create custom food: HTTP {r.status_code}{hint}"
            + (f" - {detail}" if detail else "")
        )

    # MFP returns a bare list of the created food object(s); older docs/clients
    # assumed {"item": {...}}. Accept both.
    new_id = None
    try:
        body = r.json()
        if isinstance(body, list) and body:
            new_id = body[0].get("id")
        elif isinstance(body, dict):
            new_id = (body.get("item") or body).get("id")
    except Exception:
        pass
    if new_id is None:
        logger.warning("Food created but MyFitnessPal returned no id")

    logger.info(f"Created custom food {new_id}: {spec['description']}")
    return {"id": new_id, "status": r.status_code, "description": spec["description"]}


def delete_custom_food(client, food_id: str) -> int:
    """Delete a custom food by id. MFP has no update endpoint — recreate + delete."""
    csrf = _get_csrf_token(client)
    r = client.session.delete(
        f"{MFP_WEB_BASE}/api/services/foods/{food_id}",
        headers=_web_headers(csrf),
        timeout=30,
    )
    if r.status_code not in (200, 204):
        detail = _api_error_detail(r)
        raise RuntimeError(
            f"Failed to delete custom food {food_id}: HTTP {r.status_code}"
            + (f" - {detail}" if detail else "")
        )
    logger.info(f"Deleted custom food {food_id}")
    return r.status_code


def add_food_to_diary(
    client, mfp_id: str, meal: str, target_date: date, quantity: float = 1.0, unit: Optional[str] = None
) -> Optional[str]:
    """
    Add a food item to the diary for a specific date and meal.

    Args:
        client: Authenticated myfitnesspal.Client instance
        mfp_id: MyFitnessPal food item ID
        meal: Meal name (Breakfast, Lunch, Dinner, Snacks)
        target_date: Date to add the food entry
        quantity: Number of servings (default 1.0)
        unit: Optional serving unit to log against (e.g. "oz")

    Returns:
        The new entry's UUID, or None if MFP did not return one

    Raises:
        RuntimeError: If the operation fails
    """
    food = get_food_v2(client, mfp_id)
    serving_size = select_serving_size(food, unit)

    meal_name = meal.strip().capitalize()
    if meal_name not in VALID_MEALS:
        raise RuntimeError(
            f"Invalid meal {meal!r}. Expected one of: {', '.join(VALID_MEALS)}"
        )

    entry = {
        "type": "food_entry",
        "date": target_date.strftime("%Y-%m-%d"),
        "meal_name": meal_name,
        "servings": float(quantity),
        "food": {"id": str(food["id"]), "version": str(food["version"])},
        "serving_size": serving_size,
    }

    response = client.session.post(
        f"{MFP_API_BASE}/v2/diary",
        headers=_mfp_api_headers(client, json_body=True),
        data=json.dumps({"items": [entry]}),
        timeout=30,
    )

    if response.status_code not in (200, 201):
        detail = ""
        try:
            body = response.json()
            detail = body.get("error_details", {}).get("item_error") or body.get(
                "error_description", ""
            )
        except Exception:
            pass
        raise RuntimeError(
            f"Failed to add food to diary: HTTP {response.status_code}"
            + (f" - {detail}" if detail else "")
        )

    logger.info(
        f"Added food {mfp_id} ({serving_size['value']} {serving_size['unit']} "
        f"x{quantity}) to {meal_name} for {target_date}"
    )

    # MFP returns the new entry's id here and nowhere else - the diary page
    # exposes only legacy numeric ids, which the v2 API does not accept.
    try:
        return response.json()["items"][0]["id"]
    except (ValueError, KeyError, IndexError):
        logger.warning("Entry created but MyFitnessPal returned no entry id")
        return None


def list_diary_entries(client, target_date: date) -> List[Dict[str, str]]:
    """
    Scrape the diary page for the given date and return a list of entries
    with their internal food_entry_id (needed for deletion), name, and meal.

    Returns:
        List of {"entry_id", "name", "meal"} dicts in display order.
    """
    import re

    date_str = target_date.strftime("%Y-%m-%d")
    diary_url = f"{client.BASE_URL_SECURE}food/diary?date={date_str}"
    # Use the library's session to ensure cookies/CSRF/etc. are aligned
    response = client.session.get(diary_url)
    src = response.text

    entries: List[Dict[str, str]] = []
    # Walk through the HTML linearly. Track the most recent meal header.
    current_meal = None
    pattern = re.compile(
        r'(class="meal_header"[^>]*>\s*<[^>]+>([^<]+)</[^>]+>)|'
        r'(<a[^>]+data-food-entry-id="(\d+)"[^>]+class="js-show-edit-food"[^>]*>'
        r'([^<]+)</a>)',
        re.DOTALL,
    )
    for m in pattern.finditer(src):
        if m.group(2):
            current_meal = m.group(2).strip()
        elif m.group(4):
            entries.append({
                "entry_id": m.group(4),
                "name": m.group(5).strip(),
                "meal": current_meal or "",
            })
    return entries


def remove_diary_entry_v2(client, entry_id: str) -> None:
    """
    Delete a food diary entry by the UUID the v2 diary API assigned it
    (what `add_food_to_diary` returns - a different id space than the
    legacy numeric `food_entry_id` used by `remove_food_entry`).
    """
    response = client.session.delete(
        f"{MFP_API_BASE}/v2/diary/{entry_id}",
        headers=_mfp_api_headers(client),
        timeout=30,
    )
    if response.status_code in (200, 204):
        logger.info(f"Removed diary entry {entry_id}")
        return
    raise RuntimeError(
        f"Remove failed for entry {entry_id}: HTTP {response.status_code}"
    )


def remove_food_entry(client, entry_id: str) -> None:
    """
    Delete a food diary entry by its legacy numeric food_entry_id, as
    returned by `list_diary_entries` (see `remove_diary_entry_v2` for the
    v2 UUID case).

    Uses the legacy /food/remove/{id} endpoint with X-CSRF-Token from
    the diary page meta tag.
    """
    import re

    # Need a fresh CSRF token from the diary page
    diary_resp = client.session.get(
        f"{client.BASE_URL_SECURE}food/diary"
    )
    csrf_match = re.search(
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
        diary_resp.text,
    )
    if not csrf_match:
        raise RuntimeError("Could not extract csrf-token from diary page")
    csrf = csrf_match.group(1)

    response = client.session.request(
        "DELETE",
        f"{client.BASE_URL_SECURE}food/remove/{entry_id}",
        headers={
            "Referer": f"{client.BASE_URL_SECURE}food/diary",
            "X-CSRF-Token": csrf,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        },
        allow_redirects=False,
    )
    # Success = 302 redirect to diary, or 200 with empty body
    if response.status_code in (200, 204, 302, 303):
        logger.info(f"Removed diary entry {entry_id}")
        return
    raise RuntimeError(
        f"Remove failed for entry {entry_id}: HTTP {response.status_code}"
    )


def set_water_intake(client, target_date: date, cups: float) -> None:
    """
    Set water intake for a specific date.
    
    Args:
        client: Authenticated myfitnesspal.Client instance
        target_date: Date to set water intake
        cups: Number of cups of water
    
    Raises:
        RuntimeError: If the operation fails
    """
    from urllib import parse
    
    try:
        # Get the diary page for the target date to extract CSRF token
        date_str = target_date.strftime("%Y-%m-%d")
        diary_url = parse.urljoin(
            client.BASE_URL_SECURE,
            f"food/diary/{client.effective_username}?date={date_str}"
        )
        
        # Use the library's method to get the document
        document = client._get_document_for_url(diary_url)
        
        # Extract authenticity token
        authenticity_token = document.xpath(
            "(//input[@name='authenticity_token']/@value)[1]"
        )
        if not authenticity_token:
            raise RuntimeError("Could not find authenticity token on diary page")
        authenticity_token = authenticity_token[0]
        
        # Build the URL for setting water
        # MyFitnessPal uses /food/diary/{username}/water endpoint
        water_url = parse.urljoin(
            client.BASE_URL_SECURE,
            f"food/diary/{client.effective_username}/water"
        )
        
        # Prepare the data for the POST request
        post_data = {
            "authenticity_token": authenticity_token,
            "date": date_str,
            "water": str(cups),
        }
        
        # Set water intake
        headers = {
            "Referer": diary_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }
        
        response = client.session.post(water_url, data=post_data, headers=headers)
        response.raise_for_status()
        
        if response.status_code != 200:
            raise RuntimeError(f"Failed to set water: HTTP {response.status_code}")
        
        logger.info(f"Successfully set water intake to {cups} cups for {target_date}")
        
    except Exception as e:
        # Don't expose internal error details to avoid leaking sensitive information
        error_msg = str(e)
        # Only include safe error information
        if "HTTP" in error_msg or "status" in error_msg.lower():
            raise RuntimeError(f"Failed to set water intake: {error_msg}")
        else:
            raise RuntimeError("Failed to set water intake. Please check your authentication and try again.")


# ============================================================================
# MCP Tools
# ============================================================================


@mcp.tool(
    name="mfp_get_diary",
    annotations={
        "title": "Get Food Diary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_diary(params: GetDiaryInput) -> str:
    """
    Get the food diary for a specific date including all meals and their nutritional information.

    Returns meals (Breakfast, Lunch, Dinner, Snacks) with each food entry's name,
    quantity, and complete nutrition breakdown (calories, protein, carbs, fat, etc.).
    Also includes daily totals and goals.

    Args:
        params: GetDiaryInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Formatted diary data with meals, entries, nutrition, and goals
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        # Build response data
        data = {
            "date": str(target_date),
            "meals": {},
            "daily_totals": {},
            "daily_goals": {},
            "water": day.water,
            "notes": day.notes or "",
        }

        # Process meals
        for meal in day.meals:
            meal_data = {
                "entries": [format_meal_entry(entry) for entry in meal.entries],
                "totals": format_nutrition_dict(meal.totals),
            }
            data["meals"][meal.name] = meal_data

        # Get daily totals and goals
        totals = {}
        for entry in day.entries:
            for key, value in entry.totals.items():
                val = float(value.magnitude) if hasattr(value, "magnitude") else value
                totals[key] = totals.get(key, 0) + val
        data["daily_totals"] = totals
        data["daily_goals"] = day.goals

        return format_response(
            data, params.response_format, f"Food Diary for {target_date}"
        )

    except Exception as e:
        return f"Error retrieving diary: {str(e)}"


@mcp.tool(
    name="mfp_search_food",
    annotations={
        "title": "Search Food Database",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_search_food(params: SearchFoodInput) -> str:
    """
    Search the MyFitnessPal food database for food items.

    Returns a list of matching foods with their name, brand, serving size,
    calories, and MFP ID (which can be used with mfp_get_food_details).

    Args:
        params: SearchFoodInput containing:
            - query (str): Search query (e.g., 'chicken breast')
            - limit (int): Maximum results to return (default 10)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of matching food items with basic nutrition info
    """
    try:
        client = get_mfp_client()
        results = client.get_food_search_results(params.query)

        # Limit results
        results = results[: params.limit]

        data = {"query": params.query, "count": len(results), "results": []}

        for item in results:
            data["results"].append(
                {
                    "name": item.name,
                    "brand": item.brand,
                    "serving": item.serving,
                    "calories": item.calories,
                    "mfp_id": item.mfp_id,
                }
            )

        return format_response(
            data, params.response_format, f"Food Search Results for '{params.query}'"
        )

    except Exception as e:
        return f"Error searching foods: {str(e)}"


@mcp.tool(
    name="mfp_get_food_details",
    annotations={
        "title": "Get Food Item Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_food_details(params: GetFoodDetailsInput) -> str:
    """
    Get detailed nutritional information for a specific food item by its MFP ID.

    Returns complete nutrition breakdown including calories, macros (protein, carbs, fat),
    fiber, sugar, sodium, cholesterol, vitamins, minerals, and available serving sizes.

    Args:
        params: GetFoodDetailsInput containing:
            - mfp_id (str): MyFitnessPal food item ID from search results
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Complete nutritional information for the food item
    """
    try:
        client = get_mfp_client()
        # client.get_food_item_details() scrapes a now-client-rendered page
        # and raises on nearly every food; get_food_v2 is the reliable path.
        food = get_food_v2(client, params.mfp_id)
        nutrition = food.get("nutritional_contents", {}) or {}
        energy = nutrition.get("energy") or {}

        data = {
            "mfp_id": params.mfp_id,
            "description": food.get("description", "N/A"),
            "brand_name": food.get("brand_name") or None,
            "verified": food.get("verified", False),
            "calories": energy.get("value"),
            # nutrition values below are per this many grams of the food
            "nutrition_basis_grams": nutrition.get("grams"),
            "nutrition": {
                "protein": nutrition.get("protein"),
                "carbohydrates": nutrition.get("carbohydrates"),
                "fat": nutrition.get("fat"),
                "fiber": nutrition.get("fiber"),
                "sugar": nutrition.get("sugar"),
                "sodium": nutrition.get("sodium"),
                "cholesterol": nutrition.get("cholesterol"),
                "saturated_fat": nutrition.get("saturated_fat"),
                "polyunsaturated_fat": nutrition.get("polyunsaturated_fat"),
                "monounsaturated_fat": nutrition.get("monounsaturated_fat"),
                "trans_fat": nutrition.get("trans_fat"),
                "potassium": nutrition.get("potassium"),
                "vitamin_a": nutrition.get("vitamin_a"),
                "vitamin_c": nutrition.get("vitamin_c"),
                "calcium": nutrition.get("calcium"),
                "iron": nutrition.get("iron"),
            },
            "servings": [
                f"{s['value']} {s['unit']}" for s in food.get("serving_sizes", [])
            ],
        }

        return format_response(data, params.response_format, "Food Item Details")

    except Exception as e:
        return f"Error getting food details: {str(e)}"


@mcp.tool(
    name="mfp_get_measurements",
    annotations={
        "title": "Get Body Measurements",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_measurements(params: GetMeasurementsInput) -> str:
    """
    Get body measurements (weight, body fat, etc.) over a date range.

    Returns historical measurement data with dates and values. Useful for
    tracking weight loss progress and body composition changes.

    Args:
        params: GetMeasurementsInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - start_date (str, optional): Start date, defaults to 30 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Measurement history with dates and values
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=30)

        # client.get_measurements() scrapes a "dehydratedState" key that no
        # longer exists on the (now client-rendered) page - KeyErrors every
        # call. The v2 endpoint below works, but its begin_date/end_date/type
        # params don't actually filter server-side, so we filter here.
        response = client.session.get(
            f"{MFP_API_BASE}/v2/measurements",
            params={
                "type": params.measurement,
                "begin_date": start.strftime("%Y-%m-%d"),
                "end_date": end.strftime("%Y-%m-%d"),
            },
            headers=_mfp_api_headers(client),
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Could not fetch measurements: HTTP {response.status_code}"
            )

        wanted_type = params.measurement.strip().lower()
        measurements: OrderedDict[str, float] = OrderedDict(
            sorted(
                (
                    (item["date"], float(item["value"]))
                    for item in response.json().get("items", [])
                    if item.get("type", "").strip().lower() == wanted_type
                    and start <= parse_date(item["date"]) <= end
                ),
                key=lambda pair: pair[0],
            )
        )

        data = {
            "measurement_type": params.measurement,
            "start_date": str(start),
            "end_date": str(end),
            "count": len(measurements),
            "values": ordered_dict_to_dict(measurements),
        }

        # Calculate summary stats if we have data
        if measurements:
            values = list(measurements.values())
            data["summary"] = {
                "latest": values[-1] if values else None,
                "earliest": values[0] if values else None,
                "change": round(values[-1] - values[0], 2) if len(values) >= 2 else 0,
                "min": min(values),
                "max": max(values),
                "average": round(sum(values) / len(values), 2),
            }

        return format_response(
            data, params.response_format, f"{params.measurement} History"
        )

    except Exception as e:
        return f"Error getting measurements: {str(e)}"


@mcp.tool(
    name="mfp_set_measurement",
    annotations={
        "title": "Log Body Measurement",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_measurement(params: SetMeasurementInput) -> str:
    """
    Log a new body measurement (weight, body fat, etc.) for today.

    Records the measurement value in MyFitnessPal for tracking progress.

    Args:
        params: SetMeasurementInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - value (float): Measurement value (e.g., 185.5)

    Returns:
        str: Confirmation message with the logged value
    """
    try:
        client = get_mfp_client()
        client.set_measurements(params.measurement, params.value)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.measurement}: {params.value}",
                "measurement": params.measurement,
                "value": params.value,
                "date": str(date.today()),
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting measurement: {str(e)}"


@mcp.tool(
    name="mfp_get_exercises",
    annotations={
        "title": "Get Exercise Log",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_exercises(params: GetExercisesInput) -> str:
    """
    Get logged exercises for a specific date.

    Returns both cardiovascular and strength training exercises with their
    details (duration, calories burned, sets, reps, weight, etc.).

    Args:
        params: GetExercisesInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of exercises with details and calories burned
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "exercises": []}

        for exercise in day.exercises:
            data["exercises"].append(format_exercise(exercise))

        # Calculate total calories burned
        total_burned = 0
        for ex in data["exercises"]:
            for entry in ex.get("entries", []):
                if "nutrition_information" in entry:
                    total_burned += entry["nutrition_information"].get(
                        "calories burned", 0
                    )

        data["total_calories_burned"] = total_burned

        return format_response(
            data, params.response_format, f"Exercise Log for {target_date}"
        )

    except Exception as e:
        return f"Error getting exercises: {str(e)}"


@mcp.tool(
    name="mfp_get_goals",
    annotations={
        "title": "Get Nutrition Goals",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_goals(params: GetGoalsInput) -> str:
    """
    Get the user's daily nutrition goals (calories, protein, carbs, fat, etc.).

    Returns the configured daily targets for all tracked nutrients.

    Args:
        params: GetGoalsInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily nutrition goals and targets
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "goals": day.goals}

        return format_response(data, params.response_format, "Daily Nutrition Goals")

    except Exception as e:
        return f"Error getting goals: {str(e)}"


@mcp.tool(
    name="mfp_set_goals",
    annotations={
        "title": "Update Nutrition Goals",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_set_goals(params: SetGoalsInput) -> str:
    """
    Update daily nutrition goals (calories, protein, carbs, fat).

    Sets new daily targets for the specified nutrients. Only updates the
    values that are provided; others remain unchanged.

    Args:
        params: SetGoalsInput containing:
            - calories (int, optional): Daily calorie goal
            - protein (int, optional): Daily protein goal in grams
            - carbohydrates (int, optional): Daily carb goal in grams
            - fat (int, optional): Daily fat goal in grams

    Returns:
        str: Confirmation message with updated goals
    """
    try:
        # Check that at least one goal is provided
        if not any(
            [params.calories, params.protein, params.carbohydrates, params.fat]
        ):
            return "Error: Please provide at least one goal to update (calories, protein, carbohydrates, or fat)"

        client = get_mfp_client()

        # Build kwargs for set_new_goal
        kwargs = {}
        if params.calories:
            kwargs["energy"] = params.calories
        if params.protein:
            kwargs["protein"] = params.protein
        if params.carbohydrates:
            kwargs["carbohydrates"] = params.carbohydrates
        if params.fat:
            kwargs["fat"] = params.fat

        client.set_new_goal(**kwargs)

        return json.dumps(
            {
                "success": True,
                "message": "Successfully updated nutrition goals",
                "updated_goals": {
                    "calories": params.calories,
                    "protein": params.protein,
                    "carbohydrates": params.carbohydrates,
                    "fat": params.fat,
                },
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting goals: {str(e)}"


# WATER — always millilitres.
#
# python-myfitnesspal's `_get_water` (myfitnesspal/client.py:769) calls the
# `/food/water` endpoint and reads `result.json()["item"]["milliliters"]`
# directly, so `day.water` is unambiguously ml regardless of the account's
# display unit. The old code returned `water_cups = day.water` and
# `water_ml = day.water * 236.588` — a double bug: the raw ml value was
# mislabelled as cups, and the "converted" ml was raw_ml * 236.588. On a
# millilitre account that turned an 8,737 ml day into 2,067 litres.
#
# Fix: return the ml value under its correct name. That's the whole story.
#
# No `water_goal` is included: `day.goals` carries only calories,
# carbohydrates, fat, protein, sodium and sugar (verified against a live
# account and against python-myfitnesspal's `_get_goals`). MFP's water goal
# lives elsewhere and isn't exposed through this client path.
def _water_payload(day, date_str: str) -> Dict[str, Any]:
    """Build the mfp_get_water response. Pure: no network, no client."""
    return {"date": date_str, "water_ml": day.water}


@mcp.tool(
    name="mfp_get_water",
    annotations={
        "title": "Get Water Intake",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_water(params: GetWaterInput) -> str:
    """
    Get water intake for a specific date, in millilitres.

    MyFitnessPal's `/food/water` endpoint returns the amount in a field
    literally named `milliliters` (see python-myfitnesspal's `_get_water`),
    so this value is always ml regardless of what unit the account's UI is
    configured to display.

    Args:
        params: GetWaterInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: JSON with `date` and `water_ml`
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)
        return json.dumps(_water_payload(day, str(target_date)), indent=2)

    except Exception as e:
        return f"Error getting water intake: {str(e)}"


@mcp.tool(
    name="mfp_add_food_to_diary",
    annotations={
        "title": "Add Food to Diary",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_add_food_to_diary(params: AddFoodToDiaryInput) -> str:
    """
    Add a food item to your MyFitnessPal food diary for a specific date and meal.

    This tool adds a food entry to your diary. You can search for foods using
    mfp_search_food to find the food ID (mfp_id) needed for this tool.

    Args:
        params: AddFoodToDiaryInput containing:
            - mfp_id (str): MyFitnessPal food item ID (from mfp_search_food)
            - meal (str): Meal name - 'Breakfast', 'Lunch', 'Dinner', or 'Snacks' (default: 'Breakfast')
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - quantity (float): Number of servings (default: 1.0)
            - unit (str, optional): Unit/serving size (e.g., '1 cup', '100g')

    Returns:
        str: Confirmation message with details of the added food entry
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        
        # Normalize meal name (capitalize first letter)
        meal = params.meal.strip().capitalize()
        if meal.lower() == "snack":
            meal = "Snacks"
        
        # Add food to diary
        entry_id = add_food_to_diary(
            client=client,
            mfp_id=params.mfp_id,
            meal=meal,
            target_date=target_date,
            quantity=params.quantity,
            unit=params.unit,
        )

        try:
            food_name = get_food_v2(client, params.mfp_id).get("description", "Food item")
        except Exception:
            food_name = "Food item"

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully added {food_name} to {meal}",
                "entry_id": entry_id,
                "date": str(target_date),
                "meal": meal,
                "food_id": params.mfp_id,
                "food_name": food_name,
                "quantity": params.quantity,
                "unit": params.unit,
            },
            indent=2,
        )
        
    except Exception as e:
        return f"Error adding food to diary: {str(e)}"


@mcp.tool(
    name="mfp_remove_food_from_diary",
    annotations={
        "title": "Remove Food From Diary",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_remove_food_from_diary(params: RemoveFoodFromDiaryInput) -> str:
    """
    Remove (delete) one or more food entries from your diary.

    Two modes:

    1. By entry_id (precise): delete exactly the entry whose id matches -
       this is the UUID `mfp_add_food_to_diary` returned when you logged it.
       Use this when you already know the ID.

    2. By name_contains (fuzzy): list the day's entries, find ones whose
       name contains the given substring (case-insensitive), optionally
       restricted to a meal, and delete up to max_matches of them.

    Args:
        params: RemoveFoodFromDiaryInput with one of:
            - entry_id: the entry's UUID, as returned by
              mfp_add_food_to_diary (NOT a food_entry_id from the diary page)
            - name_contains: substring match against entry names
            - meal: restrict matching to one meal
            - max_matches: safety cap for fuzzy matches (default 1)
            - date: date to operate on (default today)

    Returns:
        JSON describing each entry that was removed.
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        # Mode 1: delete a single entry by its v2 UUID (what add returns)
        if params.entry_id:
            remove_diary_entry_v2(client, params.entry_id)
            return json.dumps({
                "success": True,
                "removed": [{"entry_id": params.entry_id}],
                "date": str(target_date),
            }, indent=2)

        # Mode 2: fuzzy match by name (+ optional meal filter)
        if not params.name_contains:
            return ("Error removing food: provide either entry_id or "
                    "name_contains")

        entries = list_diary_entries(client, target_date)
        needle = params.name_contains.lower()
        meal_filter = (
            params.meal.lower() if params.meal else None
        )

        matches = []
        for e in entries:
            if needle not in e["name"].lower():
                continue
            if meal_filter and meal_filter not in e["meal"].lower():
                continue
            matches.append(e)

        if not matches:
            return json.dumps({
                "success": False,
                "removed": [],
                "message": (
                    f"No entries matched '{params.name_contains}'"
                    + (f" in {params.meal}" if params.meal else "")
                ),
            }, indent=2)

        to_remove = matches[: params.max_matches]
        removed = []
        for e in to_remove:
            remove_food_entry(client, e["entry_id"])
            removed.append({
                "entry_id": e["entry_id"],
                "name": e["name"],
                "meal": e["meal"],
            })

        return json.dumps({
            "success": True,
            "removed": removed,
            "matched_count": len(matches),
            "remaining_matches_skipped": max(
                0, len(matches) - len(to_remove)
            ),
            "date": str(target_date),
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        return f"Error removing food: {e}"


@mcp.tool(
    name="mfp_set_water",
    annotations={
        "title": "Log Water Intake",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_water(params: SetWaterInput) -> str:
    """
    Log water intake for a specific date.

    Sets the number of cups of water consumed for the day. MyFitnessPal uses
    cups as the unit (1 cup = ~237ml).

    Args:
        params: SetWaterInput containing:
            - cups (float): Number of cups of water (e.g., 2.5 for 2.5 cups)
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation message with the logged water amount
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        
        # Set water intake
        set_water_intake(client=client, target_date=target_date, cups=params.cups)
        
        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.cups} cups of water",
                "date": str(target_date),
                "cups": params.cups,
                "milliliters": round(params.cups * 236.588, 2),
            },
            indent=2,
        )
        
    except Exception as e:
        return f"Error setting water intake: {str(e)}"


@mcp.tool(
    name="mfp_get_report",
    annotations={
        "title": "Get Nutrition Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_report(params: GetReportInput) -> str:
    """
    Get a nutrition report over a date range.

    Returns daily values for the specified nutrient/metric over the date range.
    Useful for analyzing trends and patterns in nutrition intake.

    Args:
        params: GetReportInput containing:
            - report_name (str): Report type (e.g., 'Net Calories', 'Protein')
            - start_date (str, optional): Start date, defaults to 7 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily values and summary statistics for the report period
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=7)

        report = client.get_report(
            report_name=params.report_name,
            report_category="Nutrition",
            lower_bound=start,
            upper_bound=end,
        )

        data = {
            "report_name": params.report_name,
            "start_date": str(start),
            "end_date": str(end),
            "values": (
                ordered_dict_to_dict(report) if isinstance(report, OrderedDict) else report
            ),
        }

        # Calculate summary stats
        if report:
            values = list(report.values())
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            if numeric_values:
                data["summary"] = {
                    "total": sum(numeric_values),
                    "average": round(sum(numeric_values) / len(numeric_values), 2),
                    "min": min(numeric_values),
                    "max": max(numeric_values),
                }

        return format_response(
            data, params.response_format, f"{params.report_name} Report"
        )

    except Exception as e:
        return f"Error getting report: {str(e)}"


# ============================================================================
# Cookie Management Tool
# ============================================================================


def _verify_cookies_and_format(cookies: Dict[str, str], source: str) -> str:
    """Verify cookies via a live MFP round-trip, then persist on success.

    Persisting only after verification matches the auto-discovery path's
    anti-poisoning behavior — a stale/expired session can't clobber a
    previously good `cookies.json`.
    """
    if not _has_real_mfp_session(cookies):
        return (
            f"No MyFitnessPal session token found in {source}. "
            "Make sure you are logged into myfitnesspal.com in that browser, "
            "then try again."
        )
    try:
        import myfitnesspal
        cookiejar = dict_to_cookiejar(cookies)
        client = myfitnesspal.Client(cookiejar=cookiejar)
        _ = client.get_date(date.today())
    except Exception as e:
        return (
            f"Cookies were extracted from {source} but verification failed: "
            f"{e}. The session may have expired — log in again and retry. "
            f"(cookies.json was NOT overwritten.)"
        )
    save_cookies(cookies)
    return (
        f"Successfully extracted and verified {len(cookies)} cookies "
        f"from {source}. Authentication is now working."
    )


@mcp.tool()
def refresh_browser_cookies(browser: str = "auto") -> str:
    """
    Extract and save session cookies from your web browser.

    Use this tool when authentication fails and you need to refresh your
    MyFitnessPal session. You must be logged into myfitnesspal.com in the
    target browser.

    Args:
        browser: Source to extract cookies from. Options:
                 - 'auto' (default): scan every installed Chromium-based
                   browser on macOS (Arc, Chrome, Edge, Brave, Vivaldi,
                   Opera, ...) and use the first one with a valid session.
                 - 'arc', 'chrome', 'chromium', 'edge', 'brave', 'vivaldi',
                   'opera': force a specific Chromium browser (macOS).
                 - 'firefox': use browser_cookie3 (Firefox is not Chromium).

    Returns:
        Success message or error description.
    """
    browser_key = browser.lower().strip()

    # 'auto' — discover every Chromium browser via keychain Safe Storage
    if browser_key == "auto":
        result = try_chromium_browsers_for_session_cookies()
        if not result:
            return (
                "Auto-discovery did not find a Chromium browser with a "
                "valid MyFitnessPal session. Log into myfitnesspal.com in "
                "Arc, Chrome, Edge, Brave, Vivaldi, or Opera, then retry. "
                "(macOS only — on Linux/Windows, pass 'chrome' or "
                "'firefox' instead.)"
            )
        browser_name, cookies = result
        return _verify_cookies_and_format(cookies, browser_name)

    # Explicit Chromium browser
    if browser_key in _CHROMIUM_BROWSER_ALIASES:
        canonical = _CHROMIUM_BROWSER_ALIASES[browser_key]
        if sys.platform == "darwin":
            service_name = f"{canonical} Safe Storage"
            cookies = _try_extract_from_chromium_browser(service_name)
            if cookies is None:
                return (
                    f"Could not read cookies from {canonical}. Make sure "
                    "the browser is installed and you have logged in at "
                    "least once."
                )
            return _verify_cookies_and_format(cookies, canonical)
        # Non-macOS: keychain-based path doesn't apply. browser_cookie3
        # handles chrome/chromium on Linux/Windows via their default
        # profile paths; other Chromium browsers aren't supported there.
        if browser_key in ("chrome", "chromium"):
            try:
                import browser_cookie3
                cj = browser_cookie3.chrome(domain_name=".myfitnesspal.com")
                cookies = {c.name: c.value for c in cj}
            except Exception as e:
                return f"Error extracting cookies from {browser_key}: {e}"
            return _verify_cookies_and_format(cookies, browser_key)
        return (
            f"{canonical} cookie extraction requires macOS (keychain-backed "
            f"Safe Storage). On this platform, use 'chrome' or 'firefox'."
        )

    # Firefox via browser_cookie3 (it has its own format, not Chromium)
    if browser_key == "firefox":
        try:
            import browser_cookie3
            cj = browser_cookie3.firefox(domain_name=".myfitnesspal.com")
            cookies = {c.name: c.value for c in cj}
        except Exception as e:
            return f"Error extracting cookies from firefox: {e}"
        return _verify_cookies_and_format(cookies, "firefox")

    valid_options = sorted({*_CHROMIUM_BROWSER_ALIASES, "firefox", "auto"})
    return (
        f"Unsupported browser: {browser!r}. Use 'auto' to scan all installed "
        f"Chromium browsers, or one of: {', '.join(valid_options)}."
    )


# ============================================================================
# Main Entry Point
# ============================================================================



@mcp.tool(
    name="mfp_create_custom_food",
    annotations={
        "title": "Create Custom Food",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_create_custom_food(params: CreateCustomFoodInput) -> str:
    """
    Create a private custom food in the user's MyFitnessPal account.

    Fills the full nutrition panel MFP supports (macros, fats breakdown,
    cholesterol, sodium, potassium, fiber, sugars, and the four %DV micros).
    Uses the cookie-authenticated web endpoint, so no browser needs to be
    running. Returns the new food's id, which mfp_add_food_to_diary accepts.

    CARBS ARE NET (with the default country_code="NL"): pass net carbs in
    `carbs`; MFP stores net_carbs as given and reports total = carbs + fiber.
    Never pre-add fiber. Verified: carbs=42/fiber=8 stores 50/42 under "NL" but
    42/34 with country_code omitted, so the field is load-bearing, not cosmetic.

    MFP has no update endpoint. To correct a food, create the corrected version
    then mfp_delete_custom_food the old one.

    Args:
        params: CreateCustomFoodInput (description, brand_name, serving_amount,
            serving_unit, calories + optional nutrients, public, response_format)

    Returns:
        str: The created food's id, description and HTTP status
    """
    try:
        client = get_mfp_client()
        result = create_custom_food(client, params.model_dump())
        return format_response(result, params.response_format, "Custom Food Created")
    except Exception as e:
        return f"Error creating custom food: {str(e)}"


@mcp.tool(
    name="mfp_list_own_foods",
    annotations={
        "title": "List Own Custom Foods",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_list_own_foods(params: ListOwnFoodsInput) -> str:
    """
    List the user's own custom foods, newest first.

    Private custom foods do not reliably surface in mfp_search_food, so this is
    the way to find the id of something previously created.

    Args:
        params: ListOwnFoodsInput (search, limit, response_format)

    Returns:
        str: Matching custom foods with id, description, brand and calories
    """
    try:
        client = get_mfp_client()
        foods = list_own_foods(client, params.search)[: params.limit]
        data = {
            "count": len(foods),
            "foods": [
                {
                    "id": f.get("id"),
                    "description": f.get("description"),
                    "brand_name": f.get("brand_name"),
                    "calories": (f.get("nutritional_contents", {}).get("energy", {}) or {}).get("value"),
                    "serving": (f.get("serving_sizes") or [{}])[0].get("unit"),
                    "public": f.get("public"),
                }
                for f in foods
            ],
        }
        return format_response(data, params.response_format, "My Custom Foods")
    except Exception as e:
        return f"Error listing own foods: {str(e)}"


@mcp.tool(
    name="mfp_delete_custom_food",
    annotations={
        "title": "Delete Custom Food",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_delete_custom_food(params: DeleteCustomFoodInput) -> str:
    """
    Delete one of the user's custom foods by id.

    Destructive and not recoverable. A food actively referenced by a logged
    diary entry may be refused by MyFitnessPal.

    Args:
        params: DeleteCustomFoodInput (food_id)

    Returns:
        str: Confirmation with the HTTP status
    """
    try:
        client = get_mfp_client()
        status = delete_custom_food(client, params.food_id)
        data = {"food_id": params.food_id, "deleted": True, "status": status}
        return format_response(data, params.response_format, "Custom Food Deleted")
    except Exception as e:
        return f"Error deleting custom food: {str(e)}"


# ============================================================================
# Fasting (Intermittent) — write-only CRUD
# ============================================================================
#
# MyFitnessPal's fasting feature lives at /v2/diary/fasting_entry. It supports
# POST (create), PATCH (update), and DELETE — but NOT GET. There is no public
# read/list endpoint: the mobile app hydrates its Fasting History screen via a
# delta-sync channel (mobile-sync-api.myfitnesspal.com/v2.1/sync) that requires
# a pre-issued sync_token, is scoped to the mobile OAuth client, and rejects
# the web-session bearer we authenticate with. See the README for details.
#
# Reads therefore stay in the MFP app; the MCP owns writes.
#
# Schema (matches what the iOS app sends, verified 2026-08-07):
#     {
#       "items": [
#         {
#           "type": "fasting_entry",
#           "id": "UPPERCASE-UUID",
#           "fast_started": "YYYY-MM-DDTHH:MM:SSZ",
#           "fast_ended":   "YYYY-MM-DDTHH:MM:SSZ"
#         }
#       ]
#     }


_FASTING_ENDPOINT = f"{MFP_API_BASE}/v2/diary/fasting_entry"


def _normalize_fasting_timestamp(ts: str) -> str:
    """Normalize an ISO 8601 timestamp to MFP's form: `YYYY-MM-DDTHH:MM:SSZ` (UTC).

    Accepts naive strings (assumed UTC) and timezone-aware strings (converted
    to UTC). Raises ValueError on anything that doesn't parse as ISO 8601.
    """
    # `datetime.fromisoformat` in Python 3.10 doesn't understand a trailing
    # `Z`; swap it for `+00:00` first.
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(
            f"Not an ISO 8601 timestamp: {ts!r} ({e})"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_fasting_id() -> str:
    """Fresh uppercase UUIDv4 — matches the format the iOS app uses."""
    return str(uuid.uuid4()).upper()


def _build_fasting_payload(
    entry_id: str, fast_started: str, fast_ended: str
) -> Dict[str, Any]:
    """Build the request body for POST/PATCH /v2/diary/fasting_entry.

    Both timestamps are normalized to UTC ISO 8601 with a trailing `Z`, matching
    the shape observed on the wire. Raises ValueError on invalid input:
    missing id, unparseable timestamps, or end <= start.
    """
    if not entry_id:
        raise ValueError("entry_id must be a non-empty string")
    started = _normalize_fasting_timestamp(fast_started)
    ended = _normalize_fasting_timestamp(fast_ended)
    if ended <= started:
        raise ValueError(
            f"fast_ended ({ended}) must be strictly after fast_started ({started})"
        )
    return {
        "items": [
            {
                "type": "fasting_entry",
                "id": entry_id,
                "fast_started": started,
                "fast_ended": ended,
            }
        ]
    }


def create_fasting_entry(
    client,
    fast_started: str,
    fast_ended: str,
    entry_id: Optional[str] = None,
) -> Dict[str, Any]:
    """POST a new fasting entry. Returns the created record (with id + timestamps)."""
    entry_id = entry_id or _generate_fasting_id()
    payload = _build_fasting_payload(entry_id, fast_started, fast_ended)
    response = client.session.post(
        _FASTING_ENDPOINT,
        headers=_mfp_api_headers(client, json_body=True),
        data=json.dumps(payload),
        timeout=30,
    )
    if response.status_code != 201:
        raise RuntimeError(
            f"Failed to log fast: HTTP {response.status_code} — "
            f"{_api_error_detail(response)}"
        )
    # Guard against a well-formed 201 whose body doesn't match the
    # captured schema — surface a clear error instead of KeyError /
    # IndexError bubbling up as "Error logging fast: 'items'".
    try:
        entry = response.json()["items"][0]
    except (ValueError, KeyError, IndexError, TypeError) as e:
        raise RuntimeError(
            f"MFP returned HTTP 201 with an unexpected body: {response.text[:200]} ({e})"
        ) from None
    return {
        "id": entry["id"],
        "fast_started": entry["fast_started"],
        "fast_ended": entry["fast_ended"],
        "created_at": entry.get("created_at"),
        "status": response.status_code,
    }


def update_fasting_entry(
    client, entry_id: str, fast_started: str, fast_ended: str
) -> Dict[str, Any]:
    """PATCH an existing fasting entry. MFP's PATCH is a full replacement of
    the two time fields — both must be sent, matching the iOS app's behavior."""
    payload = _build_fasting_payload(entry_id, fast_started, fast_ended)
    response = client.session.patch(
        f"{_FASTING_ENDPOINT}/{entry_id}",
        headers=_mfp_api_headers(client, json_body=True),
        data=json.dumps(payload),
        timeout=30,
    )
    if response.status_code != 204:
        raise RuntimeError(
            f"Failed to update fast: HTTP {response.status_code} — "
            f"{_api_error_detail(response)}"
        )
    item = payload["items"][0]
    return {
        "id": entry_id,
        "fast_started": item["fast_started"],
        "fast_ended": item["fast_ended"],
        "status": response.status_code,
    }


def delete_fasting_entry(client, entry_id: str) -> Dict[str, Any]:
    """DELETE a fasting entry by id."""
    if not entry_id:
        raise ValueError("entry_id must be a non-empty string")
    response = client.session.delete(
        f"{_FASTING_ENDPOINT}/{entry_id}",
        headers=_mfp_api_headers(client),
        timeout=30,
    )
    if response.status_code != 204:
        raise RuntimeError(
            f"Failed to delete fast: HTTP {response.status_code} — "
            f"{_api_error_detail(response)}"
        )
    return {"id": entry_id, "deleted": True, "status": response.status_code}


# UUID pattern for fasting-entry ids. Any 8-4-4-4-12 hex is accepted (the
# endpoint doesn't strictly require v4), but leading/trailing whitespace and
# non-hex characters are rejected up-front — otherwise garbage ids hit MFP
# and come back as opaque 400s.
_FASTING_ID_PATTERN = r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"


class LogFastInput(BaseModel):
    """Input for `mfp_log_fast`."""

    model_config = ConfigDict(extra="forbid")

    fast_started: str = Field(
        description=(
            "Fast start time as ISO 8601 (e.g. '2026-08-06T13:00:00Z'). Naive "
            "timestamps are assumed UTC; timezone-aware ones are converted "
            "to UTC."
        ),
    )
    fast_ended: str = Field(
        description="Fast end time, same format. Must be strictly after fast_started.",
    )
    id: Optional[str] = Field(
        default=None,
        description=(
            "Optional UUID (8-4-4-4-12 hex) for the new entry. Auto-generated "
            "as an uppercase v4 UUID if omitted, matching MFP's iOS convention."
        ),
        pattern=_FASTING_ID_PATTERN,
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON)


class UpdateFastInput(BaseModel):
    """Input for `mfp_update_fast`."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        description="UUID (8-4-4-4-12 hex) of the fasting entry to update.",
        pattern=_FASTING_ID_PATTERN,
    )
    fast_started: str = Field(description="New start time (ISO 8601).")
    fast_ended: str = Field(
        description="New end time (ISO 8601). Must be strictly after fast_started."
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON)


class DeleteFastInput(BaseModel):
    """Input for `mfp_delete_fast`."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        description="UUID (8-4-4-4-12 hex) of the fasting entry to delete.",
        pattern=_FASTING_ID_PATTERN,
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON)


@mcp.tool(
    name="mfp_log_fast",
    annotations={
        "title": "Log Intermittent Fast",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_log_fast(params: LogFastInput) -> str:
    """
    Log a completed intermittent fasting window in MyFitnessPal.

    Creates a new entry with the given start and end times. If `id` is
    omitted, a fresh uppercase UUIDv4 is generated (matches how the iOS
    app self-assigns ids). The returned `id` is what `mfp_update_fast` and
    `mfp_delete_fast` accept — save it if you plan to modify the entry
    later.

    Args:
        params: LogFastInput (fast_started, fast_ended, id?, response_format)

    Returns:
        str: The created entry with id, timestamps, created_at, and status
    """
    try:
        client = get_mfp_client()
        result = create_fasting_entry(
            client, params.fast_started, params.fast_ended, params.id
        )
        return format_response(result, params.response_format, "Fast Logged")
    except Exception as e:
        return f"Error logging fast: {str(e)}"


@mcp.tool(
    name="mfp_update_fast",
    annotations={
        "title": "Update Fasting Entry",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_update_fast(params: UpdateFastInput) -> str:
    """
    Update an existing fasting entry's start and end times.

    MFP's PATCH is a full replacement of the two time fields — both must be
    supplied even if only one is changing.

    The MCP cannot list fasts (MFP exposes no read endpoint); the `id` must
    come from a prior `mfp_log_fast` call or be captured from the MFP app.

    Args:
        params: UpdateFastInput (id, fast_started, fast_ended, response_format)

    Returns:
        str: The updated entry (id, timestamps, status)
    """
    try:
        client = get_mfp_client()
        result = update_fasting_entry(
            client, params.id, params.fast_started, params.fast_ended
        )
        return format_response(result, params.response_format, "Fast Updated")
    except Exception as e:
        return f"Error updating fast: {str(e)}"


@mcp.tool(
    name="mfp_delete_fast",
    annotations={
        "title": "Delete Fasting Entry",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_delete_fast(params: DeleteFastInput) -> str:
    """
    Delete a fasting entry by id.

    Destructive and not recoverable. The `id` must come from a prior
    `mfp_log_fast` call or be captured from the MFP app — the MCP cannot
    list existing fasts because MFP exposes no read endpoint.

    Args:
        params: DeleteFastInput (id, response_format)

    Returns:
        str: Confirmation with the deleted id and HTTP status
    """
    try:
        client = get_mfp_client()
        result = delete_fasting_entry(client, params.id)
        return format_response(result, params.response_format, "Fast Deleted")
    except Exception as e:
        return f"Error deleting fast: {str(e)}"


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()