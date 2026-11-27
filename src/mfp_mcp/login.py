"""Log in to MyFitnessPal with a headed Chrome and save the session cookies.

Usage:
    python -m mfp_mcp.login [--dry-run | --check] [--no-attempt-log]

The cookie file is the one the MCP server reads, `server.COOKIES_FILE`, read
when `main` runs. `main` takes a `cookies_file` keyword for tests.

Credentials come from `MFP_USERNAME` and `MFP_PASSWORD`, through the server's
`get_decrypted_credential`, so Fernet-encrypted values work as they do for the
server. An unset value is prompted for on a terminal: the username with
`input`, the password with `getpass`. A typed value is used as typed.

Chrome runs headed, since Cloudflare Turnstile never clears in headless Chrome.
On Linux it draws on a private Xvfb display, found on PATH. On macOS the window
opens off-screen. The browser login needs `websockets>=11`.

With no flag the command checks the saved session first and logs in only when
that check fails. `--dry-run` logs in and verifies, but writes nothing.
`--check` never logs in: it checks the age of the saved file and verifies it.

Each real form submission appends one line to the file named by
`MFP_LOGIN_LOG`, with the date and `MFP_LOGIN_ROLE`. Six lines block any
further submission. With `MFP_LOGIN_LOG` unset, a submission needs
`--no-attempt-log`.

Exit codes:
    0      session saved, verified in dry-run, or still valid
    2      setup error: bad usage, a missing or undecryptable credential,
           no Chrome, no Xvfb, no attempt log, or no `websockets>=11`
    3      captcha, Turnstile that never clears, lock or rate-limit page
    4      session fails verification, or the saved file is too old
    5      any other page after the submission, a timeout, or an unexpected error
    6      the attempt log already holds six lines
    128+N  stopped by signal N (SIGINT, SIGTERM or SIGHUP), after cleanup

Every output line, argparse usage and errors included, goes through one
redacting Reporter. It never prints a secret value. Two prompts are fixed text
printed outside it: `input` writes the username prompt, and `getpass` writes
the password prompt to the terminal. Neither holds a secret.
"""

from __future__ import annotations

import argparse
import getpass
import html
import importlib.util
import json
import logging
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, Protocol
from urllib.parse import quote, quote_plus

import requests

from . import server

ENV_KEYS = ("MFP_USERNAME", "MFP_PASSWORD")
SECRET_KEY_VAR = "MFP_SECRET_KEY"
CHILD_ENV_PREFIX = "MFP_"
PROMPT_USERNAME = "MyFitnessPal email: "
PROMPT_PASSWORD = "MyFitnessPal password: "

LOGIN_URL = "https://www.myfitnesspal.com/account/login"
AUTH_URL = "https://www.myfitnesspal.com/user/auth_token?refresh=true"
MFP_DOMAIN = "myfitnesspal.com"
# The user agent python-myfitnesspal sends (myfitnesspal/client.py:83-87 in 2.1.2).
LIBRARY_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36"
)

LINUX_CHROMES = ("google-chrome", "google-chrome-stable", "chromium")
MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SCREEN = (1366, 768)
XVFB_TIMEOUT = 15.0
TEMP_PREFIX = "mfp-login-"

EMAIL_SEL = "#email"
PASSWORD_SEL = "#password"
TURNSTILE_SEL = 'input[name="cf-turnstile-response"]'

MAX_ATTEMPTS = 6
MAX_AGE = timedelta(days=29)
FORM_TIMEOUT = 30.0
TURNSTILE_TIMEOUT = 30.0
SESSION_TIMEOUT = 60.0
HTTP_TIMEOUT = 30.0
EXCERPT_LEN = 300
ERROR_DETAIL_LEN = 200

EXIT_OK, EXIT_CONFIG, EXIT_CHALLENGE, EXIT_VERIFY, EXIT_OTHER, EXIT_LIMIT = 0, 2, 3, 4, 5, 6

STOP_SIGNALS = tuple(
    sig for sig in (getattr(signal, n, None) for n in ("SIGINT", "SIGTERM", "SIGHUP")) if sig
)

CHALLENGE_WORDS = (
    "captcha",
    "verify you are human",
    "verifique se você é humano",
    "just a moment",
    "too many",
    "rate limit",
    "try again later",
    "tente novamente mais tarde",
    "muitas tentativas",
    "locked",
    "bloquead",
    "temporarily",
)


class LoginError(Exception):
    """A stop with a known exit code. `message` holds no secret by construction."""

    def __init__(self, code: int, message: str, excerpt: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.excerpt = excerpt


class CDPError(Exception):
    """A DevTools call answered with an error. Holds the method, never params."""


class _Stopped(BaseException):
    """Raised by the signal handler. A BaseException, so no `except Exception` eats it."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


class _ParserExit(Exception):
    """Raised in place of argparse's `sys.exit`, so `main` returns the status."""

    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


# --- messages ----------------------------------------------------------------
# Every printed line is built here, then passed through `redact`.


def msg_credentials_ok() -> str:
    return "credentials: ok"


def msg_credential_missing(key: str) -> str:
    return f"credentials: {key} is not set and there is no terminal to prompt on"


def msg_credential_no_key(key: str) -> str:
    return (
        f"credentials: {key} looks encrypted but there is no key, "
        f"set {SECRET_KEY_VAR} or store it in the keychain"
    )


def msg_credential_bad_token(key: str) -> str:
    return f"credentials: {key} is a bad token, it failed to decrypt with the key found"


def msg_no_websockets() -> str:
    return 'setup: the browser login needs websockets>=11, run: pip install "websockets>=11"'


def msg_no_chrome(platform: str) -> str:
    return f"chrome: none found for {platform}"


def msg_chrome(path: str) -> str:
    return f"chrome: {path}"


def msg_xvfb(path: str) -> str:
    return f"display: {path}"


def msg_no_xvfb() -> str:
    return "display: no Xvfb on PATH, install it, for example: sudo apt install xvfb"


def msg_browser_started(where: str) -> str:
    return f"browser: started headed on {where}"


def msg_fill_failed() -> str:
    return "page: a login field did not take its text, not submitted"


def msg_log_unset() -> str:
    return "attempts: MFP_LOGIN_LOG unset, pass --no-attempt-log to log in without it"


def msg_log_full(count: int) -> str:
    return f"attempts: log holds {count} lines, limit {MAX_ATTEMPTS}, refused"


def msg_attempt_logged(count: int) -> str:
    return f"attempts: logged line {count} of {MAX_ATTEMPTS}"


def msg_attempt_skipped() -> str:
    return "attempts: not logged (--no-attempt-log)"


def msg_form_found() -> str:
    return "page: login form found"


def msg_form_missing(seconds: float) -> str:
    return f"page: no login form after {seconds:.0f}s"


def msg_consent() -> str:
    return "page: consent banner dismissed"


def msg_turnstile(present: bool) -> str:
    return "turnstile: present, waiting" if present else "turnstile: absent"


def msg_turnstile_cleared() -> str:
    return "turnstile: cleared"


def msg_turnstile_blocked(seconds: float) -> str:
    return f"turnstile: not cleared after {seconds:.0f}s, not submitted"


def msg_submitted() -> str:
    return "submit: sent"


def msg_session_set() -> str:
    return "session: cookie set"


def msg_challenge(reason: str) -> str:
    return f"challenge: {reason}"


def msg_timeout(seconds: float) -> str:
    return f"session: no session cookie after {seconds:.0f}s"


def msg_page_text(excerpt: str) -> str:
    return f"page: {excerpt}"


def msg_cookies(cookies: dict[str, str]) -> str:
    names = ", ".join(sorted(cookies))
    return f"cookies: {len(cookies)} kept: {names}"


def msg_no_session() -> str:
    return "cookies: no session cookie among them"


def msg_verify(label: str, ok: bool, reason: str) -> str:
    return f"verify {label}: ok" if ok else f"verify {label}: fail ({reason})"


def msg_dry_run(count: int) -> str:
    return f"dry-run: {count} cookies, session ok"


def msg_saved(count: int, path: Path) -> str:
    return f"saved: {count} cookies to {path}"


def msg_check_missing() -> str:
    return "check: no cookie file"


def msg_check_unreadable() -> str:
    return "check: cookie file unreadable"


def msg_check_age(days: int) -> str:
    return f"check: cookie file is {days} days old, limit {MAX_AGE.days}"


def msg_check_ok() -> str:
    return "check: session still valid"


def msg_stopped(signum: int) -> str:
    return f"stopped: {signal.Signals(signum).name}, cleaned up"


def msg_unexpected(exc: BaseException) -> str:
    return f"error: unexpected {type(exc).__name__}"


def msg_error(exc: BaseException, secrets: Iterable[str] = ()) -> str:
    """The type and the start of the message. Redacts before the cut."""
    detail = redact(str(exc), secrets)[:ERROR_DETAIL_LEN]
    return f"error: {type(exc).__name__}: {detail}" if detail else f"error: {type(exc).__name__}"


def _secret_forms(secret: str) -> set[str]:
    """The raw secret and the encodings it may show up in on a page or a URL."""
    escaped = html.escape(secret)
    forms = {
        secret,
        quote(secret, safe=""),
        quote(secret),
        quote_plus(secret, safe=""),
        quote_plus(secret),
        json.dumps(secret)[1:-1],
        json.dumps(secret, ensure_ascii=False)[1:-1],
        escaped,
        escaped.replace("&#x27;", "&#39;").replace("&quot;", "&#34;"),
        html.escape(secret, quote=False),
    }
    forms.discard("")
    return forms


def redact(text: str, secrets: Iterable[str]) -> str:
    """Replace each secret, raw, URL-encoded, JSON-escaped or HTML-escaped, with `***`."""
    forms: set[str] = set()
    for s in secrets:
        if s:
            forms |= _secret_forms(s)
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, "***")
    return text


class Reporter:
    """Prints one redacted line per stage."""

    def __init__(self, write: Callable[[str], None] | None = None) -> None:
        self._write = write or (lambda s: print(s, flush=True))
        self._secrets: set[str] = set()

    @property
    def secrets(self) -> frozenset[str]:
        return frozenset(self._secrets)

    def add_secrets(self, values: Iterable[str | None]) -> None:
        self._secrets.update(v for v in values if isinstance(v, str) and v)

    def line(self, msg: str) -> None:
        self._write(redact(msg, self._secrets))


# --- credentials -----------------------------------------------------------------


def _is_tty() -> bool:
    return sys.stdin.isatty()


def _prompt(key: str) -> str:
    if key == "MFP_PASSWORD":
        return getpass.getpass(PROMPT_PASSWORD)
    return input(PROMPT_USERNAME)


def read_credentials(reporter: Reporter) -> tuple[str, str]:
    """`MFP_USERNAME` and `MFP_PASSWORD` from the environment, or typed on a terminal.

    The key lookup runs only when a set value looks like a Fernet token, and then
    once. A key found in the keychain is put in `MFP_SECRET_KEY`, so the server's
    `get_decrypted_credential` reuses it; `main` restores that variable when it ends.
    """
    raws = {key: os.environ.get(key) or "" for key in ENV_KEYS}
    env_key = os.environ.get(SECRET_KEY_VAR)
    reporter.add_secrets([*raws.values(), env_key])
    secret_key: str | None = None
    if any(raw and server.looks_like_fernet_token(raw) for raw in raws.values()):
        secret_key = server.get_secret_key()
        reporter.add_secrets([secret_key])
        if secret_key and not env_key:
            os.environ[SECRET_KEY_VAR] = secret_key

    values: list[str] = []
    for key in ENV_KEYS:
        raw = raws[key]
        if not raw:
            if not _is_tty():
                raise LoginError(EXIT_CONFIG, msg_credential_missing(key))
            value = _prompt(key)
            if not value:
                raise LoginError(EXIT_CONFIG, msg_credential_missing(key))
        elif server.looks_like_fernet_token(raw) and not secret_key:
            raise LoginError(EXIT_CONFIG, msg_credential_no_key(key))
        else:
            decrypted = server.get_decrypted_credential(key)
            if decrypted is None:
                raise LoginError(EXIT_CONFIG, msg_credential_bad_token(key))
            value = decrypted
        reporter.add_secrets([value])
        values.append(value)
    return values[0], values[1]


# --- Chrome finder ---------------------------------------------------------------


def find_chrome(
    platform: str, path: str | None, exists: Callable[[str], bool] = os.path.exists
) -> str:
    if platform.startswith("linux"):
        for name in LINUX_CHROMES:
            found = shutil.which(name, path=path)
            if found:
                return found
    elif platform == "darwin" and exists(MAC_CHROME):
        return MAC_CHROME
    raise LoginError(EXIT_CONFIG, msg_no_chrome(platform))


# --- virtual display ------------------------------------------------------------


def _child_env(base: dict[str, str]) -> dict[str, str]:
    """`base` without any `MFP_*` variable, so no child sees a credential or the key."""
    return {k: v for k, v in base.items() if not k.startswith(CHILD_ENV_PREFIX)}


def _run_cmd(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, env=_child_env(dict(os.environ)),
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=300)


def find_xvfb(platform: str, path: str | None) -> str | None:
    """Xvfb on PATH. macOS needs none."""
    if platform == "darwin":
        return None
    found = shutil.which("Xvfb", path=path)
    if found:
        return found
    raise LoginError(EXIT_CONFIG, msg_no_xvfb())


def xvfb_args(xvfb: str, fd: int) -> list[str]:
    """Pick a free display, listen only on the abstract socket, leave no lock file."""
    return [xvfb, "-displayfd", str(fd), "-nolisten", "tcp", "-nolisten", "unix", "-nolock",
            "-screen", "0", f"{SCREEN[0]}x{SCREEN[1]}x24"]


def parse_display(raw: bytes) -> int:
    text = raw.decode("ascii", "replace").strip()
    if not text.isdigit():
        raise ValueError("Xvfb reported no display number")
    return int(text)


def chrome_args(chrome: str, user_data_dir: Path, platform: str) -> list[str]:
    """Headed Chrome with its own user agent. Never `--enable-automation`."""
    args = [
        chrome,
        "--remote-debugging-port=0",
        "--password-store=basic",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={user_data_dir}",
        "--disable-blink-features=AutomationControlled",
        f"--window-size={SCREEN[0]},{SCREEN[1]}",
    ]
    if platform == "darwin":
        args.append("--window-position=-32000,-32000")
    else:
        args += ["--window-position=0,0", "--ozone-platform=x11"]
    args.append("about:blank")
    return args


def browser_env(base: dict[str, str], root: Path, display: int | None) -> dict[str, str]:
    """No `MFP_*` variable. HOME and TMPDIR in our temp folder. On Linux, our display only."""
    env = _child_env(base)
    env.update(HOME=str(root), TMPDIR=str(root))
    if display is not None:
        env["DISPLAY"] = f":{display}"
        env.pop("WAYLAND_DISPLAY", None)
    return env


# --- attempt log ----------------------------------------------------------------


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def attempt_precheck(log_path: str | None, no_attempt_log: bool) -> None:
    """Refuse before any browser starts. A set log always applies its limit."""
    if not log_path:
        if no_attempt_log:
            return
        raise LoginError(EXIT_CONFIG, msg_log_unset())
    count = _count_lines(Path(log_path))
    if count >= MAX_ATTEMPTS:
        raise LoginError(EXIT_LIMIT, msg_log_full(count))


def record_attempt(
    log_path: str | None, role: str, no_attempt_log: bool, now: datetime, reporter: Reporter
) -> None:
    """Append one line right before a real submission."""
    attempt_precheck(log_path, no_attempt_log)
    if not log_path:
        reporter.line(msg_attempt_skipped())
        return
    path = Path(log_path)
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{now.isoformat(timespec='seconds')} {role}\n")
    reporter.line(msg_attempt_logged(_count_lines(path)))


# --- cookies, verification, write ------------------------------------------------


def _is_mfp_domain(domain: str) -> bool:
    d = domain.lower()
    return d.lstrip(".") == MFP_DOMAIN or d.endswith("." + MFP_DOMAIN)


def filter_cookies(raw: Iterable[dict[str, Any]]) -> tuple[dict[str, str], dict[str, str]]:
    """Keep cookies of myfitnesspal.com and its subdomains: name->value, name->domain."""
    values: dict[str, str] = {}
    domains: dict[str, str] = {}
    for c in raw:
        domain = str(c.get("domain", ""))
        if _is_mfp_domain(domain) and isinstance(c.get("name"), str):
            values[c["name"]] = str(c.get("value", ""))
            domains[c["name"]] = domain
    return values, domains


def verify_session(
    cookies: dict[str, str],
    user_agent: str,
    session_factory: Callable[[], Any] = requests.Session,
) -> tuple[bool, str]:
    """GET the auth token the way the server's client does. Never returns the body."""
    session = session_factory()
    try:
        session.headers["User-Agent"] = user_agent
        for name, value in cookies.items():
            # The server re-stamps every cookie on .myfitnesspal.com (server.py:120-155).
            session.cookies.set(name, value, domain=".myfitnesspal.com", path="/")
        try:
            resp = session.get(AUTH_URL, timeout=HTTP_TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            return False, type(e).__name__
        if resp.status_code != 200:
            return False, f"status {resp.status_code}"
        if not resp.headers.get("Content-Type", "").startswith("application/json"):
            return False, "not json"
        try:
            data = resp.json()
        except ValueError:
            return False, "not json"
        if not isinstance(data, dict) or "access_token" not in data:
            return False, "no access_token"
        return True, "ok"
    finally:
        session.close()


Verifier = Callable[[dict[str, str], str], tuple[bool, str]]


def verify_both(
    cookies: dict[str, str], chrome_ua: str, verify: Verifier, reporter: Reporter
) -> bool:
    ok_all = True
    for label, ua in (("chrome-ua", chrome_ua), ("library-ua", LIBRARY_UA)):
        ok, reason = verify(cookies, ua)
        reporter.line(msg_verify(label, ok, reason))
        ok_all = ok_all and ok
    return ok_all


def build_payload(
    cookies: dict[str, str], domains: dict[str, str], user_agent: str, now: datetime
) -> dict[str, Any]:
    """The server's `save_cookies` format (server.py:75-91) plus `domains` and `user_agent`."""
    return {
        "cookies": cookies,
        "saved_at": now.isoformat(),
        "domains": domains,
        "user_agent": user_agent,
    }


def write_cookie_file(target: Path, payload: dict[str, Any]) -> None:
    """Write atomically: temp file in the same folder, mode 0600, then rename."""
    folder = target.parent
    if not folder.exists():
        folder.mkdir(parents=True, mode=0o700)
        folder.chmod(0o700)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".cookies-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def finalize(
    raw: Iterable[dict[str, Any]],
    chrome_ua: str,
    target: Path,
    dry_run: bool,
    verify: Verifier,
    reporter: Reporter,
    now: datetime,
) -> int:
    cookies, domains = filter_cookies(raw)
    reporter.add_secrets(cookies.values())
    reporter.line(msg_cookies(cookies))
    if not server._has_real_mfp_session(cookies):
        reporter.line(msg_no_session())
        return EXIT_VERIFY
    if not verify_both(cookies, chrome_ua, verify, reporter):
        return EXIT_VERIFY
    if dry_run:
        reporter.line(msg_dry_run(len(cookies)))
        return EXIT_OK
    write_cookie_file(target, build_payload(cookies, domains, chrome_ua, now))
    reporter.line(msg_saved(len(cookies), target))
    return EXIT_OK


def run_check(target: Path, verify: Verifier, reporter: Reporter, now: datetime) -> int:
    if not target.is_file():
        reporter.line(msg_check_missing())
        return EXIT_VERIFY
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        saved_at = datetime.fromisoformat(data["saved_at"])
        cookies = data["cookies"]
        if not isinstance(cookies, dict):
            raise TypeError("cookies is not an object")
    except (OSError, ValueError, KeyError, TypeError):
        reporter.line(msg_check_unreadable())
        return EXIT_VERIFY
    reporter.add_secrets(v for v in cookies.values() if isinstance(v, str))
    age = now - saved_at
    if age >= MAX_AGE:
        reporter.line(msg_check_age(age.days))
        return EXIT_VERIFY
    if not server._has_real_mfp_session(cookies):
        reporter.line(msg_no_session())
        return EXIT_VERIFY
    ua = data.get("user_agent") if isinstance(data.get("user_agent"), str) else LIBRARY_UA
    if not verify_both(cookies, ua, verify, reporter):
        return EXIT_VERIFY
    reporter.line(msg_check_ok())
    return EXIT_OK


# --- page text -------------------------------------------------------------------


def page_excerpt(
    text: str, session_set: bool, shows_form: bool, secrets: Iterable[str] = ()
) -> str:
    """First 300 chars of a login or challenge page. Never a page behind a session.

    Redacts the raw text first, then squeezes whitespace, then cuts. So neither a
    squeeze nor the cut can leave part of a secret behind.
    """
    if session_set or not shows_form:
        return ""
    return " ".join(redact(text, secrets).split())[:EXCERPT_LEN]


def classify_page(text: str) -> int:
    low = text.lower()
    return EXIT_CHALLENGE if any(w in low for w in CHALLENGE_WORDS) else EXIT_OTHER


# --- login flow ---------------------------------------------------------------------


class Page(Protocol):
    user_agent: str

    def navigate(self, url: str) -> None: ...
    def dismiss_consent(self) -> bool: ...
    def exists(self, selector: str) -> bool: ...
    def fill(self, selector: str, text: str) -> None: ...
    def value_length(self, selector: str) -> int: ...
    def submit(self) -> None: ...
    def cookies(self) -> list[dict[str, Any]]: ...
    def text(self) -> str: ...
    def shows_form(self) -> bool: ...


def _utf16_len(text: str) -> int:
    """The length JavaScript's `.value.length` reports: UTF-16 code units."""
    return len(text.encode("utf-16-le")) // 2


def _session_in(raw: Iterable[dict[str, Any]]) -> bool:
    return server._has_real_mfp_session(filter_cookies(raw)[0])


def _stop(page: Page, code: int, message: str, secrets: Iterable[str] = ()) -> LoginError:
    session_set = _session_in(page.cookies())
    excerpt = page_excerpt(page.text(), session_set, page.shows_form(), secrets)
    return LoginError(code, message, excerpt)


def login_flow(
    page: Page,
    username: str,
    password: str,
    gate: Callable[[], None],
    reporter: Reporter,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[dict[str, Any]]:
    """Fill and submit the form. Returns every browser cookie once a session exists."""
    page.navigate(LOGIN_URL)
    deadline = monotonic() + FORM_TIMEOUT
    while not (page.exists(EMAIL_SEL) and page.exists(PASSWORD_SEL)):
        if page.dismiss_consent():
            reporter.line(msg_consent())
        if monotonic() >= deadline:
            err = _stop(page, EXIT_OTHER, msg_form_missing(FORM_TIMEOUT), reporter.secrets)
            err.code = classify_page(page.text())
            raise err
        sleep(1.0)
    if page.dismiss_consent():
        reporter.line(msg_consent())
    reporter.line(msg_form_found())

    page.fill(EMAIL_SEL, username)
    page.fill(PASSWORD_SEL, password)
    sleep(2.0)
    filled = (page.value_length(EMAIL_SEL), page.value_length(PASSWORD_SEL))
    if filled != (_utf16_len(username), _utf16_len(password)):
        raise _stop(page, EXIT_OTHER, msg_fill_failed(), reporter.secrets)

    present = page.exists(TURNSTILE_SEL)
    reporter.line(msg_turnstile(present))
    if present:
        deadline = monotonic() + TURNSTILE_TIMEOUT
        while page.value_length(TURNSTILE_SEL) == 0:
            if monotonic() >= deadline:
                raise _stop(page, EXIT_CHALLENGE, msg_turnstile_blocked(TURNSTILE_TIMEOUT),
                            reporter.secrets)
            sleep(1.0)
        reporter.line(msg_turnstile_cleared())

    gate()
    page.submit()
    reporter.line(msg_submitted())

    deadline = monotonic() + SESSION_TIMEOUT
    while not _session_in(page.cookies()):
        if monotonic() >= deadline:
            text = page.text()
            code = classify_page(text)
            if code == EXIT_CHALLENGE:
                msg = msg_challenge("page after submit")
            else:
                msg = msg_timeout(SESSION_TIMEOUT)
            raise _stop(page, code, msg, reporter.secrets)
        sleep(1.0)
    reporter.line(msg_session_set())
    sleep(2.0)
    return page.cookies()


# --- Chrome over DevTools -------------------------------------------------------------


class CDP:
    """Minimal synchronous DevTools client over one target websocket."""

    def __init__(self, ws_url: str, timeout: float = 30.0) -> None:
        from websockets.sync.client import connect

        # Entered as a context manager: a bare connect() is deprecated in websockets 15+.
        self._stack = ExitStack()
        self._ws = self._stack.enter_context(connect(ws_url, max_size=None, open_timeout=timeout))
        self._id = 0

    def call(
        self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0
    ) -> dict[str, Any]:
        self._id += 1
        mid = self._id
        self._ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"DevTools {method} timed out")
            msg = json.loads(self._ws.recv(timeout=remaining))
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CDPError(f"DevTools {method} failed: {msg['error'].get('message', '')}")
                return msg.get("result", {})

    def close(self) -> None:
        self._stack.close()


CONSENT_JS = r"""
(() => {
  const ids = ['#onetrust-accept-btn-handler', '#truste-consent-button',
               'button[id*="accept" i]', 'button[class*="accept" i]'];
  for (const s of ids) {
    const b = document.querySelector(s);
    if (b && b.offsetParent !== null) { b.click(); return true; }
  }
  const words = /^(accept|accept all|i agree|agree|aceitar|aceitar todos|concordo|ok)$/i;
  for (const b of document.querySelectorAll('button')) {
    if (b.offsetParent !== null && words.test((b.innerText || '').trim())) {
      b.click(); return true;
    }
  }
  return false;
})()
"""

SUBMIT_JS = r"""
(() => {
  const pw = document.querySelector('#password');
  const form = pw && pw.form;
  const btn = (form || document).querySelector('button[type="submit"], input[type="submit"]');
  if (btn) { btn.click(); return 'button'; }
  if (form) { form.requestSubmit(); return 'form'; }
  return 'none';
})()
"""

FORM_JS = (
    "!!document.querySelector('form input, #challenge-form, "
    "iframe[src*=\"challenges.cloudflare.com\"]')"
)


class CDPPage:
    """The `Page` protocol on top of one Chrome tab."""

    def __init__(self, cdp: CDP, user_agent: str) -> None:
        self._cdp = cdp
        self.user_agent = user_agent

    def _eval(self, expr: str) -> Any:
        res = self._cdp.call("Runtime.evaluate", {"expression": expr, "returnByValue": True})
        if "exceptionDetails" in res:
            raise CDPError("DevTools Runtime.evaluate raised in the page")
        return res.get("result", {}).get("value")

    def navigate(self, url: str) -> None:
        self._cdp.call("Page.navigate", {"url": url})
        deadline = time.monotonic() + FORM_TIMEOUT
        while self._eval("document.readyState") != "complete" and time.monotonic() < deadline:
            time.sleep(0.5)

    def dismiss_consent(self) -> bool:
        return bool(self._eval(CONSENT_JS))

    def exists(self, selector: str) -> bool:
        return bool(self._eval(f"!!document.querySelector({json.dumps(selector)})"))

    def fill(self, selector: str, text: str) -> None:
        sel = json.dumps(selector)
        self._eval(
            f"(() => {{ const e = document.querySelector({sel}); "
            "e.focus(); e.select && e.select(); }})()"
        )
        # The text travels only inside Input.insertText, never in an expression.
        self._cdp.call("Input.insertText", {"text": text})

    def value_length(self, selector: str) -> int:
        """`.value.length`, in UTF-16 code units, as JavaScript counts."""
        sel = json.dumps(selector)
        return int(self._eval(f"((document.querySelector({sel}) || {{}}).value || '').length") or 0)

    def submit(self) -> None:
        if self._eval(SUBMIT_JS) == "none":
            for kind in ("keyDown", "keyUp"):
                self._cdp.call(
                    "Input.dispatchKeyEvent",
                    {"type": kind, "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13},
                )

    def cookies(self) -> list[dict[str, Any]]:
        try:
            return self._cdp.call("Network.getAllCookies").get("cookies", [])
        except CDPError:
            urls = ["https://www.myfitnesspal.com", "https://myfitnesspal.com", "https://api.myfitnesspal.com"]
            return self._cdp.call("Network.getCookies", {"urls": urls}).get("cookies", [])

    def text(self) -> str:
        return str(self._eval("document.body ? document.body.innerText : ''") or "")

    def shows_form(self) -> bool:
        return bool(self._eval(FORM_JS))


def _local_http() -> requests.Session:
    """A session for the local DevTools endpoint. It ignores proxy variables."""
    s = requests.Session()
    s.trust_env = False
    return s


def _spawn(
    args: list[str], env: dict[str, str], pass_fds: tuple[int, ...] = ()
) -> subprocess.Popen[bytes]:
    """Start a process in its own group, so one killpg takes all its children."""
    return subprocess.Popen(
        args,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        pass_fds=pass_fds,
        start_new_session=True,
    )


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def start_xvfb(xvfb: str, env: dict[str, str]) -> tuple[subprocess.Popen[bytes], int]:
    """Start Xvfb on a free display and return it with the display number."""
    read_fd, write_fd = os.pipe()
    try:
        proc = _spawn(xvfb_args(xvfb, write_fd), env, pass_fds=(write_fd,))
    finally:
        os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], XVFB_TIMEOUT)
        raw = os.read(read_fd, 32) if ready else b""
    finally:
        os.close(read_fd)
    try:
        return proc, parse_display(raw)
    except ValueError:
        _kill_group(proc)
        raise LoginError(EXIT_CONFIG, msg_no_xvfb()) from None


class ChromeProcess:
    """One headed Chrome in its own process group, with HOME and TMPDIR in `root`."""

    def __init__(self, chrome: str, root: Path, env: dict[str, str]) -> None:
        self.user_data_dir = root / "profile"
        platform = "darwin" if sys.platform == "darwin" else "linux"
        self.proc = _spawn(chrome_args(chrome, self.user_data_dir, platform), env)

    def port(self, timeout: float = 30.0) -> int:
        marker = self.user_data_dir / "DevToolsActivePort"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise OSError(f"Chrome exited with code {self.proc.returncode}")
            if marker.is_file():
                first = marker.read_text(encoding="utf-8").splitlines()[:1]
                if first and first[0].strip().isdigit():
                    return int(first[0])
            time.sleep(0.2)
        raise TimeoutError("DevToolsActivePort never appeared")

    def kill(self) -> None:
        _kill_group(self.proc)


def _is_own_temp_root(root: Path | str) -> bool:
    """True only for a folder `chrome_session` makes: `<tempdir>/mfp-login-*`."""
    text = str(root)
    if not text:
        return False
    path = Path(text)
    if not path.is_absolute():
        return False
    return path.parent == Path(tempfile.gettempdir()) and path.name.startswith(TEMP_PREFIX)


def _kill_leftovers(root: Path | str, proc_dir: Path = Path("/proc")) -> None:
    """Kill any of our processes whose command line names the temp folder (Linux).

    Refuses any `root` that is not this command's own temp folder, so a bad
    needle can never match unrelated processes.
    """
    if not _is_own_temp_root(root):
        return
    if not proc_dir.is_dir():
        return
    needle = str(root).encode()
    me = os.getpid()
    for entry in proc_dir.iterdir():
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        try:
            if entry.stat().st_uid != os.getuid():
                continue
            if needle in (entry / "cmdline").read_bytes():
                os.kill(int(entry.name), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            continue


@contextmanager
def chrome_session(chrome: str, reporter: Reporter, xvfb: str | None) -> Iterator[Page]:
    """Start Xvfb when given, then a headed Chrome, and yield a page.

    Always kills Chrome and Xvfb and removes the temp folder. A stop signal
    reaches here as the `_Stopped` that `main`'s handler raises, so this
    `finally` cleans up on SIGINT, SIGTERM and SIGHUP too.
    """
    root = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
    procs: list[subprocess.Popen[bytes]] = []
    cdp: CDP | None = None

    def cleanup() -> None:
        # Chrome first, then the display it draws on.
        for p in reversed(procs):
            _kill_group(p)
        _kill_leftovers(root)
        shutil.rmtree(root, ignore_errors=True)
        if root.exists():
            time.sleep(1.0)
            shutil.rmtree(root, ignore_errors=True)

    try:
        http = _local_http()
        display: int | None = None
        if xvfb:
            xproc, display = start_xvfb(xvfb, browser_env(dict(os.environ), root, None))
            procs.append(xproc)
        browser = ChromeProcess(chrome, root, browser_env(dict(os.environ), root, display))
        procs.append(browser.proc)
        port = browser.port()
        version = http.get(f"http://127.0.0.1:{port}/json/version", timeout=10).json()
        user_agent = version["User-Agent"]
        targets = http.get(f"http://127.0.0.1:{port}/json/list", timeout=10).json()
        page_ws = next(t["webSocketDebuggerUrl"] for t in targets if t.get("type") == "page")
        cdp = CDP(page_ws)
        where = f"Xvfb :{display}" if display is not None else "an off-screen window"
        reporter.line(msg_browser_started(where))
        yield CDPPage(cdp, user_agent)
    finally:
        try:
            if cdp is not None:
                try:
                    cdp.close()
                except Exception:  # noqa: BLE001 - closing a dying socket must not mask the result
                    pass
        finally:
            cleanup()


# --- entry points ------------------------------------------------------------------------


def _runtime_errors() -> tuple[type[BaseException], ...]:
    errors: list[type[BaseException]] = [CDPError, TimeoutError, OSError, requests.RequestException,
                                         ValueError, KeyError, StopIteration]
    try:
        from websockets.exceptions import WebSocketException

        errors.append(WebSocketException)
    except ImportError:
        pass
    return tuple(errors)


def _has_websockets_sync() -> bool:
    """True when `websockets.sync.client` exists, so `websockets>=11` is installed.

    A plain `import websockets` passes on 10.x, which has no `sync` package.
    `find_spec` raises when a parent package is missing, hence the `try`.
    """
    try:
        return importlib.util.find_spec("websockets.sync.client") is not None
    except (ImportError, ValueError):
        return False


def _now() -> datetime:
    return datetime.now()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _monotonic() -> float:
    return time.monotonic()


def run_login(
    *,
    dry_run: bool,
    no_attempt_log: bool,
    target: Path,
    reporter: Reporter,
    env: dict[str, str],
    browser_factory: Callable[[str, Reporter, str | None], Any] | None = None,
    verify: Verifier | None = None,
    chrome_finder: Callable[[], str] | None = None,
    xvfb_finder: Callable[[], str | None] | None = None,
    now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
) -> int:
    """Read credentials, find Chrome and Xvfb, log in, verify and write.

    Every `None` default is resolved here, at call time, from the module globals.
    """
    browser_factory = browser_factory or chrome_session
    verify = verify or verify_session
    now = now or _now
    sleep = sleep or _sleep
    monotonic = monotonic or _monotonic
    path = env.get("PATH", os.defpath)
    try:
        username, password = read_credentials(reporter)
        reporter.line(msg_credentials_ok())
        log_path = env.get("MFP_LOGIN_LOG")
        role = env.get("MFP_LOGIN_ROLE", "")
        attempt_precheck(log_path, no_attempt_log)
        chrome = chrome_finder() if chrome_finder else find_chrome(sys.platform, path)
        reporter.line(msg_chrome(chrome))
        xvfb = xvfb_finder() if xvfb_finder else find_xvfb(sys.platform, path)
        if xvfb:
            reporter.line(msg_xvfb(xvfb))

        def gate() -> None:
            record_attempt(log_path, role, no_attempt_log, now(), reporter)

        try:
            with browser_factory(chrome, reporter, xvfb) as page:
                raw = login_flow(page, username, password, gate, reporter, sleep, monotonic)
                user_agent = page.user_agent
        except LoginError:
            raise
        except _runtime_errors() as e:
            reporter.line(msg_error(e, reporter.secrets))
            return EXIT_OTHER
        return finalize(raw, user_agent, target, dry_run, verify, reporter, now())
    except LoginError as e:
        reporter.line(e.message)
        if e.excerpt and e.code in (EXIT_CHALLENGE, EXIT_OTHER):
            reporter.line(msg_page_text(e.excerpt))
        return e.code


class _ArgParser(argparse.ArgumentParser):
    """An ArgumentParser whose usage, help and errors go through the Reporter."""

    def __init__(self, *args: Any, reporter: Reporter, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._reporter = reporter

    def _emit(self, text: str) -> None:
        for line in text.rstrip("\n").splitlines():
            self._reporter.line(line)

    def print_usage(self, file: Any = None) -> None:
        self._emit(self.format_usage())

    def print_help(self, file: Any = None) -> None:
        self._emit(self.format_help())

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            self._emit(message)
        raise _ParserExit(status)

    def error(self, message: str) -> NoReturn:
        self.print_usage()
        self.exit(EXIT_CONFIG, f"{self.prog}: error: {message}\n")


def parse_args(argv: list[str] | None, reporter: Reporter) -> argparse.Namespace:
    p = _ArgParser(prog="mfp-mcp-login", description="MyFitnessPal login through a headed Chrome.",
                   reporter=reporter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="log in and verify, write nothing")
    mode.add_argument("--check", action="store_true", help="verify the saved file, never log in")
    p.add_argument("--no-attempt-log", action="store_true",
                   help="allow a login with MFP_LOGIN_LOG unset")
    return p.parse_args(argv)


@contextmanager
def _quiet_logging() -> Iterator[None]:
    """Silence the `mfp_mcp` logger and the root handlers, then put both back.

    The server logs at ERROR on a failed decryption, so raising the level is not
    enough. The root handlers go too, so no other library's logger prints.
    """
    mfp_logger = logging.getLogger("mfp_mcp")
    root = logging.getLogger()
    old_disabled = mfp_logger.disabled
    old_handlers = root.handlers[:]
    mfp_logger.disabled = True
    root.handlers = [logging.NullHandler()]
    try:
        yield
    finally:
        root.handlers = old_handlers
        mfp_logger.disabled = old_disabled


def _target_path(cookies_file: str | os.PathLike[str] | None) -> Path:
    """The cookie target: `cookies_file` when given, else `server.COOKIES_FILE` read now."""
    return Path(server.COOKIES_FILE if cookies_file is None else cookies_file)


def _main(args: argparse.Namespace, target: Path, reporter: Reporter) -> int:
    if args.check:
        return run_check(target, verify_session, reporter, _now())
    if not args.dry_run and run_check(target, verify_session, reporter, _now()) == EXIT_OK:
        return EXIT_OK
    if not _has_websockets_sync():
        reporter.line(msg_no_websockets())
        return EXIT_CONFIG
    return run_login(
        dry_run=args.dry_run,
        no_attempt_log=args.no_attempt_log,
        target=target,
        reporter=reporter,
        env=dict(os.environ),
    )


def main(
    argv: list[str] | None = None, *, cookies_file: str | os.PathLike[str] | None = None
) -> int:
    """Run the command and return its exit code. No `Exception` escapes it.

    SIGINT, SIGTERM and SIGHUP are handled for the whole run. The first one
    raises `_Stopped`, which unwinds through every cleanup, and `main` returns
    128 plus the signal. Later signals are ignored while that cleanup runs.
    """
    reporter = Reporter()
    state = {"stopped": False, "done": False}

    def on_signal(signum: int, frame: Any) -> None:
        if state["stopped"] or state["done"]:
            return
        state["stopped"] = True
        raise _Stopped(signum)

    old_handlers: dict[int, Any] = {}
    key_was_set = SECRET_KEY_VAR in os.environ
    old_key = os.environ.get(SECRET_KEY_VAR)
    with _quiet_logging():
        try:
            for sig in STOP_SIGNALS:
                old_handlers[sig] = signal.signal(sig, on_signal)
            try:
                args = parse_args(argv, reporter)
                target = _target_path(cookies_file)
                return _main(args, target, reporter)
            except _ParserExit as e:
                return e.status
            except Exception as e:  # noqa: BLE001 - one redacted line, never a traceback
                reporter.line(msg_unexpected(e))
                return EXIT_OTHER
        except _Stopped as e:
            reporter.line(msg_stopped(e.signum))
            return 128 + e.signum
        finally:
            state["done"] = True
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
            if key_was_set and old_key is not None:
                os.environ[SECRET_KEY_VAR] = old_key
            else:
                os.environ.pop(SECRET_KEY_VAR, None)


if __name__ == "__main__":
    sys.exit(main())
