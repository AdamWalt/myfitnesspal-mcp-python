"""Log in to MyFitnessPal with a headed Chrome and save the session cookies.

Usage:
    python -m mfp_mcp.login [--dry-run | --check] [--install-xvfb]

The cookie file is the one the MCP server reads, `server.COOKIES_FILE`, read
when `main` runs. `main` takes a `cookies_file` keyword for tests.

Credentials come from `MFP_USERNAME` and `MFP_PASSWORD`, through the server's
`get_decrypted_credential`, so Fernet-encrypted values work as they do for the
server. An unset value is prompted for on a terminal: the username with
`input`, the password with `getpass`. A typed value is used as typed.

Chrome runs headed, since Cloudflare Turnstile never clears in headless Chrome.
On Linux it is Google Chrome or Chromium from PATH; a snap Chromium is skipped.
It draws on a private Xvfb display, found on PATH. The display admits only
clients holding a random X cookie, kept in a 0600 file in the run's temp
folder; Xvfb and Chrome get the file's path, never the cookie. With no Xvfb
there, the run exits 2 and prints the install command for the package tool it
finds. With `--install-xvfb`, `apt-get` on PATH and a terminal, it runs
`sudo apt-get install xvfb` itself, so apt asks for consent. On macOS the
window opens off-screen; that path is experimental and was never run live. On
Windows the command exits 2: run it under WSL2, where the Linux steps apply.

Chrome speaks DevTools over two pipes, never a TCP port, so no other local
user can reach it. It reads commands on fd 3 and writes replies on fd 4. The
child closes every other fd before exec, the pipe `subprocess` reports exec
errors on included, so a Chrome that cannot start shows as exit code 255.
`find_chrome` returns only an executable.

Chrome and Xvfb are found before any credential prompt, so a missing tool
fails before a password is typed.

With no flag the command checks the saved session first and logs in only when
that check fails. `--dry-run` logs in and verifies, but writes no cookie file.
`--check` never logs in: it checks the age of the saved file and verifies it.

The attempt log `login-attempts.log` and the run lock `login.lock` sit in the
cookie file's folder, created with mode 0700 when missing. Every run but
`--check` takes the lock first, an exclusive `flock` held for the whole run, so
a second run exits 2. That run then drops log lines older than 30 days. Each
form submission, dry runs included, appends one UTC stamp just before submit.
Three submissions in the last 24 hours refuse a login with exit 6, before any
credential prompt or browser. A line that is not a timestamp counts inside the
window and is never dropped. A stamp with no offset is read as UTC. `--check`
takes no lock and never reads or writes the log.

Exit codes:
    0      session saved, verified in dry-run, or still valid
    2      setup error: bad usage, Windows, a missing or undecryptable
           credential, no Chrome, no Xvfb, a failed Xvfb install or start,
           or another run holds the lock
    3      captcha, Turnstile that never clears, lock or rate-limit page
    4      session fails verification, or the saved file is too old
    5      any other page after the submission, a timeout, or an unexpected error
    6      three submissions in the last 24 hours, or unreadable log lines
    128+N  stopped by signal N (SIGINT, SIGTERM or SIGHUP), after cleanup

Every output line, argparse usage and errors included, goes through one
redacting Reporter. It never prints a secret value. Two prompts are fixed text
printed outside it: `input` writes the username prompt, and `getpass` writes
the password prompt to the terminal. Neither holds a secret. The apt install
that `--install-xvfb` runs writes to the terminal directly.

Known limits:
    - Consent banners inside an iframe are not dismissed.
    - The timeouts are 30 seconds for the form and Turnstile, and 60 seconds
      for the session cookie.
    - Live runs used Google Chrome 157 only.
"""

from __future__ import annotations

import argparse
import getpass
import html
import json
import logging
import os
import secrets
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
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

LINUX_CHROMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CHROME_URL = "https://www.google.com/chrome/"
BREW_CHROME = "brew install --cask google-chrome"
SNAP_PREFIX = "/snap/"
SNAP_SNIFF_BYTES = 4096
# The install command per package tool, in the order they are looked for on PATH.
XVFB_INSTALL = (
    ("apt-get", "sudo apt-get install xvfb"),
    ("dnf", "sudo dnf install xorg-x11-server-Xvfb"),
    ("pacman", "sudo pacman -S xorg-server-xvfb"),
)
SCREEN = (1366, 768)
XVFB_TIMEOUT = 15.0
XVFB_TERM_GRACE = 5.0
XVFB_LOG = "xvfb.log"
XAUTH_FILE = "xauth"
# One Xauthority record: family 65535 with an empty address and display number
# matches any display, so it works before `-displayfd` reports the number.
XAUTH_FAMILY_WILD = 65535
XAUTH_PROTOCOL = b"MIT-MAGIC-COOKIE-1"
XAUTH_COOKIE_LEN = 16
XVFB_TAIL_LINES = 5
# Chrome's startup: a page target within 30 seconds, polled every 0.2 seconds.
CHROME_START_TIMEOUT = 30.0
PAGE_POLL = 0.2
# The longest single wait on the reply pipe, so a dead Chrome is seen soon.
CDP_POLL = 1.0
CDP_READ_BYTES = 65536
# How long a Chrome that closed its pipe gets to exit, so its code can be read.
CHROME_EXIT_WAIT = 5.0
TEMP_PREFIX = "mfp-login-"

EMAIL_SEL = "#email"
PASSWORD_SEL = "#password"
TURNSTILE_SEL = 'input[name="cf-turnstile-response"]'

ATTEMPT_LOG = "login-attempts.log"
LOCK_FILE = "login.lock"
WINDOW_MAX = 3
WINDOW = timedelta(hours=24)
ATTEMPT_KEEP = timedelta(days=30)
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
    """A DevTools call answered with an error.

    Holds the method, and for an evaluate the page step and Chrome's exception
    class and description. Never params, and never the evaluated expression.
    """


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


def msg_windows() -> str:
    return (
        "platform: Windows is not supported directly. Run mfp-mcp-login under WSL2, "
        "where the Linux steps apply"
    )


def msg_macos_experimental() -> str:
    return "platform: macOS support is experimental and was never run live"


def msg_no_chrome(platform: str) -> str:
    if platform.startswith("linux"):
        return f"chrome: none found on PATH, install Google Chrome from {CHROME_URL}"
    if platform == "darwin":
        return f"chrome: Google Chrome not found, install it with: {BREW_CHROME}"
    return f"chrome: none found for {platform}"


def msg_chrome_snap(path: str) -> str:
    return (
        f"chrome: skipped {path}, a snap Chromium, which this command does not support. "
        f"Install Google Chrome from {CHROME_URL}"
    )


def msg_chrome(path: str) -> str:
    return f"chrome: {path}"


def msg_xvfb(path: str) -> str:
    return f"display: {path}"


def _install_text(hint: str | None) -> str:
    return f"install it: {hint}" if hint else "install Xvfb with your package manager"


def msg_no_xvfb(hint: str | None, can_install: bool) -> str:
    text = f"display: no Xvfb on PATH, {_install_text(hint)}"
    return f"{text}, or run again with --install-xvfb" if can_install else text


def msg_xvfb_cannot_install(reason: str, hint: str | None) -> str:
    return f"display: --install-xvfb cannot run, {reason}. No Xvfb on PATH, {_install_text(hint)}"


def msg_xvfb_installing(step: str) -> str:
    return f"display: no Xvfb on PATH, running: {step}"


def msg_xvfb_install_failed(step: str, code: int) -> str:
    if code == 0:
        return f"display: install step '{step}' exited with code 0, but no Xvfb is on PATH"
    return f"display: install step '{step}' failed, exited with code {code}"


def msg_xvfb_start_failed(tail: str) -> str:
    detail = f", it said: {tail}" if tail else ", it printed nothing"
    return f"display: Xvfb did not start{detail}"


def msg_browser_started(where: str) -> str:
    return f"browser: started headed on {where}"


def msg_fill_failed() -> str:
    return "page: a login field did not take its text, not submitted"


def msg_lock_held(path: Path) -> str:
    return f"lock: another mfp-mcp-login run holds {path}, try again when it ends"


def msg_log_full(path: Path, count: int, reopen: datetime) -> str:
    return (
        f"attempts: {count} logins in the last 24 hours, limit {WINDOW_MAX}, refused. "
        f"Log: {path}. Next login allowed from {reopen.isoformat(timespec='seconds')}"
    )


def msg_log_unreadable(path: Path, count: int) -> str:
    return (
        f"attempts: {path} holds {count} unreadable lines, each counts against the limit "
        f"of {WINDOW_MAX} per 24 hours, refused. Delete those lines to log in again"
    )


def msg_attempt_logged(count: int) -> str:
    return f"attempts: logged, {count} of {WINDOW_MAX} in the last 24 hours"


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
    """The type and the start of the message, on one line.

    Redacts first, then squeezes whitespace, then cuts. A page exception's
    description holds its stack, so the squeeze keeps it on one line.
    """
    detail = " ".join(redact(str(exc), secrets).split())[:ERROR_DETAIL_LEN]
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


def _runs_the_snap(path: str) -> bool:
    """True when the first 4 KB of a `chromium-browser` wrapper name `/snap/`."""
    try:
        with open(path, "rb") as f:
            return SNAP_PREFIX.encode() in f.read(SNAP_SNIFF_BYTES)
    except OSError:
        return False


def _is_snap(name: str, found: str, resolve: Callable[[str], str]) -> bool:
    if found.startswith(SNAP_PREFIX):
        return True
    if resolve(found).startswith(SNAP_PREFIX):
        return True
    return name == "chromium-browser" and _runs_the_snap(found)


def find_chrome(
    platform: str,
    path: str | None,
    exists: Callable[[str], bool] = os.path.exists,
    *,
    reporter: Reporter | None = None,
    which: Callable[..., str | None] = shutil.which,
    resolve: Callable[[str], str] = os.path.realpath,
) -> str:
    """The first Chrome on PATH that is not a snap, or the macOS app.

    A snap Chromium is skipped three ways: a PATH hit under `/snap/`, a hit that
    resolves under `/snap/`, and a `chromium-browser` script that runs the snap.
    """
    if platform.startswith("linux"):
        for name in LINUX_CHROMES:
            found = which(name, path=path)
            if not found:
                continue
            if _is_snap(name, found, resolve):
                if reporter is not None:
                    reporter.line(msg_chrome_snap(found))
                continue
            return found
    elif platform == "darwin" and exists(MAC_CHROME):
        return MAC_CHROME
    raise LoginError(EXIT_CONFIG, msg_no_chrome(platform))


# --- virtual display ------------------------------------------------------------


def _child_env(base: dict[str, str]) -> dict[str, str]:
    """`base` without any `MFP_*` variable, so no child sees a credential or the key."""
    return {k: v for k, v in base.items() if not k.startswith(CHILD_ENV_PREFIX)}


def _xvfb_hint(path: str | None) -> tuple[str | None, str | None]:
    """The install command for the first package tool on PATH, and `apt-get`'s path."""
    hint: str | None = None
    for tool, command in XVFB_INSTALL:
        if shutil.which(tool, path=path):
            hint = command
            break
    return hint, shutil.which("apt-get", path=path)


def find_xvfb(
    platform: str,
    path: str | None,
    *,
    install: bool = False,
    env: dict[str, str] | None = None,
    reporter: Reporter | None = None,
) -> str | None:
    """Xvfb on PATH, which wins with or without `install`. macOS needs none.

    With no Xvfb, `install`, `apt-get` on PATH and a terminal, run
    `sudo apt-get install xvfb`, or `apt-get install xvfb` as root, on the
    terminal so apt asks for consent. Then look on PATH again. Every tool is
    looked up on `path` alone, and the child gets `path` with no `MFP_*` variable.
    """
    if platform == "darwin":
        return None
    found = shutil.which("Xvfb", path=path)
    if found:
        return found
    hint, apt_get = _xvfb_hint(path)
    if not install:
        raise LoginError(EXIT_CONFIG, msg_no_xvfb(hint, apt_get is not None))
    if apt_get is None:
        raise LoginError(EXIT_CONFIG, msg_xvfb_cannot_install("no apt-get on PATH", hint))
    if not _is_tty():
        raise LoginError(EXIT_CONFIG, msg_xvfb_cannot_install("no terminal for apt", hint))
    if os.geteuid() == 0:
        cmd, step = [apt_get, "install", "xvfb"], "apt-get install xvfb"
    else:
        sudo = shutil.which("sudo", path=path)
        if sudo is None:
            raise LoginError(EXIT_CONFIG, msg_xvfb_cannot_install("no sudo on PATH", hint))
        cmd, step = [sudo, apt_get, "install", "xvfb"], "sudo apt-get install xvfb"
    child = _child_env(dict(os.environ) if env is None else env)
    if path is not None:
        child["PATH"] = path
    if reporter is not None:
        reporter.line(msg_xvfb_installing(step))
    code = subprocess.run(cmd, env=child, check=False).returncode
    found = shutil.which("Xvfb", path=path)
    if code != 0 or not found:
        raise LoginError(EXIT_CONFIG, msg_xvfb_install_failed(step, code))
    return found


def xauth_path(root: Path) -> Path:
    """The X cookie file of the run whose temp folder is `root`."""
    return root / XAUTH_FILE


def _xauth_field(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def write_xauth(path: Path, cookie: bytes | None = None) -> None:
    """Write one wildcard MIT-MAGIC-COOKIE-1 record to a new 0600 file at `path`.

    The cookie is 16 random bytes unless given. An existing file raises
    `FileExistsError`: the X server reloads the file whenever it changes, and
    lets anyone in when a reload finds no record, so the file is written once,
    whole, before Xvfb starts, and never again. The cookie never leaves here.
    """
    if cookie is None:
        cookie = secrets.token_bytes(XAUTH_COOKIE_LEN)
    record = (struct.pack(">H", XAUTH_FAMILY_WILD) + _xauth_field(b"") + _xauth_field(b"")
              + _xauth_field(XAUTH_PROTOCOL) + _xauth_field(cookie))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(record)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def xvfb_args(xvfb: str, fd: int, auth: Path) -> list[str]:
    """Pick a free display, listen only on the abstract socket, admit only `auth`'s cookie.

    Xvfb keeps its display lock file, which keeps two servers off one display.
    Cleanup sends SIGTERM first, so Xvfb removes its own `/tmp/.X<n>-lock`.
    """
    return [xvfb, "-displayfd", str(fd), "-auth", str(auth), "-nolisten", "tcp",
            "-nolisten", "unix", "-screen", "0", f"{SCREEN[0]}x{SCREEN[1]}x24"]


def parse_display(raw: bytes) -> int:
    text = raw.decode("ascii", "replace").strip()
    if not text.isdigit():
        raise ValueError("Xvfb reported no display number")
    return int(text)


def chrome_args(chrome: str, user_data_dir: Path, platform: str) -> list[str]:
    """Headed Chrome with its own user agent. Never `--enable-automation`."""
    args = [
        chrome,
        "--remote-debugging-pipe",
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
    """No `MFP_*` variable. HOME and TMPDIR in our temp folder. On Linux, our display only.

    With a display, XAUTHORITY names this run's X cookie file. Without one, as
    for Xvfb itself and on macOS, an inherited XAUTHORITY is dropped.
    """
    env = _child_env(base)
    env.update(HOME=str(root), TMPDIR=str(root))
    env.pop("XAUTHORITY", None)
    if display is not None:
        env["DISPLAY"] = f":{display}"
        env["XAUTHORITY"] = str(xauth_path(root))
        env.pop("WAYLAND_DISPLAY", None)
    return env


# --- attempt log ----------------------------------------------------------------


def _ensure_folder(folder: Path) -> None:
    """Create `folder` with mode 0700 when it is missing. An existing one keeps its mode."""
    if folder.exists():
        return
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    folder.chmod(0o700)


def _write_atomic(path: Path, text: str, prefix: str, errors: str = "strict") -> None:
    """Write a temp file in the same folder with mode 0600, then rename it over `path`."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=prefix, suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", errors=errors) as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def attempt_log_path(target: Path) -> Path:
    """The attempt log, beside the cookie target. Resolved per call, never from CONFIG_DIR."""
    return target.parent / ATTEMPT_LOG


def lock_path(target: Path) -> Path:
    return target.parent / LOCK_FILE


@contextmanager
def run_lock(target: Path) -> Iterator[None]:
    """Hold an exclusive `flock` on `login.lock` beside `target` for the whole block.

    flock binds to the open file description, so a second open in the same
    process conflicts too. Closing the descriptor releases the lock.
    """
    import fcntl

    path = lock_path(target)
    _ensure_folder(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LoginError(EXIT_CONFIG, msg_lock_held(path)) from None
        yield
    finally:
        os.close(fd)


def _read_log(path: Path) -> list[str]:
    """Every line of the log, blank ones included. Bytes that are not UTF-8 survive."""
    if not path.is_file():
        return []
    return path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()


def _parse_stamp(line: str) -> datetime | None:
    """The line's time, a naive stamp read as UTC. None when the line is not a stamp.

    A stamp so close to the ends of the calendar that its reopen time or its UTC
    form overflows is not a stamp either, so it counts as unreadable.
    """
    try:
        stamp = datetime.fromisoformat(line.strip())
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    try:
        stamp + WINDOW
        stamp.astimezone(timezone.utc)
    except OverflowError:
        return None
    return stamp


def _window(lines: Iterable[str], now: datetime) -> tuple[list[datetime], int]:
    """Stamps inside the last 24 hours, oldest first, and the count of unreadable lines.

    Blank lines count as nothing. A stamp later than `now` counts, so a clock
    set back never frees the window early.
    """
    stamps: list[datetime] = []
    unreadable = 0
    for line in lines:
        if not line.strip():
            continue
        stamp = _parse_stamp(line)
        if stamp is None:
            unreadable += 1
        elif stamp > now - WINDOW:
            stamps.append(stamp)
    return sorted(stamps), unreadable


def check_attempt_window(log: Path, now: datetime) -> None:
    """Refuse with exit 6 when the last 24 hours already hold three submissions.

    The reopen time is when enough counted stamps age out to leave room for one
    more. With exactly three counted lines that is the oldest plus 24 hours.
    """
    stamps, unreadable = _window(_read_log(log), now)
    count = len(stamps) + unreadable
    if count < WINDOW_MAX:
        return
    if unreadable >= WINDOW_MAX:
        raise LoginError(EXIT_LIMIT, msg_log_unreadable(log, unreadable))
    reopen = stamps[count - WINDOW_MAX] + WINDOW
    raise LoginError(EXIT_LIMIT, msg_log_full(log, count, reopen))


def prune_attempts(log: Path, now: datetime) -> None:
    """Drop stamps older than 30 days and blank lines. Unreadable lines stay.

    The file is rewritten atomically, and only when a line goes.
    """
    lines = _read_log(log)
    cutoff = now - ATTEMPT_KEEP
    kept = []
    for line in lines:
        if not line.strip():
            continue
        stamp = _parse_stamp(line)
        if stamp is None or stamp >= cutoff:
            kept.append(line)
    if kept == lines:
        return
    text = "".join(f"{line}\n" for line in kept)
    _write_atomic(log, text, ".attempts-", errors="surrogateescape")


def record_attempt(log: Path, now: datetime, reporter: Reporter) -> None:
    """Append one UTC stamp right before a submission. A dry run records one too."""
    _ensure_folder(log.parent)
    old = log.read_bytes() if log.is_file() else b""
    lead = b"\n" if old and not old.endswith(b"\n") else b""
    fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, lead + f"{now.isoformat(timespec='seconds')}\n".encode())
    finally:
        os.close(fd)
    stamps, unreadable = _window(_read_log(log), now)
    reporter.line(msg_attempt_logged(len(stamps) + unreadable))


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
    _ensure_folder(target.parent)
    _write_atomic(target, json.dumps(payload, indent=2), ".cookies-")


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
    def fill(self, selector: str, text: str) -> bool: ...
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


def _form_missing(page: Page, reporter: Reporter) -> LoginError:
    """The stop for a login form that never settles. A challenge page exits 3."""
    err = _stop(page, EXIT_OTHER, msg_form_missing(FORM_TIMEOUT), reporter.secrets)
    err.code = classify_page(page.text())
    return err


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
            raise _form_missing(page, reporter)
        sleep(1.0)
    if page.dismiss_consent():
        reporter.line(msg_consent())
    reporter.line(msg_form_found())

    # A fill that finds no field means the form re-rendered under it. Start
    # over from the first field, so both land in the same form.
    deadline = monotonic() + FORM_TIMEOUT
    while not (page.fill(EMAIL_SEL, username) and page.fill(PASSWORD_SEL, password)):
        if monotonic() >= deadline:
            raise _form_missing(page, reporter)
        sleep(1.0)
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
    """Minimal synchronous DevTools client over Chrome's two pipes.

    Commands go out on `cmd_fd` and replies and events come in on `reply_fd`.
    Each message is one JSON text ended by a NUL byte, both ways. Once
    `session_id` is set, every command carries it, so it reaches that page.
    The caller owns both fds and closes them.

    A closed pipe or a dead `proc` raises `OSError` with Chrome's exit code.
    """

    def __init__(self, proc: subprocess.Popen[bytes], cmd_fd: int, reply_fd: int) -> None:
        self._proc = proc
        self._cmd_fd = cmd_fd
        self._reply_fd = reply_fd
        self._buf = b""
        self._id = 0
        self.session_id: str | None = None

    def _exited(self) -> OSError:
        """Chrome's exit as an `OSError`, with the code from a wait.

        A bare `poll` can still read `None` just after the pipe closed.
        """
        try:
            code = self._proc.wait(timeout=CHROME_EXIT_WAIT)
        except subprocess.TimeoutExpired:
            return OSError("Chrome did not exit")
        return OSError(f"Chrome exited with code {code}")

    def _send(self, msg: dict[str, Any]) -> None:
        view = memoryview(json.dumps(msg).encode("utf-8") + b"\0")
        while view:
            try:
                written = os.write(self._cmd_fd, view)
            except BrokenPipeError as e:
                raise self._exited() from e
            view = view[written:]

    def _next(self, method: str, deadline: float) -> dict[str, Any]:
        """The next whole message on the reply pipe, waiting until `deadline`."""
        while b"\0" not in self._buf:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                raise TimeoutError(f"DevTools {method} timed out")
            ready, _, _ = select.select([self._reply_fd], [], [], min(remaining, CDP_POLL))
            if not ready:
                if self._proc.poll() is not None:
                    raise self._exited()
                continue
            chunk = os.read(self._reply_fd, CDP_READ_BYTES)
            if not chunk:
                raise self._exited()
            self._buf += chunk
        raw, _, self._buf = self._buf.partition(b"\0")
        message: dict[str, Any] = json.loads(raw)
        return message

    def call(
        self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0
    ) -> dict[str, Any]:
        self._id += 1
        mid = self._id
        msg: dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
        if self.session_id is not None:
            msg["sessionId"] = self.session_id
        self._send(msg)
        deadline = _monotonic() + timeout
        while True:
            reply = self._next(method, deadline)
            # Events and other replies carry no matching id; they are dropped.
            if reply.get("id") == mid:
                if "error" in reply:
                    raise CDPError(f"DevTools {method} failed: {reply['error'].get('message', '')}")
                result: dict[str, Any] = reply.get("result", {})
                return result


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


def _eval_error(step: str, details: dict[str, Any]) -> str:
    """The step, then Chrome's exception class and description, as Chrome sent them.

    No cut here: the Reporter redacts first, then `msg_error` cuts.
    """
    exception = details.get("exception") or {}
    cls = str(exception.get("className") or "")
    # Chrome's `text`, such as "Uncaught", stands in only when it sent no class.
    description = str(exception.get("description") or ("" if cls else details.get("text")) or "")
    if cls and not description.startswith(cls):
        description = f"{cls}: {description}" if description else cls
    label = f"DevTools Runtime.evaluate raised in the page during {step}"
    return f"{label}: {description}" if description else label


class CDPPage:
    """The `Page` protocol on top of one Chrome tab."""

    def __init__(self, cdp: CDP, user_agent: str) -> None:
        self._cdp = cdp
        self.user_agent = user_agent

    def _eval(self, expr: str, step: str) -> Any:
        """Evaluate `expr` in the page. `step` names the call in any error.

        The error carries Chrome's exception class and description, uncut.
        The Reporter redacts them before any cut. `expr` never enters it.
        """
        res = self._cdp.call("Runtime.evaluate", {"expression": expr, "returnByValue": True})
        if "exceptionDetails" in res:
            raise CDPError(_eval_error(step, res["exceptionDetails"]))
        return res.get("result", {}).get("value")

    def navigate(self, url: str) -> None:
        self._cdp.call("Page.navigate", {"url": url})
        deadline = time.monotonic() + FORM_TIMEOUT
        while (self._eval("document.readyState", "navigate") != "complete"
               and time.monotonic() < deadline):
            time.sleep(0.5)

    def dismiss_consent(self) -> bool:
        return bool(self._eval(CONSENT_JS, "dismiss_consent"))

    def exists(self, selector: str) -> bool:
        expr = f"!!document.querySelector({json.dumps(selector)})"
        return bool(self._eval(expr, f"exists {selector}"))

    def fill(self, selector: str, text: str) -> bool:
        """Focus the field and type `text`. `False`, with no text sent, when it is gone."""
        sel = json.dumps(selector)
        found = self._eval(
            f"(() => {{ const e = document.querySelector({sel}); if (!e) return false; "
            # A plain piece: its braces are single, not f-string doubled.
            "e.focus(); e.select && e.select(); return true; })()",
            f"fill {selector}",
        )
        if found is not True:
            return False
        # The text travels only inside Input.insertText, never in an expression.
        self._cdp.call("Input.insertText", {"text": text})
        return True

    def value_length(self, selector: str) -> int:
        """`.value.length`, in UTF-16 code units, as JavaScript counts."""
        sel = json.dumps(selector)
        expr = f"((document.querySelector({sel}) || {{}}).value || '').length"
        return int(self._eval(expr, f"value_length {selector}") or 0)

    def submit(self) -> None:
        if self._eval(SUBMIT_JS, "submit") == "none":
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
        return str(self._eval("document.body ? document.body.innerText : ''", "text") or "")

    def shows_form(self) -> bool:
        return bool(self._eval(FORM_JS, "shows_form"))


def _spawn(
    args: list[str],
    env: dict[str, str],
    pass_fds: tuple[int, ...] = (),
    stderr: Any = None,
    preexec_fn: Callable[[], None] | None = None,
    close_fds: bool = True,
) -> subprocess.Popen[bytes]:
    """Start a process in its own group, so one killpg takes all its children.

    stderr goes to `stderr` when given, else nowhere. `preexec_fn` runs in the
    child before exec, and with `close_fds` off it closes fds itself.
    """
    return subprocess.Popen(
        args,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL if stderr is None else stderr,
        pass_fds=pass_fds,
        start_new_session=True,
        preexec_fn=preexec_fn,  # noqa: PLW1509 - the login runs in one thread
        close_fds=close_fds,
    )


def _signal_group(proc: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


def _kill_group(proc: subprocess.Popen[bytes], grace: float = 0.0) -> None:
    """SIGKILL the group. With `grace`, SIGTERM first, and SIGKILL only after it."""
    if proc.poll() is None:
        if grace > 0:
            _signal_group(proc, signal.SIGTERM)
            try:
                proc.wait(timeout=grace)
                return
            except subprocess.TimeoutExpired:
                pass
        _signal_group(proc, signal.SIGKILL)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def _tail(path: Path, secrets: Iterable[str]) -> str:
    """The last lines of a log, redacted, then cut to the error detail length."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    joined = " / ".join(lines[-XVFB_TAIL_LINES:])
    return redact(joined, secrets)[-ERROR_DETAIL_LEN:]


def start_xvfb(
    xvfb: str,
    env: dict[str, str],
    root: Path,
    reporter: Reporter,
    xprocs: list[subprocess.Popen[bytes]],
    auth: Path,
) -> tuple[subprocess.Popen[bytes], int]:
    """Start Xvfb on a free display and return it with the display number.

    `auth` is the X cookie file, already written in full. Xvfb admits only
    clients that hold its cookie.

    The new process goes into `xprocs` before the wait for its display number,
    so a stop signal during that wait still reaches the caller's cleanup. It
    stays there on failure too, so cleanup can kill it again.

    Its stderr goes to a file in `root`. When no display number comes back, the
    error holds the last lines of that file.
    """
    read_fd, write_fd = os.pipe()
    log = root / XVFB_LOG
    try:
        with open(log, "wb") as err:
            proc = _spawn(xvfb_args(xvfb, write_fd, auth), env, pass_fds=(write_fd,),
                          stderr=err)
            xprocs.append(proc)
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
        _kill_group(proc, XVFB_TERM_GRACE)
        raise LoginError(EXIT_CONFIG,
                         msg_xvfb_start_failed(_tail(log, reporter.secrets))) from None


class ChromeProcess:
    """One headed Chrome in its own process group, with HOME and TMPDIR in `root`.

    Chrome speaks DevTools on two pipes. It reads commands on fd 3 and writes
    replies on fd 4. `cmd_fd` and `reply_fd` are this side's ends. They go into
    `fds` as soon as they exist, so the caller's cleanup closes them on every
    path. The child's ends are closed here once Chrome holds its copies.
    """

    def __init__(
        self, chrome: str, root: Path, env: dict[str, str], platform: str, fds: list[int]
    ) -> None:
        # Imported here, before the fork: an import in the forked child can deadlock.
        import fcntl

        self.user_data_dir = root / "profile"
        child: list[int] = []
        try:
            cmd_read, cmd_write = os.pipe()
            child.append(cmd_read)
            fds.append(cmd_write)
            reply_read, reply_write = os.pipe()
            fds.append(reply_read)
            child.append(reply_write)
            self.cmd_fd, self.reply_fd = cmd_write, reply_read

            def map_pipes() -> None:
                # In the child, before exec. Copy both ends above 4 first, so an end
                # that already sits on 3 or 4 is never overwritten before it moves.
                # dup2 clears close-on-exec on 3 and 4. Then every fd above 4 goes.
                cmd = fcntl.fcntl(cmd_read, fcntl.F_DUPFD, 5)
                reply = fcntl.fcntl(reply_write, fcntl.F_DUPFD, 5)
                os.dup2(cmd, 3)
                os.dup2(reply, 4)
                os.closerange(5, os.sysconf("SC_OPEN_MAX"))

            self.proc = _spawn(chrome_args(chrome, self.user_data_dir, platform), env,
                               preexec_fn=map_pipes, close_fds=False)
        finally:
            for fd in child:
                os.close(fd)

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


def _can_mask() -> bool:
    return hasattr(signal, "pthread_sigmask")


def _run_held(cleanup: Callable[[], None], old_mask: Iterable[int] | None) -> None:
    """Run `cleanup` with the stop signals blocked, then put `old_mask` back.

    A signal held meanwhile is delivered by the restore. A `_Stopped` raised
    by the block call itself is kept and raised after cleanup.
    """
    if old_mask is None:
        cleanup()
        return
    pending: BaseException | None = None
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    except BaseException as e:  # noqa: BLE001 - raised below, once cleanup ran
        pending = e
    try:
        cleanup()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        if pending is not None:
            raise pending


def _open_page(cdp: CDP) -> str:
    """Attach `cdp` to Chrome's first page and return Chrome's user agent.

    The targets are polled every `PAGE_POLL` seconds. No page within
    `CHROME_START_TIMEOUT` raises `OSError`. Every later command on `cdp`
    carries the page's session id.
    """
    deadline = _monotonic() + CHROME_START_TIMEOUT
    user_agent = str(cdp.call("Browser.getVersion", timeout=CHROME_START_TIMEOUT)["userAgent"])
    while True:
        left = deadline - _monotonic()
        if left <= 0:
            raise OSError("Chrome opened no page")
        infos = cdp.call("Target.getTargets", timeout=left).get("targetInfos", [])
        page = next((info for info in infos if info.get("type") == "page"), None)
        if page is not None:
            break
        _sleep(PAGE_POLL)
    attached = cdp.call("Target.attachToTarget", {"targetId": page["targetId"], "flatten": True})
    cdp.session_id = str(attached["sessionId"])
    return user_agent


@contextmanager
def chrome_session(
    chrome: str, reporter: Reporter, xvfb: str | None, platform: str
) -> Iterator[Page]:
    """Start Xvfb when given, then a headed Chrome, and yield a page.

    Always kills Chrome and Xvfb and removes the temp folder. A stop signal
    reaches here as the `_Stopped` that `main`'s handler raises, so this
    `finally` cleans up on SIGINT, SIGTERM and SIGHUP too.

    The cleanup itself runs with those signals blocked. One that arrives
    during it is held until every step ran, then raised, so the run still
    exits 128 plus the signal. The mask is per thread, and the login runs in
    one thread. Without `pthread_sigmask`, the cleanup runs unblocked.
    """
    # Read before anything exists: CPython runs pending handlers inside this call.
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, []) if _can_mask() else None
    root = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
    procs: list[subprocess.Popen[bytes]] = []
    xprocs: list[subprocess.Popen[bytes]] = []
    fds: list[int] = []

    def cleanup() -> None:
        # Our ends of Chrome's pipes first. Then Chrome, then the display it draws
        # on. Xvfb gets SIGTERM first, so it removes its display lock file.
        while fds:
            with suppress(OSError):
                os.close(fds.pop())
        for p in procs:
            _kill_group(p)
        for p in xprocs:
            _kill_group(p, XVFB_TERM_GRACE)
        _kill_leftovers(root)
        shutil.rmtree(root, ignore_errors=True)
        if root.exists():
            time.sleep(1.0)
            shutil.rmtree(root, ignore_errors=True)

    try:
        display: int | None = None
        if xvfb:
            # Whole before Xvfb starts: the X server lets anyone in while it has no record.
            auth = xauth_path(root)
            write_xauth(auth)
            _, display = start_xvfb(xvfb, browser_env(dict(os.environ), root, None), root,
                                    reporter, xprocs, auth)
        browser = ChromeProcess(chrome, root, browser_env(dict(os.environ), root, display),
                                platform, fds)
        procs.append(browser.proc)
        cdp = CDP(browser.proc, browser.cmd_fd, browser.reply_fd)
        user_agent = _open_page(cdp)
        where = f"Xvfb :{display}" if display is not None else "an off-screen window"
        reporter.line(msg_browser_started(where))
        yield CDPPage(cdp, user_agent)
    finally:
        _run_held(cleanup, old_mask)


# --- entry points ------------------------------------------------------------------------


def _runtime_errors() -> tuple[type[BaseException], ...]:
    return (CDPError, TimeoutError, OSError, requests.RequestException, ValueError, KeyError,
            StopIteration)


def _now() -> datetime:
    """Naive local time, for the cookie file's `saved_at`, as the server reads it."""
    return datetime.now()


def _utc_now() -> datetime:
    """Aware UTC time, for attempt stamps only. Its isoformat ends `+00:00`, never `Z`."""
    return datetime.now(timezone.utc)


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _monotonic() -> float:
    return time.monotonic()


def run_login(
    *,
    dry_run: bool,
    target: Path,
    reporter: Reporter,
    env: dict[str, str],
    platform: str,
    install_xvfb: bool = False,
    browser_factory: Callable[[str, Reporter, str | None, str], Any] | None = None,
    verify: Verifier | None = None,
    chrome_finder: Callable[[], str] | None = None,
    xvfb_finder: Callable[[], str | None] | None = None,
    now: Callable[[], datetime] | None = None,
    utc_now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
) -> int:
    """Find Chrome and Xvfb, read credentials, log in, verify and write.

    `main` calls it under the run lock, after the attempt window check. Chrome
    and Xvfb come first, so a missing tool fails before any credential prompt.
    Both are looked up on `env`'s PATH alone. The attempt record goes to the log
    beside `target`, just before submit. `now` stamps the cookie file and
    `utc_now` the attempt, so `saved_at` stays naive. Every `None` default is
    resolved here, at call time, from the module globals.
    """
    browser_factory = browser_factory or chrome_session
    verify = verify or verify_session
    now = now or _now
    utc_now = utc_now or _utc_now
    sleep = sleep or _sleep
    monotonic = monotonic or _monotonic
    path = env.get("PATH", os.defpath)
    # Lines printed before `read_credentials` still hide the raw variables.
    reporter.add_secrets(env.get(key) for key in (*ENV_KEYS, SECRET_KEY_VAR))
    try:
        if chrome_finder:
            chrome = chrome_finder()
        else:
            chrome = find_chrome(platform, path, reporter=reporter)
        reporter.line(msg_chrome(chrome))
        if xvfb_finder:
            xvfb = xvfb_finder()
        else:
            xvfb = find_xvfb(platform, path, install=install_xvfb, env=env, reporter=reporter)
        if xvfb:
            reporter.line(msg_xvfb(xvfb))
        username, password = read_credentials(reporter)
        reporter.line(msg_credentials_ok())
        log = attempt_log_path(target)

        def gate() -> None:
            record_attempt(log, utc_now(), reporter)

        try:
            with browser_factory(chrome, reporter, xvfb, platform) as page:
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
    p.add_argument("--install-xvfb", action="store_true",
                   help="on Linux with no Xvfb on PATH, install it with "
                        "'sudo apt-get install xvfb' on this terminal; apt asks first")
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


def _platform() -> str:
    """`sys.platform`, read once per run by `main`. A seam for tests."""
    return sys.platform


def _main(args: argparse.Namespace, target: Path, reporter: Reporter, platform: str) -> int:
    """Windows stops first, macOS prints its line, then `--check` alone, with no lock.

    Every other run holds the lock throughout. Under the lock: prune the log,
    check the saved session unless `--dry-run`, then the attempt window, and
    only then `run_login`. Nothing before the Windows check imports `fcntl`.
    """
    if platform == "win32":
        reporter.line(msg_windows())
        return EXIT_CONFIG
    if platform == "darwin":
        reporter.line(msg_macos_experimental())
    if args.check:
        return run_check(target, verify_session, reporter, _now())
    try:
        with run_lock(target):
            log = attempt_log_path(target)
            prune_attempts(log, _utc_now())
            if not args.dry_run and run_check(target, verify_session, reporter, _now()) == EXIT_OK:
                return EXIT_OK
            check_attempt_window(log, _utc_now())
            return run_login(
                dry_run=args.dry_run,
                target=target,
                reporter=reporter,
                env=dict(os.environ),
                platform=platform,
                install_xvfb=args.install_xvfb,
            )
    except LoginError as e:
        reporter.line(e.message)
        return e.code


def main(
    argv: list[str] | None = None, *, cookies_file: str | os.PathLike[str] | None = None
) -> int:
    """Run the command and return its exit code. No `Exception` escapes it.

    SIGINT, SIGTERM and SIGHUP are handled for the whole run. The first one
    raises `_Stopped`, which unwinds through every cleanup, and `main` returns
    128 plus the signal. Later signals are ignored while that cleanup runs.
    One that arrives during the browser cleanup is held until it ends.
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
                return _main(args, target, reporter, _platform())
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
