"""Tests for the mfp-mcp-login command, `mfp_mcp.login`.

No network, no browser, no display, no keychain. An autouse fixture points
HOME at the test's temp folder, removes every MFP_* variable, fakes the
keychain, and puts tripwires on Chrome, child processes, signals to foreign
PIDs and sockets, so a test that forgets a fake fails instead of reaching out.
"""

from __future__ import annotations

import html
import importlib.machinery
import importlib.metadata
import importlib.util
import inspect
import io
import json
import logging
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mfp_mcp import login, server  # noqa: E402

PASSWORD = "S3cret!x"
COOKIE_VALUE = "tok-123"
EMAIL = "user@example.com"
NOW = datetime(2026, 11, 11, 12, 0, 0)
# The attempt clock, aware UTC. Kept apart from NOW, which stamps `saved_at`.
UTC_NOW = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)
LOG_NAME = "login-attempts.log"
LOCK_NAME = "login.lock"
SESSION = "__Secure-next-auth.session-token"
SPECIAL = 'p@ss w0rd+"<&>'

# Names no test may run for real. The fixture's PATH leaves them out, and the
# subprocess guard fails any call to one that does not resolve under tmp_path.
MASKED = frozenset({
    "sudo", "apt", "apt-get", "dpkg", "dpkg-deb", "dnf", "pacman", "pkexec", "snap",
    "Xvfb", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
})

# Saved before the fixture replaces them, for tests of the functions themselves.
ORIG = {
    name: getattr(login, name, None)
    for name in ("chrome_session", "_spawn", "verify_session", "_has_websockets_sync",
                 "_kill_leftovers", "_utc_now", "find_xvfb", "find_chrome")
}


def _tripwire(name: str):
    def fail(*args, **kwargs):
        pytest.fail(f"{name} reached without a fake")

    return fail


class _TripwireKeyring:
    def get_password(self, service, account):
        pytest.fail("the real keychain was reached")


class _Guard:
    """Wraps `subprocess` and `os` as `login` sees them."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path.resolve()
        self.allowed_pids: set[int] = set()

    def inside_tmp(self, argv0: str, env: dict | None) -> bool:
        # The lookup `subprocess` makes: env's PATH, else os.defpath, when env is given.
        path = os.pathsep.join(os.get_exec_path(env))
        resolved = argv0 if os.sep in argv0 else __import__("shutil").which(argv0, path=path)
        return bool(resolved) and Path(resolved).resolve().is_relative_to(self.tmp)

    def check_cmd(self, args, kwargs) -> bool:
        cmd = args[0] if args else kwargs.get("args")
        argv = [cmd] if isinstance(cmd, (str, bytes, os.PathLike)) else list(cmd)
        argv0 = os.fsdecode(argv[0])
        inside = self.inside_tmp(argv0, kwargs.get("env"))
        if os.path.basename(argv0) in MASKED and not inside:
            pytest.fail(f"refused to run {argv0} for real")
        return inside

    def check_pid(self, pid: int, group: bool) -> None:
        if pid <= 1:
            pytest.fail(f"refused a signal to pid {pid}")
        if pid in self.allowed_pids:
            return
        if not group and pid == os.getpid():
            return
        pytest.fail(f"refused a signal to foreign pid {pid}")


class _GuardedSubprocess:
    def __init__(self, guard: _Guard) -> None:
        self._guard = guard

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def run(self, *args, **kwargs):
        self._guard.check_cmd(args, kwargs)
        return subprocess.run(*args, **kwargs)

    def call(self, *args, **kwargs):
        self._guard.check_cmd(args, kwargs)
        return subprocess.call(*args, **kwargs)

    def Popen(self, *args, **kwargs):  # noqa: N802 - mirrors subprocess.Popen
        inside = self._guard.check_cmd(args, kwargs)
        proc = subprocess.Popen(*args, **kwargs)
        if inside:
            self._guard.allowed_pids.add(proc.pid)
        return proc


class _GuardedOs:
    def __init__(self, guard: _Guard) -> None:
        self._guard = guard

    def __getattr__(self, name):
        return getattr(os, name)

    def kill(self, pid, sig):
        self._guard.check_pid(pid, group=False)
        return os.kill(pid, sig)

    def killpg(self, pgid, sig):
        self._guard.check_pid(pgid, group=True)
        return os.killpg(pgid, sig)


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


SAFE_BIN = "safe-bin"


def _safe_bin(tmp_path: Path) -> Path:
    """Links under this test's tmp_path to every /usr/bin entry but the masked names."""
    folder = tmp_path / SAFE_BIN
    folder.mkdir()
    for entry in os.scandir("/usr/bin"):
        if entry.name not in MASKED:
            os.symlink(entry.path, folder / entry.name)
    return folder


def _under(path, tmp_path: Path) -> bool:
    return path is not None and str(path) != "" and Path(path).resolve().is_relative_to(
        tmp_path.resolve())


def _guard_targets(tmp_path: Path):
    """Wrap `main` and `run_login` so a test cannot reach either with a real target.

    The attempt log and the lock sit beside the target, so a target under
    tmp_path keeps both there too.
    """
    real_main, real_run_login = login.main, login.run_login

    def main(argv=None, *, cookies_file=None):
        if not _under(cookies_file, tmp_path):
            pytest.fail(f"login.main reached without a tmp_path cookies_file: {cookies_file!r}")
        return real_main(argv, cookies_file=cookies_file)

    def run_login(**kwargs):
        target = kwargs.get("target")
        if not _under(target, tmp_path):
            pytest.fail(f"login.run_login reached without a tmp_path target: {target!r}")
        return real_run_login(**kwargs)

    return main, run_login


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    for key in list(os.environ):
        if key.startswith("MFP_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("PATH", str(_safe_bin(tmp_path)))
    temp = tmp_path / "tmp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))

    monkeypatch.setattr(server, "keyring", _TripwireKeyring())
    monkeypatch.setattr(server, "CONFIG_DIR", tmp_path / ".mfp_mcp")
    monkeypatch.setattr(server, "COOKIES_FILE", tmp_path / ".mfp_mcp" / "cookies.json")

    for name in ("chrome_session", "_spawn", "verify_session"):
        monkeypatch.setattr(login, name, _tripwire(f"login.{name}"), raising=False)
    monkeypatch.setattr(socket.socket, "connect", _tripwire("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", _tripwire("socket.connect_ex"))

    guard = _Guard(tmp_path)
    monkeypatch.setattr(login, "subprocess", _GuardedSubprocess(guard), raising=False)
    monkeypatch.setattr(login, "os", _GuardedOs(guard), raising=False)

    main, run_login = _guard_targets(tmp_path)
    monkeypatch.setattr(login, "main", main)
    monkeypatch.setattr(login, "run_login", run_login)

    monkeypatch.setattr(login, "_has_websockets_sync", lambda: True, raising=False)
    monkeypatch.setattr(login, "_is_tty", lambda: False, raising=False)
    clock = FakeClock()
    monkeypatch.setattr(login, "_sleep", clock.sleep, raising=False)
    monkeypatch.setattr(login, "_monotonic", clock.monotonic, raising=False)
    monkeypatch.setattr(login, "_now", lambda: NOW, raising=False)
    monkeypatch.setattr(login, "_utc_now", lambda: UTC_NOW, raising=False)
    yield guard
    # `read_credentials` may set MFP_SECRET_KEY outside `main`; drop it here.
    for key in list(os.environ):
        if key.startswith("MFP_"):
            os.environ.pop(key)


class Capture:
    """Reporter stand-in that keeps rendered lines."""

    def __init__(self) -> None:
        self.reporter = login.Reporter(write=self.lines_append)
        self.lines: list[str] = []

    def lines_append(self, text: str) -> None:
        self.lines.append(text)


def _lines(capsys) -> list[str]:
    out = capsys.readouterr()
    assert "Traceback" not in out.out + out.err
    return out.out.splitlines()


def _fake_exe(folder: Path, name: str) -> Path:
    path = folder / name
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


# --- fixture guards ----------------------------------------------------------


def test_fixture_guards_block_package_tools_and_foreign_signals():
    with pytest.raises(pytest.fail.Exception):
        login.subprocess.run(["sudo", "true"])
    with pytest.raises(pytest.fail.Exception):
        login.os.kill(1, 0)
    with pytest.raises(pytest.fail.Exception):
        login.os.killpg(os.getpid(), 0)
    assert os.environ["HOME"] == str(Path.home())
    assert not any(k.startswith("MFP_") for k in os.environ)


def test_fixture_path_is_a_link_folder_under_tmp_path(tmp_path):
    folder = Path(os.environ["PATH"])
    assert folder == tmp_path / SAFE_BIN
    names = set(os.listdir(folder))
    assert names == {n for n in os.listdir("/usr/bin")} - MASKED
    assert not names & MASKED
    assert all((folder / n).is_symlink() for n in names)


def test_fixture_guards_need_tmp_targets(tmp_path, monkeypatch):
    """`main` needs a cookies_file under tmp_path, `run_login` a target there."""
    with pytest.raises(pytest.fail.Exception):
        login.main(["--check"])
    with pytest.raises(pytest.fail.Exception):
        login.main(["--check"], cookies_file="/srv/u/cookies.json")
    kwargs = {"dry_run": True, "env": {}, "reporter": Capture().reporter,
              "browser_factory": _tripwire("browser")}
    with pytest.raises(pytest.fail.Exception):
        login.run_login(target=Path("/srv/u/cookies.json"), **kwargs)
    with pytest.raises(pytest.fail.Exception):
        login.run_login(target=None, **kwargs)


def test_fixture_guard_resolves_like_subprocess_without_env_path(tmp_path, monkeypatch,
                                                                 _isolate):
    """With `env` given but no PATH in it, `subprocess` searches os.defpath, not PATH."""
    fakes = tmp_path / "fakes"
    fakes.mkdir()
    _fake_exe(fakes, "sudo")
    monkeypatch.setenv("PATH", os.pathsep.join([str(fakes), os.environ["PATH"]]))
    assert _isolate.inside_tmp("sudo", None) is True
    assert _isolate.inside_tmp("sudo", {"PATH": str(fakes)}) is True
    assert _isolate.inside_tmp("sudo", {"LANG": "C"}) is False
    assert _isolate.inside_tmp("sudo", {}) is False


# --- Chrome finder ----------------------------------------------------------


def test_find_chrome_linux_order_on_fake_path(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    chromium = _fake_exe(a, "chromium")
    stable = _fake_exe(b, "google-chrome-stable")
    path = os.pathsep.join([str(a), str(b)])
    assert login.find_chrome("linux", path) == str(stable)
    stable.unlink()
    assert login.find_chrome("linux", path) == str(chromium)
    browser = _fake_exe(b, "chromium-browser")
    assert login.find_chrome("linux", path) == str(chromium)
    chromium.unlink()
    assert login.find_chrome("linux", path) == str(browser)


def _which_map(found: dict[str, str]):
    """A `which` seam that answers only for the names given."""
    def which(name, path=None):
        return found.get(name)

    return which


def test_find_chrome_skips_a_snap_path_before_resolving(tmp_path):
    cap = Capture()
    resolved: list[str] = []
    real = _fake_exe(tmp_path, "chromium-browser")

    def resolve(p):
        resolved.append(p)
        return p

    which = _which_map({"chromium": "/snap/bin/chromium", "chromium-browser": str(real)})
    found = login.find_chrome("linux", str(tmp_path), reporter=cap.reporter, which=which,
                              resolve=resolve)
    assert found == str(real)
    assert resolved == [str(real)]
    assert cap.lines == [login.msg_chrome_snap("/snap/bin/chromium")]
    assert "Google Chrome" in cap.lines[0]


def test_find_chrome_skips_a_path_that_resolves_into_the_snap(tmp_path):
    cap = Capture()
    fake = _fake_exe(tmp_path, "chromium")
    snap = "/snap/chromium/current/usr/lib/chromium-browser/chrome"
    which = _which_map({"chromium": str(fake)})
    with pytest.raises(login.LoginError) as err:
        login.find_chrome("linux", str(tmp_path), reporter=cap.reporter, which=which,
                          resolve=lambda p: snap if p == str(fake) else p)
    assert err.value.code == 2
    assert cap.lines == [login.msg_chrome_snap(str(fake))]


def test_find_chrome_skips_a_chromium_browser_script_that_runs_the_snap(tmp_path):
    cap = Capture()
    wrapper = tmp_path / "chromium-browser"
    wrapper.write_text('#!/bin/sh\nexec /snap/bin/chromium "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    with pytest.raises(login.LoginError) as err:
        login.find_chrome("linux", str(tmp_path), reporter=cap.reporter)
    assert err.value.code == 2
    assert cap.lines == [login.msg_chrome_snap(str(wrapper))]
    wrapper.write_text("#!/bin/sh\nexec /opt/chromium/chrome \"$@\"\n", encoding="utf-8")
    assert login.find_chrome("linux", str(tmp_path), reporter=cap.reporter) == str(wrapper)


@pytest.mark.parametrize("start, skipped", [(4090, True), (4091, False)],
                         ids=["last-byte-4096", "last-byte-4097"])
def test_chromium_browser_sniff_reads_the_first_4_kb_only(tmp_path, start, skipped):
    """`/snap/` ending on byte 4096 is seen. Ending on byte 4097, it is not."""
    wrapper = tmp_path / "chromium-browser"
    head = b"#!/bin/sh\n"
    wrapper.write_bytes(head + b"#" * (start - len(head)) + b"/snap/bin/chromium\n")
    wrapper.chmod(0o755)
    assert wrapper.read_bytes().index(b"/snap/") == start
    cap = Capture()
    if skipped:
        with pytest.raises(login.LoginError):
            login.find_chrome("linux", str(tmp_path), reporter=cap.reporter)
        assert cap.lines == [login.msg_chrome_snap(str(wrapper))]
    else:
        assert login.find_chrome("linux", str(tmp_path), reporter=cap.reporter) == str(wrapper)
        assert cap.lines == []


def test_only_a_chromium_browser_script_is_sniffed(tmp_path):
    """A `chromium` script that names `/snap/` is not a snap wrapper by its text alone."""
    script = tmp_path / "chromium"
    script.write_text('#!/bin/sh\n# moved off /snap/ long ago\nexec /opt/c "$@"\n',
                      encoding="utf-8")
    script.chmod(0o755)
    cap = Capture()
    assert login.find_chrome("linux", str(tmp_path), reporter=cap.reporter) == str(script)
    assert cap.lines == []


def test_find_chrome_none_exits_2(tmp_path):
    with pytest.raises(login.LoginError) as err:
        login.find_chrome("linux", str(tmp_path))
    assert err.value.code == 2
    assert err.value.message == login.msg_no_chrome("linux")
    assert "https://www.google.com/chrome/" in err.value.message


def test_find_chrome_macos_uses_app_path():
    mac = login.MAC_CHROME
    assert login.find_chrome("darwin", "", exists=lambda p: p == mac) == mac
    with pytest.raises(login.LoginError) as err:
        login.find_chrome("darwin", "", exists=lambda p: False)
    assert err.value.code == 2
    assert "brew install --cask google-chrome" in err.value.message


# --- virtual display and Chrome flags ---------------------------------------


def test_find_xvfb_prefers_path(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    on_path = _fake_exe(bin_dir, "Xvfb")
    assert login.find_xvfb("linux", str(bin_dir)) == str(on_path)


class _FakeTools:
    """Fake package tools in a folder put before the fixture's link folder.

    The fake `sudo` logs its argv and environment, then runs its arguments.
    The fake `apt-get` logs its argv, then makes a fake Xvfb unless told to fail.
    """

    def __init__(self, tmp_path: Path, names: tuple[str, ...], apt_exit: int = 0,
                 apt_makes_xvfb: bool = True) -> None:
        self.dir = tmp_path / "fakes"
        self.dir.mkdir()
        self.log = tmp_path / "fakes.log"
        self.env_log = tmp_path / "sudo.env"
        self.path = os.pathsep.join([str(self.dir), os.environ["PATH"]])
        scripts = {
            "sudo": f'echo "sudo $*" >> {self.log}\nenv > {self.env_log}\nexec "$@"\n',
            "apt-get": (f'echo "apt-get $*" >> {self.log}\n'
                        + (f"printf '#!/bin/sh\\n' > {self.dir}/Xvfb\n"
                           f"chmod 755 {self.dir}/Xvfb\n" if apt_makes_xvfb else "")
                        + f"exit {apt_exit}\n"),
            "dnf": f'echo "dnf $*" >> {self.log}\n',
            "pacman": f'echo "pacman $*" >> {self.log}\n',
        }
        for name in names:
            exe = self.dir / name
            exe.write_text("#!/bin/sh\n" + scripts[name], encoding="utf-8")
            exe.chmod(0o755)

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


def test_find_xvfb_missing_without_the_flag_names_apt_get_and_installs_nothing(tmp_path,
                                                                             monkeypatch):
    """No Xvfb, `apt-get` on PATH, no flag: exit 2 with the hint, and no tool runs."""
    tools = _FakeTools(tmp_path, ("sudo", "apt-get"))
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    with pytest.raises(login.LoginError) as err:
        login.find_xvfb("linux", tools.path, env=dict(os.environ, PATH=tools.path))
    assert err.value.code == 2
    assert err.value.message == login.msg_no_xvfb("sudo apt-get install xvfb", True)
    assert "sudo apt-get install xvfb" in err.value.message
    assert "--install-xvfb" in err.value.message
    assert tools.calls() == []
    assert not (tools.dir / "Xvfb").exists()


def test_install_flag_runs_sudo_apt_get_and_uses_the_new_xvfb(tmp_path, monkeypatch, capsys):
    tools = _FakeTools(tmp_path, ("sudo", "apt-get"))
    monkeypatch.setenv("PATH", tools.path)
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    monkeypatch.setattr(login, "find_xvfb", ORIG["find_xvfb"])
    monkeypatch.setenv("MFP_SECRET_KEY", "k3y")
    monkeypatch.setenv("MFP_FOO", "bar")
    code = login.main(["--dry-run", "--install-xvfb"], cookies_file=tmp_path / "c.json")
    assert code == 0
    apt_get = str(tools.dir / "apt-get")
    assert tools.calls() == [f"sudo {apt_get} install xvfb", "apt-get install xvfb"]
    assert browser.xvfb == str(tools.dir / "Xvfb")
    out = _lines(capsys)
    assert login.msg_xvfb_installing("sudo apt-get install xvfb") in out
    assert login.msg_xvfb(str(tools.dir / "Xvfb")) in out
    sudo_env = tools.env_log.read_text(encoding="utf-8")
    assert [line for line in sudo_env.splitlines() if line.startswith("MFP_")] == []


def test_install_flag_strips_every_mfp_variable_from_sudo(tmp_path, monkeypatch):
    tools = _FakeTools(tmp_path, ("sudo", "apt-get"))
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    env = dict(os.environ, PATH=tools.path, MFP_USERNAME=EMAIL, MFP_PASSWORD=PASSWORD,
               MFP_SECRET_KEY="k3y", MFP_FOO="bar")
    found = login.find_xvfb("linux", tools.path, install=True, env=env)
    assert found == str(tools.dir / "Xvfb")
    seen = dict(line.split("=", 1) for line in
                tools.env_log.read_text(encoding="utf-8").splitlines() if "=" in line)
    assert sorted(k for k in seen if k.startswith("MFP_")) == []
    assert seen["PATH"] == tools.path
    assert PASSWORD not in tools.env_log.read_text(encoding="utf-8")


def test_install_flag_as_root_runs_apt_get_without_sudo(tmp_path, monkeypatch):
    tools = _FakeTools(tmp_path, ("sudo", "apt-get"))
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    monkeypatch.setattr(login.os, "geteuid", lambda: 0)
    found = login.find_xvfb("linux", tools.path, install=True,
                            env=dict(os.environ, PATH=tools.path))
    assert found == str(tools.dir / "Xvfb")
    assert tools.calls() == ["apt-get install xvfb"]


def test_install_flag_without_a_tty_exits_2_and_runs_nothing(tmp_path, monkeypatch, capsys):
    tools = _FakeTools(tmp_path, ("sudo", "apt-get"))
    monkeypatch.setenv("PATH", tools.path)
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    monkeypatch.setattr(login, "find_xvfb", ORIG["find_xvfb"])
    code = login.main(["--dry-run", "--install-xvfb"], cookies_file=tmp_path / "c.json")
    assert code == 2
    last = _lines(capsys)[-1]
    assert last == login.msg_xvfb_cannot_install("no terminal for apt",
                                                 "sudo apt-get install xvfb")
    assert "sudo apt-get install xvfb" in last
    assert tools.calls() == []
    assert browser.started == 0


def test_install_flag_with_xvfb_on_path_runs_nothing(tmp_path, monkeypatch):
    tools = _FakeTools(tmp_path, ("sudo", "apt-get"))
    on_path = _fake_exe(tools.dir, "Xvfb")
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    found = login.find_xvfb("linux", tools.path, install=True,
                            env=dict(os.environ, PATH=tools.path))
    assert found == str(on_path)
    assert tools.calls() == []


@pytest.mark.parametrize("apt_exit, makes, code", [
    (100, False, 100), (0, False, 0), (100, True, 100),
], ids=["apt-exits-100", "apt-ok-but-no-xvfb", "apt-exits-100-after-making-xvfb"])
def test_find_xvfb_install_failure_exits_2_naming_the_step_and_code(tmp_path, monkeypatch,
                                                                    apt_exit, makes, code):
    tools = _FakeTools(tmp_path, ("sudo", "apt-get"), apt_exit=apt_exit, apt_makes_xvfb=makes)
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    with pytest.raises(login.LoginError) as err:
        login.find_xvfb("linux", tools.path, install=True, env=dict(os.environ, PATH=tools.path))
    assert err.value.code == 2
    assert err.value.message == login.msg_xvfb_install_failed("sudo apt-get install xvfb", code)
    assert "'sudo apt-get install xvfb'" in err.value.message
    assert f"exited with code {code}" in err.value.message
    assert len(tools.calls()) == 2


@pytest.mark.parametrize("names, hint", [
    (("dnf",), "sudo dnf install xorg-x11-server-Xvfb"),
    (("pacman",), "sudo pacman -S xorg-server-xvfb"),
    (("dnf", "pacman"), "sudo dnf install xorg-x11-server-Xvfb"),
    ((), None),
], ids=["dnf", "pacman", "dnf-first", "none"])
@pytest.mark.parametrize("flag", [False, True], ids=["no-flag", "flag"])
def test_find_xvfb_without_apt_get_prints_the_distro_command(tmp_path, monkeypatch, names, hint,
                                                             flag):
    tools = _FakeTools(tmp_path, ("sudo", *names))
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    with pytest.raises(login.LoginError) as err:
        login.find_xvfb("linux", tools.path, install=flag, env=dict(os.environ, PATH=tools.path))
    assert err.value.code == 2
    if flag:
        assert err.value.message == login.msg_xvfb_cannot_install("no apt-get on PATH", hint)
    else:
        assert err.value.message == login.msg_no_xvfb(hint, False)
    assert "--install-xvfb" not in err.value.message or flag
    if hint:
        assert hint in err.value.message
    else:
        assert "install Xvfb" in err.value.message
    assert tools.calls() == []


def test_find_xvfb_macos_needs_none(tmp_path):
    assert login.find_xvfb("darwin", str(tmp_path)) is None


def test_xvfb_args():
    args = login.xvfb_args("/x/Xvfb", 7)
    assert args == [
        "/x/Xvfb", "-displayfd", "7", "-nolisten", "tcp", "-nolisten", "unix",
        "-screen", "0", "1366x768x24",
    ]
    assert "-nolock" not in args


def test_xvfb_start_failure_prints_its_own_stderr(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "_spawn", ORIG["_spawn"])
    fake = tmp_path / "Xvfb"
    fake.write_text("#!/bin/sh\necho boom >&2\nexit 1\n", encoding="utf-8")
    fake.chmod(0o755)
    root = tmp_path / "root"
    root.mkdir()
    cap = Capture()
    env = login.browser_env(dict(os.environ), root, None)
    with pytest.raises(login.LoginError) as err:
        login.start_xvfb(str(fake), env, root, cap.reporter)
    assert err.value.code == 2
    assert err.value.message == login.msg_xvfb_start_failed("boom")
    assert "boom" in err.value.message
    assert not err.value.message.startswith("display: no Xvfb")


def test_xvfb_start_failure_redacts_its_stderr_before_the_cut(tmp_path):
    cap = Capture()
    cap.reporter.add_secrets([PASSWORD])
    log = tmp_path / "xvfb.log"
    log.write_text("\n".join(["one", "two", "three", "four", "five", "six",
                              f"bad {PASSWORD}"]) + "\n", encoding="utf-8")
    tail = login._tail(log, cap.reporter.secrets)
    assert tail == "three / four / five / six / bad ***"
    # A cut first would keep the password's last letters, which no redaction finds.
    log.write_text(PASSWORD + "x" * 196, encoding="utf-8")
    assert login._tail(log, [PASSWORD]) == "***" + "x" * 196
    assert login._tail(tmp_path / "none.log", []) == ""


class _LiveProc:
    """A process that ignores SIGTERM until told otherwise."""

    pid = 424_242

    def __init__(self, dies_on_term: bool) -> None:
        self.dies_on_term = dies_on_term
        self.waits: list[float | None] = []
        self.alive = True

    def poll(self):
        return None if self.alive else 0

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.alive:
            raise subprocess.TimeoutExpired("Xvfb", timeout)
        return 0


@pytest.mark.parametrize("dies_on_term, sent", [
    (True, [signal.SIGTERM]),
    (False, [signal.SIGTERM, signal.SIGKILL]),
], ids=["exits-on-sigterm", "needs-sigkill"])
def test_xvfb_cleanup_sends_sigterm_before_sigkill(monkeypatch, dies_on_term, sent):
    proc = _LiveProc(dies_on_term)
    signals: list[tuple[int, int]] = []

    def killpg(pgid, sig):
        signals.append((pgid, sig))
        if sig == signal.SIGKILL or (sig == signal.SIGTERM and proc.dies_on_term):
            proc.alive = False

    monkeypatch.setattr(login.os, "killpg", killpg)
    login._kill_group(proc, login.XVFB_TERM_GRACE)
    assert signals == [(proc.pid, s) for s in sent]
    assert proc.waits[0] == 5.0
    assert login.XVFB_TERM_GRACE == 5.0


def test_chrome_session_stops_chrome_then_sends_xvfb_sigterm_first(tmp_path, monkeypatch):
    """`chrome_session` itself: Chrome gets SIGKILL, Xvfb SIGTERM, then SIGKILL."""
    chrome, xvfb = _LiveProc(False), _LiveProc(False)
    chrome.pid, xvfb.pid = 515_151, 616_161
    signals: list[tuple[int, int]] = []

    def killpg(pgid, sig):
        signals.append((pgid, sig))
        if sig == signal.SIGKILL:
            (chrome if pgid == chrome.pid else xvfb).alive = False

    monkeypatch.setattr(login.os, "killpg", killpg)
    monkeypatch.setattr(login, "chrome_session", ORIG["chrome_session"])
    monkeypatch.setattr(login, "_kill_leftovers", lambda root, *a: None)
    monkeypatch.setattr(login, "start_xvfb", lambda *a: (xvfb, 9))
    spawned: list[list[str]] = []

    def spawn(args, env, pass_fds=(), stderr=None):
        spawned.append(args)
        return chrome

    monkeypatch.setattr(login, "_spawn", spawn)

    def port(self, timeout=30.0):
        raise OSError("Chrome exited")

    monkeypatch.setattr(login.ChromeProcess, "port", port)
    session = login.chrome_session("/fake/chrome", Capture().reporter, "/fake/Xvfb", "darwin")
    with pytest.raises(OSError), session:
        pass
    assert signals == [(chrome.pid, signal.SIGKILL), (xvfb.pid, signal.SIGTERM),
                       (xvfb.pid, signal.SIGKILL)]
    assert "--window-position=-32000,-32000" in spawned[0]


def test_parse_display():
    assert login.parse_display(b"0\n") == 0
    assert login.parse_display(b"12") == 12
    with pytest.raises(ValueError):
        login.parse_display(b"")
    with pytest.raises(ValueError):
        login.parse_display(b":0")


def test_chrome_args_linux_headed(tmp_path):
    args = login.chrome_args("/usr/bin/google-chrome", tmp_path / "profile", "linux")
    assert args[0] == "/usr/bin/google-chrome"
    assert args[-1] == "about:blank"
    assert not any(a.startswith("--headless") for a in args)
    assert not any(a.startswith("--enable-automation") for a in args)
    assert not any(a.startswith("--user-agent") for a in args)
    assert args[1:] == [
        "--remote-debugging-port=0", "--password-store=basic", "--no-first-run",
        "--no-default-browser-check", f"--user-data-dir={tmp_path / 'profile'}",
        "--disable-blink-features=AutomationControlled", "--window-size=1366,768",
        "--window-position=0,0", "--ozone-platform=x11", "about:blank",
    ]


def test_chrome_args_macos_off_screen(tmp_path):
    args = login.chrome_args(login.MAC_CHROME, tmp_path / "profile", "darwin")
    assert not any(a.startswith("--headless") for a in args)
    assert "--window-position=-32000,-32000" in args
    assert "--window-position=0,0" not in args
    assert "--ozone-platform=x11" not in args


def test_browser_env_points_home_and_display_at_ours(tmp_path):
    base = {"HOME": "/srv/u", "TMPDIR": "/tmp", "DISPLAY": ":5", "WAYLAND_DISPLAY": "wayland-0",
            "PATH": "/usr/bin", "MFP_USERNAME": EMAIL, "MFP_PASSWORD": PASSWORD,
            "MFP_SECRET_KEY": "k3y", "MFP_FOO": "bar"}
    env = login.browser_env(base, tmp_path, 3)
    assert env == {"HOME": str(tmp_path), "TMPDIR": str(tmp_path), "DISPLAY": ":3",
                   "PATH": "/usr/bin"}
    mac = login.browser_env(base, tmp_path, None)
    assert mac == {"HOME": str(tmp_path), "TMPDIR": str(tmp_path), "DISPLAY": ":5",
                   "WAYLAND_DISPLAY": "wayland-0", "PATH": "/usr/bin"}
    assert base["HOME"] == "/srv/u"
    assert base["MFP_PASSWORD"] == PASSWORD


# --- cookie filter and session test -----------------------------------------


RAW_COOKIES = [
    {"name": SESSION, "value": "v1", "domain": "www.myfitnesspal.com"},
    {"name": "cf_clearance", "value": "v2", "domain": ".myfitnesspal.com"},
    {"name": "_ga", "value": "v3", "domain": ".google.com"},
    {"name": "sid", "value": "v4", "domain": "notmyfitnesspal.com"},
]


def test_cookie_filter_keeps_only_mfp_domains():
    cookies, domains = login.filter_cookies(RAW_COOKIES)
    assert cookies == {SESSION: "v1", "cf_clearance": "v2"}
    assert domains == {SESSION: "www.myfitnesspal.com", "cf_clearance": ".myfitnesspal.com"}


def test_session_test():
    """The login now uses the server's own rule, `_has_real_mfp_session`."""
    cookies, _ = login.filter_cookies(RAW_COOKIES)
    assert server._has_real_mfp_session(cookies) is True
    assert server._has_real_mfp_session({"__Host-next-auth.csrf-token": "x"}) is False
    assert server._has_real_mfp_session({"_mfp_session": "x"}) is True
    assert not hasattr(login, "has_session")


def test_every_session_check_uses_the_server_rule(tmp_path, monkeypatch):
    """`finalize`, `run_check` and `_session_in` all ask the server's function."""
    seen: list[str] = []

    def rule(cookies):
        seen.append(",".join(sorted(cookies)))
        return False

    monkeypatch.setattr(server, "_has_real_mfp_session", rule)
    cap = Capture()
    assert login.finalize(RAW_COOKIES[:2], "UA/1", tmp_path / "c.json", True, _ok_verify,
                          cap.reporter, NOW) == 4
    f = _cookie_file(tmp_path / "s.json", NOW - timedelta(days=1))
    assert login.run_check(f, _ok_verify, cap.reporter, NOW) == 4
    assert login._session_in(RAW_COOKIES) is False
    assert seen == [f"{SESSION},cf_clearance", SESSION, f"{SESSION},cf_clearance"]


# --- payload, writer, finalize ----------------------------------------------


def test_payload_builder():
    payload = login.build_payload({"a": "1"}, {"a": ".myfitnesspal.com"}, "UA/1", NOW)
    assert payload == {
        "cookies": {"a": "1"},
        "saved_at": "2026-11-11T12:00:00",
        "domains": {"a": ".myfitnesspal.com"},
        "user_agent": "UA/1",
    }


def _ok_verify(cookies, ua):
    return True, "ok"


def _bad_verify(cookies, ua):
    return False, "status 403"


def test_finalize_writes_atomic_0600_file(tmp_path):
    target = tmp_path / "cfg" / "cookies.json"
    cap = Capture()
    raw = RAW_COOKIES[:2]
    code = login.finalize(raw, "UA/1", target, False, _ok_verify, cap.reporter, NOW)
    assert code == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    data = json.loads(target.read_text(encoding="utf-8"))
    assert set(data) == {"cookies", "saved_at", "domains", "user_agent"}
    assert data["cookies"] == {SESSION: "v1", "cf_clearance": "v2"}
    assert datetime.fromisoformat(data["saved_at"]) == NOW
    assert sorted(p.name for p in target.parent.iterdir()) == ["cookies.json"]


def test_finalize_failed_verification_keeps_old_bytes(tmp_path):
    target = tmp_path / "cookies.json"
    target.write_bytes(b"old bytes")
    cap = Capture()
    code = login.finalize(RAW_COOKIES[:2], "UA/1", target, False, _bad_verify, cap.reporter, NOW)
    assert code == 4
    assert target.read_bytes() == b"old bytes"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cookies.json", SAFE_BIN, "tmp"]
    assert any("chrome-ua" in line and "fail" in line for line in cap.lines)


def test_finalize_names_the_failing_user_agent(tmp_path):
    def verify(cookies, ua):
        return (ua != login.LIBRARY_UA, "status 403")

    cap = Capture()
    code = login.finalize(RAW_COOKIES[:2], "UA/1", tmp_path / "c.json", True, verify,
                          cap.reporter, NOW)
    assert code == 4
    assert "verify chrome-ua: ok" in cap.lines
    assert "verify library-ua: fail (status 403)" in cap.lines


def test_finalize_dry_run_writes_nothing(tmp_path):
    target = tmp_path / "c.json"
    cap = Capture()
    code = login.finalize(RAW_COOKIES, "UA/1", target, True, _ok_verify, cap.reporter, NOW)
    assert code == 0
    assert not target.exists()
    assert cap.lines[-1] == "dry-run: 2 cookies, session ok"


def test_finalize_without_session_cookie_exits_4(tmp_path):
    cap = Capture()
    raw = [RAW_COOKIES[1]]
    assert login.finalize(raw, "UA/1", tmp_path / "c.json", True, _ok_verify, cap.reporter,
                          NOW) == 4


def test_write_failure_leaves_no_temp_file(tmp_path, monkeypatch):
    target = tmp_path / "cookies.json"
    target.write_bytes(b"old")

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(login.os, "replace", boom)
    with pytest.raises(OSError):
        login.write_cookie_file(target, {"cookies": {}})
    assert target.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cookies.json", SAFE_BIN, "tmp"]


# --- verification over HTTP (fake session) ----------------------------------


class FakeResponse:
    def __init__(self, status: int, ctype: str, body):
        self.status_code = status
        self.headers = {"Content-Type": ctype}
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeSession:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.headers: dict[str, str] = {}
        self.cookie_calls: list[tuple] = []
        self.cookies = self
        self.urls: list[str] = []

    def set(self, name, value, domain, path):
        self.cookie_calls.append((name, value, domain, path))

    def get(self, url, timeout, allow_redirects):
        self.urls.append(url)
        return self.response

    def close(self):
        pass


@pytest.mark.parametrize(
    "resp, expected",
    [
        (FakeResponse(200, "application/json; charset=utf-8", {"access_token": "x"}), True),
        (FakeResponse(200, "text/html", {"access_token": "x"}), False),
        (FakeResponse(200, "application/json", {"error": "no"}), False),
        (FakeResponse(200, "application/json", ValueError("bad json")), False),
        (FakeResponse(403, "application/json", {"access_token": "x"}), False),
    ],
)
def test_verify_session(resp, expected):
    fake = FakeSession(resp)
    ok, _reason = ORIG["verify_session"]({SESSION: "v1"}, "UA/1", session_factory=lambda: fake)
    assert ok is expected
    assert fake.headers["User-Agent"] == "UA/1"
    assert fake.urls == [login.AUTH_URL]
    assert fake.cookie_calls == [(SESSION, "v1", ".myfitnesspal.com", "/")]


def test_library_ua_matches_the_installed_client():
    spec = importlib.util.find_spec("myfitnesspal")
    assert spec is not None and spec.submodule_search_locations
    client = Path(spec.submodule_search_locations[0]) / "client.py"
    assert f'"User-Agent": "{login.LIBRARY_UA}"' in client.read_text(encoding="utf-8")


def test_local_http_ignores_proxy_variables():
    session = login._local_http()
    try:
        assert session.trust_env is False
    finally:
        session.close()


# --- --check age rule -------------------------------------------------------


def _cookie_file(path: Path, saved_at: datetime) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"cookies": {SESSION: COOKIE_VALUE}, "saved_at": saved_at.isoformat(),
                    "user_agent": "UA/1"}),
        encoding="utf-8",
    )
    return path


def test_check_age_rule(tmp_path):
    cap = Capture()
    old = _cookie_file(tmp_path / "old.json", NOW - timedelta(days=29, hours=1))
    assert login.run_check(old, _ok_verify, cap.reporter, NOW) == 4
    fresh = _cookie_file(tmp_path / "fresh.json", NOW - timedelta(days=28))
    assert login.run_check(fresh, _ok_verify, cap.reporter, NOW) == 0


def test_check_boundary_exactly_29_days_fails(tmp_path):
    cap = Capture()
    f = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=29))
    assert login.run_check(f, _ok_verify, cap.reporter, NOW) == 4


def test_check_missing_or_broken_file_exits_4(tmp_path):
    cap = Capture()
    assert login.run_check(tmp_path / "none.json", _ok_verify, cap.reporter, NOW) == 4
    broken = tmp_path / "b.json"
    broken.write_text("{not json", encoding="utf-8")
    assert login.run_check(broken, _ok_verify, cap.reporter, NOW) == 4


def test_check_failed_verification_exits_4(tmp_path):
    cap = Capture()
    f = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    assert login.run_check(f, _bad_verify, cap.reporter, NOW) == 4


def test_check_reads_server_cookie_file_at_call_time(tmp_path, monkeypatch):
    """The default target is `server.COOKIES_FILE`, read on each call, never at import."""
    monkeypatch.setattr(login, "verify_session", _ok_verify)
    cap = Capture()
    args = login.parse_args(["--check"], cap.reporter)
    assert login._target_path(None) == server.COOKIES_FILE
    assert login._main(args, login._target_path(None), cap.reporter, "linux") == 4
    assert cap.lines == ["check: no cookie file"]
    moved = _cookie_file(tmp_path / "elsewhere" / "cookies.json", NOW - timedelta(days=1))
    monkeypatch.setattr(server, "COOKIES_FILE", moved)
    assert login._target_path(None) == moved
    assert login._main(args, login._target_path(None), cap.reporter, "linux") == 0
    assert cap.lines[-1] == "check: session still valid"
    given = tmp_path / "given.json"
    assert login._target_path(given) == given
    assert login._target_path(str(given)) == given


def test_main_resolves_its_target_through_the_helper(tmp_path, monkeypatch, capsys):
    seen: list[object] = []

    def recorder(cookies_file):
        seen.append(cookies_file)
        return Path(cookies_file)

    monkeypatch.setattr(login, "_target_path", recorder)
    monkeypatch.setattr(login, "verify_session", _ok_verify)
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    assert login.main(["--check"], cookies_file=target) == 0
    assert seen == [target]
    assert _lines(capsys)[-1] == "check: session still valid"


# --- login flow fakes -------------------------------------------------------


class FakePage:
    """Login page double. Submitting sets the session cookie."""

    user_agent = "Mozilla/5.0 Chrome/157.0.0.0"

    def __init__(self, turnstile_len: int | None = None, session_after_submit: bool = True,
                 text: str = "Log in Email Password", drop_fill: str | None = None):
        self.turnstile_len = turnstile_len
        self.session_after_submit = session_after_submit
        self.page_text = text
        self.drop_fill = drop_fill
        self.filled: dict[str, str] = {}
        self.submitted = False

    def navigate(self, url: str) -> None:
        self.url = url

    def dismiss_consent(self) -> bool:
        return False

    def exists(self, selector: str) -> bool:
        if selector in (login.EMAIL_SEL, login.PASSWORD_SEL):
            return True
        if selector == login.TURNSTILE_SEL:
            return self.turnstile_len is not None
        return False

    def fill(self, selector: str, text: str) -> None:
        if selector != self.drop_fill:
            self.filled[selector] = text

    def value_length(self, selector: str) -> int:
        if selector in (login.EMAIL_SEL, login.PASSWORD_SEL):
            return len(self.filled.get(selector, ""))
        return self.turnstile_len or 0

    def submit(self) -> None:
        self.submitted = True

    def cookies(self) -> list[dict]:
        if self.submitted and self.session_after_submit:
            return list(RAW_COOKIES)
        return [RAW_COOKIES[1]]

    def text(self) -> str:
        return self.page_text

    def shows_form(self) -> bool:
        return True


class Utf16Page(FakePage):
    """Counts `.value.length` the way JavaScript does, in UTF-16 code units."""

    def value_length(self, selector: str) -> int:
        if selector in (login.EMAIL_SEL, login.PASSWORD_SEL):
            return len(self.filled.get(selector, "").encode("utf-16-le")) // 2
        return self.turnstile_len or 0


class FakeBrowser:
    def __init__(self, page: FakePage, error: Exception | None = None):
        self.page = page
        self.error = error
        self.started = 0
        self.cleaned = 0
        self.xvfb: str | None = "unset"
        self.platform = "unset"

    def __call__(self, chrome: str, reporter, xvfb: str | None, platform: str):
        self.started += 1
        self.xvfb = xvfb
        self.platform = platform
        if self.error is not None:
            raise self.error
        return self

    def __enter__(self):
        return self.page

    def __exit__(self, *exc):
        self.cleaned += 1
        return False


def _stamp(ago: timedelta) -> str:
    """An attempt line as the command writes it: UTC, seconds, `+00:00`."""
    return (UTC_NOW - ago).isoformat(timespec="seconds")


def _seed_log(folder: Path, lines: list[str]) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    log = folder / LOG_NAME
    log.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return log


def _log_lines(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").splitlines()


def _run_login(monkeypatch, tmp_path, log_lines: int, page: FakePage,
               xvfb_finder=lambda: "/fake/Xvfb", password: str = PASSWORD,
               browser: FakeBrowser | None = None):
    """Credentials come from this test's environment. The log sits beside the target."""
    monkeypatch.setenv("MFP_USERNAME", EMAIL)
    monkeypatch.setenv("MFP_PASSWORD", password)
    log = _seed_log(tmp_path, [_stamp(timedelta(hours=i + 1)) for i in range(log_lines)])
    browser = browser or FakeBrowser(page)
    clock = FakeClock()
    cap = Capture()
    code = login.run_login(
        dry_run=True, target=tmp_path / "c.json",
        reporter=cap.reporter, env=dict(os.environ, PATH=""), platform="linux",
        browser_factory=browser,
        verify=_ok_verify, chrome_finder=lambda: "/fake/chrome", xvfb_finder=xvfb_finder,
        now=lambda: NOW, utc_now=lambda: UTC_NOW, sleep=clock.sleep, monotonic=clock.monotonic,
    )
    return code, browser, log, cap


# The lines `_fake_main_browser`'s finders print, before any credential line.
FOUND = [login.msg_chrome("/fake/chrome"), login.msg_xvfb("/fake/Xvfb")]


def _fake_main_browser(monkeypatch, tmp_path, page: FakePage, password: str = PASSWORD,
                       error: Exception | None = None, creds: bool = True) -> FakeBrowser:
    """Fakes for a run through `main`: browser, finders and verify."""
    if creds:
        monkeypatch.setenv("MFP_USERNAME", EMAIL)
        monkeypatch.setenv("MFP_PASSWORD", password)
    browser = FakeBrowser(page, error)
    monkeypatch.setattr(login, "chrome_session", browser)
    monkeypatch.setattr(login, "find_chrome", lambda platform, path, **kw: "/fake/chrome")
    monkeypatch.setattr(login, "find_xvfb", lambda platform, path, **kw: "/fake/Xvfb")
    monkeypatch.setattr(login, "verify_session", _ok_verify)
    return browser


# --- attempt counter and login flow -----------------------------------------


def test_browser_gets_the_xvfb_found(tmp_path, monkeypatch):
    code, browser, _log, _ = _run_login(monkeypatch, tmp_path, 0, FakePage())
    assert code == 0
    assert browser.xvfb == "/fake/Xvfb"


def test_missing_xvfb_refuses_before_browser(tmp_path, monkeypatch):
    def finder() -> str:
        raise login.LoginError(2, login.msg_no_xvfb(None, False))

    code, browser, log, cap = _run_login(monkeypatch, tmp_path, 0, FakePage(), xvfb_finder=finder)
    assert code == 2
    assert browser.started == 0
    assert log.read_text(encoding="utf-8") == ""
    assert cap.lines[-1] == login.msg_no_xvfb(None, False)


@pytest.mark.parametrize("dropped", ["email", "password"])
def test_field_not_filled_exits_5_without_submit(tmp_path, monkeypatch, dropped):
    selector = login.EMAIL_SEL if dropped == "email" else login.PASSWORD_SEL
    page = FakePage(turnstile_len=500, drop_fill=selector)
    code, _browser, log, cap = _run_login(monkeypatch, tmp_path, 0, page)
    assert code == 5
    assert page.submitted is False
    assert log.read_text(encoding="utf-8") == ""
    assert login.msg_fill_failed() in cap.lines


def test_fill_check_counts_utf16_units(tmp_path, monkeypatch):
    """A non-BMP password: JavaScript reports 5 units for `p🔒ss`, Python len says 4."""
    password = "p\U0001f512ss"
    assert len(password) == 4
    assert login._utf16_len(password) == 5
    page = Utf16Page()
    code, _browser, _log, cap = _run_login(monkeypatch, tmp_path, 0, page, password=password)
    assert code == 0
    assert page.submitted is True
    assert login.msg_fill_failed() not in cap.lines


def test_attempt_log_full_refuses_before_browser(tmp_path, monkeypatch):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    lines = [_stamp(timedelta(hours=h)) for h in (1, 2, 3)]
    log = _seed_log(tmp_path, lines)
    assert login.main([], cookies_file=tmp_path / "c.json") == 6
    assert browser.started == 0
    assert _log_lines(log) == lines


def test_attempt_log_two_lines_append_a_third_and_five_refuse(tmp_path, monkeypatch, capsys):
    page = FakePage()
    browser = _fake_main_browser(monkeypatch, tmp_path, page)
    two = [_stamp(timedelta(hours=h)) for h in (1, 2)]
    log = _seed_log(tmp_path, two)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert browser.started == 1
    assert page.submitted is True
    assert _log_lines(log) == [*two, "2026-11-27T12:00:00+00:00"]
    out = _lines(capsys)
    assert login.msg_attempt_logged(3) in out
    assert out[-1] == "dry-run: 2 cookies, session ok"
    five = [_stamp(timedelta(hours=h)) for h in range(1, 6)]
    _seed_log(tmp_path, five)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 6
    assert browser.started == 1
    assert _log_lines(log) == five


@pytest.mark.parametrize("third, code", [
    (timedelta(hours=23, minutes=59), 6),
    (timedelta(hours=24, minutes=1), 0),
], ids=["23h59m-inside", "24h01m-outside"])
def test_window_edge_with_a_fixed_clock(tmp_path, monkeypatch, third, code):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    _seed_log(tmp_path, [_stamp(timedelta(hours=1))] * 2 + [_stamp(third)])
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == code
    assert browser.started == (1 if code == 0 else 0)


def test_prune_drops_lines_older_than_30_days(tmp_path, monkeypatch):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    keep, drop = _stamp(timedelta(days=29)), _stamp(timedelta(days=31))
    log = _seed_log(tmp_path, [drop, "", keep])
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert _log_lines(log) == [keep, _stamp(timedelta(0))]


def test_a_run_that_finds_a_valid_session_still_prunes(tmp_path, monkeypatch):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    keep, drop = _stamp(timedelta(days=29)), _stamp(timedelta(days=31))
    log = _seed_log(tmp_path, [drop, keep])
    assert login.main([], cookies_file=target) == 0
    assert browser.started == 0
    assert _log_lines(log) == [keep]


def test_prune_failure_leaves_the_log_and_no_temp_file(tmp_path, monkeypatch):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    log = _seed_log(tmp_path, [_stamp(timedelta(days=31))])
    before = log.read_bytes()

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(login.os, "replace", boom)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 5
    assert log.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == [LOG_NAME, LOCK_NAME, SAFE_BIN, "tmp"]
    assert browser.started == 0


def test_unreadable_line_counts_and_survives_a_prune(tmp_path, monkeypatch):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    recent = [_stamp(timedelta(hours=h)) for h in (1, 2)]
    log = _seed_log(tmp_path, ["garbage", *recent])
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 6
    assert browser.started == 0
    assert _log_lines(log) == ["garbage", *recent]
    _seed_log(tmp_path, ["garbage", _stamp(timedelta(days=31)), recent[0]])
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert browser.started == 1
    assert _log_lines(log) == ["garbage", recent[0], _stamp(timedelta(0))]


def test_bytes_that_are_not_utf8_survive_a_prune(tmp_path, monkeypatch):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    log = tmp_path / LOG_NAME
    log.write_bytes(b"\xff\xfe junk\n" + _stamp(timedelta(days=31)).encode() + b"\n")
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert log.read_bytes() == b"\xff\xfe junk\n" + b"2026-11-27T12:00:00+00:00\n"


def test_three_unreadable_lines_exit_6_naming_the_file_and_count(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    log = _seed_log(tmp_path, ["garbage", "2026-13-01T00:00:00", "dev"])
    assert login.main([], cookies_file=tmp_path / "c.json") == 6
    out = _lines(capsys)
    assert out == ["check: no cookie file", login.msg_log_unreadable(log, 3)]
    assert str(log) in out[-1]
    assert "holds 3 unreadable lines" in out[-1]
    assert "Delete those lines" in out[-1]
    assert browser.started == 0


def test_exit_6_names_the_file_and_the_reopen_time(tmp_path, monkeypatch, capsys):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    log = _seed_log(tmp_path, [_stamp(timedelta(hours=h)) for h in (1, 2, 3)])
    assert login.main([], cookies_file=tmp_path / "c.json") == 6
    last = _lines(capsys)[-1]
    oldest = UTC_NOW - timedelta(hours=3)
    assert last == login.msg_log_full(log, 3, oldest + timedelta(hours=24))
    assert str(log) in last
    assert "from 2026-11-28T09:00:00+00:00" in last


@pytest.mark.parametrize("lines, count, reopen", [
    ([timedelta(hours=h) for h in range(1, 6)], 5, "2026-11-28T09:00:00+00:00"),
    (["garbage", *(timedelta(hours=h) for h in (1, 2, 3))], 4, "2026-11-28T10:00:00+00:00"),
], ids=["five-stamps", "one-unreadable-three-stamps"])
def test_reopen_time_is_when_the_window_drops_below_three(tmp_path, monkeypatch, capsys,
                                                          lines, count, reopen):
    """Over three counted lines, the oldest one ageing out still leaves three."""
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    log = _seed_log(tmp_path, [x if isinstance(x, str) else _stamp(x) for x in lines])
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 6
    assert _lines(capsys) == [
        login.msg_log_full(log, count, datetime.fromisoformat(reopen))
    ]


def test_far_future_stamps_count_as_unreadable_and_exit_6(tmp_path, monkeypatch, capsys):
    """A stamp whose reopen time or UTC form overflows is unreadable, so exit 6 says delete it.

    Before, three such lines made the reopen time overflow: exit 5, no hint.
    """
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    lines = ["9999-12-31T23:00:00+00:00", "9999-12-31T23:59:59", "9999-12-31T22:00:00-05:00"]
    log = _seed_log(tmp_path, lines)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 6
    assert _lines(capsys) == [login.msg_log_unreadable(log, 3)]
    assert browser.started == 0
    assert _log_lines(log) == lines
    assert login._parse_stamp("0001-01-01T00:00:00+05:00") is None
    assert login._parse_stamp("9999-12-30T12:00:00+00:00") is not None


def test_naive_stamp_is_read_as_utc(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    recent = [_stamp(timedelta(hours=1)), _stamp(timedelta(minutes=30))]
    log = _seed_log(tmp_path, ["2026-11-27T10:00:00", *recent])
    assert login.main([], cookies_file=tmp_path / "c.json") == 6
    # As an unreadable line it would reopen at 11:00, from the oldest stamp left.
    reopen = datetime(2026, 11, 28, 10, 0, 0, tzinfo=timezone.utc)
    assert _lines(capsys)[-1] == login.msg_log_full(log, 3, reopen)
    _seed_log(tmp_path, ["2026-11-26T11:00:00", *recent])
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert browser.started == 1


def test_written_stamp_is_utc_and_parses_on_this_python(tmp_path, monkeypatch):
    monkeypatch.setattr(login, "_utc_now", ORIG["_utc_now"])
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    before = datetime.now(timezone.utc).replace(microsecond=0)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    after = datetime.now(timezone.utc)
    (line,) = _log_lines(tmp_path / LOG_NAME)
    assert line.endswith("+00:00")
    stamp = datetime.fromisoformat(line)
    assert stamp.utcoffset() == timedelta(0)
    assert before <= stamp <= after


def test_record_starts_a_new_line_when_the_log_lacks_one(tmp_path, monkeypatch):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    log = tmp_path / LOG_NAME
    log.write_bytes(_stamp(timedelta(hours=5)).encode())
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert _log_lines(log) == [_stamp(timedelta(hours=5)), _stamp(timedelta(0))]


def test_fresh_home_gets_a_0700_folder_holding_the_log(tmp_path, monkeypatch):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    fresh = tmp_path / "fresh"
    assert login.main(["--dry-run"], cookies_file=fresh / "c.json") == 0
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o700
    assert _log_lines(fresh / LOG_NAME) == ["2026-11-27T12:00:00+00:00"]
    assert sorted(p.name for p in fresh.iterdir()) == [LOG_NAME, LOCK_NAME]


def test_fresh_lock_file_has_mode_0600(tmp_path, monkeypatch):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    old_umask = os.umask(0o022)
    try:
        assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    finally:
        os.umask(old_umask)
    lock = tmp_path / LOCK_NAME
    assert stat.S_IMODE(os.stat(lock).st_mode) == 0o600


def _hold_lock(folder: Path) -> int:
    """Take the lock the way another run would: flock on its own open of login.lock."""
    import fcntl

    folder.mkdir(parents=True, exist_ok=True)
    fd = os.open(folder / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def test_held_lock_exits_2_before_the_session_check(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    old = _stamp(timedelta(days=31))
    log = _seed_log(tmp_path, [old])
    fd = _hold_lock(tmp_path)
    try:
        assert login.main([], cookies_file=tmp_path / "c.json") == 2
        assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 2
    finally:
        os.close(fd)
    assert _lines(capsys) == [login.msg_lock_held(tmp_path / LOCK_NAME)] * 2
    assert browser.started == 0
    assert _log_lines(log) == [old]
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert browser.started == 1
    assert _log_lines(log) == [_stamp(timedelta(0))]


def test_check_runs_while_the_lock_is_held(tmp_path, monkeypatch, capsys):
    """Regression guard, kept on purpose: `--check` takes no lock."""
    monkeypatch.setattr(login, "verify_session", _ok_verify)
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    fd = _hold_lock(tmp_path)
    try:
        assert login.main(["--check"], cookies_file=target) == 0
        assert _lines(capsys)[-1] == "check: session still valid"
        target.unlink()
        assert login.main(["--check"], cookies_file=target) == 4
    finally:
        os.close(fd)
    assert _lines(capsys) == ["check: no cookie file"]


def test_check_leaves_the_log_byte_for_byte(tmp_path, monkeypatch):
    """Regression guard, kept on purpose: `--check` never prunes or writes the log."""
    monkeypatch.setattr(login, "verify_session", _ok_verify)
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    log = _seed_log(tmp_path, [_stamp(timedelta(days=40)), "garbage", "",
                               _stamp(timedelta(hours=1))])
    before = log.read_bytes()
    assert login.main(["--check"], cookies_file=target) == 0
    assert log.read_bytes() == before
    assert not (tmp_path / LOCK_NAME).exists()


def test_window_check_comes_before_the_credential_prompt(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage(), creds=False)
    monkeypatch.setattr("builtins.input", _tripwire("input"))
    monkeypatch.setattr(login.getpass, "getpass", _tripwire("getpass"))
    log = _seed_log(tmp_path, [_stamp(timedelta(hours=h)) for h in (1, 2, 3)])
    assert login.main([], cookies_file=tmp_path / "c.json") == 6
    reopen = UTC_NOW + timedelta(hours=21)
    assert _lines(capsys) == ["check: no cookie file", login.msg_log_full(log, 3, reopen)]
    assert browser.started == 0


def test_window_check_comes_before_the_websockets_check(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    _hide_websockets(monkeypatch)
    log = _seed_log(tmp_path, [_stamp(timedelta(hours=h)) for h in (1, 2, 3)])
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 6
    reopen = UTC_NOW + timedelta(hours=21)
    assert _lines(capsys) == [login.msg_log_full(log, 3, reopen)]
    assert browser.started == 0


def test_dry_run_with_a_full_window_exits_6_before_any_browser(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    lines = [_stamp(timedelta(hours=h)) for h in (1, 2, 3)]
    log = _seed_log(tmp_path, lines)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 6
    assert browser.started == 0
    assert _log_lines(log) == lines
    assert _lines(capsys)[-1].startswith("attempts: 3 logins in the last 24 hours")


def test_dry_run_appends_exactly_one_line(tmp_path, monkeypatch):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    log = _seed_log(tmp_path, [_stamp(timedelta(hours=5))])
    before = log.read_bytes()
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert log.read_bytes() == before + b"2026-11-27T12:00:00+00:00\n"
    assert not (tmp_path / "c.json").exists()


def test_saved_at_stays_naive_while_the_attempt_stamp_is_utc(tmp_path, monkeypatch):
    """A dry run writes no cookie file, so a plain run shows the finalize stamp."""
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    target = tmp_path / "c.json"
    assert login.main([], cookies_file=target) == 0
    saved_at = datetime.fromisoformat(json.loads(target.read_text(encoding="utf-8"))["saved_at"])
    assert saved_at.tzinfo is None
    assert saved_at == NOW
    assert _log_lines(tmp_path / LOG_NAME) == ["2026-11-27T12:00:00+00:00"]


def test_turnstile_never_clears_exits_3_without_counting(tmp_path, monkeypatch):
    page = FakePage(turnstile_len=0, text="Verify you are human " + PASSWORD)
    code, _browser, log, cap = _run_login(monkeypatch, tmp_path, 0, page)
    assert code == 3
    assert page.submitted is False
    assert log.read_text(encoding="utf-8") == ""
    assert any(line.startswith("page: Verify you are human") for line in cap.lines)
    assert all(PASSWORD not in line for line in cap.lines)


def test_turnstile_cleared_submits(tmp_path, monkeypatch):
    page = FakePage(turnstile_len=500)
    code, _browser, log, _ = _run_login(monkeypatch, tmp_path, 0, page)
    assert code == 0
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1


def test_no_session_after_submit_times_out_with_5(tmp_path, monkeypatch):
    page = FakePage(session_after_submit=False, text="Enter the code we emailed you")
    code, _browser, log, cap = _run_login(monkeypatch, tmp_path, 0, page)
    assert code == 5
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1
    assert any(line.startswith("page: Enter the code") for line in cap.lines)


def test_lock_page_after_submit_exits_3(tmp_path, monkeypatch):
    page = FakePage(session_after_submit=False, text="Too many attempts. Try again later.")
    code, *_ = _run_login(monkeypatch, tmp_path, 0, page)
    assert code == 3


def test_runtime_error_detail_is_redacted_before_the_cut(tmp_path, monkeypatch):
    browser = FakeBrowser(FakePage(), error=OSError("x" * 199 + PASSWORD))
    code, _browser, _log, cap = _run_login(monkeypatch, tmp_path, 0, FakePage(), browser=browser)
    assert code == 5
    assert cap.lines[-1] == "error: OSError: " + "x" * 199 + "*"


# --- CDPPage over a fake DevTools client -------------------------------------


class FakeCDP:
    def __init__(self, value=None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.value = value

    def call(self, method, params=None, timeout=30.0):
        self.calls.append((method, dict(params or {})))
        return {"result": {"value": self.value}}


def test_cdp_fill_keeps_the_text_out_of_every_expression():
    cdp = FakeCDP()
    page = login.CDPPage(cdp, "UA/1")
    page.fill(login.PASSWORD_SEL, SPECIAL)
    expressions = [p["expression"] for m, p in cdp.calls if m == "Runtime.evaluate"]
    assert len(expressions) == 1
    for form in (SPECIAL, json.dumps(SPECIAL), json.dumps(SPECIAL)[1:-1], "w0rd"):
        assert form not in expressions[0]
    assert [p for m, p in cdp.calls if m == "Input.insertText"] == [{"text": SPECIAL}]


def test_cdp_value_length_returns_the_page_count():
    page = login.CDPPage(FakeCDP(value=5), "UA/1")
    assert page.value_length(login.PASSWORD_SEL) == 5


# --- credentials ------------------------------------------------------------


def _token(key: bytes, text: str) -> str:
    return Fernet(key).encrypt(text.encode()).decode()


class _Counter:
    def __init__(self, result=None) -> None:
        self.calls = 0
        self.result = result

    def __call__(self, *args, **kwargs):
        self.calls += 1
        return self.result


def test_credentials_plain(monkeypatch):
    monkeypatch.setenv("MFP_USERNAME", "user@example.com")
    monkeypatch.setenv("MFP_PASSWORD", "hunter2")
    cap = Capture()
    assert login.read_credentials(cap.reporter) == ("user@example.com", "hunter2")
    assert cap.reporter.secrets == frozenset({"user@example.com", "hunter2"})


def test_credentials_fernet(monkeypatch):
    key = Fernet.generate_key()
    token = _token(key, "hunter2")
    monkeypatch.setenv("MFP_USERNAME", EMAIL)
    monkeypatch.setenv("MFP_PASSWORD", token)
    monkeypatch.setattr(server, "get_secret_key", lambda: key.decode())
    cap = Capture()
    assert login.read_credentials(cap.reporter) == (EMAIL, "hunter2")
    assert {token, key.decode(), "hunter2", EMAIL} <= cap.reporter.secrets


def test_unset_password_on_a_tty_prompts_with_getpass(monkeypatch):
    monkeypatch.setenv("MFP_USERNAME", EMAIL)
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    secret_key = _Counter()
    monkeypatch.setattr(server, "get_secret_key", secret_key)
    prompts: list[str] = []

    def typed(value):
        def fake(prompt=""):
            prompts.append(prompt)
            return value

        return fake

    monkeypatch.setattr(login.getpass, "getpass", typed("typed"))
    assert login.read_credentials(Capture().reporter) == (EMAIL, "typed")
    monkeypatch.setattr(login.getpass, "getpass", typed("gAAAAAxyz"))
    assert login.read_credentials(Capture().reporter) == (EMAIL, "gAAAAAxyz")
    assert prompts == [login.PROMPT_PASSWORD, login.PROMPT_PASSWORD]
    assert secret_key.calls == 0


def test_unset_username_on_a_tty_prompts_with_input(monkeypatch):
    monkeypatch.setenv("MFP_PASSWORD", PASSWORD)
    monkeypatch.setattr(login, "_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "typed@example.com")
    monkeypatch.setattr(login.getpass, "getpass", _tripwire("getpass"))
    assert login.read_credentials(Capture().reporter) == ("typed@example.com", PASSWORD)


def test_unset_without_a_tty_exits_2_naming_the_variable(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage(), creds=False)
    monkeypatch.setenv("MFP_USERNAME", EMAIL)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 2
    lines = _lines(capsys)
    assert lines == [*FOUND, login.msg_credential_missing("MFP_PASSWORD")]
    assert "MFP_PASSWORD" in lines[-1]
    assert browser.started == 0


def test_ciphertext_without_a_key_exits_2_saying_no_key(tmp_path, monkeypatch, capsys):
    token = _token(Fernet.generate_key(), "hunter2")
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage(), password=token)
    monkeypatch.setattr(server, "get_secret_key", lambda: None)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 2
    lines = _lines(capsys)
    assert lines == [*FOUND, login.msg_credential_no_key("MFP_PASSWORD")]
    assert "no key" in lines[-1]
    assert token not in "\n".join(lines)
    assert browser.started == 0


def test_ciphertext_with_a_wrong_key_exits_2_saying_bad_token(tmp_path, monkeypatch, capsys):
    token = _token(Fernet.generate_key(), "hunter2")
    wrong = Fernet.generate_key().decode()
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage(), password=token)
    monkeypatch.setattr(server, "get_secret_key", lambda: wrong)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 2
    lines = _lines(capsys)
    assert lines == [*FOUND, login.msg_credential_bad_token("MFP_PASSWORD")]
    assert "failed to decrypt" in lines[-1] and "bad token" in lines[-1]
    out = "\n".join(lines)
    assert token not in out and wrong not in out
    assert "MFP_SECRET_KEY" not in os.environ
    assert browser.started == 0


def test_keychain_key_is_read_once_for_two_tokens(tmp_path, monkeypatch, capsys):
    key = Fernet.generate_key()
    user_token, pass_token = _token(key, EMAIL), _token(key, "hunter2")
    page = FakePage()
    _fake_main_browser(monkeypatch, tmp_path, page, creds=False)
    monkeypatch.setenv("MFP_USERNAME", user_token)
    monkeypatch.setenv("MFP_PASSWORD", pass_token)
    calls: list[tuple[str, str]] = []

    class CountingKeyring:
        def get_password(self, service, account):
            calls.append((service, account))
            return key.decode()

    monkeypatch.setattr(server, "keyring", CountingKeyring())
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert page.filled == {login.EMAIL_SEL: EMAIL, login.PASSWORD_SEL: "hunter2"}
    assert calls == [(server.KEYRING_SERVICE, server.KEYRING_SECRET_KEY_ACCOUNT)]
    assert "MFP_SECRET_KEY" not in os.environ
    out = "\n".join(_lines(capsys))
    for secret in (key.decode(), user_token, pass_token, "hunter2", EMAIL):
        assert secret not in out


def test_existing_secret_key_variable_is_left_as_it_was(tmp_path, monkeypatch):
    key = Fernet.generate_key().decode()
    page = FakePage()
    _fake_main_browser(monkeypatch, tmp_path, page, password=_token(key.encode(), "hunter2"))
    monkeypatch.setenv("MFP_SECRET_KEY", key)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert page.filled[login.PASSWORD_SEL] == "hunter2"
    assert os.environ["MFP_SECRET_KEY"] == key


def test_plain_credentials_never_touch_the_keychain(tmp_path, monkeypatch):
    page = FakePage()
    _fake_main_browser(monkeypatch, tmp_path, page, password="hunter2")
    secret_key = _Counter()
    keyring_calls = _Counter()
    monkeypatch.setattr(server, "get_secret_key", secret_key)
    monkeypatch.setattr(server, "keyring", types.SimpleNamespace(get_password=keyring_calls))
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert page.filled == {login.EMAIL_SEL: EMAIL, login.PASSWORD_SEL: "hunter2"}
    assert (secret_key.calls, keyring_calls.calls) == (0, 0)


# --- websockets check ---------------------------------------------------------


def _hide_websockets(monkeypatch) -> None:
    monkeypatch.setattr(login, "_has_websockets_sync", ORIG["_has_websockets_sync"])
    monkeypatch.setitem(sys.modules, "websockets", None)
    monkeypatch.setitem(sys.modules, "websockets.sync", None)


WS_HINT = 'pip install "websockets>=11"'


def test_missing_websockets_exits_2_before_any_browser(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    _hide_websockets(monkeypatch)
    assert login.main([], cookies_file=tmp_path / "c.json") == 2
    lines = _lines(capsys)
    assert lines == ["check: no cookie file", login.msg_no_websockets()]
    assert WS_HINT in lines[-1]
    assert browser.started == 0


def test_dry_run_without_websockets_exits_2_before_any_browser(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    _hide_websockets(monkeypatch)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 2
    assert _lines(capsys) == [login.msg_no_websockets()]
    assert browser.started == 0


def test_check_runs_without_websockets(tmp_path, monkeypatch, capsys):
    """Regression guard, kept on purpose: `--check` needs no extra."""
    _hide_websockets(monkeypatch)
    monkeypatch.setattr(login, "verify_session", _ok_verify)
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    assert login.main(["--check"], cookies_file=target) == 0
    assert _lines(capsys)[-1] == "check: session still valid"


def test_valid_session_without_websockets_exits_0(tmp_path, monkeypatch, capsys):
    """Regression guard, kept on purpose: the session check runs first."""
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    _hide_websockets(monkeypatch)
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    assert login.main([], cookies_file=target) == 0
    assert _lines(capsys)[-1] == "check: session still valid"
    assert browser.started == 0


def _fake_package(name: str, package: bool) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__spec__ = importlib.machinery.ModuleSpec(name, None, is_package=package)
    if package:
        module.__path__ = []
    return module


def test_websockets_check_needs_the_sync_client(monkeypatch):
    check = ORIG["_has_websockets_sync"]
    monkeypatch.setitem(sys.modules, "websockets", _fake_package("websockets", True))
    monkeypatch.delitem(sys.modules, "websockets.sync", raising=False)
    monkeypatch.delitem(sys.modules, "websockets.sync.client", raising=False)
    assert check() is False  # a 10.x install: no `sync` package
    monkeypatch.setitem(sys.modules, "websockets.sync", _fake_package("websockets.sync", True))
    monkeypatch.setitem(sys.modules, "websockets.sync.client",
                        _fake_package("websockets.sync.client", False))
    assert check() is True


# --- packaging ----------------------------------------------------------------

REPO = Path(__file__).resolve().parents[1]


def _requirement_name(requirement: str) -> str:
    return re.split(r"[\s<>=!~;\[(]", requirement, maxsplit=1)[0].lower()


def _load_toml(path: Path) -> dict:
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomli as tomllib
        except ImportError:
            pytest.skip("tomli is not installed, and Python 3.10 has no tomllib")
    with path.open("rb") as fh:
        return tomllib.load(fh)


def test_module_imports_with_websockets_hidden(monkeypatch):
    """The base install has no websockets, so `mfp_mcp.login` imports without it."""
    import mfp_mcp

    hidden = {"websockets", "websockets.sync", "websockets.sync.client"}
    hidden |= {name for name in sys.modules if name.startswith("websockets.")}
    for name in hidden:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.delitem(sys.modules, "mfp_mcp.login")
    monkeypatch.setattr(mfp_mcp, "login", login)
    fresh = importlib.import_module("mfp_mcp.login")
    assert fresh is not login
    assert callable(fresh.main)
    with pytest.raises(ImportError):
        importlib.import_module("websockets")


def test_pyproject_declares_the_command_and_the_login_extra():
    project = _load_toml(REPO / "pyproject.toml")["project"]
    assert project["scripts"]["mfp-mcp-login"] == "mfp_mcp.login:main"
    assert project["optional-dependencies"]["login"] == ["websockets>=11", "requests"]
    base = {_requirement_name(req) for req in project["dependencies"]}
    assert "websockets" not in base


def test_installed_entry_point_runs_login_main():
    """An install check: it reads the env's dist-info, written by `pip install -e .`."""
    scripts = importlib.metadata.entry_points(group="console_scripts")
    found = [(ep.name, ep.value) for ep in scripts if ep.name == "mfp-mcp-login"]
    assert found == [("mfp-mcp-login", "mfp_mcp.login:main")]


# --- signals ------------------------------------------------------------------


class SignalPage(FakePage):
    def __init__(self, sig: int) -> None:
        super().__init__()
        self.sig = sig

    def navigate(self, url: str) -> None:
        os.kill(os.getpid(), self.sig)


STOPS = [(signal.SIGINT, 130), (signal.SIGTERM, 143), (signal.SIGHUP, 129)]


@pytest.mark.parametrize("sig, code", STOPS, ids=["SIGINT", "SIGTERM", "SIGHUP"])
def test_signal_during_the_browser_step_returns_128_plus_signal(
    tmp_path, monkeypatch, capsys, sig, code
):
    kills: list = []
    monkeypatch.setattr(login, "_kill_leftovers", lambda *a, **k: kills.append(a))
    browser = _fake_main_browser(monkeypatch, tmp_path, SignalPage(sig))
    before = {s: signal.getsignal(s) for s, _ in STOPS}
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == code
    assert browser.cleaned == 1
    assert kills == []
    assert {s: signal.getsignal(s) for s, _ in STOPS} == before
    assert _lines(capsys)[-1] == login.msg_stopped(sig)


@pytest.mark.parametrize("sig, code", STOPS, ids=["SIGINT", "SIGTERM", "SIGHUP"])
def test_signal_during_run_check_never_kills_leftovers(tmp_path, monkeypatch, capsys, sig, code):
    kills: list = []
    monkeypatch.setattr(login, "_kill_leftovers", lambda *a, **k: kills.append(a))

    def verify(cookies, ua):
        os.kill(os.getpid(), sig)
        return True, "ok"

    monkeypatch.setattr(login, "verify_session", verify)
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    assert login.main([], cookies_file=target) == code
    assert kills == []
    assert _lines(capsys)[-1] == login.msg_stopped(sig)


class FakeProc:
    pid = 999_999
    returncode = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


def test_signal_inside_the_real_chrome_session_cleans_its_root(tmp_path, monkeypatch, capsys):
    """`chrome_session` itself, with every child faked: the stop unwinds its cleanup."""
    kills: list = []
    spawned: list[tuple[list[str], dict]] = []
    monkeypatch.setattr(login, "chrome_session", ORIG["chrome_session"])
    monkeypatch.setattr(login, "_kill_leftovers", lambda root, *a: kills.append(Path(root)))
    monkeypatch.setattr(login, "_spawn", lambda args, env, pass_fds=(): (
        spawned.append((args, env)) or FakeProc()))

    def port(self, timeout=30.0):
        os.kill(os.getpid(), signal.SIGTERM)
        return 0

    monkeypatch.setattr(login.ChromeProcess, "port", port)
    monkeypatch.setattr(login, "find_chrome", lambda platform, path, **kw: "/fake/chrome")
    monkeypatch.setattr(login, "find_xvfb", lambda platform, path, **kw: None)
    monkeypatch.setenv("MFP_USERNAME", EMAIL)
    monkeypatch.setenv("MFP_PASSWORD", PASSWORD)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 143
    assert len(kills) == 1
    root = kills[0]
    assert root.parent == tmp_path / "tmp" and root.name.startswith("mfp-login-")
    assert not root.exists()
    assert [args[0] for args, _ in spawned] == ["/fake/chrome"]
    assert sorted(k for k in spawned[0][1] if k.startswith("MFP_")) == []
    assert spawned[0][1]["HOME"] == str(root)
    assert _lines(capsys)[-1] == login.msg_stopped(signal.SIGTERM)


def _proc_entry(proc_dir: Path, pid: int | str, cmdline: bytes) -> None:
    entry = proc_dir / str(pid)
    entry.mkdir(parents=True)
    (entry / "cmdline").write_bytes(cmdline)


@pytest.mark.parametrize("needle", ["", ".", "/tmp", "/srv/x", "/srv/mfp-login-abc", "TEMPDIR",
                                    "TEMPDIR/other-abc", "TEMPDIR/mfp-login-abc/../x"])
def test_kill_leftovers_refuses_any_foreign_root(tmp_path, monkeypatch, needle):
    temp = tempfile.gettempdir()
    needle = needle.replace("TEMPDIR", temp)
    proc_dir = tmp_path / "proc"
    _proc_entry(proc_dir, 4242, b"chrome\0--user-data-dir=" + needle.encode() + b"/profile\0")
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(login.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    ORIG["_kill_leftovers"](needle, proc_dir=proc_dir)
    assert sent == []


def test_kill_leftovers_kills_only_the_process_naming_our_root(tmp_path, monkeypatch):
    root = Path(tempfile.gettempdir()) / "mfp-login-abc"
    proc_dir = tmp_path / "proc"
    _proc_entry(proc_dir, 4242, b"chrome\0--user-data-dir=" + str(root).encode() + b"/profile\0")
    _proc_entry(proc_dir, 5151, b"bash\0-c\0sleep 1\0")
    _proc_entry(proc_dir, os.getpid(), str(root).encode())
    _proc_entry(proc_dir, "self", str(root).encode())
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(login.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    ORIG["_kill_leftovers"](root, proc_dir=proc_dir)
    assert sent == [(4242, signal.SIGKILL)]


# --- platform, discovery order -------------------------------------------------


def test_no_chrome_exits_2_before_the_credential_check(tmp_path, monkeypatch, capsys):
    """No Chrome, no credentials, no TTY: the Chrome message, not the credential one."""
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage(), creds=False)
    monkeypatch.setattr(login, "find_chrome", ORIG["find_chrome"])
    monkeypatch.setattr("builtins.input", _tripwire("input"))
    monkeypatch.setattr(login.getpass, "getpass", _tripwire("getpass"))
    assert login.main([], cookies_file=tmp_path / "c.json") == 2
    lines = _lines(capsys)
    assert lines == ["check: no cookie file", login.msg_no_chrome("linux")]
    assert "https://www.google.com/chrome/" in lines[-1]
    assert browser.started == 0


def test_darwin_without_the_app_exits_2_naming_brew(tmp_path, monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    monkeypatch.setattr(login, "find_chrome", ORIG["find_chrome"])
    monkeypatch.setattr(login, "_platform", lambda: "darwin")
    assert not os.path.exists(login.MAC_CHROME)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 2
    lines = _lines(capsys)
    assert lines == [login.msg_macos_experimental(), login.msg_no_chrome("darwin")]
    assert "brew install --cask google-chrome" in lines[-1]
    assert browser.started == 0


def test_darwin_prints_the_experimental_line_once_and_passes_its_platform(tmp_path,
                                                                         monkeypatch, capsys):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    calls: list[str] = []
    seen: dict[str, str] = {}

    def platform():
        calls.append("darwin")
        return "darwin"

    def chrome(platform, path, **kw):
        seen["chrome"] = platform
        return "/fake/chrome"

    def xvfb(platform, path, **kw):
        seen["xvfb"] = platform
        return ORIG["find_xvfb"](platform, path, **kw)

    monkeypatch.setattr(login, "_platform", platform)
    monkeypatch.setattr(login, "find_chrome", chrome)
    monkeypatch.setattr(login, "find_xvfb", xvfb)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    out = _lines(capsys)
    assert out.count(login.msg_macos_experimental()) == 1
    assert out[0] == login.msg_macos_experimental()
    assert calls == ["darwin"]
    assert seen == {"chrome": "darwin", "xvfb": "darwin"}
    assert browser.platform == "darwin"
    assert browser.xvfb is None


def test_darwin_check_prints_the_experimental_line_first(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(login, "verify_session", _ok_verify)
    monkeypatch.setattr(login, "_platform", lambda: "darwin")
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    assert login.main(["--check"], cookies_file=target) == 0
    out = _lines(capsys)
    assert out[0] == login.msg_macos_experimental()
    assert out.count(login.msg_macos_experimental()) == 1
    assert out[-1] == "check: session still valid"


@pytest.mark.parametrize("argv", [[], ["--dry-run"], ["--check"], ["--install-xvfb"]])
def test_windows_exits_2_with_the_wsl2_line_before_anything(tmp_path, monkeypatch, capsys,
                                                            argv):
    browser = _fake_main_browser(monkeypatch, tmp_path, FakePage())
    monkeypatch.setattr(login, "_platform", lambda: "win32")
    monkeypatch.setitem(sys.modules, "fcntl", None)
    monkeypatch.setattr(login, "verify_session", _tripwire("verify_session"))
    target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
    assert login.main(argv, cookies_file=target) == 2
    lines = _lines(capsys)
    assert lines == [login.msg_windows()]
    assert "WSL2" in lines[0]
    assert browser.started == 0
    assert not (tmp_path / LOCK_NAME).exists()


def test_help_names_the_install_flag_and_the_sudo_install(tmp_path, monkeypatch):
    written: list[str] = []
    real = login.Reporter
    monkeypatch.setattr(login, "Reporter", lambda: real(write=written.append))
    assert login.main(["--help"], cookies_file=tmp_path / "c.json") == 0
    text = " ".join(" ".join(written).split())
    assert "--install-xvfb" in text
    assert "sudo apt-get install xvfb" in text


# --- main: catch-all, usage, logging, paths -----------------------------------


def test_unexpected_exception_prints_one_line_and_returns_5(tmp_path, monkeypatch, capsys):
    _fake_main_browser(monkeypatch, tmp_path, FakePage(), password="hunter2",
                       error=RuntimeError("hunter2"))
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 5
    out = capsys.readouterr()
    assert "hunter2" not in out.out + out.err
    assert "Traceback" not in out.out + out.err
    errors = [line for line in out.out.splitlines() if line.startswith("error")]
    assert errors == ["error: unexpected RuntimeError"]
    assert out.out.splitlines()[-1] == errors[0]


def test_unknown_flag_exits_2_through_the_reporter(tmp_path, monkeypatch, capsys):
    """The dev chose to route argparse output through the Reporter, not stderr."""
    written: list[str] = []
    real = login.Reporter
    monkeypatch.setattr(login, "Reporter", lambda: real(write=written.append))
    assert login.main(["--nope"], cookies_file=tmp_path / "c.json") == 2
    out = capsys.readouterr()
    assert (out.out, out.err) == ("", "")
    assert written[0].startswith("usage: mfp-mcp-login")
    assert written[-1] == "mfp-mcp-login: error: unrecognized arguments: --nope"
    written.clear()
    assert login.main(["--help"], cookies_file=tmp_path / "c.json") == 0
    assert written[0].startswith("usage: mfp-mcp-login")
    assert any("--dry-run" in line for line in written)


def test_logging_is_silent_during_main(tmp_path, monkeypatch):
    root_buf, mfp_buf = io.StringIO(), io.StringIO()
    root_handler, mfp_handler = logging.StreamHandler(root_buf), logging.StreamHandler(mfp_buf)
    root, mfp = logging.getLogger(), logging.getLogger("mfp_mcp")
    root.addHandler(root_handler)
    mfp.addHandler(mfp_handler)
    try:
        def verify(cookies, ua):
            logging.getLogger("mfp_mcp").error("x")
            logging.getLogger("some.library").warning("z")
            return True, "ok"

        monkeypatch.setattr(login, "verify_session", verify)
        target = _cookie_file(tmp_path / "c.json", NOW - timedelta(days=1))
        assert login.main(["--check"], cookies_file=target) == 0
        assert (root_buf.getvalue(), mfp_buf.getvalue()) == ("", "")
        logging.getLogger("mfp_mcp").error("y")
        assert (root_buf.getvalue(), mfp_buf.getvalue()) == ("y\n", "y\n")
    finally:
        root.removeHandler(root_handler)
        mfp.removeHandler(mfp_handler)


def test_dry_run_writes_only_the_expected_paths(tmp_path, monkeypatch):
    homes: list[str] = []

    class HomePage(FakePage):
        def navigate(self, url: str) -> None:
            homes.extend([os.environ["HOME"], str(Path.home())])

    _fake_main_browser(monkeypatch, tmp_path, HomePage())
    links = [Path(SAFE_BIN, name) for name in os.listdir(tmp_path / SAFE_BIN)]
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 0
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == sorted(
        [Path(LOG_NAME), Path(LOCK_NAME), Path(SAFE_BIN), Path("tmp"), *links]
    )
    assert homes == [str(tmp_path), str(tmp_path)]
    assert os.environ["HOME"] == str(tmp_path)


def test_login_writes_the_cookie_file_it_is_given(tmp_path, monkeypatch, capsys):
    _fake_main_browser(monkeypatch, tmp_path, FakePage())
    target = tmp_path / "given" / "cookies.json"
    assert login.main([], cookies_file=target) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["cookies"] == {
        SESSION: "v1", "cf_clearance": "v2"
    }
    assert not server.COOKIES_FILE.exists()
    assert _lines(capsys)[-1] == f"saved: 2 cookies to {target}"


# --- page excerpt -----------------------------------------------------------


def test_page_excerpt_rules():
    long_text = "Log in  \n here " + "x " * 400
    excerpt = login.page_excerpt(long_text, session_set=False, shows_form=True)
    assert excerpt.startswith("Log in here x")
    assert len(excerpt) == 300
    assert login.page_excerpt("Diary", session_set=True, shows_form=True) == ""
    assert login.page_excerpt("Diary", session_set=False, shows_form=False) == ""


def test_excerpt_cut_never_leaves_a_password_prefix(tmp_path, monkeypatch, capsys):
    password = "Zq9xLm4Kp"
    body = "a" * 297 + password + "b" * (1000 - 297 - len(password))
    assert len(body) == 1000 and body.index(password) == 297
    page = FakePage(session_after_submit=False, text=body)
    _fake_main_browser(monkeypatch, tmp_path, page, password=password)
    assert login.main(["--dry-run"], cookies_file=tmp_path / "c.json") == 5
    lines = _lines(capsys)
    excerpts = [line[len("page: "):] for line in lines if line.startswith("page: a")]
    assert len(excerpts) == 1
    assert excerpts[0] == "a" * 297 + "***"
    out = "\n".join(lines)
    for size in range(3, len(password) + 1):
        assert password[:size] not in out


def test_excerpt_redacts_before_squeezing_spaces(tmp_path, monkeypatch):
    password = "a  b9Zq"
    page = FakePage(session_after_submit=False, text=f"Log in Email Password {password} end")
    code, _browser, _log, cap = _run_login(monkeypatch, tmp_path, 0, page, password=password)
    assert code == 5
    assert "page: Log in Email Password *** end" in cap.lines
    for line in cap.lines:
        assert "a  b9Zq" not in line and "a b9Zq" not in line


# --- redaction of every message ---------------------------------------------


SECRET_BEARING = f"x {PASSWORD} y {COOKIE_VALUE} z {EMAIL}"

MESSAGE_CALLS = {
    "msg_credentials_ok": lambda f: f(),
    "msg_credential_missing": lambda f: f("MFP_PASSWORD"),
    "msg_credential_no_key": lambda f: f("MFP_PASSWORD"),
    "msg_credential_bad_token": lambda f: f("MFP_PASSWORD"),
    "msg_no_websockets": lambda f: f(),
    "msg_windows": lambda f: f(),
    "msg_macos_experimental": lambda f: f(),
    "msg_no_chrome": lambda f: f("linux"),
    "msg_chrome_snap": lambda f: f("/snap/bin/chromium"),
    "msg_chrome": lambda f: f("/usr/bin/google-chrome"),
    "msg_browser_started": lambda f: f("Xvfb :0"),
    "msg_xvfb": lambda f: f("/usr/bin/Xvfb"),
    "msg_no_xvfb": lambda f: f("sudo apt-get install xvfb", True),
    "msg_xvfb_cannot_install": lambda f: f("no terminal for apt", "sudo apt-get install xvfb"),
    "msg_xvfb_installing": lambda f: f("sudo apt-get install xvfb"),
    "msg_xvfb_install_failed": lambda f: f("sudo apt-get install xvfb", 100),
    "msg_xvfb_start_failed": lambda f: f(SECRET_BEARING),
    "msg_fill_failed": lambda f: f(),
    "msg_lock_held": lambda f: f(Path("/x") / LOCK_NAME),
    "msg_log_full": lambda f: f(Path("/x") / LOG_NAME, 3, UTC_NOW),
    "msg_log_unreadable": lambda f: f(Path("/x") / LOG_NAME, 3),
    "msg_attempt_logged": lambda f: f(3),
    "msg_form_found": lambda f: f(),
    "msg_form_missing": lambda f: f(30),
    "msg_consent": lambda f: f(),
    "msg_turnstile": lambda f: f(True),
    "msg_turnstile_cleared": lambda f: f(),
    "msg_turnstile_blocked": lambda f: f(30),
    "msg_submitted": lambda f: f(),
    "msg_session_set": lambda f: f(),
    "msg_challenge": lambda f: f(SECRET_BEARING),
    "msg_timeout": lambda f: f(60),
    "msg_page_text": lambda f: f(SECRET_BEARING),
    "msg_cookies": lambda f: f({SESSION: COOKIE_VALUE, "x": PASSWORD}),
    "msg_no_session": lambda f: f(),
    "msg_verify": lambda f: f("chrome-ua", False, SECRET_BEARING),
    "msg_dry_run": lambda f: f(2),
    "msg_saved": lambda f: f(2, Path("/x/cookies.json")),
    "msg_check_missing": lambda f: f(),
    "msg_check_unreadable": lambda f: f(),
    "msg_check_age": lambda f: f(29),
    "msg_check_ok": lambda f: f(),
    "msg_stopped": lambda f: f(signal.SIGTERM),
    "msg_unexpected": lambda f: f(RuntimeError(SECRET_BEARING)),
    "msg_error": lambda f: f(RuntimeError(SECRET_BEARING)),
}


def test_every_message_builder_is_covered():
    builders = {n for n, obj in inspect.getmembers(login, inspect.isfunction)
                if n.startswith("msg_")}
    assert builders == set(MESSAGE_CALLS)


@pytest.mark.parametrize("name", sorted(MESSAGE_CALLS))
def test_message_never_carries_a_secret(name):
    secrets = [PASSWORD, COOKIE_VALUE, EMAIL]
    raw = MESSAGE_CALLS[name](getattr(login, name))
    rendered = login.redact(raw, secrets)
    for s in secrets:
        assert s not in rendered


def test_cookie_message_lists_names_only_before_redaction():
    assert login.msg_cookies({SESSION: COOKIE_VALUE, "b": PASSWORD}) == (
        f"cookies: 2 kept: {SESSION}, b"
    )


def test_redact_handles_url_encoded_form():
    out = login.redact("pw=S3cret%21x", [PASSWORD])
    assert PASSWORD not in out and "S3cret%21x" not in out


def test_reporter_redacts_registered_secrets():
    cap = Capture()
    cap.reporter.add_secrets([PASSWORD, COOKIE_VALUE])
    cap.reporter.line(f"oops {PASSWORD} {COOKIE_VALUE}")
    assert cap.lines == ["oops *** ***"]


def _forms(secret: str) -> dict[str, str]:
    return {
        "raw": secret,
        "percent": quote(secret, safe=""),
        "plus": quote_plus(secret),
        "json": json.dumps(secret)[1:-1],
        "html": html.escape(secret),
    }


def test_ciphertext_and_key_never_print_in_any_form(monkeypatch):
    """Registered by `read_credentials`: the raw ciphertext and MFP_SECRET_KEY."""
    monkeypatch.setenv("MFP_USERNAME", EMAIL)
    monkeypatch.setenv("MFP_PASSWORD", "gAAAAAsecret")
    monkeypatch.setenv("MFP_SECRET_KEY", "k3y")
    cap = Capture()
    with pytest.raises(login.LoginError) as err:
        login.read_credentials(cap.reporter)
    assert err.value.code == 2
    assert err.value.message == login.msg_credential_bad_token("MFP_PASSWORD")
    for secret in ("gAAAAAsecret", "k3y"):
        for form in _forms(secret).values():
            cap.reporter.line(f"before {form} after")
    assert cap.lines == ["before *** after"] * 10


@pytest.mark.parametrize("form", ["raw", "percent", "plus", "json", "html"])
def test_reporter_redacts_each_encoded_form(form):
    cap = Capture()
    cap.reporter.add_secrets([SPECIAL])
    encoded = _forms(SPECIAL)[form]
    cap.reporter.line(f"before {encoded} after")
    assert cap.lines == ["before *** after"]


def test_error_truncation_never_leaves_a_secret_prefix():
    exc = RuntimeError("x" * 199 + "hunter2")
    assert login.msg_error(exc, {"hunter2"}) == "error: RuntimeError: " + "x" * 199 + "*"
    cap = Capture()
    cap.reporter.add_secrets(["hunter2"])
    cap.reporter.line(login.msg_error(exc, cap.reporter.secrets))
    assert cap.lines == ["error: RuntimeError: " + "x" * 199 + "*"]
