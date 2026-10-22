from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from surveyor.errors import ProbeError
from surveyor.probe import (
    ALLOWED_PROGRAMS,
    ProbeLog,
    _scrubbed_env,
    read_int,
    read_text,
    resolve,
    run,
)

ROOT = Path(__file__).resolve().parents[1]


def test_allowlist_blocks_shells_and_privilege_escalation():
    for program in ("sh", "bash", "sudo", "osascript", "rm"):
        with pytest.raises(ProbeError, match="allowlisted"):
            run([program, "-c", "true"])


def test_empty_vector_is_rejected():
    with pytest.raises(ProbeError):
        run([])


def test_every_allowlisted_program_has_a_caller():
    """Least privilege: the allowlist grows when a scanner needs it.

    A program nobody calls is an attack surface with no upside, so the
    allowlist is checked against the scanners that use it.
    """

    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "src" / "surveyor" / "scanners").glob("*.py")
    )
    unused = sorted(program for program in ALLOWED_PROGRAMS if f'"{program}"' not in sources)
    assert not unused, f"allowlisted but never used by a scanner: {unused}"


def test_a_program_that_is_not_installed_returns_a_failed_probe(monkeypatch):
    monkeypatch.setattr("surveyor.probe.resolve", lambda program: None)
    probe = run(["sysctl", "-n", "surveyor.nope"])
    assert probe.ok is False
    assert probe.reason == "not installed"


def test_a_failing_command_returns_a_failed_probe():
    probe = run(["sysctl", "-n", "surveyor.definitely.not.a.key"])
    assert probe.ok is False
    assert probe.reason.startswith("exited")


def test_real_probe_captures_stdout():
    probe = run(["uname", "-s"])
    assert probe.ok is True
    assert probe.stdout.strip()
    assert probe.stderr == ""


def test_a_probe_runs_an_absolute_path():
    """The name in the allowlist is not what gets executed."""

    probe = run(["uname", "-s"])
    assert probe.ok is True
    assert probe.resolved.startswith("/")
    assert os.path.isabs(probe.resolved)


def test_resolution_does_not_trust_a_world_writable_directory(tmp_path, monkeypatch):
    """A name earlier in PATH must not be able to shadow an allowlisted tool."""

    fake = tmp_path / "uname"
    fake.write_text("#!/bin/sh\necho pwned\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    # The curated search path is tried first, so the real tool still wins.
    resolved = resolve("uname")
    assert resolved is not None
    assert not str(resolved).startswith(str(tmp_path))
    probe = run(["uname", "-s"])
    assert "pwned" not in probe.stdout


def test_secret_environment_is_scrubbed(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "shhh")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    monkeypatch.setenv("NORMAL_SETTING", "visible")
    env = _scrubbed_env()
    assert "GITHUB_TOKEN" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "SSH_AUTH_SOCK" not in env
    assert env["NORMAL_SETTING"] == "visible"
    assert env["LC_ALL"] == "C"


def test_a_timed_out_probe_kills_the_whole_process_group(tmp_path, monkeypatch):
    """A probe that overruns is killed, and so is everything it spawned."""

    import surveyor.probe as probe_module

    if probe_module.resolve("python3") is None:  # pragma: no cover - host without python3
        pytest.skip("python3 is not on this host")

    monkeypatch.setattr(probe_module, "ALLOWED_PROGRAMS", frozenset({"python3"}))
    pidfile = tmp_path / "pid"
    script = (
        "import subprocess, sys, time; "
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        f"open({str(pidfile)!r}, 'w').write(str(p.pid)); "
        "time.sleep(30)"
    )
    probe = probe_module.run(["python3", "-c", script], timeout=2.0)
    assert probe.ok is False
    assert "timed out" in probe.reason

    pid = int(pidfile.read_text())
    for _ in range(40):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    pytest.fail("the probe's grandchild survived the timeout")


def test_read_text_handles_missing_files(tmp_path):
    assert read_text(tmp_path / "nope") is None
    path = tmp_path / "value"
    path.write_text("42\n")
    assert read_int(path) == 42
    assert read_int(tmp_path / "missing") is None


def test_read_text_respects_limit(tmp_path):
    path = tmp_path / "long"
    path.write_text("x" * 100)
    assert len(read_text(path, limit=10)) == 10


def test_probe_log_collects_notes_only_for_failures():
    log = ProbeLog()
    log.add(run(["uname", "-s"]))
    assert log.notes() == []
    with pytest.raises(ProbeError):
        run(["sh"])


def test_probe_log_notes_only_failures():
    log = ProbeLog()
    log.add(run(["uname", "-s"]))
    probe = run(["sysctl", "-n", "surveyor.definitely.not.a.key"])
    if not probe.ok:
        log.add(probe)
        assert log.failures
        assert log.notes()
    assert subprocess is not None
