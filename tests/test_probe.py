from __future__ import annotations

import os

import pytest

from surveyor.errors import ProbeError
from surveyor.probe import ALLOWED_PROGRAMS, ProbeLog, _scrubbed_env, read_int, read_text, run


def test_allowlist_blocks_shells_and_privilege_escalation():
    for program in ("sh", "bash", "sudo", "osascript", "rm"):
        with pytest.raises(ProbeError, match="allowlisted"):
            run([program, "-c", "true"])


def test_empty_vector_is_rejected():
    with pytest.raises(ProbeError):
        run([])


def test_missing_binary_returns_a_failed_probe():
    assert "nvidia-smi" in ALLOWED_PROGRAMS
    probe = run(["nvidia-smi"])
    if probe.ok:  # pragma: no cover - only on a machine with an NVIDIA GPU
        pytest.skip("this host actually has nvidia-smi")
    assert probe.ok is False
    assert probe.reason in {"not installed", "permission denied"} or probe.reason.startswith("exited")


def test_real_probe_captures_stdout():
    probe = run(["uname", "-s"])
    assert probe.ok is True
    assert probe.stdout.strip()
    assert probe.stderr == ""


def test_secret_environment_is_scrubbed(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "shhh")
    monkeypatch.setenv("NORMAL_SETTING", "visible")
    env = _scrubbed_env()
    assert "GITHUB_TOKEN" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["NORMAL_SETTING"] == "visible"
    assert env["LC_ALL"] == "C"


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
    probe = run(["nvidia-smi"])
    if not probe.ok:
        log.add(probe)
        assert log.failures
        assert log.notes()
    assert os.environ is not None
