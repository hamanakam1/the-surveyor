"""The daemon.

A daemon that dies on a bad cycle is a daemon that is not there when the
machine comes back. The one failure that *is* fatal is a ledger that cannot
be written to, because without a store there is nowhere to record anything.
"""

from __future__ import annotations

import threading

import pytest

from surveyor.config import Config
from surveyor.daemon import run_daemon


class _StopAfter:
    """Stop the daemon after a given number of cycles, without sleeping."""

    def __init__(self, cycles: int) -> None:
        self.event = threading.Event()
        self.lines: list[str] = []
        self.cycles = cycles

    def __call__(self, line: str) -> None:
        self.lines.append(line)
        if len(self.lines) >= self.cycles:
            self.event.set()


def test_one_cycle_records_a_survey(tmp_path, capsys):
    stats = run_daemon(Config(store=tmp_path / "ledger"), once=True)
    assert stats.cycles == 1
    assert stats.recorded == 1
    assert stats.unchanged == 0
    assert "nodes" in capsys.readouterr().out


def test_a_second_cycle_finds_nothing_changed(tmp_path):
    stop = _StopAfter(2)
    stats = run_daemon(
        Config(store=tmp_path / "ledger"), interval=1, stop=stop.event, emit=stop
    )
    assert stats.cycles == 2
    assert stats.recorded == 1
    assert stats.unchanged == 1


def test_a_bad_cycle_does_not_kill_the_daemon(tmp_path, monkeypatch):
    """The whole point of running on a timer is to be there when it comes back."""

    import surveyor.daemon as daemon_module

    calls = {"n": 0}
    real_survey = daemon_module.survey

    def flaky(config, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("the scanner exploded")
        return real_survey(config, **kwargs)

    monkeypatch.setattr(daemon_module, "survey", flaky)
    stop = _StopAfter(2)
    stats = run_daemon(
        Config(store=tmp_path / "ledger"), interval=1, stop=stop.event, emit=stop
    )

    assert stats.cycles == 2
    assert stats.failures == 1
    assert stats.recorded == 1, "the daemon must recover and carry on"
    assert any("cycle failed" in line for line in stop.lines)


def test_an_unwritable_ledger_is_fatal(tmp_path, monkeypatch):
    """Without a store there is nowhere to record the survey."""

    import surveyor.daemon as daemon_module
    from surveyor.errors import StoreError

    def explode(config, **kwargs):
        raise StoreError("the ledger is on fire")

    monkeypatch.setattr(daemon_module, "survey", explode)
    with pytest.raises(StoreError):
        run_daemon(Config(store=tmp_path / "ledger"), once=True)


def test_json_lines_are_one_object_per_cycle(tmp_path):
    import json

    stop = _StopAfter(2)
    run_daemon(
        Config(store=tmp_path / "ledger"),
        interval=1,
        stop=stop.event,
        emit=stop,
        json_lines=True,
    )
    assert len(stop.lines) == 2
    for line in stop.lines:
        assert json.loads(line)["cycle"] >= 1
