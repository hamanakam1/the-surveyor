"""The daemon.

A daemon that dies on a bad cycle is a daemon that is not there when the
machine comes back. The one failure that *is* fatal is a ledger that cannot
be written to, because without a store there is nowhere to record anything.

The survey is stubbed throughout. A daemon test that surveyed the real
machine would be asserting that the machine did not change between two
cycles, which is a property of the machine and not of the daemon.
"""

from __future__ import annotations

import threading

import pytest

from surveyor.config import Config
from surveyor.daemon import run_daemon
from surveyor.model import Node, Topology


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


def _stubbed(monkeypatch, topologies: list[Topology]) -> None:
    """Make the daemon see the plats it is given, and nothing else."""

    import surveyor.daemon as daemon_module

    queue = list(topologies)

    def fake_survey(config, **kwargs):
        from surveyor.compiler import CompilationReport

        topology = queue.pop(0) if len(queue) > 1 else queue[0]
        return CompilationReport(topology=topology)

    monkeypatch.setattr(daemon_module, "survey", fake_survey)


def _plat(**facts) -> Topology:
    topology = Topology(site="edge", generated_at="2026-01-01T00:00:00Z")
    topology.add(Node("host:lab", "host", "lab", facts=facts))
    return topology


def test_one_cycle_records_a_survey(tmp_path, monkeypatch, capsys):
    _stubbed(monkeypatch, [_plat()])
    stats = run_daemon(Config(store=tmp_path / "ledger"), once=True)
    assert stats.cycles == 1
    assert stats.recorded == 1
    assert stats.unchanged == 0
    assert "nodes" in capsys.readouterr().out


def test_a_second_cycle_finds_nothing_changed(tmp_path, monkeypatch):
    _stubbed(monkeypatch, [_plat()])
    stop = _StopAfter(2)
    stats = run_daemon(
        Config(store=tmp_path / "ledger"), interval=1, stop=stop.event, emit=stop
    )
    assert stats.cycles == 2
    assert stats.recorded == 1
    assert stats.unchanged == 1


def test_a_changed_plat_is_recorded(tmp_path, monkeypatch):
    _stubbed(monkeypatch, [_plat(), _plat(extra="yes")])
    stop = _StopAfter(2)
    stats = run_daemon(
        Config(store=tmp_path / "ledger"), interval=1, stop=stop.event, emit=stop
    )
    assert stats.cycles == 2
    assert stats.recorded == 2
    # The first plat is structural too: everything in it is new.
    assert stats.structural_changes == 2


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


def test_json_lines_are_one_object_per_cycle(tmp_path, monkeypatch):
    import json

    _stubbed(monkeypatch, [_plat()])
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
