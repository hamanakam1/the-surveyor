"""Invalid daemon limits must not start work or acquire resources."""

from __future__ import annotations

import threading
from unittest.mock import Mock

import pytest

from surveyor import cli, daemon
from surveyor.compiler import CompilationReport
from surveyor.config import Config
from surveyor.errors import ConfigError


def _guard_startup(monkeypatch):
    guarded = {
        "Ledger": Mock(),
        "InstanceLock": Mock(),
        "Notifier": Mock(),
        "_install_stop_handlers": Mock(return_value={}),
        "survey": Mock(side_effect=AssertionError("invalid limits must not survey")),
    }
    for name, guard in guarded.items():
        monkeypatch.setattr(daemon, name, guard)
    return guarded


@pytest.mark.parametrize("field", ["interval", "max_cycles"])
@pytest.mark.parametrize("value", [0, -1, True, False, 1.5, float("nan"), float("inf"), "1", [], {}])
def test_invalid_explicit_limits_fail_before_startup(tmp_path, monkeypatch, field, value):
    guarded = _guard_startup(monkeypatch)
    store = tmp_path / "ledger"

    with pytest.raises(ConfigError, match=field):
        daemon.run_daemon(Config(store=store), once=True, emit=lambda line: None, **{field: value})

    for guard in guarded.values():
        guard.assert_not_called()
    assert not store.exists()


@pytest.mark.parametrize("value", [None, 0, -1, True, False, 1.5, float("nan"), float("inf"), "1"])
def test_invalid_configured_cadence_fails_before_startup(tmp_path, monkeypatch, value):
    config = Config(store=tmp_path / "ledger")
    # A caller may mutate a Config after construction. Validate the effective
    # daemon boundary independently of configuration-file parsing.
    config.interval = value
    guarded = _guard_startup(monkeypatch)

    with pytest.raises(ConfigError, match="interval"):
        daemon.run_daemon(config, once=True, emit=lambda line: None)

    for guard in guarded.values():
        guard.assert_not_called()
    assert not config.store.exists()


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--interval", "0"), ("--interval", "-1"), ("--max-cycles", "0"), ("--max-cycles", "-1")],
)
def test_cli_rejects_zero_and_negative_limits_before_startup(tmp_path, monkeypatch, capsys, flag, value):
    config = Config(store=tmp_path / "ledger")
    monkeypatch.setattr(cli, "_config", lambda args: config)
    guarded = _guard_startup(monkeypatch)

    assert cli.main(["daemon", flag, value, "--once", "--json-lines"]) == cli.EXIT_ERROR
    assert "positive integer" in capsys.readouterr().err
    for guard in guarded.values():
        guard.assert_not_called()
    assert not config.store.exists()


@pytest.mark.parametrize("interval", [None, 1, 7])
def test_positive_cadence_and_cycle_limit_keep_their_behavior(tmp_path, monkeypatch, topology, interval):
    config = Config(store=tmp_path / "ledger", interval=3)
    survey = Mock(return_value=CompilationReport(topology=topology))
    monkeypatch.setattr(daemon, "survey", survey)
    monkeypatch.setattr(daemon, "_install_stop_handlers", lambda stop: {})
    clock = [0.0]
    monkeypatch.setattr(daemon.time, "monotonic", lambda: clock[0])
    stop = Mock(spec=threading.Event)
    stop.is_set.return_value = False

    def advance(seconds):
        clock[0] += seconds
        return False

    stop.wait.side_effect = advance
    stats = daemon.run_daemon(
        config, interval=interval, max_cycles=2, stop=stop, emit=lambda line: None
    )

    assert stats.cycles == 2
    assert survey.call_count == 2
    assert stats.recorded == 1
    assert stats.unchanged == 1
    assert clock[0] == (config.interval if interval is None else interval)


def test_none_cycle_limit_still_allows_once(tmp_path, monkeypatch, topology):
    survey = Mock(return_value=CompilationReport(topology=topology))
    monkeypatch.setattr(daemon, "survey", survey)
    monkeypatch.setattr(daemon, "_install_stop_handlers", lambda stop: {})

    stats = daemon.run_daemon(Config(store=tmp_path / "ledger"), once=True, max_cycles=None)

    assert stats.cycles == 1
    survey.assert_called_once()


def test_explicit_cadence_overrides_the_configured_value(tmp_path, monkeypatch, topology):
    config = Config(store=tmp_path / "ledger")
    config.interval = 0
    monkeypatch.setattr(daemon, "survey", Mock(return_value=CompilationReport(topology=topology)))
    monkeypatch.setattr(daemon, "_install_stop_handlers", lambda stop: {})

    assert daemon.run_daemon(config, interval=1, once=True).cycles == 1
