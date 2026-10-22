from __future__ import annotations

import tomllib

import pytest

from surveyor.config import Config, default_store
from surveyor.errors import ConfigError


def test_defaults_are_run_ready():
    config = Config()
    assert config.scanners == ("power", "host", "network", "workloads", "services")
    assert config.scribe == "template"
    assert config.redact is False
    assert config.store == default_store()
    assert config.max_workloads >= 1


def test_from_mapping_accepts_scanner_strings():
    config = Config.from_mapping({"scanners": "host, power", "site": "attic"})
    assert config.scanners == ("host", "power")
    assert config.site == "attic"


def test_unknown_keys_are_rejected_with_a_hint():
    with pytest.raises(ConfigError) as excinfo:
        Config.from_mapping({"scannner": ["host"]})
    message = str(excinfo.value)
    assert "unknown configuration key" in message
    assert "did you mean 'scanners'" in message


def test_invalid_scribe_backend_is_rejected():
    with pytest.raises(ConfigError, match="scribe backend"):
        Config(scribe="gpt-in-the-cloud")


def test_interval_must_be_positive():
    with pytest.raises(ConfigError, match="interval"):
        Config(interval=0)


def test_scanners_cannot_be_empty():
    with pytest.raises(ConfigError, match="at least one scanner"):
        Config(scanners=())


def test_load_toml_round_trip(tmp_path):
    original = Config(site="boat", scanners=("host",), interval=45, redact=True)
    path = tmp_path / "surveyor.toml"
    path.write_text(original.to_toml())
    tomllib.loads(path.read_text())  # the emitted file must be valid TOML
    loaded = Config.load(path)
    assert loaded.site == "boat"
    assert loaded.scanners == ("host",)
    assert loaded.interval == 45
    assert loaded.redact is True


def test_load_json(tmp_path):
    path = tmp_path / "surveyor.json"
    path.write_text('{"site": "json-site", "include_local_services": true}')
    loaded = Config.load(path)
    assert loaded.site == "json-site"
    assert loaded.include_local_services is True


def test_unknown_extension_is_rejected(tmp_path):
    path = tmp_path / "surveyor.ini"
    path.write_text("site=oops")
    with pytest.raises(ConfigError, match="unsupported configuration format"):
        Config.load(path)


def test_missing_explicit_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        Config.load(tmp_path / "nope.toml")


def test_environment_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("SURVEYOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SURVEYOR_SITE", "env-site")
    monkeypatch.setenv("SURVEYOR_SCANNERS", "host,network")
    monkeypatch.setenv("SURVEYOR_REDACT", "true")
    config = Config.load()
    assert config.site == "env-site"
    assert config.scanners == ("host", "network")
    assert config.redact is True
    assert config.store == tmp_path / "home" / "ledger"


def test_bad_environment_boolean(monkeypatch):
    monkeypatch.setenv("SURVEYOR_REDACT", "maybe")
    with pytest.raises(ConfigError, match="SURVEYOR_REDACT"):
        Config.load()


def test_overrides_only_apply_when_set():
    config = Config(site="a")
    assert config.with_overrides(site=None, store=None).site == "a"
    assert config.with_overrides(site="b").site == "b"


def test_describe_is_single_line():
    description = Config().describe()
    assert "\n" not in description
    assert "scanners=" in description
