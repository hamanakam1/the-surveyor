"""Integer resource limits must not silently coerce booleans or fractions."""

from __future__ import annotations

import pytest

from surveyor.config import Config
from surveyor.errors import ConfigError


@pytest.mark.parametrize("field", ["interval", "max_workloads"])
@pytest.mark.parametrize("value", [True, False, 1.0, 1.9, float("inf"), None])
def test_mapping_limits_reject_noninteger_values(field, value):
    with pytest.raises(ConfigError, match=rf"{field} must be an integer"):
        Config.from_mapping({field: value})


@pytest.mark.parametrize("field", ["interval", "max_workloads"])
@pytest.mark.parametrize("value", [True, 1.0, 1.9, "2", None])
def test_direct_config_limits_require_integers(field, value):
    with pytest.raises(ConfigError, match=rf"{field} must be an integer"):
        Config(**{field: value})


@pytest.mark.parametrize("field", ["interval", "max_workloads"])
@pytest.mark.parametrize("value", [1, 12, "1", " 12 ", "+12", "012"])
def test_positive_integer_mapping_limits_stay_supported(field, value):
    config = Config.from_mapping({field: value})
    assert getattr(config, field) == int(value)
    assert type(getattr(config, field)) is int


@pytest.mark.parametrize("field", ["interval", "max_workloads"])
@pytest.mark.parametrize("value", ["true", "1.9"])
def test_toml_numeric_limits_fail_before_a_store_is_created(tmp_path, monkeypatch, field, value):
    monkeypatch.setenv("SURVEYOR_HOME", str(tmp_path / "home"))
    for name in ("SURVEYOR_INTERVAL", "SURVEYOR_MAX_WORKLOADS"):
        monkeypatch.delenv(name, raising=False)
    store = tmp_path / "ledger"
    path = tmp_path / "config.toml"
    path.write_text(f'store = "{store}"\n{field} = {value}\n')
    with pytest.raises(ConfigError, match=rf"{field} must be an integer"):
        Config.load(path)
    assert not store.exists()
