"""Layered configuration: defaults < file < environment < CLI flags.

The Surveyor is meant to be dropped onto an unfamiliar box and run without a
config file, so every field has a safe default. Configuration exists to narrow
the survey, not to make it possible.
"""

from __future__ import annotations

import difflib
import json
import os
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Mapping

from .errors import ConfigError
from .notify import FORMATS, THRESHOLDS, mask_url
from .util import boolish

#: Scanners enabled on a bare ``surveyor scan``.
DEFAULT_SCANNERS: tuple[str, ...] = ("power", "host", "network", "workloads")

CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "site",
        "store",
        "scanners",
        "scanner_timeout",
        "redact",
        "include_virtual_interfaces",
        "include_loopback",
        "include_local_services",
        "max_workloads",
        "ollama_endpoint",
        "ollama_model",
        "scribe",
        "llm_timeout",
        "interval",
        "log_level",
        "notify",
        "notify_on",
        "notify_timeout",
        "notify_format",
    }
)

SCRIBE_BACKENDS: tuple[str, ...] = ("template", "ollama")
LOG_LEVELS: tuple[str, ...] = ("quiet", "info", "debug")


def surveyor_home() -> Path:
    override = os.environ.get("SURVEYOR_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".surveyor"


def default_store() -> Path:
    return surveyor_home() / "ledger"


def default_config_path() -> Path:
    return surveyor_home() / "config.toml"


@dataclass(slots=True)
class Config:
    """Everything a survey needs to know before it starts looking."""

    site: str = "edge"
    store: Path = field(default_factory=default_store)
    scanners: tuple[str, ...] = DEFAULT_SCANNERS
    scanner_timeout: float = 12.0
    redact: bool = False
    include_virtual_interfaces: bool = False
    include_loopback: bool = False
    include_local_services: bool = False
    max_workloads: int = 200
    ollama_endpoint: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"
    scribe: str = "template"
    llm_timeout: float = 30.0
    interval: int = 300
    log_level: str = "info"
    notify: tuple[str, ...] = ()
    notify_on: str = "warning"
    notify_timeout: float = 10.0
    notify_format: str = "text"

    def __post_init__(self) -> None:
        self.store = Path(self.store).expanduser()
        self.scanners = tuple(dict.fromkeys(name.strip().lower() for name in self.scanners if name.strip()))
        if not self.scanners:
            raise ConfigError("at least one scanner must be enabled")
        if self.scribe not in SCRIBE_BACKENDS:
            raise ConfigError(
                f"scribe backend must be one of {', '.join(SCRIBE_BACKENDS)}; got {self.scribe!r}"
            )
        if self.log_level not in LOG_LEVELS:
            raise ConfigError(
                f"log_level must be one of {', '.join(LOG_LEVELS)}; got {self.log_level!r}"
            )
        if self.interval < 1:
            raise ConfigError("interval must be at least 1 second")
        if self.scanner_timeout <= 0 or self.llm_timeout <= 0:
            raise ConfigError("timeouts must be positive")
        if self.max_workloads < 1:
            raise ConfigError("max_workloads must be at least 1")
        if not self.site.strip():
            raise ConfigError("site must not be blank")
        if self.notify_on not in THRESHOLDS:
            raise ConfigError(
                f"notify_on must be one of {', '.join(THRESHOLDS)}; got {self.notify_on!r}"
            )
        if self.notify_format not in FORMATS:
            raise ConfigError(
                f"notify_format must be one of {', '.join(FORMATS)}; got {self.notify_format!r}"
            )
        if self.notify_timeout <= 0:
            raise ConfigError("notify_timeout must be positive")
        for endpoint in self.notify:
            if not endpoint.lower().startswith(("http://", "https://")):
                raise ConfigError(
                    f"notify endpoint must be an http(s) URL: {mask_url(endpoint)}"
                )

    # -- loading ----------------------------------------------------------
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Config:
        if not isinstance(data, Mapping):
            raise ConfigError("configuration must be a mapping of keys to values")
        unknown = set(data) - CONFIG_KEYS
        if unknown:
            known = sorted(CONFIG_KEYS)
            hints = []
            for key in sorted(unknown):
                match = difflib.get_close_matches(key, known, n=1)
                hints.append(f"{key!r}" + (f" (did you mean {match[0]!r}?)" if match else ""))
            raise ConfigError(
                "unknown configuration key(s): " + ", ".join(hints) + f". Known keys: {', '.join(known)}"
            )

        values: dict[str, Any] = {}
        for key, value in data.items():
            if key == "scanners":
                if isinstance(value, str):
                    values[key] = tuple(part.strip() for part in value.split(",") if part.strip())
                elif isinstance(value, (list, tuple)):
                    values[key] = tuple(str(part) for part in value)
                else:
                    raise ConfigError("scanners must be a list of scanner names")
            elif key == "store":
                values[key] = Path(str(value)).expanduser()
            elif key == "redact":
                if isinstance(value, bool):
                    values[key] = value
                elif isinstance(value, str) and boolish(value) is not None:
                    values[key] = bool(boolish(value))
                else:
                    raise ConfigError("redact must be true or false")
            elif key in {
                "include_virtual_interfaces",
                "include_loopback",
                "include_local_services",
            }:
                if isinstance(value, bool):
                    values[key] = value
                elif isinstance(value, str) and boolish(value) is not None:
                    values[key] = bool(boolish(value))
                else:
                    raise ConfigError(f"{key} must be true or false")
            elif key in {"scanner_timeout", "llm_timeout"}:
                values[key] = float(value)
            elif key in {"max_workloads", "interval"}:
                values[key] = int(value)
            elif key == "notify":
                if isinstance(value, str):
                    values[key] = tuple(part.strip() for part in value.split(",") if part.strip())
                elif isinstance(value, (list, tuple)):
                    values[key] = tuple(str(part).strip() for part in value if str(part).strip())
                else:
                    raise ConfigError("notify must be a list of webhook URLs")
            elif key == "notify_on":
                values[key] = str(value).strip().lower()
            elif key == "notify_format":
                values[key] = str(value).strip().lower()
            elif key == "notify_timeout":
                values[key] = float(value)
            elif key in {"site", "ollama_endpoint", "ollama_model", "scribe", "log_level"}:
                values[key] = str(value).strip()
            else:  # pragma: no cover - guarded by CONFIG_KEYS
                values[key] = value

        return cls(**values)

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load configuration from disk, applying environment overrides.

        With no explicit path, ``$SURVEYOR_HOME/config.toml`` is used when it
        exists; otherwise defaults are returned.
        """

        target = Path(path).expanduser() if path else default_config_path()
        if path is None and not target.exists():
            return cls().with_env()

        if not target.exists():
            raise ConfigError(f"configuration file not found: {target}")

        raw = _read_config_file(target)
        return cls.from_mapping(raw).with_env()

    def with_env(self) -> Config:
        updates: dict[str, Any] = {}
        mapping = {
            "SURVEYOR_SITE": ("site", str),
            "SURVEYOR_STORE": ("store", Path),
            "SURVEYOR_SCANNERS": ("scanners", lambda value: tuple(
                part.strip() for part in str(value).split(",") if part.strip()
            )),
            "SURVEYOR_INTERVAL": ("interval", int),
            "SURVEYOR_SCANNER_TIMEOUT": ("scanner_timeout", float),
            "SURVEYOR_SCRIBE": ("scribe", str),
            "SURVEYOR_OLLAMA_ENDPOINT": ("ollama_endpoint", str),
            "SURVEYOR_OLLAMA_MODEL": ("ollama_model", str),
            "SURVEYOR_LOG_LEVEL": ("log_level", str),
            "SURVEYOR_NOTIFY_ON": ("notify_on", str),
            "SURVEYOR_NOTIFY_FORMAT": ("notify_format", str),
            "SURVEYOR_NOTIFY_TIMEOUT": ("notify_timeout", float),
        }
        for env_key, (attr, caster) in mapping.items():
            if env_key in os.environ and os.environ[env_key] != "":
                try:
                    updates[attr] = caster(os.environ[env_key])
                except ValueError as exc:
                    raise ConfigError(f"{env_key} is invalid: {exc}") from exc
        if os.environ.get("SURVEYOR_NOTIFY"):
            updates["notify"] = tuple(
                part.strip()
                for part in os.environ["SURVEYOR_NOTIFY"].split(",")
                if part.strip()
            )
        for env_key, attr in (
            ("SURVEYOR_REDACT", "redact"),
            ("SURVEYOR_INCLUDE_LOCAL_SERVICES", "include_local_services"),
        ):
            if env_key not in os.environ:
                continue
            parsed = boolish(os.environ[env_key])
            if parsed is None:
                raise ConfigError(f"{env_key} must be true or false")
            updates[attr] = parsed
        if not updates:
            return self
        return replace(self, **updates)

    def with_overrides(self, **overrides: Any) -> Config:
        clean = {key: value for key, value in overrides.items() if value is not None}
        return replace(self, **clean) if clean else self

    # -- emitting ---------------------------------------------------------
    def to_mapping(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for item in fields(self):
            value = getattr(self, item.name)
            data[item.name] = str(value) if isinstance(value, Path) else (
                list(value) if isinstance(value, tuple) else value
            )
        return data

    def to_toml(self) -> str:
        """Minimal TOML writer so ``surveyor init`` needs no dependency."""

        lines = [
            "# The Surveyor configuration",
            "# Every key here is optional; delete anything you do not need.",
            "",
        ]
        for key, value in self.to_mapping().items():
            if isinstance(value, bool):
                lines.append(f"{key} = {'true' if value else 'false'}")
            elif isinstance(value, (int, float)):
                lines.append(f"{key} = {value}")
            elif isinstance(value, list):
                rendered = ", ".join(json.dumps(str(item)) for item in value)
                lines.append(f"{key} = [{rendered}]")
            else:
                lines.append(f"{key} = {json.dumps(str(value))}")
        lines.append("")
        return "\n".join(lines)

    def describe(self) -> str:
        return (
            f"site={self.site} store={self.store} scanners={','.join(self.scanners)} "
            f"scribe={self.scribe} redact={str(self.redact).lower()}"
        )


def _read_config_file(path: Path) -> Mapping[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    if suffix in {".toml", ""}:
        try:
            import tomllib

            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ConfigError(
                f"{path} is YAML; install the optional extra (pip install 'the-surveyor[yaml]') "
                "or use TOML/JSON"
            ) from exc
        try:
            loaded = yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001 - third-party parser surface
            raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
        if loaded is None:
            return {}
        if not isinstance(loaded, Mapping):
            raise ConfigError(f"{path}: YAML root must be a mapping")
        return loaded
    raise ConfigError(
        f"unsupported configuration format {suffix!r}; use .toml (recommended), .json, or .yaml"
    )
