"""Scanner interface and registry.

A scanner is a strategy: one small function that observes one dimension of the
system and returns nodes and edges. Scanners are registered by name, run
concurrently, and are individually sandboxed by the compiler so a single
broken probe cannot take down the survey.
"""

from __future__ import annotations

import difflib
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import Config
from ..errors import ConfigError
from ..model import Edge, Node
from ..probe import ProbeLog


@dataclass(slots=True)
class ScanContext:
    """What a scanner may know about the run."""

    config: Config
    site: str
    platform: str = field(default_factory=lambda: sys.platform)
    probes: ProbeLog = field(default_factory=ProbeLog)

    @property
    def timeout(self) -> float:
        return self.config.scanner_timeout


@dataclass(slots=True)
class ScanResult:
    """What a scanner observed, plus how the observation went."""

    scanner: str
    layer: str
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    duration_ms: int = 0
    ok: bool = True
    error: str = ""

    @property
    def summary(self) -> str:
        if not self.ok:
            return f"{self.scanner}: failed ({self.error})"
        return (
            f"{self.scanner}: {len(self.nodes)} nodes, {len(self.edges)} edges "
            f"in {self.duration_ms}ms"
        )

    def warn(self, message: str) -> None:
        if message and message not in self.notes:
            self.notes.append(message)

    def to_observation(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "layer": self.layer,
            "ok": self.ok,
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "duration_ms": self.duration_ms,
            "notes": list(self.notes),
            "error": self.error,
        }


ScannerFn = Callable[[ScanContext], ScanResult]


@dataclass(slots=True)
class ScannerSpec:
    name: str
    layer: str
    description: str
    fn: ScannerFn
    #: The programs this scanner uses, per platform. Declared next to the
    #: scanner that wants them, so "why is my power layer empty?" has an
    #: answer. An empty list means the scanner reads the filesystem
    #: directly and needs no program at all.
    tools: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def tools_for(self, platform: str) -> tuple[str, ...]:
        """The programs this scanner uses on a given platform."""

        if platform in self.tools:
            return self.tools[platform]
        return self.tools.get("any", ())

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        try:
            result = self.fn(ctx)
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ScanResult(
                scanner=self.name,
                layer=self.layer,
                duration_ms=elapsed,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                notes=[f"scanner raised {type(exc).__name__}; survey continued"],
            )
        result.scanner = self.name
        result.layer = result.layer or self.layer
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result


_REGISTRY: dict[str, ScannerSpec] = {}
_BOOTSTRAPPED = False


def register(
    name: str,
    layer: str,
    description: str,
    tools: dict[str, tuple[str, ...]] | None = None,
) -> Callable[[ScannerFn], ScannerFn]:
    """Register a scanner under a stable CLI name."""

    def decorator(fn: ScannerFn) -> ScannerFn:
        key = name.strip().lower()
        if key in _REGISTRY:
            raise RuntimeError(f"scanner {key!r} is already registered")
        _REGISTRY[key] = ScannerSpec(
            name=key,
            layer=layer,
            description=description,
            fn=fn,
            tools=dict(tools or {}),
        )
        return fn

    return decorator


def registry() -> dict[str, ScannerSpec]:
    """Return the registered scanners, importing the built-ins exactly once.

    The bootstrap must not be guarded by ``if not _REGISTRY``: a test or plugin
    that imports a single scanner module first would otherwise hide the rest of
    the built-ins forever.
    """

    global _BOOTSTRAPPED  # noqa: PLW0603 - module state, set once
    if not _BOOTSTRAPPED:
        _BOOTSTRAPPED = True
        from . import host, network, power, services, workloads  # noqa: F401

    return dict(sorted(_REGISTRY.items()))


def resolve(names: tuple[str, ...] | list[str]) -> list[ScannerSpec]:
    known = registry()
    resolved: list[ScannerSpec] = []
    for name in names:
        key = name.strip().lower()
        if key not in known:
            hint = difflib.get_close_matches(key, list(known), n=1)
            raise ConfigError(
                f"unknown scanner {name!r}" + (f" (did you mean {hint[0]!r}?)" if hint else "")
                + f"; available: {', '.join(known)}"
            )
        resolved.append(known[key])
    return resolved
