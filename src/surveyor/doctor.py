"""Self-diagnosis: why is my map empty?

The Surveyor is dropped onto boxes nobody has looked at. The first question
is always the same — *why did it not see my power supply, my containers, my
network?* — and the answer is always one of three things: the tool is not
installed, the tool is not on the allowlist, or the scanner was told to
skip it.

This module answers all three without running a survey.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .probe import ALLOWED_PROGRAMS, resolve
from .scanners.base import ScannerSpec, registry


@dataclass
class ToolStatus:
    """One program the Surveyor is allowed to run."""

    name: str
    path: str = ""
    available: bool = False

    @property
    def where(self) -> str:
        return self.path if self.available else "not installed"

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.name, "available": self.available, "path": self.path}


@dataclass
class ScannerStatus:
    """One scanner, and whether it has what it needs."""

    name: str
    layer: str
    description: str
    enabled: bool
    tools: list[ToolStatus] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        """Whether this scanner can work on this machine.

        A scanner that declares no tools for this platform reads the
        filesystem directly and is always ready. A scanner that declares
        tools is ready when it has at least one of them.
        """

        if not self.tools:
            return True
        return any(tool.available for tool in self.tools)

    @property
    def missing(self) -> list[str]:
        return [tool.name for tool in self.tools if not tool.available]

    @property
    def partial(self) -> bool:
        """Some of the scanner's tools are here and some are not."""

        return self.ready and bool(self.missing)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.name,
            "layer": self.layer,
            "description": self.description,
            "enabled": self.enabled,
            "ready": self.ready,
            "missing": self.missing,
            "tools": [tool.to_dict() for tool in self.tools],
        }


@dataclass
class Report:
    """Everything the doctor found."""

    platform: str
    python: str
    version: str
    store: str
    store_writable: bool
    config_path: str
    config_present: bool
    scanners: list[ScannerStatus] = field(default_factory=list)
    tools: list[ToolStatus] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        """The things that would make a survey see less than it should."""

        found: list[str] = []
        for scanner in self.scanners:
            if scanner.enabled and not scanner.ready:
                found.append(
                    f"{scanner.name}: needs one of "
                    f"{', '.join(tool.name for tool in scanner.tools)}"
                )
        if not self.store_writable:
            found.append(f"{self.store} is not writable; surveys cannot be recorded")
        return found

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "python": self.python,
            "version": self.version,
            "store": self.store,
            "store_writable": self.store_writable,
            "config": self.config_path,
            "config_present": self.config_present,
            "scanners": [scanner.to_dict() for scanner in self.scanners],
            "tools": [tool.to_dict() for tool in self.tools],
            "problems": self.problems,
        }


def _writable(path: Path) -> bool:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return os.access(probe, os.W_OK)


def examine(config: Config, *, config_path: str = "") -> Report:
    """Look at this machine and say what the Surveyor can and cannot see."""

    from . import OET_VERSION, __version__

    specs: dict[str, ScannerSpec] = registry()
    enabled = set(config.scanners)
    platform_key = platform.system().lower()

    tools: dict[str, ToolStatus] = {}
    for name in sorted(ALLOWED_PROGRAMS):
        path = resolve(name)
        tools[name] = ToolStatus(name=name, path=path or "", available=bool(path))

    scanners: list[ScannerStatus] = []
    for name, spec in specs.items():
        status = ScannerStatus(
            name=name,
            layer=spec.layer,
            description=spec.description,
            enabled=name in enabled,
            tools=[
                tools[tool] for tool in spec.tools_for(platform_key) if tool in tools
            ],
        )
        scanners.append(status)

    store = Path(config.store).expanduser()
    return Report(
        platform=f"{platform.system().lower()}/{platform.machine()}",
        python=platform.python_version(),
        version=f"{__version__} (OET {OET_VERSION})",
        store=str(store),
        store_writable=_writable(store),
        config_path=config_path,
        config_present=bool(config_path) and Path(config_path).exists(),
        scanners=scanners,
        tools=list(tools.values()),
    )


def render(report: Report) -> str:
    """The report, as text."""

    lines = [f"◈ the-surveyor {report.version}"]
    lines.append(f"  platform   {report.platform} · Python {report.python}")
    lines.append(f"  store      {report.store} ({'writable' if report.store_writable else 'NOT writable'})")
    if report.config_present:
        lines.append(f"  config     {report.config_path}")
    else:
        lines.append("  config     none found; using the defaults")
    lines.append("")

    for scanner in report.scanners:
        if not scanner.enabled:
            mark = " "
            state = "not enabled"
        elif scanner.ready:
            mark = "✓"
            state = "ready" if not scanner.missing else (
                f"ready (no {', '.join(scanner.missing)})"
            )
        else:
            mark = "!"
            state = "needs " + " or ".join(tool.name for tool in scanner.tools)
        lines.append(f"  {mark} {scanner.name:<10} {scanner.layer:<9} {state}")
        lines.append(f"      {scanner.description}")

    missing = [tool for tool in report.tools if not tool.available]
    lines.append("")
    if missing:
        lines.append(
            f"  {len(missing)} of {len(report.tools)} allowlisted tools are not installed here: "
            + ", ".join(tool.name for tool in missing)
        )
    else:
        lines.append(f"  all {len(report.tools)} allowlisted tools are installed here")

    for problem in report.problems:
        lines.append(f"  ! {problem}")
    return "\n".join(lines)


def interpreter() -> str:
    """The interpreter this is running under, for the curious."""

    return sys.executable
