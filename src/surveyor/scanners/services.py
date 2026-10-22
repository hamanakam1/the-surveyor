"""Scheduled services: the things the machine runs on a timer.

A container is visible because something is running it. A systemd unit is
the same kind of fact wearing different clothes: the machine runs it, it
has a name, it has a state, and when it stops, the map changed.

The identity convention follows the OET rule -- ``workload:<runtime>:<name>``
-- so a unit is ``workload:systemd:nginx.service`` and a launchd agent is
``workload:launchd:com.apple.example``.

Only units that *exist* are recorded. A unit that is masked, or that the
package manager has left behind as ``not-found``, is not on this machine
and pretending otherwise would fill the map with ghosts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..identity import host_id as local_host_id
from ..model import KIND_WORKLOAD, LAYER_WORKLOAD, REL_RUNS, Edge, Node
from ..probe import ProbeLog, run
from .base import ScanContext, ScanResult, register

#: ``systemctl list-units --all --no-legend``:
#: "  nginx.service loaded active running A high performance web server"
_SYSTEMD_UNIT = re.compile(
    r"^(?P<unit>\S+)\s+(?P<load>\S+)\s+(?P<active>\S+)\s+(?P<sub>\S+)\s*(?P<description>.*)$"
)

#: A line inside the ``services = {`` block of ``launchctl print system``:
#: "               0      - \tcom.apple.backgroundassets.managed.relay.service"
_LAUNCHD_SERVICE = re.compile(r"^\s*(?P<pid>-|\d+)\s+(?P<status>\S+)\s+(?P<label>\S+)\s*$")


@dataclass(slots=True)
class Unit:
    """One scheduled service."""

    name: str
    runtime: str
    description: str = ""
    active: str = ""
    sub: str = ""
    load: str = ""

    @property
    def exists(self) -> bool:
        """Whether this unit is really on the machine.

        ``not-found`` means the package left a stub behind; ``masked``
        means somebody deliberately disabled it. Neither is a service the
        machine runs.
        """

        return self.load not in {"not-found", "masked", "bad"}

    @property
    def id(self) -> str:
        return f"workload:{self.runtime}:{self.name}"

    def to_facts(self) -> dict[str, object]:
        facts: dict[str, object] = {"runtime": self.runtime, "unit": self.name}
        if self.description:
            facts["description"] = self.description
        return facts

    def to_telemetry(self) -> dict[str, object]:
        telemetry: dict[str, object] = {}
        if self.active:
            telemetry["active_state"] = self.active
        if self.sub:
            telemetry["sub_state"] = self.sub
        return telemetry


def parse_systemd_units(text: str) -> list[Unit]:
    """Parse ``systemctl list-units`` output."""

    units: list[Unit] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        match = _SYSTEMD_UNIT.match(raw.strip())
        if not match:
            continue
        units.append(
            Unit(
                name=match.group("unit"),
                runtime="systemd",
                description=match.group("description").strip(),
                active=match.group("active"),
                sub=match.group("sub"),
                load=match.group("load"),
            )
        )
    return units


def parse_launchd_services(text: str) -> list[Unit]:
    """Parse the ``services`` block of ``launchctl print system``.

    The *system* domain, not the user session. A user session lists an
    agent for every application the operator happens to have open, and
    those come and go with what they are doing: they are weather, and
    recording them would make the workload layer churn on every scan.
    The system domain holds the machine's own daemons, which do not.
    """

    units: list[Unit] = []
    inside = False
    for raw in text.splitlines():
        if not inside:
            if raw.startswith("\tservices = {"):
                inside = True
            continue
        if raw.startswith("\t}"):
            break
        match = _LAUNCHD_SERVICE.match(raw)
        if not match:
            continue
        units.append(
            Unit(
                name=match.group("label"),
                runtime="launchd",
                load="loaded",
            )
        )
    return units


@register(
    "services",
    LAYER_WORKLOAD,
    "Scheduled services: systemd units and launchd daemons",
)
def scan_services(ctx: ScanContext) -> ScanResult:
    result = ScanResult(scanner="services", layer=LAYER_WORKLOAD)
    log = ProbeLog()
    host = local_host_id()

    units: list[Unit] = []
    if ctx.platform == "darwin":
        probe = log.add(run(["launchctl", "print", "system"], timeout=ctx.timeout))
        if probe.ok:
            units = parse_launchd_services(probe.stdout)
        else:
            result.warn(f"launchctl print system unavailable: {probe.reason}")
    elif ctx.platform.startswith("linux"):
        probe = log.add(
            run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--no-legend",
                    "--no-pager",
                ],
                timeout=ctx.timeout,
            )
        )
        if probe.ok:
            units = parse_systemd_units(probe.stdout)
        else:
            result.warn(f"systemctl list-units unavailable: {probe.reason}")
    else:  # pragma: no cover - unsupported platforms are reported, not fatal
        result.warn(f"scheduled services are not implemented for {ctx.platform!r}")

    ghosts = 0
    for unit in units:
        if not unit.exists:
            ghosts += 1
            continue
        result.nodes.append(
            Node(
                id=unit.id,
                kind=KIND_WORKLOAD,
                label=unit.name,
                facts=unit.to_facts(),
                telemetry=unit.to_telemetry(),
                tags=("service", unit.runtime),
                source="services",
            )
        )
        result.edges.append(Edge(host, REL_RUNS, unit.id, {"runtime": unit.runtime}))

    if ghosts:
        result.warn(f"{ghosts} unit(s) reported but not present on this machine omitted")
    for note in log.notes():
        result.warn(note)
    if not result.nodes:
        result.warn("no scheduled services observed")
    return result
