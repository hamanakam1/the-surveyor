"""Power scanner: what is actually feeding the machine.

A survey that does not know where the electrons come from is only half a map.
This scanner reads the platform's power-supply view and emits a
``power_source`` node per observed supply, plus a ``powers`` edge into the host.

Values that drift (charge, cycle count) are telemetry. Values that describe the
installation (chemistry, design capacity) are facts.
"""

from __future__ import annotations

import os
import re
from typing import Any

from ..identity import host_id as local_host_id
from ..model import (
    KIND_POWER_SOURCE,
    LAYER_POWER,
    REL_POWERS,
    Edge,
    Node,
)
from ..probe import ProbeLog, read_int, read_text, run
from ..util import humanize_key, slug
from .base import ScanContext, ScanResult, register

_PERCENT = re.compile(r"(?P<percent>\d{1,3})%")
_REMAINING = re.compile(r"(?P<hours>\d+):(?P<minutes>\d{2}) remaining")
_IOREG_PAIR = re.compile(r'"([A-Za-z0-9_]+)"\s*=\s*("?[^"\n]*"?)')


def _supply_node(
    *,
    supply_id: str,
    label: str,
    facts: dict[str, Any],
    telemetry: dict[str, Any],
    tags: tuple[str, ...],
) -> Node:
    return Node(
        id=supply_id,
        kind=KIND_POWER_SOURCE,
        label=label,
        layer=LAYER_POWER,
        facts=facts,
        telemetry=telemetry,
        tags=tags,
        source="power",
    )


def _power_edge(supply_id: str, host_id: str, priority: int, kind: str) -> Edge:
    return Edge(supply_id, REL_POWERS, host_id, {"priority": priority, "kind": kind})


def _parse_duration(text: str) -> int | None:
    match = _REMAINING.search(text)
    if not match:
        return None
    return int(match.group("hours")) * 60 + int(match.group("minutes"))


def _parse_pmset_batt(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Parse ``pmset -g batt`` into (drawing_from, battery snapshots)."""

    drawing = ""
    header = re.search(r"drawing from '([^']+)'", text)
    if header:
        drawing = header.group(1).strip()

    batteries: list[dict[str, Any]] = []
    for raw in text.splitlines():
        if not raw.strip().startswith("-"):
            continue
        name, _, detail = raw.partition("\t")
        if not detail:
            _, _, detail = raw.partition(" ")
        entry: dict[str, Any] = {
            "name": name.strip().lstrip("-").split(" (id=")[0].strip(),
            "detail": detail.strip(),
        }
        percent = _PERCENT.search(detail)
        if percent:
            entry["charge_percent"] = int(percent.group("percent"))
        remaining = _parse_duration(detail)
        if remaining is not None:
            entry["minutes_remaining"] = remaining
        lowered = detail.lower()
        # "discharging" contains "charging", so the more specific state has
        # to be tested first or every discharging battery reads as charging.
        for state in ("discharging", "finishing charge", "charged", "charging", "ac attached"):
            if state in lowered:
                entry["state"] = state
                break
        if "present: true" in lowered or "present: false" in lowered:
            entry["present"] = "present: true" in lowered
        if "no battery" in lowered or "no batteries" in lowered:
            entry["absent"] = True
        batteries.append(entry)
    return drawing, batteries


def _parse_ioreg_battery(text: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, raw in _IOREG_PAIR.findall(text):
        cleaned = raw.strip().strip('"')
        if cleaned.lstrip("-").isdigit():
            values[key] = int(cleaned)
        elif cleaned:
            values[key] = cleaned
    return values


def _scan_macos(ctx: ScanContext, result: ScanResult, log: ProbeLog, host_id: str) -> None:
    batt = log.add(run(["pmset", "-g", "batt"], timeout=ctx.timeout))
    if not batt.ok:
        result.warn(f"pmset -g batt unavailable: {batt.reason}")
        return

    drawing, batteries = _parse_pmset_batt(batt.stdout)
    on_ac = bool(drawing) and "AC" in drawing
    if on_ac:
        result.nodes.append(
            _supply_node(
                supply_id="power:ac",
                label="AC mains",
                # macOS reports that the machine is drawing from mains and
                # nothing more. It cannot say whether that is a wall socket
                # or a UPS, so the plat does not claim to know.
                facts={"role": "ac", "source": "ac"},
                telemetry={"present": True},
                tags=("ac", "always-on"),
            )
        )
        result.edges.append(_power_edge("power:ac", host_id, priority=1, kind="ac"))
        result.warn(
            "macOS does not distinguish a UPS from a wall socket; "
            "the mains supply is recorded as unverified"
        )

    for index, entry in enumerate(batteries):
        if entry.get("absent") or entry.get("present") is False:
            continue
        telemetry = {
            key: value
            for key, value in entry.items()
            if key in {"charge_percent", "minutes_remaining", "state", "present"}
        }
        supply_id = f"power:battery:internal-{index}"
        result.nodes.append(
            _supply_node(
                supply_id=supply_id,
                label="Internal battery",
                facts={"source": "battery", "role": "battery", "chemistry": "li-ion"},
                telemetry=telemetry,
                tags=("battery", "internal"),
            )
        )
        result.edges.append(_power_edge(supply_id, host_id, priority=3, kind="battery"))

    ioreg = log.add(run(["ioreg", "-rn", "AppleSmartBattery"], timeout=ctx.timeout))
    if ioreg.ok:
        values = _parse_ioreg_battery(ioreg.stdout)
        if "BatterySerialNumber" in values:
            for node in result.nodes:
                if node.id.startswith("power:battery:"):
                    node.facts["serial"] = str(values["BatterySerialNumber"])
                    if "DesignCapacity" in values:
                        node.facts["design_capacity_mah"] = values["DesignCapacity"]
                    if "Temperature" in values:
                        node.telemetry["temperature_c"] = round(
                            float(values["Temperature"]) / 10, 1
                        )
                    if "CycleCount" in values:
                        node.telemetry["cycle_count"] = values["CycleCount"]
    else:
        result.warn(f"ioreg battery detail unavailable: {ioreg.reason}")


_SYS_POWER = "/sys/class/power_supply"


def _scan_linux(_ctx: ScanContext, result: ScanResult, host_id: str) -> None:
    try:
        entries = sorted(os.listdir(_SYS_POWER))
    except OSError:
        result.warn(f"{_SYS_POWER} unavailable; power layer not observed")
        return

    for entry in entries:
        base = f"{_SYS_POWER}/{entry}"
        kind = (read_text(f"{base}/type", limit=32) or "").strip()
        if not kind:
            continue
        telemetry: dict[str, Any] = {}
        facts: dict[str, Any] = {"role": kind.lower(), "device": entry}

        capacity = read_int(f"{base}/capacity")
        if capacity is not None:
            telemetry["charge_percent"] = capacity
        status = (read_text(f"{base}/status", limit=32) or "").strip()
        if status:
            telemetry["state"] = status
        online = read_int(f"{base}/online")
        if online is not None:
            telemetry["present"] = bool(online)
        energy = read_int(f"{base}/energy_now")
        if energy is not None:
            telemetry["energy_now_wh"] = round(energy / 1_000_000, 1)
        power = read_int(f"{base}/power_now")
        if power is not None:
            telemetry["draw_w"] = round(power / 1_000_000, 1)
        for key, target in (
            ("manufacturer", "manufacturer"),
            ("model_name", "model"),
            ("technology", "chemistry"),
            ("serial_number", "serial"),
        ):
            value = (read_text(f"{base}/{key}", limit=128) or "").strip()
            if value:
                facts[target] = value
        design = read_int(f"{base}/energy_full_design")
        if design is not None:
            facts["design_capacity_wh"] = round(design / 1_000_000, 1)
        cycles = read_int(f"{base}/cycle_count")
        if cycles is not None:
            telemetry["cycle_count"] = cycles

        lower = kind.lower()
        if lower == "mains":
            if online is not None and not online:
                continue
            priority = 1
            # The same node macOS calls "power:ac", with the same meaning:
            # mains, without a claim about where the mains comes from.
            facts["role"] = "ac"
            facts["source"] = "ac"
            supply_id = "power:ac"
            label = "AC mains"
        elif lower == "ups":
            priority = 2
            supply_id = f"power:{slug(entry)}"
            label = f"UPS {entry}"
        elif lower == "battery":
            priority = 3
            supply_id = f"power:{slug(entry)}"
            label = f"Battery {entry}"
        else:
            priority = 4
            supply_id = f"power:{slug(entry)}"
            label = f"{humanize_key(kind)} {entry}"

        result.nodes.append(
            _supply_node(
                supply_id=supply_id,
                label=label,
                facts=facts,
                telemetry=telemetry,
                tags=(lower, "observed"),
            )
        )
        result.edges.append(_power_edge(supply_id, host_id, priority=priority, kind=lower))


@register(
    "power",
    LAYER_POWER,
    "Power sources and charge state: AC, batteries, UPS, solar where the OS reports it",
)
def scan_power(ctx: ScanContext) -> ScanResult:
    result = ScanResult(scanner="power", layer=LAYER_POWER)
    log = ProbeLog()
    host_id = local_host_id()

    if ctx.platform == "darwin":
        _scan_macos(ctx, result, log, host_id)
    elif ctx.platform.startswith("linux"):
        _scan_linux(ctx, result, host_id)
    else:  # pragma: no cover - unsupported platform
        result.warn(f"power is not implemented for {ctx.platform!r}")

    for note in log.notes():
        result.warn(note)
    if not result.nodes:
        result.warn("no power sources reported by this platform")
    return result
