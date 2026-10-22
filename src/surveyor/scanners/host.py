"""Bare-metal scanner: CPU, memory, thermals, and board identity.

Everything here comes from ``sysctl`` / ``/proc`` / ``/sys``. Nothing requires
root, and nothing is inferred: if a value is unavailable it is simply absent
from the map.
"""

from __future__ import annotations

import os
import platform
import re
import time
from dataclasses import dataclass
from typing import Any

from ..identity import host_id as local_host_id
from ..identity import hostname as local_hostname
from ..model import KIND_HOST, LAYER_METAL, Node
from ..probe import ProbeLog, read_int, read_text, run

from .base import ScanContext, ScanResult, register

_THERMAL_NOTE_LIMIT = 200


def _macos_identity(ctx: ScanContext, log: ProbeLog) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    probes = {
        "arch": ("uname", ["uname", "-m"]),
        "model": ("sysctl", ["sysctl", "-n", "hw.model"]),
        "cpu_model": ("sysctl", ["sysctl", "-n", "machdep.cpu.brand_string"]),
        "cpu_cores": ("sysctl", ["sysctl", "-n", "hw.ncpu"]),
        "cpu_cores_physical": ("sysctl", ["sysctl", "-n", "hw.physicalcpu"]),
        "mem_bytes": ("sysctl", ["sysctl", "-n", "hw.memsize"]),
    }
    for key, (_program, argv) in probes.items():
        probe = log.add(run(argv, timeout=ctx.timeout))
        if not probe.ok:
            continue
        value = probe.first_line()
        if not value:
            continue
        if key in {"cpu_cores", "cpu_cores_physical", "mem_bytes"}:
            try:
                facts[key] = int(value)
            except ValueError:
                continue
        else:
            facts[key] = value

    sw_vers = log.add(run(["sw_vers"], timeout=ctx.timeout))
    if sw_vers.ok:
        for raw in sw_vers.lines():
            if ":" not in raw:
                continue
            key, _, value = raw.partition(":")
            label = key.strip()
            if label == "ProductName":
                facts["os"] = value.strip()
            elif label == "ProductVersion":
                facts["os_version"] = value.strip()
            elif label == "BuildVersion":
                facts["os_build"] = value.strip()

    boot = log.add(run(["sysctl", "-n", "kern.boottime"], timeout=ctx.timeout))
    if boot.ok:
        match = re.search(r"sec\s*=\s*(\d+)", boot.stdout)
        if match:
            facts["telemetry_uptime_seconds"] = max(0, int(time.time()) - int(match.group(1)))
    return facts


def _linux_identity(ctx: ScanContext, log: ProbeLog) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    pretty = read_text("/etc/os-release")
    if pretty:
        for line in pretty.splitlines():
            if line.startswith("PRETTY_NAME="):
                facts["os"] = line.split("=", 1)[1].strip().strip('"')
                break
    kernel = log.add(run(["uname", "-r"], timeout=ctx.timeout))
    if kernel.ok:
        facts["kernel"] = kernel.first_line()
    machine = log.add(run(["uname", "-m"], timeout=ctx.timeout))
    if machine.ok:
        facts["arch"] = machine.first_line()

    cpuinfo = read_text("/proc/cpuinfo")
    if cpuinfo:
        for line in cpuinfo.splitlines():
            key, _, value = line.partition(":")
            key = key.strip()
            if key == "model name" and "cpu_model" not in facts:
                facts["cpu_model"] = value.strip()
            elif key == "cpu cores" and "cpu_cores_physical" not in facts:
                facts["cpu_cores_physical"] = int(value.strip() or 0) or None
        # ``cpu cores`` is per-socket; count sockets for a truthful total.
        sockets = sum(1 for line in cpuinfo.splitlines() if line.strip().startswith("physical id"))
        physical = facts.get("cpu_cores_physical")
        if isinstance(physical, int) and sockets > 0:
            facts["cpu_cores_physical"] = physical * sockets

    meminfo = read_text("/proc/meminfo")
    if meminfo:
        for line in meminfo.splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    facts["mem_bytes"] = int(parts[1]) * 1024
                break

    uptime = read_text("/proc/uptime")
    if uptime:
        try:
            facts["telemetry_uptime_seconds"] = int(float(uptime.split()[0]))
        except (ValueError, IndexError):
            pass

    model = read_text("/sys/devices/virtual/dmi/id/product_name")
    if model and model.strip():
        facts["model"] = model.strip()
    return facts


def _thermal_telemetry(ctx: ScanContext, log: ProbeLog) -> dict[str, Any]:
    telemetry: dict[str, Any] = {}
    temperature = read_int("/sys/class/thermal/thermal_zone0/temp")
    if temperature is not None:
        telemetry["temperature_c"] = round(temperature / 1000, 1)
    if ctx.platform == "darwin":
        therm = log.add(run(["pmset", "-g", "therm"], timeout=ctx.timeout))
        if therm.ok:
            for line in therm.lines():
                if "CPU_Speed_Limit" in line and "=" in line:
                    try:
                        telemetry["cpu_speed_limit"] = int(line.split("=")[-1].strip())
                    except ValueError:
                        pass
                elif not line.lower().startswith("note:") and "warning" in line.lower():
                    telemetry["thermal_warning"] = line.strip()[:_THERMAL_NOTE_LIMIT]
    return telemetry


def _memory_telemetry() -> dict[str, Any]:
    telemetry: dict[str, Any] = {}
    if hasattr(os, "sysconf"):
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            available = os.sysconf("SC_AVPHYS_PAGES")
            telemetry["mem_available_gib"] = round(available * page_size / (1024**3), 1)
        except (ValueError, OSError, AttributeError):
            pass
    return telemetry


def _load_telemetry() -> dict[str, Any]:
    telemetry: dict[str, Any] = {}
    try:
        one, five, fifteen = os.getloadavg()
        telemetry.update(
            {"load_1m": round(one, 2), "load_5m": round(five, 2), "load_15m": round(fifteen, 2)}
        )
    except (OSError, AttributeError):
        pass
    return telemetry


def _virtualisation() -> str | None:
    if os.path.exists("/.dockerenv"):
        return "docker"
    if os.path.exists("/run/.containerenv"):
        return "podman"
    return None


#: ``df -P -k``: filesystem, 1024-blocks, used, available, capacity, mount.
_DF_LINE = re.compile(
    r"^(?P<fs>\S+)\s+(?P<blocks>\d+)\s+(?P<used>\d+)\s+(?P<avail>\d+)\s+"
    r"(?P<pct>\d+)%\s+(?P<mount>.+)$"
)

#: Pseudo-filesystems that are not storage.
_PSEUDO_FS = frozenset(
    {
        "autofs",
        "devfs",
        "devtmpfs",
        "proc",
        "procfs",
        "pseudofs",
        "snapfs",
        "sysfs",
        "tmpfs",
        "auto_home",
        "devfs",
        "fdescfs",
        "cgroup",
        "cgroup2",
        "securityfs",
        "debugfs",
        "tracefs",
        "configfs",
        "fusectl",
        "mqueue",
        "hugetlbfs",
        "ramfs",
        "binfmt_misc",
        "efivarfs",
        "nsfs",
        "squashfs",
        "overlay",
        "none",
    }
)


@dataclass(slots=True)
class Filesystem:
    """One mounted filesystem."""

    device: str
    mount: str
    total_bytes: int = 0
    used_bytes: int = 0
    free_bytes: int = 0
    percent: int = 0


def parse_df(text: str) -> list[Filesystem]:
    """Parse POSIX ``df -P -k`` output."""

    filesystems: list[Filesystem] = []
    for raw in text.splitlines():
        match = _DF_LINE.match(raw.strip())
        if not match:
            continue
        device = match.group("fs")
        if device in _PSEUDO_FS:
            continue
        blocks = int(match.group("blocks"))
        filesystems.append(
            Filesystem(
                device=device,
                mount=match.group("mount").strip(),
                total_bytes=blocks * 1024,
                used_bytes=int(match.group("used")) * 1024,
                free_bytes=int(match.group("avail")) * 1024,
                percent=int(match.group("pct")),
            )
        )
    return filesystems


def _storage(
    ctx: ScanContext, log: ProbeLog
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """What is attached to this machine, and how much room is left.

    The size of a disk and where it is mounted are shape. How full it is
    is weather: a disk that fills up has not changed, it has merely run
    out of room, and the map should not churn every time it does.

    Sizes are *not* summed. On an APFS volume, or any filesystem with
    several volumes on one container, five mounts can report the same
    capacity, and adding them up would report five times the disk the
    machine actually has.
    """

    probe = log.add(run(["df", "-P", "-k"], timeout=ctx.timeout))
    if not probe.ok:
        return {}, {}, []

    filesystems = parse_df(probe.stdout)
    if not filesystems:
        return {}, {}, []

    notes: list[str] = []
    capacities = [item.total_bytes for item in filesystems]
    if len(capacities) != len(set(capacities)):
        notes.append(
            "several filesystems share a container; sizes are reported per "
            "filesystem and are not summed"
        )

    facts: dict[str, Any] = {
        "storage_filesystems": len(filesystems),
        "storage_mounts": sorted(item.mount for item in filesystems),
        "storage_capacity_bytes": max(capacities),
    }
    telemetry: dict[str, Any] = {
        "storage_used_bytes": max(item.used_bytes for item in filesystems),
        "storage_free_bytes": max(item.free_bytes for item in filesystems),
        "storage_used_percent": max(item.percent for item in filesystems),
    }
    return facts, telemetry, notes


@register(
    "host",
    LAYER_METAL,
    "CPU, memory, storage, thermals, and board identity of the machine running the survey",
)
def scan_host(ctx: ScanContext) -> ScanResult:
    log = ProbeLog()
    result = ScanResult(scanner="host", layer=LAYER_METAL)

    if ctx.platform == "darwin":
        facts = _macos_identity(ctx, log)
    elif ctx.platform.startswith("linux"):
        facts = _linux_identity(ctx, log)
    else:  # pragma: no cover - unsupported platforms are reported, not fatal
        result.warn(f"platform {ctx.platform!r} is not fully supported; surveying basics only")
        facts = {"os": platform.system(), "arch": platform.machine()}

    uptime_seconds = facts.pop("telemetry_uptime_seconds", None)
    hostname = local_hostname()
    host_id = local_host_id()

    netbios = _virtualisation()
    if netbios:
        facts["virtualisation"] = netbios

    mem_bytes = facts.pop("mem_bytes", None)
    if isinstance(mem_bytes, int) and mem_bytes > 0:
        facts["mem_total_gib"] = round(mem_bytes / (1024**3))

    facts["hostname"] = hostname
    facts.setdefault("os", platform.system() or "unknown")
    facts.setdefault("arch", platform.machine() or "unknown")
    facts.setdefault("cpu_cores", os.cpu_count() or 1)
    facts["boot_mode"] = "uefi" if ctx.platform == "darwin" else _linux_boot_mode()

    telemetry: dict[str, Any] = {}
    telemetry.update(_load_telemetry())
    telemetry.update(_memory_telemetry())
    telemetry.update(_thermal_telemetry(ctx, log))
    if uptime_seconds is not None:
        telemetry["uptime_seconds"] = uptime_seconds

    storage_facts, storage_telemetry, storage_notes = _storage(ctx, log)
    facts.update(storage_facts)
    telemetry.update(storage_telemetry)
    for note in storage_notes:
        result.warn(note)

    label = hostname
    if "model" in facts:
        label = f"{hostname} ({facts['model']})"

    result.nodes.append(
        Node(
            id=host_id,
            kind=KIND_HOST,
            label=label,
            facts=facts,
            telemetry=telemetry,
            tags=("site-host", ctx.platform.split("-")[0]),
            source="host",
        )
    )
    for note in log.notes():
        result.warn(note)
    return result


def _linux_boot_mode() -> str:
    return "uefi" if os.path.isdir("/sys/firmware/efi") else "bios"
