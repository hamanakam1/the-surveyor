"""The power scanner, end to end.

Power is the layer that changes most often and is hardest to read: it has
two platforms, two entirely different sources, and a dozen small parsing
rules. These tests pin the parsers against recorded output and the scanner
against stubbed probes, so a change in ``pmset`` or in ``sysfs`` shows up as
a failing test rather than as a wrong plat.
"""

from __future__ import annotations

from pathlib import Path

from surveyor.config import Config
from surveyor.model import KIND_POWER_SOURCE
from surveyor.probe import Probe
from surveyor.scanners import power as scanner
from surveyor.scanners.base import ScanContext

PMSET_AC = (
    "Now drawing from 'AC Power'\n"
    " -InternalBattery-0 (id=23199843)\t100%; finishing charge; 0:08 remaining present: true\n"
)

PMSET_BATTERY = (
    "Now drawing from 'Battery Power'\n"
    " -InternalBattery-0 (id=23199843)\t87%; discharging; 3:42 remaining present: true\n"
)

PMSET_NO_BATTERY = (
    "Now drawing from 'AC Power'\n"
    " -InternalBattery-0 (id=23199843)\t100%; charged; no battery present: false\n"
)

IOREG = """  | "BatterySerialNumber" = "C02TEST1234"
  | "DesignCapacity" = 6249
  | "Temperature" = 305
  | "CycleCount" = 252
"""


class FakeRunner:
    """A stand-in for ``probe.run`` that answers from a table."""

    def __init__(self, table: dict[str, str]) -> None:
        self.table = table

    def __call__(self, argv, timeout: float = 8.0) -> Probe:
        vector = tuple(argv)
        command = " ".join(vector)
        best: tuple[int, str] | None = None
        for needle, output in self.table.items():
            if needle in command and (best is None or len(needle) > best[0]):
                best = (len(needle), output)
        if best is not None:
            return Probe(vector, ok=True, stdout=best[1])
        return Probe(vector, ok=False, reason="not installed")


def _run(table: dict[str, str], platform: str = "darwin"):
    runner = FakeRunner(table)
    original = scanner.run
    scanner.run = runner  # type: ignore[assignment]
    try:
        context = ScanContext(config=Config(), site="edge", platform=platform)
        return scanner.scan_power(context)
    finally:
        scanner.run = original  # type: ignore[assignment]


def _supplies(result):
    return [node for node in result.nodes if node.kind == KIND_POWER_SOURCE]


# --------------------------------------------------------------------------
# the parsers
# --------------------------------------------------------------------------
def test_parse_pmset_batt_reads_the_source_and_the_battery():
    drawing, batteries = scanner._parse_pmset_batt(PMSET_AC)
    assert drawing == "AC Power"
    assert len(batteries) == 1
    battery = batteries[0]
    assert battery["name"] == "InternalBattery-0"
    assert battery["charge_percent"] == 100
    assert battery["minutes_remaining"] == 8
    assert battery["state"] == "finishing charge"
    assert battery["present"] is True


def test_parse_pmset_batt_reads_a_discharging_battery():
    _, batteries = scanner._parse_pmset_batt(PMSET_BATTERY)
    assert batteries[0]["charge_percent"] == 87
    assert batteries[0]["minutes_remaining"] == 222
    assert batteries[0]["state"] == "discharging"


def test_parse_pmset_batt_reads_an_absent_battery():
    _, batteries = scanner._parse_pmset_batt(PMSET_NO_BATTERY)
    assert batteries[0]["present"] is False


def test_parse_ioreg_battery_reads_the_hardware_detail():
    values = scanner._parse_ioreg_battery(IOREG)
    assert values["BatterySerialNumber"] == "C02TEST1234"
    assert values["DesignCapacity"] == 6249
    assert values["Temperature"] == 305
    assert values["CycleCount"] == 252


# --------------------------------------------------------------------------
# the scanner
# --------------------------------------------------------------------------
def test_on_ac_makes_an_ac_supply_and_a_battery():
    result = _run({"pmset -g batt": PMSET_AC, "ioreg": IOREG})
    supplies = _supplies(result)
    ids = [node.id for node in supplies]
    assert "power:ac" in ids
    assert "power:battery:internal-0" in ids

    ac = next(node for node in supplies if node.id == "power:ac")
    assert ac.facts["role"] == "ac"
    # macOS cannot say whether the mains is a wall socket or a UPS, so the
    # plat does not claim to know.
    assert "utility" not in ac.tags
    assert "utility" not in ac.facts.values()
    assert any("UPS" in note for note in result.notes)

    battery = next(node for node in supplies if node.id == "power:battery:internal-0")
    assert battery.facts["serial"] == "C02TEST1234"
    assert battery.facts["design_capacity_mah"] == 6249
    assert battery.telemetry["temperature_c"] == 30.5
    assert battery.telemetry["cycle_count"] == 252


def test_on_battery_there_is_no_ac_supply():
    """A laptop unplugged is not the same machine as a laptop plugged in."""

    result = _run({"pmset -g batt": PMSET_BATTERY, "ioreg": IOREG})
    ids = [node.id for node in _supplies(result)]
    assert "power:ac" not in ids
    assert "power:battery:internal-0" in ids


def test_an_absent_battery_is_not_a_battery():
    result = _run({"pmset -g batt": PMSET_NO_BATTERY, "ioreg": IOREG})
    ids = [node.id for node in _supplies(result)]
    assert "power:battery:internal-0" not in ids
    assert "power:ac" in ids


def test_without_pmset_the_power_layer_says_so():
    result = _run({})
    assert not _supplies(result)
    assert any("pmset" in note for note in result.notes)
    assert any("no power sources" in note for note in result.notes)


def test_every_supply_powers_the_host():
    result = _run({"pmset -g batt": PMSET_AC, "ioreg": IOREG})
    host_edges = [edge for edge in result.edges if edge.relation == "powers"]
    assert len(host_edges) == 2
    assert {edge.source for edge in host_edges} == {
        "power:ac",
        "power:battery:internal-0",
    }


def test_the_power_layer_is_exactly_these_nodes():
    """The complete set, not a sample of it."""

    result = _run({"pmset -g batt": PMSET_AC, "ioreg": IOREG})
    assert {node.id for node in result.nodes} == {
        "power:ac",
        "power:battery:internal-0",
    }
    assert {edge.id for edge in result.edges} == {
        "power:ac|powers|host:mac",
        "power:battery:internal-0|powers|host:mac",
    }


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------
def _sysfs(tmp_path) -> Path:
    """A real directory that looks like /sys/class/power_supply.

    Building it on disk rather than stubbing the reads means the scanner
    reads real files, and the test does not have to patch ``os.listdir``
    for the whole process.
    """

    root = tmp_path / "power_supply"
    entries = {
        "AC": {
            "type": "Mains\n",
            "online": "1\n",
        },
        "BAT0": {
            "type": "Battery\n",
            "capacity": "87\n",
            "status": "Discharging\n",
            "energy_now": "52000000\n",
            "power_now": "12000000\n",
            "manufacturer": "SMP\n",
            "model_name": "BAT0\n",
            "technology": "Li-ion\n",
            "serial_number": "1234\n",
            "energy_full_design": "60000000\n",
            "cycle_count": "41\n",
        },
        "UPS0": {
            "type": "UPS\n",
            "online": "1\n",
        },
    }
    for name, files in entries.items():
        directory = root / name
        directory.mkdir(parents=True)
        for filename, content in files.items():
            (directory / filename).write_text(content)
    return root


def test_linux_reads_sysfs(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_SYS_POWER", str(_sysfs(tmp_path)))
    context = ScanContext(config=Config(), site="edge", platform="linux")
    result = scanner.scan_power(context)

    by_id = {node.id: node for node in _supplies(result)}
    assert set(by_id) == {"power:ac", "power:bat0", "power:ups0"}

    battery = by_id["power:bat0"]
    assert battery.facts["role"] == "battery"
    assert battery.facts["chemistry"] == "Li-ion"
    assert battery.facts["serial"] == "1234"
    assert battery.facts["design_capacity_wh"] == 60.0
    assert battery.telemetry["charge_percent"] == 87
    assert battery.telemetry["draw_w"] == 12.0
    assert battery.telemetry["cycle_count"] == 41

    # The mains supply outranks the battery, and the UPS sits between them.
    priorities = {
        edge.source: edge.facts["priority"] for edge in result.edges if edge.relation == "powers"
    }
    assert priorities["power:ac"] == 1
    assert priorities["power:ups0"] == 2
    assert priorities["power:bat0"] == 3


def test_linux_without_sysfs_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_SYS_POWER", str(tmp_path / "not-there"))
    context = ScanContext(config=Config(), site="edge", platform="linux")
    result = scanner.scan_power(context)
    assert not _supplies(result)
    assert any("power layer not observed" in note for note in result.notes)
