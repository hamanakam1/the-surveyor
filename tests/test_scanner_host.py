"""The host scanner, end to end, with the probes stubbed.

Storage and thermals are the two places where the scanner can easily report
something true-looking and false, so both are checked here.
"""

from __future__ import annotations

from surveyor.config import Config
from surveyor.probe import Probe
from surveyor.scanners import host as scanner
from surveyor.scanners.base import ScanContext

DF = """Filesystem     1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1   971350180  13340060  10525016    56%    /
/dev/disk3s5     971350180 886325376  10525016    99%    /System/Volumes/Data
"""

#: Two volumes on one container: the same capacity, reported twice.
DF_SHARED = """Filesystem     1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1   971350180  13340060  10525016    56%    /
/dev/disk3s6     971350180  48793256  10525016    83%    /System/Volumes/VM
"""

THERM_NOTE = """Note: No thermal warning level has been recorded
Note: No performance warning level has been recorded
Note: No CPU power status has been recorded
"""

THERM_WARNING = """CPU_Speed_Limit = 100
CPU_Scheduler_Limit = 100
CPU_Available_CPUs = 100
Warning: CPU speed limit exceeded
"""

NVIDIA_SMI = """NVIDIA GeForce RTX 4090, 24564, 550.54.14
NVIDIA RTX A6000, 49140, 550.54.14
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
        return scanner.scan_host(context)
    finally:
        scanner.run = original  # type: ignore[assignment]


def test_storage_size_is_a_fact_and_fullness_is_telemetry():
    result = _run({"df": DF})
    node = result.nodes[0]
    assert node.facts["storage_filesystems"] == 2
    assert node.facts["storage_capacity_bytes"] == 971350180 * 1024
    assert node.facts["storage_mounts"] == ["/", "/System/Volumes/Data"]
    assert node.telemetry["storage_used_percent"] == 99


def test_shared_containers_are_not_summed():
    """Two volumes on one disk are not two disks."""

    result = _run({"df": DF_SHARED})
    node = result.nodes[0]
    assert node.facts["storage_capacity_bytes"] == 971350180 * 1024
    assert node.telemetry["storage_used_bytes"] == 48793256 * 1024
    assert any("share a container" in note for note in result.notes)


def test_no_df_means_no_storage_claims():
    result = _run({})
    node = result.nodes[0]
    assert not [key for key in node.facts if key.startswith("storage")]
    assert not [key for key in node.telemetry if key.startswith("storage")]


def test_a_note_that_records_nothing_is_not_a_thermal_warning():
    """``pmset`` says "no warning level has been recorded". That is not a warning."""

    result = _run({"pmset -g therm": THERM_NOTE})
    assert "thermal_warning" not in result.nodes[0].telemetry


def test_a_real_thermal_warning_is_recorded():
    result = _run({"pmset -g therm": THERM_WARNING})
    telemetry = result.nodes[0].telemetry
    assert telemetry.get("cpu_speed_limit") == 100
    assert "exceeded" in telemetry.get("thermal_warning", "")


def test_the_bare_metal_layer_is_exactly_one_node():
    """The complete set, not a sample of it."""

    result = _run({"df": DF})
    from surveyor.identity import host_id

    assert {node.id for node in result.nodes} == {host_id()}
    assert result.edges == []


def test_an_accelerator_is_a_fact_about_the_machine():
    result = _run({"nvidia-smi": NVIDIA_SMI})
    facts = result.nodes[0].facts
    assert facts["accelerator"] == "nvidia"
    assert facts["accelerator_count"] == 2
    assert facts["accelerator_name"] == "NVIDIA GeForce RTX 4090"
    assert facts["accelerator_memory_gib"] == 72
    assert facts["accelerator_driver"] == "550.54.14"


def test_a_machine_without_an_accelerator_says_nothing_about_one():
    result = _run({"df": DF})
    facts = result.nodes[0].facts
    assert not [key for key in facts if key.startswith("accelerator")]
