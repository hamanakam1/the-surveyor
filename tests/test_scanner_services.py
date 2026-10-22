"""The services scanner: systemd units and launchd daemons.

The scope question matters more than the parsing here. A user session
lists an agent for every application the operator has open, and those come
and go with what they are doing — recording them would make the workload
layer churn on every scan and break the promise that a daemon writes an
entry only when the infrastructure moves.
"""

from __future__ import annotations

from surveyor.config import Config
from surveyor.model import KIND_WORKLOAD, REL_RUNS
from surveyor.probe import Probe
from surveyor.scanners import services as scanner
from surveyor.scanners.base import ScanContext

SYSTEMCTL = """  sshd.service loaded active running OpenSSH server daemon
  nginx.service loaded active running A high performance web server
  cron.service loaded inactive dead Regular background program processing daemon
  ghost.service not-found inactive dead A unit the package left behind
  masked.service masked inactive dead Somebody disabled this on purpose
  docker.service loaded active running Docker Application Container Engine
"""

LAUNCHD = """\tservices = {
\t\t       0      - \tcom.apple.backgroundassets.managed.relay.service
\t\t     516      - \tcom.apple.driverkit.AppleUserHIDDrivers-0x1000010ca
\t\t       0   (pe) \tcom.apple.lskdd
\t\t       0      0 \tcom.apple.tmp_cleaner
\t}
\tendpoints = {
\t\tcom.apple.system.coreservices.dtcd = {
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
        return scanner.scan_services(context)
    finally:
        scanner.run = original  # type: ignore[assignment]


def test_systemd_units_are_services_the_host_runs():
    result = _run({"systemctl": SYSTEMCTL}, platform="linux")
    units = [node for node in result.nodes if node.kind == KIND_WORKLOAD]
    ids = {node.id for node in units}
    assert "workload:systemd:sshd.service" in ids
    assert "workload:systemd:nginx.service" in ids
    assert "workload:systemd:cron.service" in ids

    nginx = next(node for node in units if node.id == "workload:systemd:nginx.service")
    assert nginx.facts["description"] == "A high performance web server"
    assert nginx.telemetry["active_state"] == "active"
    assert nginx.telemetry["sub_state"] == "running"

    # An installed but stopped unit is still on the machine.
    cron = next(node for node in units if node.id == "workload:systemd:cron.service")
    assert cron.telemetry["active_state"] == "inactive"


def test_units_that_are_not_really_there_are_left_out():
    """A stub the package left behind is not a service the machine runs."""

    result = _run({"systemctl": SYSTEMCTL}, platform="linux")
    ids = {node.id for node in result.nodes}
    assert "workload:systemd:ghost.service" not in ids
    assert "workload:systemd:masked.service" not in ids
    assert any("not present on this machine" in note for note in result.notes)


def test_every_service_is_run_by_the_host():
    result = _run({"systemctl": SYSTEMCTL}, platform="linux")
    runs = [edge for edge in result.edges if edge.relation == REL_RUNS]
    assert runs
    from surveyor.identity import host_id

    assert {edge.source for edge in runs} == {host_id()}
    assert {edge.facts["runtime"] for edge in runs} == {"systemd"}


def test_launchd_daemons_are_read_from_the_system_domain():
    result = _run({"launchctl": LAUNCHD})
    ids = {node.id for node in result.nodes}
    assert "workload:launchd:com.apple.lskdd" in ids
    assert "workload:launchd:com.apple.tmp_cleaner" in ids
    # The endpoints block that follows must not be read as services.
    assert not any("dtcd" in node_id for node_id in ids)


def test_without_a_scheduler_the_scanner_says_so():
    result = _run({})
    assert not result.nodes
    assert any("unavailable" in note for note in result.notes)
    assert any("no scheduled services" in note for note in result.notes)


def test_the_services_layer_is_exactly_these_nodes():
    """The complete set, not a sample of it."""

    result = _run({"systemctl": SYSTEMCTL}, platform="linux")
    assert {node.id for node in result.nodes} == {
        "workload:systemd:sshd.service",
        "workload:systemd:nginx.service",
        "workload:systemd:cron.service",
        "workload:systemd:docker.service",
    }


def test_the_services_scanner_is_registered():
    from surveyor.scanners.base import registry

    assert "services" in registry()
