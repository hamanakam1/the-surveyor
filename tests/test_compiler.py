"""The compiler: many scanners, one map.

The compiler's job is to fold several observations of the same machine into
one document without losing anything and without inventing anything. The
part worth testing is what happens when two scanners see the same thing and
disagree.
"""

from __future__ import annotations

from surveyor.compiler import compile_topology
from surveyor.config import Config
from surveyor.model import Edge, Node
from surveyor.scanners.base import ScanResult


def _result(scanner: str, nodes: list[Node], edges: list[Edge] | None = None) -> ScanResult:
    return ScanResult(scanner=scanner, layer="network", nodes=nodes, edges=edges or [])


def test_two_scanners_seeing_the_same_thing_produce_one_node():
    topology = compile_topology(
        [
            _result("network", [Node("iface:lab:en0", "interface", "en0")]),
            _result(
                "workloads",
                [Node("iface:lab:en0", "interface", "en0", facts={"name": "en0"})],
            ),
        ],
        Config(),
    )
    assert len(topology.nodes) == 1
    assert topology.nodes["iface:lab:en0"].facts["name"] == "en0"


def test_a_disagreement_is_recorded_rather_than_dropped():
    """Silence reads as agreement, and it would be a lie."""

    topology = compile_topology(
        [
            _result(
                "network",
                [Node("service:tcp:80", "service", "tcp/80", facts={"port": 80})],
            ),
            _result(
                "workloads",
                [Node("service:tcp:80", "service", "tcp/80", facts={"port": 8080})],
            ),
        ],
        Config(),
    )
    conflicts = topology.observations["conflicts"]
    assert conflicts
    assert any("port" in conflict for conflict in conflicts)
    # The first observation wins, so the map does not flip between surveys.
    assert topology.nodes["service:tcp:80"].facts["port"] == 80


def test_a_kind_conflict_is_recorded():
    topology = compile_topology(
        [
            _result("network", [Node("iface:lab:en0", "interface", "en0")]),
            _result("workloads", [Node("iface:lab:en0", "workload", "en0")]),
        ],
        Config(),
    )
    conflicts = topology.observations["conflicts"]
    assert any("kind conflict" in conflict for conflict in conflicts)
    # The first observation stands.
    assert topology.nodes["iface:lab:en0"].kind == "interface"


def test_a_dangling_edge_is_pruned_and_noted():
    topology = compile_topology(
        [
            _result(
                "network",
                [Node("host:lab", "host", "lab")],
                [Edge("host:lab", "runs", "workload:ghost", {})],
            )
        ],
        Config(),
    )
    assert not topology.dangling_edges()
    assert any("dangling" in note for note in topology.observations["warnings"])


def test_the_observations_say_which_scanners_ran():
    topology = compile_topology(
        [
            _result("network", [Node("host:lab", "host", "lab")]),
            _result("host", [Node("host:lab", "host", "lab", facts={"cpu_cores": 8})]),
        ],
        Config(),
    )
    scanners = topology.observations["scanners"]
    assert [entry["scanner"] for entry in scanners] == ["network", "host"]
    assert all(entry["ok"] for entry in scanners)


def test_compiling_a_big_survey_is_not_quadratic():
    """A merge that compares every node with every other node would show here.

    The check is a ratio rather than a wall-clock budget, so it does not
    depend on how loaded the machine is.
    """

    import time

    def compile_many(count: int) -> float:
        results = []
        for scanner in range(5):
            nodes = [
                Node(f"workload:scanner{scanner}:n{index}", "workload", f"n{index}")
                for index in range(count // 5)
            ]
            results.append(_result(f"scanner{scanner}", nodes))
        started = time.perf_counter()
        topology = compile_topology(results, Config())
        elapsed = time.perf_counter() - started
        assert len(topology.nodes) == count
        return elapsed

    # Warm up, so the first measurement does not carry the import cost.
    compile_many(200)

    small = compile_many(500)
    large = compile_many(2000)
    if small > 0.005 and large > 0.02:
        # Four times the nodes should cost roughly four times the time, not
        # sixteen.
        ratio = large / small
        assert ratio < 9, f"four times the nodes cost {ratio:.1f} times the time"
