from __future__ import annotations

from dataclasses import replace

from surveyor.differ import CRITICAL, INFO, NOTICE, WARNING, diff_topologies, render_text
from surveyor.model import Edge, Node, Topology

from conftest import build_topology, change_fact, change_telemetry, without_node


def test_identical_surveys_have_no_changes(topology):
    report = diff_topologies(topology, Topology.from_dict(topology.to_dict()))
    assert report.changes == []
    assert report.structural is False
    assert report.headline() == "No change. The map holds."


def test_added_workload_is_a_notice(topology):
    extended = Topology.from_dict(topology.to_dict())
    extended.add(Node("workload:docker:api", "workload", "api", facts={"runtime": "docker", "image": "api:1"}))
    report = diff_topologies(topology, extended)
    changes = report.by_severity(NOTICE)
    assert len(changes) == 1
    assert changes[0].entity == "workload:docker:api"
    assert report.structural is True


def test_removing_a_host_is_critical(topology):
    reduced = without_node(topology, "host:lab")
    report = diff_topologies(topology, reduced)
    critical = [change for change in report.changes if change.severity == CRITICAL]
    assert any(change.entity == "host:lab" and change.action == "removed" for change in critical)
    assert any(change.entity_type == "edge" for change in critical)


def test_removing_a_workload_is_a_warning(topology):
    reduced = without_node(topology, "workload:docker:web")
    report = diff_topologies(topology, reduced)
    removed = [change for change in report.changes if change.action == "removed" and change.entity_type == "node"]
    assert removed and removed[0].severity == WARNING


def test_fact_change_is_structural(topology):
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    modified = report.by_severity(WARNING)
    assert len(modified) == 1
    assert modified[0].field == "image"
    assert modified[0].before == "nginx:1.25"
    assert report.structural is True


def test_telemetry_drift_is_informational_only(topology):
    changed = change_telemetry(topology, "host:lab", "load_1m", 17.5)
    report = diff_topologies(topology, changed)
    assert report.structural is False
    assert len(report.by_severity(INFO)) == 1
    assert report.headline() == "Telemetry drifted; the structure is unchanged."


def test_edge_removal_severity_depends_on_relation(topology):
    changed = Topology.from_dict(topology.to_dict())
    changed.edges = [edge for edge in changed.edges if edge.relation != "powers"]
    report = diff_topologies(topology, changed)
    edge_changes = [change for change in report.changes if change.entity_type == "edge"]
    assert {change.severity for change in edge_changes} == {CRITICAL}


def test_changes_are_sorted_by_severity(topology):
    broken = without_node(topology, "host:lab")
    extended = Topology.from_dict(broken.to_dict())
    extended.add(Node("workload:docker:new", "workload", "new", facts={"runtime": "docker"}))
    report = diff_topologies(topology, extended)
    severities = [change.severity for change in report.changes]
    assert severities == sorted(severities, key=["critical", "warning", "notice", "info"].index)


def test_render_text_hides_telemetry_unless_verbose(topology):
    changed = change_telemetry(topology, "host:lab", "load_1m", 42.0)
    report = diff_topologies(topology, changed)
    terse = render_text(report)
    verbose = render_text(report, verbose=True)
    assert "telemetry drift" in terse
    assert "drifted" in verbose


def test_first_survey_lists_nodes_but_no_edges(topology):
    report = diff_topologies(None, topology)
    assert {change.entity_type for change in report.changes} == {"node"}
    assert len(report.changes) == len(topology.nodes)


def test_edge_addition_is_a_notice(topology):
    extended = Topology.from_dict(topology.to_dict())
    extended.connect(Edge("host:lab", "depends_on", "device:192.168.53.1", {}))
    report = diff_topologies(topology, extended)
    edge_changes = [change for change in report.changes if change.entity_type == "edge"]
    assert edge_changes[0].severity == NOTICE
    assert "depends on" in edge_changes[0].label


def test_label_change_is_reported(topology):
    renamed = Topology.from_dict(topology.to_dict())
    node = renamed.nodes["workload:docker:web"]
    renamed.nodes["workload:docker:web"] = replace(node, label="web-renamed")
    report = diff_topologies(topology, renamed)
    assert [(change.field, change.after) for change in report.changes] == [("label", "web-renamed")]
