from __future__ import annotations

import json
from dataclasses import replace

import pytest

from conftest import change_fact, change_telemetry, without_node
from surveyor import cli
from surveyor.differ import CRITICAL, INFO, NOTICE, WARNING, diff_topologies, render_text
from surveyor.model import Edge, Node, Topology


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


def test_edge_changes_inherit_the_layer_of_their_source(topology):
    extended = Topology.from_dict(topology.to_dict())
    extended.connect(Edge("workload:docker:web", "depends_on", "device:192.168.53.1", {}))
    report = diff_topologies(topology, extended)
    edge_changes = [change for change in report.changes if change.entity_type == "edge"]
    assert len(edge_changes) == 1
    assert edge_changes[0].layer == "workload"
    assert "Unaligned" not in render_text(report)


def test_label_change_is_reported(topology):
    renamed = Topology.from_dict(topology.to_dict())
    node = renamed.nodes["workload:docker:web"]
    renamed.nodes["workload:docker:web"] = replace(node, label="web-renamed")
    report = diff_topologies(topology, renamed)
    assert [(change.field, change.after) for change in report.changes] == [("label", "web-renamed")]


@pytest.mark.parametrize(
    ("field", "value", "severity"),
    [
        ("kind", "service", WARNING),
        ("layer", "network", WARNING),
        ("tags", ("compose",), NOTICE),
    ],
)
def test_node_shape_changes_are_structural(topology, field, value, severity):
    changed = Topology.from_dict(topology.to_dict())
    node_id = "workload:docker:web"
    before = changed.nodes[node_id]
    changed.nodes[node_id] = replace(before, **{field: value})

    report = diff_topologies(topology, changed)

    assert changed.fingerprint != topology.fingerprint
    assert report.structural is True
    assert len(report.changes) == 1
    change = report.changes[0]
    assert (change.entity_type, change.entity, change.field) == ("node", node_id, field)
    assert change.action == "modified"
    assert change.severity == severity
    assert change.before == getattr(before, field)
    assert change.after == value
    assert change.layer == changed.nodes[node_id].layer


def test_removed_node_tags_are_reported(topology):
    changed = Topology.from_dict(topology.to_dict())
    node_id = "device:192.168.53.1"
    changed.nodes[node_id] = replace(changed.nodes[node_id], tags=())

    report = diff_topologies(topology, changed)

    assert report.structural is True
    assert [(change.field, change.before, change.after) for change in report.changes] == [
        ("tags", ("gateway", "unverified"), ()),
    ]


def test_node_tag_order_and_source_do_not_change_structure(topology):
    changed = Topology.from_dict(topology.to_dict())
    node_id = "device:192.168.53.1"
    node = changed.nodes[node_id]
    changed.nodes[node_id] = replace(node, tags=tuple(reversed(node.tags)), source="other")

    assert changed.fingerprint == topology.fingerprint
    assert diff_topologies(topology, changed).changes == []


@pytest.mark.parametrize(("before", "after"), [(1, 2), (None, 2), (1, None)])
def test_edge_fact_changes_are_structural(topology, before, after):
    edge_id = "power:ac|powers|host:lab"
    previous_edge = next(edge for edge in topology.edges if edge.id == edge_id)
    previous_edge.facts = {"priority": before} if before is not None else {}
    changed = Topology.from_dict(topology.to_dict())
    current_edge = next(edge for edge in changed.edges if edge.id == edge_id)
    current_edge.facts = {"priority": after} if after is not None else {}

    report = diff_topologies(topology, changed)

    assert changed.fingerprint != topology.fingerprint
    assert report.structural is True
    assert len(report.changes) == 1
    change = report.changes[0]
    assert (change.entity_type, change.entity, change.field) == ("edge", edge_id, "priority")
    assert change.action == "modified"
    assert change.severity == WARNING
    assert change.before == before
    assert change.after == after
    assert change.layer == "power"
    assert "priority" in change.summary
    assert "priority" in render_text(report)


def test_edge_fact_changes_show_values_in_text(topology):
    changed = Topology.from_dict(topology.to_dict())
    edge = next(edge for edge in changed.edges if edge.relation == "exposes")
    edge.facts["container_port"] = 8080

    report = diff_topologies(topology, changed)

    assert report.structural is True
    assert report.changes[0].severity == WARNING
    assert "container_port 80 -> 8080" in report.changes[0].summary
    assert "container_port 80 -> 8080" in render_text(report)


@pytest.mark.parametrize(("before", "after"), [(1, 2), (None, 2), (1, None)])
def test_volatile_edge_facts_are_informational(topology, before, after):
    if before is not None:
        topology.edges[0].facts["rx_bytes"] = before
    changed = Topology.from_dict(topology.to_dict())
    if after is None:
        changed.edges[0].facts.pop("rx_bytes", None)
    else:
        changed.edges[0].facts["rx_bytes"] = after

    report = diff_topologies(topology, changed)

    assert changed.fingerprint == topology.fingerprint
    assert report.structural is False
    assert len(report.changes) == 1
    change = report.changes[0]
    assert (change.action, change.severity, change.field) == ("drifted", INFO, "rx_bytes")
    assert change.before == before
    assert change.after == after
    assert change.label not in render_text(report)
    assert f"drifted {change.label}" in render_text(report, verbose=True)


@pytest.mark.parametrize("entity_type", ["node", "edge"])
def test_diff_exit_code_for_previously_unreported_changes(topology, entity_type, tmp_path, capsys):
    changed = Topology.from_dict(topology.to_dict())
    if entity_type == "node":
        changed.nodes["host:lab"].tags = ("primary",)
    else:
        changed.edges[0].facts["priority"] = 42
    old_file = tmp_path / "previous.oet.json"
    new_file = tmp_path / "current.oet.json"
    old_file.write_text(json.dumps(topology.to_dict()))
    new_file.write_text(json.dumps(changed.to_dict()))

    exit_code = cli.main([
        "--store", str(tmp_path / "ledger"), "diff", "--exit-code", "--format", "json",
        "--from", str(old_file), "--to", str(new_file),
    ])

    assert exit_code == cli.EXIT_CHANGED
    assert json.loads(capsys.readouterr().out)["structural"] is True


@pytest.mark.parametrize("entity_type", ["node", "edge"])
@pytest.mark.parametrize(
    ("before", "after"),
    [(True, 1), (False, 0), (80, 80.0), ({"enabled": True}, {"enabled": 1}), ([False], [0])],
)
def test_json_fact_types_are_part_of_structure(topology, entity_type, before, after):
    if entity_type == "node":
        topology.nodes["host:lab"].facts["configuration"] = before
    else:
        topology.edges[0].facts["configuration"] = before
    changed = Topology.from_dict(topology.to_dict())
    if entity_type == "node":
        changed.nodes["host:lab"].facts["configuration"] = after
    else:
        changed.edges[0].facts["configuration"] = after
    # Exercise the values as they arrive from JSON, including nested types.
    changed = Topology.from_dict(json.loads(json.dumps(changed.to_dict())))

    report = diff_topologies(topology, changed)

    assert changed.fingerprint != topology.fingerprint
    assert report.structural is True
    assert len(report.changes) == 1
    change = report.changes[0]
    assert (change.entity_type, change.field, change.severity) == (
        entity_type, "configuration", WARNING,
    )
    assert json.dumps(change.before) == json.dumps(before)
    assert json.dumps(change.after) == json.dumps(after)


def test_volatile_edge_fact_type_changes_remain_informational(topology):
    topology.edges[0].facts["rx_bytes"] = 1
    changed = Topology.from_dict(topology.to_dict())
    changed.edges[0].facts["rx_bytes"] = 1.0

    report = diff_topologies(topology, changed)

    assert changed.fingerprint == topology.fingerprint
    assert report.structural is False
    assert len(report.changes) == 1
    change = report.changes[0]
    assert (change.action, change.field, change.severity) == ("drifted", "rx_bytes", INFO)


@pytest.mark.parametrize("entity_type", ["node", "edge"])
def test_nested_fact_key_order_is_not_a_change(topology, entity_type):
    before = {"configuration": {"enabled": True, "port": 80}}
    after = {"configuration": {"port": 80, "enabled": True}}
    if entity_type == "node":
        topology.nodes["host:lab"].facts = before
    else:
        topology.edges[0].facts = before
    changed = Topology.from_dict(topology.to_dict())
    if entity_type == "node":
        changed.nodes["host:lab"].facts = after
    else:
        changed.edges[0].facts = after

    assert changed.fingerprint == topology.fingerprint
    assert diff_topologies(topology, changed).changes == []


@pytest.mark.parametrize("entity_type", ["node", "edge"])
@pytest.mark.parametrize("removed", [False, True])
def test_null_fact_presence_changes_are_structural(topology, entity_type, removed):
    changed = Topology.from_dict(topology.to_dict())
    with_null = topology if removed else changed
    # Scanner code can mutate facts directly after model construction.
    if entity_type == "node":
        with_null.nodes["host:lab"].facts["configuration"] = None
    else:
        with_null.edges[0].facts["configuration"] = None

    report = diff_topologies(topology, changed)

    assert changed.fingerprint != topology.fingerprint
    assert report.structural is True
    assert len(report.changes) == 1
    change = report.changes[0]
    assert (change.entity_type, change.field, change.severity) == (
        entity_type, "configuration", WARNING,
    )
