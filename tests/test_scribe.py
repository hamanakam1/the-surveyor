from __future__ import annotations

import pytest

from conftest import build_topology, change_fact, change_telemetry, without_node
from surveyor.config import Config
from surveyor.differ import diff_topologies
from surveyor.errors import LLMError
from surveyor.model import Edge, Node, Topology
from surveyor.scribe import compose_changelog, narrative, polish


def test_narrative_for_the_first_plat_reads_like_a_surveyor():
    topology = build_topology()
    report = diff_topologies(None, topology)
    text = narrative(report, topology, None)
    assert text.startswith("The theodolite is levelled")
    assert "Power arrives from AC mains" in text
    assert "listening socket" in text


def test_narrative_reports_loss_of_a_host():
    topology = build_topology()
    reduced = without_node(topology, "host:lab")
    report = diff_topologies(topology, reduced)
    text = narrative(report, reduced, topology)
    assert "Sight was lost" in text


def test_narrative_invents_nothing(topology):
    changed = change_telemetry(topology, "host:lab", "load_1m", 9.0)
    report = diff_topologies(topology, changed)
    text = narrative(report, changed, topology)
    assert "weather" in text
    assert "9.0" not in text


def test_narrative_never_claims_the_weather_moved_when_the_map_did(topology):
    """A notice-only diff is still structural. The prose must say so."""

    extended = Topology.from_dict(topology.to_dict())
    extended.add(Node("workload:docker:api", "workload", "api", facts={"runtime": "docker"}))
    report = diff_topologies(topology, extended)
    assert report.structural is True
    text = narrative(report, extended, topology)
    assert "weather" not in text
    assert "api" in text


def test_narrative_names_nodes_before_edges(topology):
    extended = Topology.from_dict(topology.to_dict())
    extended.connect(Edge("host:lab", "runs", "workload:docker:api", {}))
    extended.add(
        Node("workload:docker:api", "workload", "api", facts={"runtime": "docker"})
    )
    report = diff_topologies(topology, extended)
    text = narrative(report, extended, topology)
    assert "api appeared on the plat" in text


def test_narrative_survives_a_diff_of_edges_only(topology):
    extended = Topology.from_dict(topology.to_dict())
    extended.connect(Edge("workload:docker:web", "depends_on", "device:192.168.53.1", {}))
    report = diff_topologies(topology, extended)
    text = narrative(report, extended, topology)
    assert "weather" not in text
    assert "appeared on the plat" in text


def test_markdown_contains_facts_and_no_model_when_template(topology):
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    output = compose_changelog(report, changed, previous=topology, backend="template")
    assert output.backend == "template"
    assert output.warning == ""
    assert "# Survey change log" in output.markdown
    assert "## Structural changes" in output.markdown
    assert "nginx:1.25" in output.markdown
    assert "nginx:1.27" in output.markdown
    assert "scribe: template" in output.markdown


@pytest.mark.parametrize(
    ("attribute", "field", "value"),
    [("site", "site", "other-site"), ("schema_version", "oet_version", "1.1")],
)
def test_markdown_reports_plat_metadata_changes(topology, attribute, field, value):
    changed = Topology.from_dict(topology.to_dict())
    setattr(changed, attribute, value)
    report = diff_topologies(topology, changed)

    output = compose_changelog(report, changed, previous=topology, backend="template")

    assert "### Plat metadata" in output.markdown
    assert f"{field}: `{getattr(topology, attribute)}` → `{value}`" in output.markdown
    assert "1 notice" in output.markdown
    assert "Nothing structural moved" not in output.narrative
    assert "weather" not in output.narrative


def test_metadata_group_keeps_node_changes_in_their_layer(topology):
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    changed.site = "other-site"
    report = diff_topologies(topology, changed)

    output = compose_changelog(report, changed, previous=topology, backend="template")

    assert "### Workloads" in output.markdown
    assert "### Plat metadata" in output.markdown
    assert "image: `nginx:1.25` → `nginx:1.27`" in output.markdown
    assert "site: `test-site` → `other-site`" in output.markdown


def test_markdown_keeps_each_modified_edge_fact(topology):
    changed = Topology.from_dict(topology.to_dict())
    power = next(edge for edge in changed.edges if edge.source == "power:ac")
    power.facts["priority"] = 9
    service = next(edge for edge in changed.edges if edge.relation == "exposes")
    service.facts["container_port"] = 9000
    report = diff_topologies(topology, changed)

    output = compose_changelog(report, changed, previous=topology, backend="template")

    assert len(report.changes) == 2
    assert "priority: `1` → `9`" in output.markdown
    assert "container_port: `80` → `9000`" in output.markdown


def test_markdown_includes_operator_note(topology):
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    output = compose_changelog(report, changed, previous=topology, note="deployed by hand")
    assert "> deployed by hand" in output.markdown


def test_markdown_flags_critical_changes(topology):
    reduced = without_node(topology, "host:lab")
    report = diff_topologies(topology, reduced)
    output = compose_changelog(report, reduced, previous=topology)
    assert "critical change" in output.markdown


def test_telemetry_only_has_no_structural_section(topology):
    changed = change_telemetry(topology, "host:lab", "load_1m", 3.0)
    report = diff_topologies(topology, changed)
    output = compose_changelog(report, changed, previous=topology)
    assert "## Structural changes" not in output.markdown
    assert "Telemetry drift" in output.markdown


def test_ollama_failure_falls_back_to_the_deterministic_draft(topology):
    config = Config(scribe="ollama", ollama_endpoint="http://127.0.0.1:9", llm_timeout=0.3)
    changed = change_fact(topology, "workload:docker:web", "image", "nginx:1.27")
    report = diff_topologies(topology, changed)
    output = compose_changelog(report, changed, previous=topology, config=config)
    assert output.backend == "template"
    assert "local model unavailable" in output.warning
    assert "nginx:1.27" in output.markdown


def test_polish_raises_llm_error_when_the_endpoint_is_dead():
    config = Config(scribe="ollama", ollama_endpoint="http://127.0.0.1:9", llm_timeout=0.2)
    topology = build_topology()
    changed = change_fact(topology, "workload:docker:web", "image", "api:2")
    report = diff_topologies(topology, changed)
    with pytest.raises(LLMError):
        polish("draft", report, config)
