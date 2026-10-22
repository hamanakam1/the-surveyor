from __future__ import annotations

import pytest

from surveyor.config import Config
from surveyor.differ import diff_topologies
from surveyor.errors import LLMError
from surveyor.scribe import compose_changelog, narrative, polish

from conftest import build_topology, change_fact, change_telemetry, without_node


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
