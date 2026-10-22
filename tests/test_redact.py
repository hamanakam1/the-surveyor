from __future__ import annotations

from surveyor.model import Edge, Node, Topology
from surveyor.redact import (
    Aliaser,
    audit,
    is_public,
    mask_ip,
    mask_mac,
    redact_topology,
)


def test_mac_addresses_keep_only_the_vendor_prefix():
    assert mask_mac("ether f0:18:98:aa:bb:cc") == "ether f0:18:98:xx:xx:xx"


def test_dash_form_mac_addresses_are_masked_too():
    assert mask_mac("ether f0-18-98-aa-bb-cc") == "ether f0-18-98-xx-xx-xx"


def test_public_addresses_lose_their_host_bits():
    assert mask_ip("93.184.216.34") == "93.184.x.x"
    assert mask_ip("8.8.8.8") == "8.8.x.x"


def test_private_and_loopback_addresses_survive():
    for address in ("192.168.53.9", "10.0.0.5", "127.0.0.1"):
        assert mask_ip(address) == address


def test_public_ipv6_loses_its_host_bits():
    assert mask_ip("2606:2800:220:1:248:1893:25c8:1946") == "2606:2800:220:1::"
    assert mask_ip("fd00::1") == "fd00::1"


def test_public_detection():
    assert is_public("1.1.1.1") is True
    assert is_public("192.168.1.1") is False
    assert is_public("not-an-ip") is False


def test_alias_is_stable_within_a_key():
    first = Aliaser("salt").alias("C02TEST123")
    second = Aliaser("salt").alias("C02TEST123")
    assert first == second
    assert first.startswith("sha256:")
    assert len(first) < 24


def test_alias_differs_between_ledgers():
    """An unkeyed digest of a hostname can be brute-forced. A keyed one cannot."""

    assert Aliaser("salt-a").alias("studio") != Aliaser("salt-b").alias("studio")


def test_alias_collapses_a_name_and_its_slug():
    aliaser = Aliaser("salt")
    assert aliaser.alias("qwen3.8:32b") == aliaser.alias("qwen3-8-32b")


def test_redaction_preserves_structure_but_hides_identifiers(topology):
    redacted = redact_topology(topology, salt="k")
    assert len(redacted.nodes) == len(topology.nodes)
    assert len(redacted.edges) == len(topology.edges)
    assert redacted.observations["redacted"] is True
    assert redacted.observations["redaction_keyed"] is True

    host = next(node for node in redacted.nodes.values() if node.kind == "host")
    assert host.facts["mac"] == "f0:18:98:xx:xx:xx"
    battery = redacted.nodes["power:battery:internal-0"]
    assert battery.facts["serial"].startswith("sha256:")
    assert battery.facts["serial"] != "C02TEST123"
    # The unredacted survey still holds the real value.
    assert topology.nodes["power:battery:internal-0"].facts["serial"] == "C02TEST123"


def test_redaction_aliases_the_hostname_in_ids_and_labels(topology):
    redacted = redact_topology(topology, salt="k")
    assert "host:lab" not in redacted.nodes
    host = next(node for node in redacted.nodes.values() if node.kind == "host")
    assert host.id.startswith("host:sha256:")
    assert "lab" not in host.label


def test_redaction_keeps_the_graph_intact(topology):
    """Aliased ids must still resolve, or the plat is a pile of shards."""

    redacted = redact_topology(topology, salt="k")
    assert not redacted.dangling_edges()
    for edge in redacted.edges:
        assert edge.source in redacted.nodes
        assert edge.target in redacted.nodes


def test_redaction_aliases_container_names():
    survey = Topology(site="x")
    survey.add(Node("host:studio", "host", "studio (Mac15,8)", facts={"hostname": "studio"}))
    survey.add(
        Node(
            "workload:docker:payments",
            "workload",
            "payments",
            facts={"runtime": "docker", "image": "nginx:1.25", "container_id": "abc123def456"},
        )
    )
    survey.add(
        Node(
            "service:tcp:8080",
            "service",
            "tcp/8080 (payments)",
            facts={"port": 8080, "proto": "tcp", "workload": "payments"},
            source="workloads",
        )
    )
    survey.connect(Edge("host:studio", "runs", "workload:docker:payments", {"runtime": "docker"}))
    survey.connect(Edge("workload:docker:payments", "exposes", "service:tcp:8080", {"container_port": 80}))

    redacted = redact_topology(survey, salt="k")
    document = redacted.to_dict()
    assert "payments" not in str(document)
    assert "studio" not in str(document)
    assert "abc123def456" not in str(document)
    # The shape survives: the same kinds, the same edges, the same ports.
    assert len(redacted.nodes) == 3
    assert len(redacted.edges) == 2
    assert not redacted.dangling_edges()
    service = next(node for node in redacted.nodes.values() if node.kind == "service")
    assert service.facts["port"] == 8080


def test_redaction_aliases_model_names():
    survey = Topology(site="x")
    survey.add(
        Node(
            "model:qwen3-8-32b",
            "model",
            "qwen3.8:32b",
            facts={"name": "qwen3.8:32b", "parameter_size": "32.8B", "digest": "a80c4f17acd5"},
            source="workloads",
        )
    )
    redacted = redact_topology(survey, salt="k")
    document = str(redacted.to_dict())
    assert "qwen3.8:32b" not in document
    assert "qwen3-8-32b" not in document
    assert "a80c4f17acd5" not in document
    # The shape of the model survives: how big it is.
    model = next(iter(redacted.nodes.values()))
    assert model.facts["parameter_size"] == "32.8B"


def test_redaction_aliases_the_owner_of_a_namespaced_image():
    survey = Topology(site="x")
    survey.add(
        Node(
            "workload:docker:app",
            "workload",
            "app",
            facts={"runtime": "docker", "image": "ghcr.io/acme-internal/payments:3.1"},
        )
    )
    redacted = redact_topology(survey, salt="k")
    image = next(iter(redacted.nodes.values())).facts["image"]
    assert "acme-internal" not in image
    assert "payments" in image


def test_official_images_are_left_alone():
    survey = Topology(site="x")
    survey.add(
        Node(
            "workload:docker:web",
            "workload",
            "web",
            facts={"runtime": "docker", "image": "nginx:1.25"},
        )
    )
    redacted = redact_topology(survey, salt="k")
    assert next(iter(redacted.nodes.values())).facts["image"] == "nginx:1.25"


def test_redaction_aliases_ssids():
    survey = Topology(site="x")
    survey.add(Node("iface:x:en0", "interface", "en0", facts={"wifi_ssid": "Hamanaka HQ"}))
    redacted = redact_topology(survey, salt="k")
    interface = next(node for node in redacted.nodes.values() if node.kind == "interface")
    alias = interface.facts["wifi_ssid"]
    assert alias.startswith("sha256:")
    assert "Hamanaka" not in alias


def test_redaction_aliases_listener_processes():
    survey = Topology(site="x")
    survey.add(
        Node(
            "service:tcp:5000",
            "service",
            "tcp/5000 (ControlCe)",
            facts={"port": 5000, "proto": "tcp", "processes": ["ControlCe"]},
        )
    )
    redacted = redact_topology(survey, salt="k")
    document = str(redacted.to_dict())
    assert "ControlCe" not in document


def test_redaction_preserves_hardware_model():
    """The class of machine is shape, not identity."""

    survey = Topology(site="x")
    survey.add(
        Node(
            "host:studio",
            "host",
            "studio (Mac15,8)",
            facts={"hostname": "studio", "model": "Mac15,8", "cpu_model": "Apple M3 Max"},
        )
    )
    redacted = redact_topology(survey, salt="k")
    host = next(iter(redacted.nodes.values()))
    assert host.facts["model"] == "Mac15,8"
    assert host.facts["cpu_model"] == "Apple M3 Max"


def test_observation_notes_are_masked_too(topology):
    topology.observations = {
        "warnings": ["interface f0:18:98:aa:bb:cc took 93.184.216.34 as a peer"],
        "conflicts": [],
    }
    redacted = redact_topology(topology, salt="k")
    warning = redacted.observations["warnings"][0]
    assert "f0:18:98:aa:bb:cc" not in warning
    assert "93.184.216.34" not in warning
    assert "f0:18:98:xx:xx:xx" in warning


def test_observation_hostname_is_aliased(topology):
    topology.observations = {"hostname": "lab", "warnings": [], "conflicts": []}
    redacted = redact_topology(topology, salt="k")
    assert redacted.observations["hostname"].startswith("sha256:")
    assert "lab" not in redacted.observations["hostname"]


def test_redacted_documents_are_self_consistent(topology):
    redacted = redact_topology(topology, salt="k")
    document = redacted.to_dict()
    restored = Topology.from_dict(document)
    assert restored.fingerprint == redacted.fingerprint
    assert restored.fingerprint == document["fingerprint"]
    assert restored.digest == redacted.digest


def test_audit_reports_a_survivor():
    """A value the policy does not know about must still be reported."""

    survey = Topology(site="x")
    survey.add(
        Node(
            "host:studio",
            "host",
            "studio",
            facts={"hostname": "studio", "operator_note": "mail ada@example.com"},
        )
    )
    redacted = redact_topology(survey, salt="k")
    findings = audit(survey, redacted, Aliaser("k"))
    kinds = {finding.kind for finding in findings}
    assert "known-identifier" not in kinds
    # The note is not a declared identifier, but an email address is an
    # identifier, and the audit is supposed to make the operator look.
    assert "email" in kinds
    assert any(finding.value == "ada@example.com" for finding in findings)


def test_audit_is_quiet_on_a_clean_plat(topology):
    redacted = redact_topology(topology, salt="k")
    findings = audit(topology, redacted, Aliaser("k"))
    assert not [finding for finding in findings if finding.kind == "known-identifier"]
