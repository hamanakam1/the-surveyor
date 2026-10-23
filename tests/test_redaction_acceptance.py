"""The acceptance test for redaction.

The roadmap promised one thing about ``--redact``: *"a test that takes a plat
containing every identifier shape the scanners can currently emit and asserts
that the redacted plat contains none of them, except the ones the policy
explicitly preserves."*

This is that test. It is deliberately one document with every shape in it, so
a scanner that starts emitting a new kind of identifier shows up as a failure
here rather than as a leak.
"""

from __future__ import annotations

import json

import pytest

from surveyor.model import Edge, Node, Topology
from surveyor.redact import Aliaser, audit, redact_topology

#: Every identifier the scanners can currently produce, and the value that
#: must not survive redaction.
IDENTIFIERS = (
    "studio",  # the hostname
    "payments",  # a container name
    "acme-internal",  # an image registry owner
    "Hamanaka HQ",  # a Wi-Fi network
    "C02TEST1234",  # a battery serial
    "3C:22:FB:44:55:66",  # a hardware address
    "00:11:22:33:44:55",  # another hardware address, in dash form
    "E4:5F:01:02:03:04",  # a third
    "550e8400-e29b-41d4-a716-446655440000",  # a UUID
    "llama3.2:3b",  # a local model
    "ada",  # the operator's own name, in a path
)

#: The values that are deliberately kept: a topology without them is a mood
#: board, and they do not identify a machine.
PRESERVED = (
    "192.168.53.209",  # a private address
    "192.168.53.0/24",  # a private subnet
    "Mac15,8",  # the class of machine
    "Apple M3 Max",  # its CPU
    "ghcr.io",  # a public registry host, shared by thousands of images
)


def _everything_plat() -> Topology:
    """A plat carrying every identifier shape the scanners emit."""

    topology = Topology(site="edge-lab", generated_at="2026-01-01T00:00:00Z")

    topology.add(
        Node(
            "host:studio",
            "host",
            "studio (Mac15,8)",
            facts={
                "hostname": "studio",
                "model": "Mac15,8",
                "cpu_model": "Apple M3 Max",
                "mac": "3C:22:FB:44:55:66",
                "hardware_uuid": "E4:5F:01:02:03:04",
                "serial": "C02TEST1234",
            },
            telemetry={"load_1m": 0.4},
            tags=("site-host",),
            source="host",
        )
    )
    topology.add(
        Node(
            "iface:studio:en0",
            "interface",
            "en0 (wifi)",
            facts={
                "name": "en0",
                "mac": "00:11:22:33:44:55",
                "address": "192.168.53.209",
                "ipv4": ["192.168.53.209/24"],
                "wifi_ssid": "Hamanaka HQ",
            },
            telemetry={"up": True},
            tags=("wifi",),
            source="network",
        )
    )
    topology.add(
        Node(
            "network:192.168.53.0/24",
            "network",
            "192.168.53.0/24",
            facts={"cidr": "192.168.53.0/24", "family": "ipv4", "private": True},
            tags=("subnet", "private"),
            source="network",
        )
    )
    topology.add(
        Node(
            "device:f0-18-98-11-22-33",
            "device",
            "gateway 192.168.53.1",
            facts={
                "role": "gateway",
                "address": "192.168.53.1",
                "mac": "f0:18:98:11:22:33",
            },
            tags=("gateway", "observed"),
            source="network",
        )
    )
    topology.add(
        Node(
            "workload:docker:payments",
            "workload",
            "payments",
            facts={
                "runtime": "docker",
                "image": "ghcr.io/acme-internal/payments:3.1",
                "container_id": "abc123def456",
                "compose_project": "acme-internal",
                "compose_service": "payments",
            },
            telemetry={"status": "Up 3 hours"},
            tags=("container", "docker"),
            source="workloads",
        )
    )
    topology.add(
        Node(
            "model:llama3-2-3b",
            "model",
            "llama3.2:3b",
            facts={"name": "llama3.2:3b", "digest": "a80c4f17acd5"},
            tags=("model",),
            source="workloads",
        )
    )
    topology.add(
        Node(
            "service:tcp:8080",
            "service",
            "tcp/8080 (payments)",
            facts={"port": 8080, "proto": "tcp", "workload": "payments"},
            tags=("published", "docker"),
            source="workloads",
        )
    )
    topology.add(
        Node(
            "volume:pgdata",
            "volume",
            "pgdata",
            facts={
                "type": "bind",
                "destination": "/data",
                "host_path": "/Users/ada/data",
            },
            tags=("volume", "bind"),
            source="workloads",
        )
    )
    topology.connect(Edge("host:studio", "runs", "workload:docker:payments", {"runtime": "docker"}))
    topology.connect(Edge("workload:docker:payments", "exposes", "service:tcp:8080", {"container_port": 80}))
    topology.connect(Edge("host:studio", "hosts", "iface:studio:en0", {"role": "interface"}))
    topology.connect(Edge("iface:studio:en0", "attaches_to", "network:192.168.53.0/24", {"address": "192.168.53.209"}))
    topology.connect(Edge("host:studio", "routes_via", "device:f0-18-98-11-22-33", {"role": "default"}))
    topology.connect(Edge("workload:docker:payments", "attaches_to", "volume:pgdata", {"destination": "/data"}))
    topology.observations = {
        "platform": "darwin/arm64",
        "hostname": "studio",
        "warnings": ["payments took 192.168.53.209 while scanning on studio"],
        "conflicts": [],
    }
    return topology


def test_no_identifier_survives_redaction():
    """Every identifier shape the scanners emit, checked in one document."""

    topology = _everything_plat()
    redacted = redact_topology(topology, salt="a-key")
    document = json.dumps(redacted.to_dict())

    for identifier in IDENTIFIERS:
        assert identifier not in document, f"{identifier!r} survived redaction"
        assert identifier.lower() not in document.lower(), (
            f"{identifier!r} survived redaction (ignoring case)"
        )


def test_the_values_the_policy_keeps_are_kept():
    topology = _everything_plat()
    redacted = redact_topology(topology, salt="a-key")
    document = json.dumps(redacted.to_dict())

    for kept in PRESERVED:
        assert kept in document, f"{kept!r} should have been kept"


def test_the_redacted_plat_is_still_a_plat():
    topology = _everything_plat()
    redacted = redact_topology(topology, salt="a-key")

    assert len(redacted.nodes) == len(topology.nodes)
    assert len(redacted.edges) == len(topology.edges)
    assert not redacted.dangling_edges()
    assert redacted.fingerprint == redacted.to_dict()["fingerprint"]


def test_the_audit_finds_nothing_in_a_clean_plat():
    topology = _everything_plat()
    redacted = redact_topology(topology, salt="a-key")
    findings = audit(topology, redacted, Aliaser("a-key"))
    assert not [finding for finding in findings if finding.kind == "known-identifier"]


def test_the_same_key_gives_the_same_alias_and_a_different_key_does_not():
    first = redact_topology(_everything_plat(), salt="key-one")
    second = redact_topology(_everything_plat(), salt="key-two")
    third = redact_topology(_everything_plat(), salt="key-one")

    assert first.to_dict() == third.to_dict(), "the same key must be stable"
    assert first.to_dict() != second.to_dict(), "a different key must differ"


@pytest.mark.parametrize("salt", ["", "key-one"])
def test_redacting_a_redacted_plat_preserves_the_document_and_graph(salt):
    topology = _everything_plat()
    topology.nodes["host:studio"].facts["serial_number"] = {"board": "BOARD-EXAMPLE"}
    topology.nodes["host:studio"].telemetry["serial"] = "TELEMETRY-EXAMPLE"
    topology.nodes["service:tcp:8080"].facts["processes"] = ["worker", "logger"]
    next(edge for edge in topology.edges if edge.relation == "runs").facts["container"] = "payments"
    first = redact_topology(topology, salt=salt)
    restored = Topology.from_dict(first.to_dict())
    second = redact_topology(restored, salt=salt)

    assert second.to_dict() == first.to_dict()
    assert second.fingerprint == first.fingerprint
    assert len(second.nodes) == len(topology.nodes)
    assert len(second.edges) == len(topology.edges)
    assert not second.dangling_edges()
    for edge in second.edges:
        assert edge.source in second.nodes
        assert edge.target in second.nodes
