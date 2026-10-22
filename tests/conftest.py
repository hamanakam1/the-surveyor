"""Synthetic survey plats used across the test suite."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from surveyor.model import Edge, Node, Topology


def build_topology(**overrides: Any) -> Topology:
    topology = Topology(site="test-site", generated_at="2026-01-01T00:00:00Z")
    topology.add(
        Node(
            "power:ac",
            "power_source",
            "AC mains",
            facts={"role": "ac", "source": "utility"},
            telemetry={"present": True},
            source="power",
        )
    )
    topology.add(
        Node(
            "power:battery:internal-0",
            "power_source",
            "Internal battery",
            facts={"role": "battery", "chemistry": "li-ion", "serial": "C02TEST123"},
            telemetry={"charge_percent": 92},
            source="power",
        )
    )
    topology.add(
        Node(
            "host:lab",
            "host",
            "lab (Mac15,8)",
            facts={"cpu_model": "Apple M3 Max", "cpu_cores": 16, "mem_total_gib": 128, "mac": "f0:18:98:aa:bb:cc"},
            telemetry={"load_1m": 1.2, "mem_available_gib": 40.0},
            source="host",
        )
    )
    topology.add(
        Node(
            "iface:lab:en0",
            "interface",
            "en0 (wifi)",
            facts={"name": "en0", "kind": "wifi", "address": "192.168.53.9", "ipv4": ["192.168.53.9/24"]},
            source="network",
        )
    )
    topology.add(
        Node(
            "network:192.168.53.0/24",
            "network",
            "192.168.53.0/24",
            facts={"cidr": "192.168.53.0/24", "private": True},
            source="network",
        )
    )
    topology.add(
        Node(
            "device:192.168.53.1",
            "device",
            "gateway 192.168.53.1",
            facts={"role": "gateway", "address": "192.168.53.1"},
            tags=("gateway", "unverified"),
            source="network",
        )
    )
    topology.add(
        Node(
            "workload:docker:web",
            "workload",
            "web",
            facts={"runtime": "docker", "image": "nginx:1.25", "container_id": "abc123def456"},
            telemetry={"status": "Up 3 hours"},
            source="workloads",
        )
    )
    topology.add(
        Node(
            "service:tcp:8080",
            "service",
            "tcp/8080 (web)",
            facts={"port": 8080, "proto": "tcp", "published": True},
            tags=("published", "docker"),
            source="workloads",
        )
    )
    topology.connect(Edge("power:ac", "powers", "host:lab", {"priority": 1}))
    topology.connect(Edge("power:battery:internal-0", "powers", "host:lab", {"priority": 3}))
    topology.connect(Edge("host:lab", "hosts", "iface:lab:en0", {"role": "interface"}))
    topology.connect(Edge("iface:lab:en0", "attaches_to", "network:192.168.53.0/24", {}))
    topology.connect(Edge("host:lab", "routes_via", "device:192.168.53.1", {"role": "default"}))
    topology.connect(Edge("host:lab", "runs", "workload:docker:web", {"runtime": "docker"}))
    topology.connect(Edge("workload:docker:web", "exposes", "service:tcp:8080", {"container_port": 80}))
    for key, value in overrides.items():
        setattr(topology, key, value)
    return topology


def with_node(topology: Topology, node: Node) -> Topology:
    clone = Topology.from_dict(topology.to_dict())
    clone.add(node)
    return clone


def without_node(topology: Topology, node_id: str) -> Topology:
    clone = Topology.from_dict(topology.to_dict())
    del clone.nodes[node_id]
    clone.prune_dangling()
    return clone


def change_fact(topology: Topology, node_id: str, key: str, value: Any) -> Topology:
    clone = Topology.from_dict(topology.to_dict())
    node = clone.nodes[node_id]
    clone.nodes[node_id] = replace(node, facts={**node.facts, key: value})
    return clone


def change_telemetry(topology: Topology, node_id: str, key: str, value: Any) -> Topology:
    clone = Topology.from_dict(topology.to_dict())
    node = clone.nodes[node_id]
    clone.nodes[node_id] = replace(node, telemetry={**node.telemetry, key: value})
    return clone


@pytest.fixture()
def topology() -> Topology:
    return build_topology()


@pytest.fixture()
def tmp_ledger(tmp_path):
    from surveyor.store import Ledger

    return Ledger(tmp_path / "ledger")
