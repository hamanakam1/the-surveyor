"""Composing many hosts into one map.

The point of the exercise is that a device is named by its hardware address,
so two hosts that both saw the same router produce the same node, and the
union of their plats joins them together without anyone having to say so.
"""

from __future__ import annotations

from surveyor.fleet import compose, host_sites, summarise, tag_hosts
from surveyor.model import Edge, Node, Topology


def _host_plat(name: str, site: str, gateway_mac: str, gateway_ip: str) -> Topology:
    topology = Topology(site=site, generated_at="2026-01-01T00:00:00Z")
    topology.add(Node(f"host:{name}", "host", name, facts={"hostname": name}))
    topology.add(
        Node(
            f"device:{gateway_mac.replace(':', '-')}",
            "device",
            f"gateway {gateway_ip}",
            facts={"role": "gateway", "address": gateway_ip, "mac": gateway_mac},
            source="network",
        )
    )
    topology.connect(
        Edge(f"host:{name}", "routes_via", f"device:{gateway_mac.replace(':', '-')}", {})
    )
    return topology


def test_two_hosts_see_one_router():
    """The router is one node, not two, because its identity is its hardware."""

    shed = _host_plat("shed", "site-a", "f0:18:98:11:22:33", "192.168.7.1")
    garage = _host_plat("garage", "site-b", "f0:18:98:11:22:33", "192.168.8.1")

    composition = compose([shed, garage], site="edge")

    assert len(composition.hosts) == 2
    assert "host:shed" in composition.hosts
    assert "host:garage" in composition.hosts
    assert len(composition.topology.nodes) == 3
    assert len(composition.topology.edges) == 2
    # Both hosts route through the same node.
    assert {edge.source for edge in composition.topology.edges} == {
        "host:shed",
        "host:garage",
    }


def test_a_disagreement_is_reported_not_resolved():
    shed = _host_plat("shed", "site-a", "f0:18:98:11:22:33", "192.168.7.1")
    garage = _host_plat("garage", "site-b", "f0:18:98:11:22:33", "10.0.0.1")

    composition = compose([shed, garage], site="edge")
    assert composition.conflicts
    assert any("address" in conflict for conflict in composition.conflicts)
    # The map keeps one of them and says so, rather than showing both.
    device = next(
        node for node in composition.topology.nodes.values() if node.kind == "device"
    )
    assert device.facts["address"] in {"192.168.7.1", "10.0.0.1"}


def test_two_names_for_one_device_are_reported_not_merged():
    """A host that has not spoken to its router names it by its address."""

    shed = _host_plat("shed", "site-a", "f0:18:98:11:22:33", "192.168.7.1")
    garage = Topology(site="site-b", generated_at="2026-01-01T00:00:00Z")
    garage.add(Node("host:garage", "host", "garage", facts={"hostname": "garage"}))
    # The same router, named by its address because the host never saw its
    # hardware address.
    garage.add(
        Node(
            "device:192.168.7.1",
            "device",
            "gateway 192.168.7.1",
            facts={"role": "gateway", "address": "192.168.7.1"},
            source="network",
        )
    )
    garage.connect(Edge("host:garage", "routes_via", "device:192.168.7.1", {}))

    composition = compose([shed, garage], site="edge")
    assert composition.ambiguous
    assert any("192.168.7.1" in finding for finding in composition.ambiguous)
    # And the two are still two nodes: the map does not guess.
    assert len(composition.topology.nodes) == 4


def test_hosts_are_tagged_with_their_site():
    shed = _host_plat("shed", "site-a", "f0:18:98:11:22:33", "192.168.7.1")
    garage = _host_plat("garage", "site-b", "aa:bb:cc:dd:ee:ff", "192.168.8.1")

    composition = compose([shed, garage], site="edge")
    sites = host_sites([shed, garage])
    tag_hosts(composition.topology, sites)

    shed_node = composition.topology.nodes["host:shed"]
    assert "site:site-a" in shed_node.tags


def test_tagging_a_composition_preserves_the_source_plat():
    source = _host_plat("shed", "site-a", "f0:18:98:11:22:33", "192.168.7.1")
    original_digest = source.digest
    composition = compose([source])

    tag_hosts(composition.topology, host_sites([source]))

    assert source.digest == original_digest
    assert source.nodes["host:shed"].tags == ()
    assert composition.topology.nodes["host:shed"].tags == ("site:site-a",)


def test_merging_edge_facts_does_not_modify_an_input_plat():
    first = _host_plat("shed", "site-a", "f0:18:98:11:22:33", "192.168.7.1")
    second = Topology.from_dict(first.to_dict())
    second.edges[0].facts["priority"] = 1
    originals = (first.digest, second.digest)

    composition = compose([first, second])

    assert composition.topology.edges[0].facts["priority"] == 1
    assert (first.digest, second.digest) == originals


def test_the_summary_says_what_was_composed():
    shed = _host_plat("shed", "site-a", "f0:18:98:11:22:33", "192.168.7.1")
    composition = compose([shed], site="edge")
    summary = summarise(composition, host_sites([shed]))
    assert summary["hosts"] == ["host:shed"]
    assert summary["nodes"] == 2
    assert summary["edges"] == 1
