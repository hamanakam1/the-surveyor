from __future__ import annotations

import pytest

from surveyor.errors import SchemaError
from surveyor.model import Edge, Node, Topology, kind_layer


def test_fingerprint_ignores_telemetry_and_time(topology):
    later = Topology.from_dict(topology.to_dict())
    later.generated_at = "2027-06-06T06:06:06Z"
    later.nodes["host:lab"].telemetry["load_1m"] = 99.0
    later.nodes["power:battery:internal-0"].telemetry["charge_percent"] = 3
    assert later.fingerprint == topology.fingerprint


def test_fingerprint_ignores_volatile_facts(topology):
    changed = Topology.from_dict(topology.to_dict())
    changed.nodes["host:lab"].facts["load_1m"] = 12.5
    assert changed.fingerprint == topology.fingerprint


def test_fingerprint_tracks_structural_facts(topology):
    changed = Topology.from_dict(topology.to_dict())
    changed.nodes["workload:docker:web"].facts["image"] = "nginx:1.27"
    assert changed.fingerprint != topology.fingerprint


def test_digest_tracks_the_document_not_only_structure(topology):
    changed = Topology.from_dict(topology.to_dict())
    changed.nodes["host:lab"].telemetry["load_1m"] = 9.9
    assert changed.digest != topology.digest
    assert changed.fingerprint == topology.fingerprint


def test_node_merge_keeps_first_fact_and_union_tags():
    first = Node("service:tcp:1", "service", "tcp/1", facts={"port": 1, "published": True}, tags=("a",))
    second = Node("service:tcp:1", "service", "tcp/1", facts={"port": 2, "processes": ["x"]}, tags=("b",))
    merged = first.merge(second)
    assert merged.facts["port"] == 1
    assert merged.facts["published"] is True
    assert merged.facts["processes"] == ["x"]
    assert merged.tags == ("a", "b")


def test_edges_are_deduplicated_and_sorted(topology):
    doubled = Topology.from_dict(topology.to_dict())
    doubled.edges.append(Edge("power:ac", "powers", "host:lab", {"priority": 1}))
    doubled.edges = Topology._dedupe_edges(doubled.edges)
    ids = [edge.id for edge in doubled.edges]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_unknown_kind_and_relation_are_rejected():
    with pytest.raises(SchemaError):
        Node("x", "mystery", "x")
    with pytest.raises(SchemaError):
        Edge("a", "bewitches", "b")


def test_device_nodes_live_in_the_network_layer():
    assert kind_layer("device") == "network"
    assert kind_layer("power_source") == "power"
    assert kind_layer("workload") == "workload"


def test_prune_dangling_edges(topology):
    broken = Topology.from_dict(topology.to_dict())
    broken.nodes.pop("workload:docker:web")
    dangling = broken.prune_dangling()
    assert dangling
    assert not broken.dangling_edges()


def test_fingerprint_is_independent_of_edge_order(topology):
    shuffled = Topology.from_dict(topology.to_dict())
    shuffled.edges.reverse()
    shuffled.edges.append(shuffled.edges.pop(0))
    assert shuffled.fingerprint == topology.fingerprint


def test_round_trip_preserves_shape(topology):
    restored = Topology.from_dict(topology.to_dict())
    assert restored.fingerprint == topology.fingerprint
    assert restored.site == topology.site


def test_from_dict_rejects_duplicate_ids(topology):
    document = topology.to_dict()
    document["nodes"].append(document["nodes"][0])
    with pytest.raises(SchemaError, match="duplicate node id"):
        Topology.from_dict(document)


def test_from_dict_rejects_unknown_schema_version(topology):
    document = topology.to_dict()
    document["oet_version"] = "9.9"
    with pytest.raises(SchemaError, match="unsupported OET version"):
        Topology.from_dict(document)


def test_counts_are_complete(topology):
    counts = topology.counts()
    assert counts["nodes"] == len(topology.nodes)
    assert counts["edges"] == len(topology.edges)
    assert counts["by_layer"]["power"] == 2
    assert counts["by_kind"]["service"] == 1
    assert counts["by_relation"]["powers"] == 2


def test_a_subgraph_keeps_only_what_was_asked_for(topology):
    subset = topology.subgraph(layers=["network"])
    assert set(subset.nodes) == {
        "iface:lab:en0",
        "network:192.168.53.0/24",
        "device:192.168.53.1",
    }
    # The edge to the host went with the host, and the plat is still valid.
    assert not subset.dangling_edges()
    assert subset.fingerprint != topology.fingerprint


def test_a_subgraph_can_be_filtered_by_kind(topology):
    subset = topology.subgraph(kinds=["model"])
    assert not subset.nodes


def test_a_subgraph_can_be_filtered_by_tag(topology):
    subset = topology.subgraph(tags=["published"])
    assert set(subset.nodes) == {"service:tcp:8080"}
    # The edge to the workload went with it.
    assert not subset.dangling_edges()


def test_a_subgraph_with_no_filter_is_the_whole_plat(topology):
    subset = topology.subgraph()
    assert set(subset.nodes) == set(topology.nodes)
    assert len(subset.edges) == len(topology.edges)
