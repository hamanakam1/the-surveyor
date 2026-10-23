"""Composing many hosts into one map.

A ledger can hold plats from several hosts. The interesting question is not
"what did this box look like" but "what does the site look like", and the
answer is a single graph.

The composition works because identity was designed for it. A device is
named by its hardware address, so two hosts that both saw the same router
produce the *same* device node, and the union of their plats joins them
together without anyone having to say so. The host nodes do not collide,
because each host is named by its own name. The edges survive, because
each host's own relations are still true.

What composition cannot do is resolve a disagreement. Two hosts may see
the same device at different addresses, and the map has to say so rather
than quietly keep one of them.
"""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .model import KIND_HOST, Topology


@dataclass
class Composition:
    """A merged map, and what could not be merged cleanly."""

    topology: Topology
    hosts: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    ambiguous: list[str] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.topology.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.topology.edges)


def compose(plats: Sequence[Topology], *, site: str = "") -> Composition:
    """Merge plats into one map.

    Nodes merge by id, edges by (source, relation, target). A fact two plats
    disagree about is recorded as a conflict and the first observation is
    kept, because a map that shows both is a map that lies about its own
    shape.
    """

    merged = Topology(site=site or (plats[0].site if plats else "edge"))
    hosts: list[str] = []
    conflicts: list[str] = []

    for plat in plats:
        for node in plat.nodes.values():
            existing = merged.nodes.get(node.id)
            if existing is None:
                merged.add(deepcopy(node))
                if node.kind == KIND_HOST:
                    hosts.append(node.id)
                continue

            for key, value in existing.facts.items():
                other = node.facts.get(key)
                if other is not None and other != value:
                    conflicts.append(
                        f"{node.id}: {key} reported as {value!r} by "
                        f"{existing.source or 'a scanner'} and {other!r} by "
                        f"{node.source or 'a scanner'}"
                    )
            merged.add(deepcopy(node))
        for edge in plat.edges:
            merged.connect(deepcopy(edge))

    return Composition(
        topology=merged,
        hosts=hosts,
        conflicts=conflicts,
        ambiguous=_shared_addresses(merged),
    )


def _shared_addresses(topology: Topology) -> list[str]:
    """Devices that two hosts may be calling by different names.

    A host that has not recently spoken to its router has no hardware
    address for it, so it names the router by its IP; a host that has
    names it by its hardware address. The two ids are different, and the
    map cannot know they are the same box. Merging them would be a guess;
    saying so is not.
    """

    by_address: dict[str, list[str]] = {}
    for node in topology.nodes.values():
        address = node.facts.get("address")
        if node.kind != "device" or not isinstance(address, str) or not address:
            continue
        by_address.setdefault(address, []).append(node.id)
    findings = []
    for address, ids in sorted(by_address.items()):
        if len(ids) > 1:
            findings.append(
                f"{address}: seen as {', '.join(sorted(ids))}; "
                "these may be the same device"
            )
    return findings



def host_sites(plats: Sequence[Topology]) -> dict[str, str]:
    """Which site each host in the composition belongs to."""

    sites: dict[str, str] = {}
    for plat in plats:
        for node in plat.nodes.values():
            if node.kind == KIND_HOST:
                sites[node.id] = plat.site
    return sites


def tag_hosts(topology: Topology, sites: dict[str, str]) -> None:
    """Mark the host nodes with the site they belong to."""

    for node in topology.nodes.values():
        if node.kind != KIND_HOST:
            continue
        site = sites.get(node.id)
        if site:
            node.tags = tuple(sorted(set(node.tags) | {f"site:{site}"}))


def summarise(composition: Composition, sites: dict[str, str]) -> dict[str, Any]:
    """A compact description of a composed map."""

    return {
        "hosts": composition.hosts,
        "sites": sites,
        "nodes": composition.node_count,
        "edges": composition.edge_count,
        "conflicts": composition.conflicts,
        "ambiguous": composition.ambiguous,
    }
