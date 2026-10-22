"""The Open Edge Topology (OET) object model.

Two ideas carry the whole design and are worth stating plainly:

**Facts vs telemetry.** A fact is part of the shape of the system: a container
image, a CPU model, an interface's address family. Telemetry is the weather:
load average, charge percentage, container uptime. Only facts are hashed into
the structural fingerprint, so a busy machine does not create a fake change
every 30 seconds.

**Fingerprint vs digest.** The fingerprint answers "is this the same map?" and
excludes timestamps and observations. The digest answers "is this the same
document?" and addresses an immutable object in the ledger.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import OET_VERSION, __version__
from .errors import SchemaError
from .util import canonical_json, digest_of, sha256_hex

SCHEMA_VERSION = OET_VERSION

LAYER_POWER = "power"
LAYER_METAL = "metal"
LAYER_NETWORK = "network"
LAYER_WORKLOAD = "workload"

#: Canonical layer order. Rendered maps and diffs always read top-down from
#: the wall socket to the container.
LAYERS: tuple[str, ...] = (LAYER_POWER, LAYER_METAL, LAYER_NETWORK, LAYER_WORKLOAD)

LAYER_LABELS: dict[str, str] = {
    LAYER_POWER: "Power",
    LAYER_METAL: "Bare metal",
    LAYER_NETWORK: "Network",
    LAYER_WORKLOAD: "Workloads",
}

KIND_HOST = "host"
KIND_POWER_SOURCE = "power_source"
KIND_INTERFACE = "interface"
KIND_NETWORK = "network"
KIND_WORKLOAD = "workload"
KIND_MODEL = "model"
KIND_SERVICE = "service"
KIND_VOLUME = "volume"
KIND_DEVICE = "device"

KINDS: frozenset[str] = frozenset(
    {
        KIND_HOST,
        KIND_POWER_SOURCE,
        KIND_INTERFACE,
        KIND_NETWORK,
        KIND_WORKLOAD,
        KIND_MODEL,
        KIND_SERVICE,
        KIND_VOLUME,
        KIND_DEVICE,
    }
)

_KIND_LAYER: dict[str, str] = {
    KIND_HOST: LAYER_METAL,
    KIND_DEVICE: LAYER_NETWORK,
    KIND_POWER_SOURCE: LAYER_POWER,
    KIND_INTERFACE: LAYER_NETWORK,
    KIND_NETWORK: LAYER_NETWORK,
    KIND_WORKLOAD: LAYER_WORKLOAD,
    KIND_MODEL: LAYER_WORKLOAD,
    KIND_SERVICE: LAYER_WORKLOAD,
    KIND_VOLUME: LAYER_WORKLOAD,
}

REL_POWERS = "powers"
REL_HOSTS = "hosts"
REL_RUNS = "runs"
REL_SERVES = "serves"
REL_ATTACHES_TO = "attaches_to"
REL_ROUTES_VIA = "routes_via"
REL_EXPOSES = "exposes"
REL_DEPENDS_ON = "depends_on"
REL_MEMBER_OF = "member_of"

RELATIONS: frozenset[str] = frozenset(
    {
        REL_POWERS,
        REL_HOSTS,
        REL_RUNS,
        REL_SERVES,
        REL_ATTACHES_TO,
        REL_ROUTES_VIA,
        REL_EXPOSES,
        REL_DEPENDS_ON,
        REL_MEMBER_OF,
    }
)

RELATION_LABELS: dict[str, str] = {
    REL_POWERS: "powers",
    REL_HOSTS: "hosts",
    REL_RUNS: "runs",
    REL_SERVES: "serves",
    REL_ATTACHES_TO: "attaches to",
    REL_ROUTES_VIA: "routes via",
    REL_EXPOSES: "exposes",
    REL_DEPENDS_ON: "depends on",
    REL_MEMBER_OF: "member of",
}

#: Fact keys that are really measurements. A scanner that files one of these
#: under ``facts`` still cannot fake a structural change: the fingerprint
#: ignores them.
VOLATILE_FACT_KEYS: frozenset[str] = frozenset(
    {
        "collected_at",
        "cpu_percent",
        "load",
        "load_1m",
        "load_5m",
        "load_15m",
        "mem_free",
        "mem_available",
        "uptime",
        "uptime_seconds",
        "charge_percent",
        "minutes_remaining",
        "status",
        "state",
        "measured_at",
        "observed_at",
        "temperature_c",
        "thermal_pressure",
        "rx_bytes",
        "tx_bytes",
        "packets",
        "age_seconds",
    }
)

_SCALAR = (str, int, float, bool)


def kind_layer(kind: str) -> str:
    """Return the canonical layer for a node kind."""

    return _KIND_LAYER.get(kind, LAYER_WORKLOAD)


def _clean_facts(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep facts JSON-safe, stable, and free of ``None`` placeholders."""

    cleaned: dict[str, Any] = {}
    if not raw:
        return cleaned
    for key, value in raw.items():
        if value is None:
            continue
        name = str(key)
        if isinstance(value, _SCALAR):
            cleaned[name] = value
        elif isinstance(value, (list, tuple)):
            items = [item for item in value if isinstance(item, _SCALAR)]
            if items:
                cleaned[name] = items
        elif isinstance(value, Mapping):
            nested = _clean_facts(value)
            if nested:
                cleaned[name] = nested
        elif isinstance(value, set):
            cleaned[name] = sorted(str(item) for item in value)
        else:
            cleaned[name] = str(value)
    return cleaned


@dataclass(slots=True)
class Node:
    """One observed thing: a host, a power source, an interface, a container."""

    id: str
    kind: str
    label: str
    layer: str = ""
    facts: dict[str, Any] = field(default_factory=dict)
    telemetry: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()
    source: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise SchemaError("node id must not be empty")
        if self.kind not in KINDS:
            raise SchemaError(f"unknown node kind {self.kind!r} for {self.id!r}")
        if not self.layer:
            self.layer = kind_layer(self.kind)
        if self.layer not in LAYERS:
            raise SchemaError(f"unknown layer {self.layer!r} for {self.id!r}")
        self.label = self.label or self.id
        self.facts = _clean_facts(self.facts)
        self.telemetry = _clean_facts(self.telemetry)
        self.tags = tuple(sorted({tag for tag in self.tags if tag}))

    @property
    def structural_facts(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in self.facts.items()
            if key not in VOLATILE_FACT_KEYS
        }

    def structural_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "layer": self.layer,
            "label": self.label,
            "facts": self.structural_facts,
            "tags": list(self.tags),
        }

    def merge(self, other: Node) -> Node:
        """Fold a duplicate observation into this node.

        Facts from ``other`` win only where this node is silent, so scanner
        order cannot flip a value back and forth between surveys.
        """

        merged_facts = dict(self.facts)
        merged_facts.update({k: v for k, v in other.facts.items() if k not in merged_facts})
        merged_telemetry = dict(self.telemetry)
        merged_telemetry.update(other.telemetry)
        return Node(
            id=self.id,
            kind=self.kind,
            label=self.label or other.label,
            layer=self.layer,
            facts=merged_facts,
            telemetry=merged_telemetry,
            tags=tuple(sorted(set(self.tags) | set(other.tags))),
            source=self.source or other.source,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "layer": self.layer,
            "label": self.label,
            "facts": dict(sorted(self.facts.items())),
            "telemetry": dict(sorted(self.telemetry.items())),
            "tags": list(self.tags),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Node:
        try:
            return cls(
                id=str(data["id"]),
                kind=str(data["kind"]),
                label=str(data.get("label") or ""),
                layer=str(data.get("layer") or ""),
                facts=dict(data.get("facts") or {}),
                telemetry=dict(data.get("telemetry") or {}),
                tags=tuple(data.get("tags") or ()),
                source=str(data.get("source") or ""),
            )
        except KeyError as exc:
            raise SchemaError(f"node is missing required field {exc.args[0]!r}") from exc


@dataclass(slots=True)
class Edge:
    """A directed relationship between two nodes."""

    source: str
    relation: str
    target: str
    facts: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source or not self.target:
            raise SchemaError("edge endpoints must not be empty")
        if self.relation not in RELATIONS:
            raise SchemaError(f"unknown relation {self.relation!r}")
        self.facts = _clean_facts(self.facts)

    @property
    def id(self) -> str:
        return f"{self.source}|{self.relation}|{self.target}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "relation": self.relation,
            "target": self.target,
            "facts": dict(sorted(self.facts.items())),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Edge:
        try:
            return cls(
                source=str(data["source"]),
                relation=str(data["relation"]),
                target=str(data["target"]),
                facts=dict(data.get("facts") or {}),
            )
        except KeyError as exc:
            raise SchemaError(f"edge is missing required field {exc.args[0]!r}") from exc


@dataclass(slots=True)
class Topology:
    """A survey plat: nodes, edges, and the circumstances of observation."""

    site: str = "edge"
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    generated_at: str = ""
    observations: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.edges = self._dedupe_edges(self.edges)

    # -- construction -----------------------------------------------------
    def add(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        merged = existing.merge(node)
        self.nodes[node.id] = merged
        return merged

    def connect(self, edge: Edge) -> None:
        self.edges.append(edge)
        self.edges = self._dedupe_edges(self.edges)

    def extend(self, nodes: Iterable[Node], edges: Iterable[Edge]) -> None:
        for node in nodes:
            self.add(node)
        self.edges.extend(edges)
        self.edges = self._dedupe_edges(self.edges)

    @staticmethod
    def _dedupe_edges(edges: Iterable[Edge]) -> list[Edge]:
        merged: dict[str, Edge] = {}
        for edge in edges:
            existing = merged.get(edge.id)
            if existing is None:
                merged[edge.id] = edge
                continue
            facts = dict(existing.facts)
            facts.update({k: v for k, v in edge.facts.items() if k not in facts})
            existing.facts = facts
        return sorted(merged.values(), key=lambda edge: edge.id)

    # -- validation -------------------------------------------------------
    def dangling_edges(self) -> list[Edge]:
        return [
            edge
            for edge in self.edges
            if edge.source not in self.nodes or edge.target not in self.nodes
        ]

    def prune_dangling(self) -> list[Edge]:
        dangling = self.dangling_edges()
        if dangling:
            keep = {edge.id for edge in self.edges} - {edge.id for edge in dangling}
            self.edges = [edge for edge in self.edges if edge.id in keep]
        return dangling

    # -- identity ---------------------------------------------------------
    def structural_payload(self) -> dict[str, Any]:
        return {
            "oet_version": self.schema_version,
            "site": self.site,
            "nodes": [
                node.structural_payload()
                for node in sorted(self.nodes.values(), key=lambda item: item.id)
            ],
            "edges": [
                {
                    "source": edge.source,
                    "relation": edge.relation,
                    "target": edge.target,
                    "facts": {
                        key: value
                        for key, value in edge.facts.items()
                        if key not in VOLATILE_FACT_KEYS
                    },
                }
                for edge in sorted(self.edges, key=lambda item: item.id)
            ],
        }

    @property
    def fingerprint(self) -> str:
        """Stable identity of the *shape* of this survey."""

        return "sha256:" + sha256_hex(canonical_json(self.structural_payload()))

    @property
    def digest(self) -> str:
        """Content address of the full document, including time and telemetry."""

        return digest_of(self.to_dict())

    # -- reporting --------------------------------------------------------
    def counts(self) -> dict[str, Any]:
        by_layer = dict.fromkeys(LAYERS, 0)
        by_kind: dict[str, int] = {}
        for node in self.nodes.values():
            by_layer[node.layer] = by_layer.get(node.layer, 0) + 1
            by_kind[node.kind] = by_kind.get(node.kind, 0) + 1
        relations: dict[str, int] = {}
        for edge in self.edges:
            relations[edge.relation] = relations.get(edge.relation, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_layer": by_layer,
            "by_kind": dict(sorted(by_kind.items())),
            "by_relation": dict(sorted(relations.items())),
        }

    def nodes_in_layer(self, layer: str) -> list[Node]:
        return sorted(
            (node for node in self.nodes.values() if node.layer == layer),
            key=lambda node: (node.kind, node.label.lower(), node.id),
        )

    def neighbours(self, node_id: str) -> Iterator[tuple[str, Edge]]:
        for edge in self.edges:
            if edge.source == node_id:
                yield edge.target, edge
            elif edge.target == node_id:
                yield edge.source, edge

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "oet_version": self.schema_version,
            "generator": {"name": "the-surveyor", "version": __version__},
            "site": self.site,
            "generated_at": self.generated_at,
            "fingerprint": self.fingerprint,
            "counts": self.counts(),
            "nodes": [
                node.to_dict()
                for node in sorted(self.nodes.values(), key=lambda item: item.id)
            ],
            "edges": [edge.to_dict() for edge in self.edges],
            "observations": self.observations,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Topology:
        if not isinstance(data, Mapping):
            raise SchemaError("OET document must be a JSON object")
        version = str(data.get("oet_version") or data.get("version") or "")
        if version.split(".", maxsplit=1)[0] != SCHEMA_VERSION.split(".")[0]:
            raise SchemaError(
                f"unsupported OET version {version!r}; this build speaks OET {SCHEMA_VERSION}"
            )
        raw_nodes: Sequence[Any] = data.get("nodes") or []
        raw_edges: Sequence[Any] = data.get("edges") or []
        topology = cls(
            site=str(data.get("site") or "edge"),
            generated_at=str(data.get("generated_at") or data.get("timestamp") or ""),
            observations=dict(data.get("observations") or {}),
            schema_version=version or SCHEMA_VERSION,
        )
        seen: set[str] = set()
        for raw in raw_nodes:
            node = Node.from_dict(raw)
            if node.id in seen:
                raise SchemaError(f"duplicate node id {node.id!r}")
            seen.add(node.id)
            topology.nodes[node.id] = node
        for raw in raw_edges:
            topology.edges.append(Edge.from_dict(raw))
        topology.edges = topology._dedupe_edges(topology.edges)
        return topology
