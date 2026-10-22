"""Structural diffing between two survey plats.

A diff answers three different questions, and conflating them is how monitoring
tools become noise:

* **What appeared or vanished?** -- structural, worth narrating.
* **What changed shape?** -- a fact changed (image, address, subnet). Structural.
* **What changed weather?** -- telemetry drift (load, charge). Recorded, but it
  never wakes the scribe and never counts as a change of the map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .model import (
    KIND_DEVICE,
    KIND_HOST,
    KIND_NETWORK,
    KIND_POWER_SOURCE,
    LAYER_LABELS,
    LAYERS,
    RELATION_LABELS,
    REL_POWERS,
    REL_RUNS,
    Topology,
)
from .util import clip

CRITICAL = "critical"
WARNING = "warning"
NOTICE = "notice"
INFO = "info"

SEVERITY_ORDER: dict[str, int] = {CRITICAL: 0, WARNING: 1, NOTICE: 2, INFO: 3}
SEVERITY_MARKERS: dict[str, str] = {
    CRITICAL: "!!",
    WARNING: "! ",
    NOTICE: "+ ",
    INFO: "~ ",
}

#: Node kinds whose disappearance means the map lost a load-bearing element.
_CRITICAL_KINDS = {KIND_POWER_SOURCE, KIND_HOST, KIND_DEVICE, KIND_NETWORK}


@dataclass(slots=True)
class Change:
    """One difference between two survey plats."""

    action: str
    entity_type: str
    entity: str
    severity: str
    label: str = ""
    field: str = ""
    before: Any = None
    after: Any = None
    layer: str = ""

    @property
    def structural(self) -> bool:
        return self.severity != INFO

    @property
    def summary(self) -> str:
        if self.entity_type == "edge":
            return f"{self.action} edge {self.label or self.entity}"
        if self.action == "modified":
            return f"{self.label or self.entity}: {self.field} {clip(self.before)} -> {clip(self.after)}"
        return f"{self.action} {self.label or self.entity}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "entity_type": self.entity_type,
            "entity": self.entity,
            "severity": self.severity,
            "label": self.label,
            "field": self.field,
            "before": self.before,
            "after": self.after,
            "layer": self.layer,
        }


@dataclass(slots=True)
class DiffReport:
    """The full comparison between a previous survey and the current one."""

    site: str
    from_digest: str = ""
    to_digest: str = ""
    from_timestamp: str = ""
    to_timestamp: str = ""
    changes: list[Change] = field(default_factory=list)

    @property
    def structural(self) -> bool:
        return any(change.structural for change in self.changes)

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    def by_severity(self, severity: str) -> list[Change]:
        return [change for change in self.changes if change.severity == severity]

    def counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for change in self.changes:
            counts[change.severity] = counts.get(change.severity, 0) + 1
        return counts

    def headline(self) -> str:
        if not self.changes:
            return "No change. The map holds."
        if not self.structural:
            return "Telemetry drifted; the structure is unchanged."
        counts = self.counts()
        parts = []
        for severity, noun in ((CRITICAL, "critical"), (WARNING, "warning"), (NOTICE, "notice")):
            if counts.get(severity):
                parts.append(f"{counts[severity]} {noun}")
        added = sum(1 for change in self.changes if change.action == "added")
        removed = sum(1 for change in self.changes if change.action == "removed")
        if added or removed:
            parts.append(f"{added} added / {removed} removed")
        return ", ".join(parts) if parts else "Structural change."

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "from": {"digest": self.from_digest, "generated_at": self.from_timestamp},
            "to": {"digest": self.to_digest, "generated_at": self.to_timestamp},
            "structural": self.structural,
            "headline": self.headline(),
            "counts": self.counts(),
            "changes": [change.to_dict() for change in self.changes],
        }


def _node_severity_removed(kind: str) -> str:
    return CRITICAL if kind in _CRITICAL_KINDS else WARNING


def _node_severity_added(kind: str) -> str:
    return WARNING if kind in _CRITICAL_KINDS else NOTICE


def _edge_severity(action: str, relation: str) -> str:
    if relation in {REL_POWERS, REL_RUNS}:
        return CRITICAL if action == "removed" else WARNING
    return WARNING if action == "removed" else NOTICE


def diff_topologies(previous: Topology | None, current: Topology) -> DiffReport:
    """Compare two surveys, newest against oldest."""

    report = DiffReport(
        site=current.site,
        to_digest=current.digest,
        to_timestamp=current.generated_at,
        from_digest=previous.digest if previous else "",
        from_timestamp=previous.generated_at if previous else "",
    )
    if previous is None:
        for node in sorted(current.nodes.values(), key=lambda item: (item.layer, item.id)):
            report.changes.append(
                Change(
                    action="added",
                    entity_type="node",
                    entity=node.id,
                    severity=NOTICE,
                    label=node.label,
                    layer=node.layer,
                    after=node.kind,
                )
            )
        return _sorted(report)

    current_ids = set(current.nodes)
    previous_ids = set(previous.nodes)

    for node_id in sorted(previous_ids - current_ids):
        node = previous.nodes[node_id]
        report.changes.append(
            Change(
                action="removed",
                entity_type="node",
                entity=node_id,
                severity=_node_severity_removed(node.kind),
                label=node.label,
                layer=node.layer,
                before=node.kind,
            )
        )

    for node_id in sorted(current_ids - previous_ids):
        node = current.nodes[node_id]
        report.changes.append(
            Change(
                action="added",
                entity_type="node",
                entity=node_id,
                severity=_node_severity_added(node.kind),
                label=node.label,
                layer=node.layer,
                after=node.kind,
            )
        )

    for node_id in sorted(current_ids & previous_ids):
        before = previous.nodes[node_id]
        after = current.nodes[node_id]
        for field_name in sorted(set(before.structural_facts) | set(after.structural_facts)):
            old = before.structural_facts.get(field_name)
            new = after.structural_facts.get(field_name)
            if old == new:
                continue
            report.changes.append(
                Change(
                    action="modified",
                    entity_type="node",
                    entity=node_id,
                    severity=WARNING,
                    label=after.label,
                    field=field_name,
                    before=old,
                    after=new,
                    layer=after.layer,
                )
            )
        if before.label != after.label:
            report.changes.append(
                Change(
                    action="modified",
                    entity_type="node",
                    entity=node_id,
                    severity=NOTICE,
                    label=after.label,
                    field="label",
                    before=before.label,
                    after=after.label,
                    layer=after.layer,
                )
            )
        telemetry_keys = sorted(
            {
                key
                for key in set(before.telemetry) | set(after.telemetry)
                if before.telemetry.get(key) != after.telemetry.get(key)
            }
        )
        if telemetry_keys:
            report.changes.append(
                Change(
                    action="drifted",
                    entity_type="node",
                    entity=node_id,
                    severity=INFO,
                    label=after.label,
                    field="telemetry",
                    before=None,
                    after=telemetry_keys[:8],
                    layer=after.layer,
                )
            )

    previous_edges = {edge.id: edge for edge in previous.edges}
    current_edges = {edge.id: edge for edge in current.edges}
    for edge_id in sorted(set(previous_edges) - set(current_edges)):
        edge = previous_edges[edge_id]
        report.changes.append(
            Change(
                action="removed",
                entity_type="edge",
                entity=edge_id,
                severity=_edge_severity("removed", edge.relation),
                label=_edge_label(previous, edge),
                before=edge.relation,
            )
        )
    for edge_id in sorted(set(current_edges) - set(previous_edges)):
        edge = current_edges[edge_id]
        report.changes.append(
            Change(
                action="added",
                entity_type="edge",
                entity=edge_id,
                severity=_edge_severity("added", edge.relation),
                label=_edge_label(current, edge),
                after=edge.relation,
            )
        )

    return _sorted(report)


def _edge_label(topology: Topology, edge: Any) -> str:
    source = topology.nodes.get(edge.source)
    target = topology.nodes.get(edge.target)
    relation = RELATION_LABELS.get(edge.relation, edge.relation)
    return (
        f"{(source.label if source else edge.source)} "
        f"--{relation}--> "
        f"{(target.label if target else edge.target)}"
    )


def _sorted(report: DiffReport) -> DiffReport:
    report.changes.sort(
        key=lambda change: (
            SEVERITY_ORDER.get(change.severity, 9),
            LAYERS.index(change.layer) if change.layer in LAYERS else 9,
            change.entity_type,
            change.entity,
            change.field,
        )
    )
    return report


def render_text(report: DiffReport, *, verbose: bool = False) -> str:
    """Human-readable diff, severity-first, with layer context."""

    lines: list[str] = []
    lines.append(f"{report.headline()}")
    if report.from_timestamp or report.to_timestamp:
        span = f"{report.from_timestamp or 'no previous plat'} -> {report.to_timestamp or 'now'}"
        lines.append(f"  {span}")
    if not report.changes:
        return "\n".join(lines)

    current_layer = ""
    shown_in_layer = 0
    hidden_in_layer = 0
    for change in report.changes:
        if change.severity == INFO and not verbose:
            continue
        layer_name = LAYER_LABELS.get(change.layer, "Unaligned")
        if layer_name != current_layer:
            if current_layer and hidden_in_layer:
                lines.append(f"  … {hidden_in_layer} more in {current_layer.lower()}")
            current_layer = layer_name
            shown_in_layer = 0
            hidden_in_layer = 0
            lines.append("")
            lines.append(f"{layer_name.upper()}")
        if shown_in_layer >= 8 and not verbose:
            hidden_in_layer += 1
            continue
        shown_in_layer += 1
        marker = SEVERITY_MARKERS.get(change.severity, "  ")
        if change.entity_type == "edge":
            lines.append(f"  {marker} {change.action} {change.label}")
        elif change.action == "modified":
            lines.append(
                f"  {marker} {change.label}: {change.field} "
                f"{clip(change.before, 48)} -> {clip(change.after, 48)}"
            )
        else:
            lines.append(f"  {marker} {change.action} {change.label}")
    if current_layer and hidden_in_layer:
        lines.append(f"  … {hidden_in_layer} more in {current_layer.lower()}")
    hidden = len(report.by_severity(INFO))
    if hidden and not verbose:
        lines.append("")
        lines.append(f"  ({hidden} telemetry drift{'s' if hidden != 1 else ''} hidden; --verbose to include)")
    return "\n".join(lines)


def iter_structural(changes: Iterable[Change]) -> Iterable[Change]:
    return (change for change in changes if change.structural)
