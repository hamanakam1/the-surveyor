"""Rendering a survey plat as something a human can read.

Three outputs, one model:

* ``ascii_map`` -- layered boxes with the important facts right-aligned.
* ``markdown`` -- what goes in a changelog or a ticket.
* ``mermaid`` -- a diagram GitHub will draw for you.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .model import (
    KIND_DEVICE,
    KIND_HOST,
    KIND_INTERFACE,
    KIND_MODEL,
    KIND_NETWORK,
    KIND_POWER_SOURCE,
    KIND_SERVICE,
    KIND_VOLUME,
    KIND_WORKLOAD,
    LAYER_LABELS,
    LAYERS,
    RELATION_LABELS,
    Node,
    Topology,
)
from .util import clip

_GLYPHS: dict[str, str] = {
    KIND_POWER_SOURCE: "◆",
    KIND_HOST: "▣",
    KIND_DEVICE: "⬡",
    KIND_INTERFACE: "⌁",
    KIND_NETWORK: "◇",
    KIND_WORKLOAD: "■",
    KIND_MODEL: "✦",
    KIND_SERVICE: "◦",
    KIND_VOLUME: "▤",
}

_KIND_ORDER = {
    KIND_POWER_SOURCE: 0,
    KIND_HOST: 1,
    KIND_DEVICE: 2,
    KIND_NETWORK: 3,
    KIND_INTERFACE: 4,
    KIND_WORKLOAD: 5,
    KIND_MODEL: 6,
    KIND_SERVICE: 7,
}


def _detail(node: Node) -> str:
    facts = node.facts
    telemetry = node.telemetry
    if node.kind == KIND_POWER_SOURCE:
        role = str(facts.get("role") or facts.get("source") or "supply")
        parts = ["utility" if role == "ac" else role]
        if "charge_percent" in telemetry:
            parts.append(f"{telemetry['charge_percent']}%")
        return " · ".join(parts)
    if node.kind == KIND_HOST:
        parts = [str(facts.get("cpu_model") or facts.get("arch") or "")]
        if "cpu_cores" in facts:
            parts.append(f"{facts['cpu_cores']} cores")
        if "mem_total_gib" in facts:
            parts.append(f"{facts['mem_total_gib']} GiB")
        return " · ".join(part for part in parts if part)
    if node.kind == KIND_NETWORK:
        return f"{facts.get('cidr', '')}"
    if node.kind == KIND_INTERFACE:
        return " · ".join(
            str(value)
            for value in (
                facts.get("kind", ""),
                facts.get("address") or "",
            )
            if value
        )
    if node.kind == KIND_WORKLOAD:
        return str(facts.get("image") or facts.get("runtime") or "")
    if node.kind == KIND_MODEL:
        parts = [str(facts.get("parameter_size") or "")]
        if "size_gib" in facts:
            parts.append(f"{facts['size_gib']} GiB")
        return " · ".join(part for part in parts if part)
    if node.kind == KIND_SERVICE:
        tags = set(node.tags)
        if "published" in tags:
            return "published"
        if "local-only" in tags:
            return "loopback only"
        if "exposed" in tags:
            return "all interfaces"
        return "listener"
    return ""


def _row(node: Node, box_width: int) -> str:
    """One node row: glyph + label on the left, salient fact on the right."""

    glyph = _GLYPHS.get(node.kind, "·")
    detail = _detail(node)
    body_width = box_width - 4  # "| " + body + " |"
    left = f"{glyph} {node.label}"
    if detail:
        gap = body_width - len(left) - len(detail)
        if gap < 2:
            left = clip(left, max(8, body_width - len(detail) - 2))
            gap = body_width - len(left) - len(detail)
        if gap >= 1:
            return "│ " + left + " " * gap + detail + " │"
    return "│ " + f"{clip(left, body_width):<{body_width}}" + " │"


def ascii_map(topology: Topology, *, width: int = 78, max_per_layer: int = 6) -> str:
    """Render the survey as stacked layer boxes plus a connection summary."""

    box_width = max(48, width)
    inner = box_width - 2

    lines: list[str] = []
    lines.append(f"◈ {topology.site} · {topology.generated_at} · {topology.fingerprint[:15]}")
    lines.append("")

    for index, layer in enumerate(LAYERS):
        nodes = sorted(
            topology.nodes_in_layer(layer),
            key=lambda node: (_KIND_ORDER.get(node.kind, 9), node.label.lower()),
        )
        title = f" {LAYER_LABELS[layer].upper()} "
        if not nodes:
            title += "· nothing observed "
        else:
            title += f"· {len(nodes)} "
        rule = "─" * max(0, box_width - 3 - len(title))
        lines.append(f"╭─{title}{rule}╮")
        if not nodes:
            lines.append("│" + " " * inner + "│")
        for node in nodes[:max_per_layer]:
            lines.append(_row(node, box_width))
        if len(nodes) > max_per_layer:
            hidden = f"… {len(nodes) - max_per_layer} more"
            lines.append("│ " + f"{hidden:<{inner - 2}}" + " │")
        lines.append("╰" + "─" * inner + "╯")
        if index < len(LAYERS) - 1:
            lines.append(" " * 12 + "│")
            lines.append(" " * 12 + "▼")

    lines.append("")
    lines.append("EDGES")
    grouped: dict[str, list[str]] = {}
    for edge in topology.edges:
        relation = RELATION_LABELS.get(edge.relation, edge.relation)
        source = topology.nodes.get(edge.source)
        target = topology.nodes.get(edge.target)
        label = f"{source.label if source else edge.source} → {target.label if target else edge.target}"
        grouped.setdefault(relation, []).append(clip(label, 54))
    if not grouped:
        lines.append("  (no relationships observed)")
    for relation in sorted(grouped):
        entries = grouped[relation]
        lines.append(f"  {relation:<12} {entries[0]}")
        for entry in entries[1:4]:
            lines.append(f"  {'':<12} {entry}")
        if len(entries) > 4:
            lines.append(f"  {'':<12} … {len(entries) - 4} more")
    counts = topology.counts()
    observed = len([layer for layer in LAYERS if topology.nodes_in_layer(layer)])
    lines.append("")
    lines.append(
        f"{counts['nodes']} nodes · {counts['edges']} edges · {observed}/4 layers observed"
    )
    return "\n".join(lines)


def markdown_table(topology: Topology) -> str:
    """Markdown rendering suitable for a changelog or a ticket body."""

    lines: list[str] = [
        f"### Survey plat — {topology.site}",
        "",
        f"- Generated: `{topology.generated_at}`",
        f"- Fingerprint: `{topology.fingerprint}`",
        f"- Nodes: **{len(topology.nodes)}** · Edges: **{len(topology.edges)}**",
        "",
    ]
    for layer in LAYERS:
        nodes = topology.nodes_in_layer(layer)
        if not nodes:
            continue
        lines.append(f"#### {LAYER_LABELS[layer]} ({len(nodes)})")
        lines.append("")
        lines.append("| Node | Kind | Detail |")
        lines.append("| --- | --- | --- |")
        for node in nodes:
            lines.append(
                f"| `{node.label}` | {node.kind} | {_detail(node) or '—'} |"
            )
        lines.append("")

    if topology.edges:
        lines.append("#### Relationships")
        lines.append("")
        lines.append("| From | Relation | To |")
        lines.append("| --- | --- | --- |")
        for edge in topology.edges[:60]:
            source = topology.nodes.get(edge.source)
            target = topology.nodes.get(edge.target)
            lines.append(
                f"| `{(source.label if source else edge.source)}` | "
                f"{RELATION_LABELS.get(edge.relation, edge.relation)} | "
                f"`{(target.label if target else edge.target)}` |"
            )
        if len(topology.edges) > 60:
            lines.append(f"| … | | {len(topology.edges) - 60} more |")
        lines.append("")

    warnings = topology.observations.get("warnings") or []
    if warnings:
        lines.append("<details><summary>Observation notes</summary>")
        lines.append("")
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines)


def _mermaid_id(node_id: str) -> str:
    return "n_" + "".join(character if character.isalnum() else "_" for character in node_id)


def _mermaid_label(text: str) -> str:
    return text.replace('"', "'").replace("[", "(").replace("]", ")").replace("|", "/")


_SHAPES: dict[str, str] = {
    KIND_POWER_SOURCE: '(["%s"])',
    KIND_HOST: '[["%s"]]',
    KIND_INTERFACE: '[/"%s"/]',
    KIND_NETWORK: '[/"%s"/]',
    KIND_WORKLOAD: '("%s")',
    KIND_MODEL: '>"%s"]',
    KIND_SERVICE: '{{"%s"}}',
}


def mermaid(topology: Topology) -> str:
    """A Mermaid ``graph TD`` that GitHub renders inline."""

    lines = ["%%{init: {'theme': 'neutral'}}%%", "graph TD"]
    for layer in LAYERS:
        nodes = topology.nodes_in_layer(layer)
        if not nodes:
            continue
        lines.append(f"  subgraph {layer.upper()}[\"{LAYER_LABELS[layer]}\"]")
        for node in nodes:
            shape = _SHAPES.get(node.kind, '["%s"]')
            lines.append(f"    {_mermaid_id(node.id)}{shape % _mermaid_label(node.label)}")
        lines.append("  end")
    for edge in topology.edges:
        if edge.source not in topology.nodes or edge.target not in topology.nodes:
            continue
        label = RELATION_LABELS.get(edge.relation, edge.relation)
        lines.append(
            f"  {_mermaid_id(edge.source)} -->|{label}| {_mermaid_id(edge.target)}"
        )
    return "\n".join(lines)


def storage_note(topology: Topology) -> str:
    """One-line summary used by the daemon log."""

    counts = topology.counts()
    by_kind: dict[str, Any] = counts["by_kind"]
    pieces: list[str] = []
    for kind in (KIND_HOST, KIND_POWER_SOURCE, KIND_WORKLOAD, KIND_SERVICE):
        if by_kind.get(kind):
            pieces.append(f"{by_kind[kind]} {kind}")
    return f"{counts['nodes']} nodes ({', '.join(pieces) or 'none'}) · {counts['edges']} edges"


def edge_legend(topology: Topology) -> Iterable[str]:
    for relation in sorted({edge.relation for edge in topology.edges}):
        yield RELATION_LABELS.get(relation, relation)
