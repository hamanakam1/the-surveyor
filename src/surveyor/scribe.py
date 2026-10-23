"""The Scribe: turns a diff into prose a human will actually read.

Two machines write every changelog entry, and they have different jobs:

* **The template engine** writes the facts. Deterministic, no network, never
  invents a node. This is what lands in the ledger.
* **The local model** (optional, Ollama) rewrites only the opening paragraph.
  If it is slow, missing, or hallucinating, the template paragraph survives.

That split is the whole point: narration may be creative, the record may not.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import Config
from .differ import CRITICAL, INFO, NOTICE, WARNING, Change, DiffReport
from .errors import LLMError
from .model import LAYER_LABELS, LAYERS, Topology
from .util import clip, short_digest

_MAX_NAMES = 3


@dataclass(slots=True)
class ScribeOutput:
    markdown: str
    backend: str
    narrative: str
    warning: str = ""


def _names(changes: list[Change], limit: int = _MAX_NAMES) -> str:
    labels = [change.label or change.entity for change in changes]
    if not labels:
        return ""
    shown = labels[:limit]
    if len(labels) > limit:
        shown.append(f"{len(labels) - limit} more")
    if len(shown) == 1:
        return shown[0]
    return ", ".join(shown[:-1]) + f" and {shown[-1]}"


def _layers_present(topology: Topology) -> str:
    present = [LAYER_LABELS[layer].lower() for layer in LAYERS if topology.nodes_in_layer(layer)]
    if not present:
        return "no layers"
    if len(present) == 1:
        return present[0]
    return ", ".join(present[:-1]) + f" and {present[-1]}"


#: The order in which things are named. A host outranks a workload, a
#: workload outranks the models and sockets it serves: those are the
#: consequences of the change, not the change itself.
_NARRATIVE_RANK = (
    "host:",
    "power:",
    "workload:",
    "model:",
    "service:",
    "network:",
    "device:",
    "iface:",
)


def _rank(change: Change) -> int:
    for index, prefix in enumerate(_NARRATIVE_RANK):
        if change.entity.startswith(prefix):
            return index
    return len(_NARRATIVE_RANK)


def _pick(changes: list[Change]) -> list[Change]:
    """The most newsworthy group of changes.

    Node changes are named before edge changes: an operator cares that a
    container appeared, not that the edge to it appeared with it. Within
    whichever pool wins, the highest severity goes first.
    """

    nodes = [change for change in changes if change.entity_type == "node"]
    pool = nodes or changes
    for level in (CRITICAL, WARNING, NOTICE):
        group = [change for change in pool if change.severity == level]
        if group:
            return sorted(group, key=_rank)
    return []


def narrative(report: DiffReport, topology: Topology, previous: Topology | None) -> str:
    """Deterministic opening paragraph, written before any model sees it."""

    if previous is None:
        counts = topology.counts()
        power = topology.nodes_in_layer("power")
        socket_count = len(
            [node for node in topology.nodes.values() if node.kind == "service"]
        )
        opening = (
            f"The theodolite is levelled and the first plat is drawn: "
            f"{counts['nodes']} nodes and {counts['edges']} edges across {_layers_present(topology)}."
        )
        details = []
        if power:
            details.append(f"Power arrives from {power[0].label}")
        if socket_count:
            details.append(
                f"{socket_count} listening socket{'s' if socket_count != 1 else ''} answer"
            )
        if details:
            return opening + " " + "; ".join(details) + "."
        return opening

    if not report.changes:
        return "The sightline fell on the same shape twice. Nothing structural moved."

    structural = [change for change in report.changes if change.severity != INFO]
    if not structural:
        return (
            f"Only the weather changed: {len(report.by_severity(INFO))} telemetry series drifted."
        )

    sentences: list[str] = []

    removed = _pick([change for change in structural if change.action == "removed"])
    added = _pick([change for change in structural if change.action == "added"])
    modified = [
        change
        for change in structural
        if change.action == "modified" and change.severity in {WARNING, CRITICAL}
    ]

    if removed:
        if any(change.severity == CRITICAL for change in removed):
            sentences.append(f"Sight was lost on {_names(removed)}.")
        else:
            sentences.append(f"{_names(removed)} came off the map.")
    if added:
        if any(change.severity == CRITICAL for change in added):
            sentences.append(f"New ground was platted: {_names(added)}.")
        else:
            sentences.append(f"{_names(added)} appeared on the plat.")
    if modified:
        first = modified[0]
        sentences.append(
            f"The shape of {first.label or first.entity} shifted: "
            f"{first.field} went from {clip(first.before, 40)} to {clip(first.after, 40)}."
        )
    if not sentences:
        # Structural, but not a presence change or a shape change: a label
        # moved. Say something true rather than nothing at all.
        sentences.append(f"{len(structural)} structural change(s) were recorded.")
    if len(sentences) > 3:
        sentences = sentences[:3]
    return " ".join(sentences)


def _bullets(report: DiffReport, severity_filter: set[str]) -> list[str]:
    lines: list[str] = []
    # Plat metadata is structural but does not belong to an OET layer.
    for layer in (*LAYERS, ""):
        layer_changes = [
            change
            for change in report.changes
            if (change.layer == layer if layer else change.entity_type == "topology")
            and change.severity in severity_filter
        ]
        if not layer_changes:
            continue
        lines.append(f"### {LAYER_LABELS.get(layer, 'Plat metadata')}")
        lines.append("")
        for change in layer_changes[:10]:
            name = change.label or change.entity
            if change.action == "modified":
                lines.append(
                    f"- `{name}` — {change.field}: "
                    f"`{clip(change.before, 60)}` → `{clip(change.after, 60)}`"
                )
            elif change.entity_type == "edge":
                lines.append(f"- **{change.action}** {name}")
            elif change.action == "drifted":
                keys = ", ".join(str(key) for key in (change.after or [])) or "telemetry"
                lines.append(f"- `{name}` drifted ({keys})")
            else:
                lines.append(f"- **{change.action}** `{name}`")
        if len(layer_changes) > 10:
            lines.append(f"- … {len(layer_changes) - 10} more in this layer")
        lines.append("")
    return lines


def compose_changelog(
    report: DiffReport,
    topology: Topology,
    *,
    previous: Topology | None = None,
    config: Config | None = None,
    note: str = "",
    backend: str | None = None,
) -> ScribeOutput:
    """Render a complete changelog entry, optionally polished by Ollama."""

    chosen = backend or (config.scribe if config else "template")
    draft = narrative(report, topology, previous)
    warning = ""
    used = "template"

    if chosen == "ollama" and config is not None:
        try:
            polished = polish(draft, report, config)
            if polished:
                draft = polished
                used = "ollama"
        except LLMError as exc:
            warning = f"local model unavailable ({exc}); the deterministic draft was used"

    counts = report.counts()
    previous_label = (
        f"`{short_digest(previous.digest)}`" if previous is not None else "_genesis_"
    )
    lines: list[str] = [
        "# Survey change log",
        "",
        f"**{topology.site}** · {previous_label} → `{short_digest(topology.digest)}` · "
        f"{topology.generated_at}",
        "",
        draft,
        "",
    ]
    if counts.get(CRITICAL):
        lines.insert(4, f"> ⚠ {counts[CRITICAL]} critical change(s) require attention.")
        lines.insert(5, "")
    if note:
        lines.extend([f"> {note}", ""])

    structural = [change for change in report.changes if change.severity != INFO]
    if structural:
        lines.append("## Structural changes")
        lines.append("")
        lines.extend(_bullets(report, {CRITICAL, WARNING, NOTICE}))
    drifted = report.by_severity(INFO)
    if drifted:
        lines.append("<details><summary>Telemetry drift (not structural)</summary>")
        lines.append("")
        for change in drifted[:12]:
            keys = ", ".join(str(key) for key in (change.after or []))
            lines.append(f"- `{change.label or change.entity}`: {keys}")
        if len(drifted) > 12:
            lines.append(f"- … {len(drifted) - 12} more")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if not report.changes:
        lines.append("_No structural or telemetry change was observed._")
        lines.append("")

    summary_bits = [
        f"{counts.get(severity, 0)} {severity}"
        for severity in (CRITICAL, WARNING, "notice")
        if counts.get(severity)
    ]
    lines.append("---")
    lines.append("")
    lines.append(
        f"{' · '.join(summary_bits) if summary_bits else 'no changes'} · "
        f"fingerprint `{topology.fingerprint[:19]}` · scribe: {used}"
    )
    if warning:
        lines.append("")
        lines.append(f"_{warning}_")
    lines.append("")
    return ScribeOutput(markdown="\n".join(lines), backend=used, narrative=draft, warning=warning)


_SYSTEM_RULES = (
    "You are the scribe of an edge data centre. Rewrite the factual summary below as "
    "two to four short sentences of plain prose. Rules: keep every host, workload and "
    "model name exactly as written; invent no facts, numbers or names; no lists, "
    "headings, code fences or markdown; at most 90 words; do not mention being an AI. "
    "A restrained surveying metaphor is welcome once, not twice."
)


def polish(draft: str, report: DiffReport, config: Config) -> str:
    """Ask the local model to rewrite the narrative. Facts are not sent as prose."""

    facts = {
        "headline": report.headline(),
        "structural": [
            {
                "action": change.action,
                "entity": change.entity_type,
                "name": change.label or change.entity,
                "field": change.field,
                "before": change.before,
                "after": change.after,
                "severity": change.severity,
            }
            for change in report.changes
            if change.severity != INFO
        ][:24],
    }
    prompt = (
        f"{_SYSTEM_RULES}\n\nFactual summary:\n{draft}\n\n"
        f"Machine-readable changes (JSON):\n{json.dumps(facts, default=str)}\n\nProse:"
    )
    endpoint = config.ollama_endpoint.rstrip("/") + "/api/generate"
    body = json.dumps(
        {
            "model": config.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 220},
        }
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - configured local endpoint
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "the-surveyor/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.llm_timeout) as response:  # noqa: S310 - configured local endpoint
            payload = json.loads(response.read(1_000_000).decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"{config.ollama_endpoint}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LLMError("model returned a non-JSON response") from exc

    text = str(payload.get("response") or "").strip() if isinstance(payload, dict) else ""
    text = text.strip("`").strip()
    if not text:
        raise LLMError("model returned an empty response")
    if len(text) > 1200:
        text = text[:1200].rsplit(" ", 1)[0]
    return " ".join(text.split())


def describe_report(report: DiffReport) -> dict[str, Any]:
    """Compact structure used by the daemon's JSON log."""

    return {
        "headline": report.headline(),
        "structural": report.structural,
        "counts": report.counts(),
        "changes": len(report.changes),
    }
