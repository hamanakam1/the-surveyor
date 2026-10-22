"""Executable validation of an OET document.

The project ships a JSON Schema, and a schema that is only read by humans is
a schema that eventually lies. This module is the same contract expressed in
code, with no dependency: the rule set is small enough that a hand-written
validator is clearer and faster than pulling in a JSON Schema engine.

What it checks:

* the shape of the document -- required fields, types, unknown fields,
* the vocabularies -- node kinds, layers, relations -- against the model's,
* the id grammar and the fingerprint format,
* that every edge points at a node that exists,
* that the declared fingerprint matches the recomputed one.

The version rule follows the specification rather than the schema's literal
reading: consumers must reject an unknown *major* and may accept an unknown
*minor*, so ``1.7`` is a valid document and ``2.0`` is not. The committed
schema says the same thing, in a pattern rather than a ``const``.

Every problem carries a stable code so that a caller -- a CI job, a test, a
human -- can react to the kind of fault rather than parse prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from .model import KINDS, LAYERS, RELATIONS, Topology

#: The node fields a plat may carry. Anything else is a mistake, not an
#: extension: the format is versioned, and extensions belong in ``facts``.
NODE_FIELDS = frozenset({"id", "kind", "layer", "label", "facts", "telemetry", "tags", "source"})

#: The edge fields a plat may carry.
EDGE_FIELDS = frozenset({"source", "relation", "target", "facts"})

#: The top-level fields a plat must carry.
REQUIRED_FIELDS = ("oet_version", "site", "generated_at", "nodes", "edges")

#: A node id is a slug, and a slug is boring on purpose.
ID_PATTERN = re.compile(r"^[a-z0-9_.:/@+-]+$")

#: A fingerprint is a digest, and a digest says so.
FINGERPRINT_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

#: A timestamp, in the form the tool writes.
TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


@dataclass(frozen=True, slots=True)
class Problem:
    """One thing wrong with a document."""

    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


def _check_attribute_value(value: Any, path: str, problems: list[Problem]) -> None:
    if _is_scalar(value):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            if not _is_scalar(item):
                problems.append(
                    Problem("bad-type", f"{path}[{index}]", "expected a scalar")
                )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not _is_scalar(item):
                problems.append(
                    Problem("bad-type", f"{path}.{key}", "expected a scalar")
                )
        return
    problems.append(
        Problem(
            "bad-type",
            path,
            "expected a scalar, a list of scalars, or a map of scalars",
        )
    )


def _check_attribute_map(value: Any, path: str, problems: list[Problem]) -> None:
    if not isinstance(value, dict):
        problems.append(Problem("bad-type", path, "expected an object"))
        return
    for key, item in value.items():
        _check_attribute_value(item, f"{path}.{key}", problems)


def _check_version(value: Any, problems: list[Problem]) -> None:
    if not isinstance(value, str):
        problems.append(Problem("bad-type", "oet_version", "expected a string"))
        return
    match = re.match(r"^(\d+)\.(\d+)$", value)
    if not match:
        problems.append(
            Problem("bad-value", "oet_version", "expected MAJOR.MINOR")
        )
        return
    major = int(match.group(1))
    if major != 1:
        problems.append(
            Problem(
                "unknown-version",
                "oet_version",
                f"OET {value} is not a 1.x document; consumers must reject an unknown major",
            )
        )


def _check_node(node: Any, index: int, problems: list[Problem]) -> None:
    path = f"nodes[{index}]"
    if not isinstance(node, dict):
        problems.append(Problem("bad-type", path, "expected an object"))
        return

    for field in ("id", "kind", "layer", "label", "facts", "telemetry"):
        if field not in node:
            problems.append(Problem("missing-field", f"{path}.{field}", "required field is missing"))

    for field in sorted(set(node) - NODE_FIELDS):
        problems.append(
            Problem("unknown-field", f"{path}.{field}", "field is not part of OET 1.0")
        )

    identifier = node.get("id")
    if isinstance(identifier, str):
        if not identifier:
            problems.append(Problem("empty", f"{path}.id", "node id must not be empty"))
        elif not ID_PATTERN.match(identifier):
            problems.append(
                Problem(
                    "bad-pattern",
                    f"{path}.id",
                    "node id must match ^[a-z0-9_.:/@+-]+$",
                )
            )
    elif identifier is not None:
        problems.append(Problem("bad-type", f"{path}.id", "expected a string"))

    kind = node.get("kind")
    if isinstance(kind, str) and kind not in KINDS:
        problems.append(
            Problem("unknown-kind", f"{path}.kind", f"unknown node kind {kind!r}")
        )

    layer = node.get("layer")
    if isinstance(layer, str) and layer not in LAYERS:
        problems.append(
            Problem("unknown-layer", f"{path}.layer", f"unknown layer {layer!r}")
        )

    label = node.get("label")
    if isinstance(label, str) and not label:
        problems.append(Problem("empty", f"{path}.label", "label must not be empty"))

    for field in ("facts", "telemetry"):
        if field in node:
            _check_attribute_map(node[field], f"{path}.{field}", problems)

    tags = node.get("tags")
    if tags is not None:
        if not isinstance(tags, list):
            problems.append(Problem("bad-type", f"{path}.tags", "expected an array"))
        else:
            for position, tag in enumerate(tags):
                if not isinstance(tag, str):
                    problems.append(
                        Problem("bad-type", f"{path}.tags[{position}]", "expected a string")
                    )
            if len(set(tags)) != len(tags):
                problems.append(
                    Problem("duplicate", f"{path}.tags", "tags must be unique")
                )

    source = node.get("source")
    if source is not None and not isinstance(source, str):
        problems.append(Problem("bad-type", f"{path}.source", "expected a string"))


def _check_edge(edge: Any, index: int, problems: list[Problem]) -> None:
    path = f"edges[{index}]"
    if not isinstance(edge, dict):
        problems.append(Problem("bad-type", path, "expected an object"))
        return

    for field in ("source", "relation", "target", "facts"):
        if field not in edge:
            problems.append(Problem("missing-field", f"{path}.{field}", "required field is missing"))

    for field in sorted(set(edge) - EDGE_FIELDS):
        problems.append(
            Problem("unknown-field", f"{path}.{field}", "field is not part of OET 1.0")
        )

    relation = edge.get("relation")
    if isinstance(relation, str) and relation not in RELATIONS:
        problems.append(
            Problem("unknown-relation", f"{path}.relation", f"unknown relation {relation!r}")
        )

    for field in ("source", "target"):
        value = edge.get(field)
        if value is not None and not isinstance(value, str):
            problems.append(Problem("bad-type", f"{path}.{field}", "expected a string"))
        elif isinstance(value, str) and not value:
            problems.append(Problem("empty", f"{path}.{field}", "edge endpoint must not be empty"))

    if "facts" in edge:
        _check_attribute_map(edge["facts"], f"{path}.facts", problems)


def _check_counts(counts: Any, problems: list[Problem]) -> None:
    if counts is None:
        return
    if not isinstance(counts, dict):
        problems.append(Problem("bad-type", "counts", "expected an object"))
        return
    allowed = {"nodes", "edges", "by_layer", "by_kind", "by_relation"}
    for field in sorted(set(counts) - allowed):
        problems.append(
            Problem("unknown-field", f"counts.{field}", "field is not part of OET 1.0")
        )
    for field in ("nodes", "edges"):
        value = counts.get(field)
        if value is None:
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append(
                Problem("bad-value", f"counts.{field}", "expected a non-negative integer")
            )
    for field in ("by_layer", "by_kind", "by_relation"):
        value = counts.get(field)
        if value is None:
            continue
        if not isinstance(value, dict):
            problems.append(Problem("bad-type", f"counts.{field}", "expected an object"))
            continue
        for key, count in value.items():
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                problems.append(
                    Problem(
                        "bad-value",
                        f"counts.{field}.{key}",
                        "expected a non-negative integer",
                    )
                )


def validate_document(document: Mapping[str, Any]) -> list[Problem]:
    """Check a plat document against the OET rules.

    Returns every problem found, not just the first: an operator fixing a
    file wants the whole list.
    """

    problems: list[Problem] = []
    if not isinstance(document, Mapping):
        return [Problem("bad-type", "", "document must be an object")]

    for field in REQUIRED_FIELDS:
        if field not in document:
            problems.append(Problem("missing-field", field, "required field is missing"))

    if "oet_version" in document:
        _check_version(document["oet_version"], problems)

    site = document.get("site")
    if site is not None:
        if not isinstance(site, str):
            problems.append(Problem("bad-type", "site", "expected a string"))
        elif not site:
            problems.append(Problem("empty", "site", "site must not be empty"))

    generated = document.get("generated_at")
    if generated is not None:
        if not isinstance(generated, str):
            problems.append(Problem("bad-type", "generated_at", "expected a string"))
        elif not TIMESTAMP_PATTERN.match(generated):
            problems.append(
                Problem("bad-timestamp", "generated_at", "expected an ISO-8601 timestamp")
            )
        else:
            try:
                datetime.fromisoformat(generated.replace("Z", "+00:00"))
            except ValueError:
                problems.append(
                    Problem("bad-timestamp", "generated_at", "not a real timestamp")
                )

    fingerprint = document.get("fingerprint")
    if fingerprint is not None:
        if not isinstance(fingerprint, str):
            problems.append(Problem("bad-type", "fingerprint", "expected a string"))
        elif not FINGERPRINT_PATTERN.match(fingerprint):
            problems.append(
                Problem(
                    "bad-pattern",
                    "fingerprint",
                    "expected sha256: followed by 64 lowercase hex digits",
                )
            )

    _check_counts(document.get("counts"), problems)

    nodes = document.get("nodes")
    seen_ids: set[str] = set()
    if nodes is not None:
        if not isinstance(nodes, list):
            problems.append(Problem("bad-type", "nodes", "expected an array"))
        else:
            for index, node in enumerate(nodes):
                _check_node(node, index, problems)
                if isinstance(node, dict) and isinstance(node.get("id"), str):
                    if node["id"] in seen_ids:
                        problems.append(
                            Problem(
                                "duplicate",
                                f"nodes[{index}].id",
                                f"node id {node['id']!r} appears more than once",
                            )
                        )
                    seen_ids.add(node["id"])

    edges = document.get("edges")
    seen_edges: set[tuple[str, str, str]] = set()
    if edges is not None:
        if not isinstance(edges, list):
            problems.append(Problem("bad-type", "edges", "expected an array"))
        else:
            for index, edge in enumerate(edges):
                _check_edge(edge, index, problems)
                if isinstance(edge, dict):
                    key = (str(edge.get("source")), str(edge.get("relation")), str(edge.get("target")))
                    if key in seen_edges:
                        problems.append(
                            Problem(
                                "duplicate",
                                f"edges[{index}]",
                                "edge appears more than once",
                            )
                        )
                    seen_edges.add(key)
                    for endpoint in ("source", "target"):
                        value = edge.get(endpoint)
                        if isinstance(value, str) and value not in seen_ids:
                            problems.append(
                                Problem(
                                    "dangling-edge",
                                    f"edges[{index}].{endpoint}",
                                    f"no node with id {value!r}",
                                )
                            )

    return problems


def validate_topology(
    topology: Topology, document: Mapping[str, Any] | None = None
) -> list[Problem]:
    """Check a live plat, including the fingerprint it declares.

    ``document`` is the document the plat was read from, when it is
    available: the fingerprint it *declared* is what has to be checked, and
    re-serialising the plat would regenerate that fingerprint and hide the
    very thing being looked for.
    """

    source = document if document is not None else topology.to_dict()
    problems = validate_document(source)
    declared = str(source.get("fingerprint") or "")
    if declared and declared != topology.fingerprint:
        problems.append(
            Problem(
                "fingerprint-mismatch",
                "fingerprint",
                f"declared {declared[:19]} does not match the document ({topology.fingerprint[:19]})",
            )
        )
    return problems


def codes(problems: Sequence[Problem]) -> list[str]:
    """The distinct problem codes, in order."""

    seen: list[str] = []
    for problem in problems:
        if problem.code not in seen:
            seen.append(problem.code)
    return seen
