#!/usr/bin/env python3
"""Generate the OET conformance suite.

Each file in ``tests/fixtures/invalid`` is a plat that is broken in exactly
one way. The file name says which way: ``<code>__<what>.json``. A test
validates every one of them and asserts the expected code comes back, so a
rule that stops being enforced fails the build.

The corpus is generated rather than hand-written so that every case is the
same document with one thing changed, and so that adding a rule is a matter
of adding a case.

Run from the repo root::

    PYTHONPATH=src python3 scripts/make_conformance.py
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

TARGET = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "invalid"

BASE: dict[str, Any] = {
    "oet_version": "1.0",
    "site": "conformance",
    "generated_at": "2026-01-01T00:00:00Z",
    "nodes": [
        {
            "id": "host:lab",
            "kind": "host",
            "layer": "metal",
            "label": "lab",
            "facts": {"cpu_cores": 4},
            "telemetry": {"load_1m": 0.4},
            "tags": [],
            "source": "host",
        },
        {
            "id": "workload:docker:web",
            "kind": "workload",
            "layer": "workload",
            "label": "web",
            "facts": {"runtime": "docker"},
            "telemetry": {},
            "tags": ["container"],
            "source": "workloads",
        },
    ],
    "edges": [
        {
            "source": "host:lab",
            "relation": "runs",
            "target": "workload:docker:web",
            "facts": {"runtime": "docker"},
        }
    ],
}


def base() -> dict[str, Any]:
    return json.loads(json.dumps(BASE))


def without(field: str) -> Callable[[], dict[str, Any]]:
    def build() -> dict[str, Any]:
        document = base()
        document.pop(field, None)
        return document

    return build


def with_node(field: str, value: Any) -> Callable[[], dict[str, Any]]:
    def build() -> dict[str, Any]:
        document = base()
        document["nodes"][0][field] = value
        return document

    return build


def with_edge(field: str, value: Any) -> Callable[[], dict[str, Any]]:
    def build() -> dict[str, Any]:
        document = base()
        document["edges"][0][field] = value
        return document

    return build


def duplicate_node() -> dict[str, Any]:
    document = base()
    document["nodes"].append(json.loads(json.dumps(document["nodes"][0])))
    return document


def duplicate_edge() -> dict[str, Any]:
    document = base()
    document["edges"].append(json.loads(json.dumps(document["edges"][0])))
    return document


def dangling_edge() -> dict[str, Any]:
    document = base()
    document["edges"][0]["target"] = "workload:ghost"
    return document


def nested_fact() -> dict[str, Any]:
    document = base()
    document["nodes"][0]["facts"] = {"ports": [{"number": 80}]}
    return document


def duplicate_tags() -> dict[str, Any]:
    document = base()
    document["nodes"][1]["tags"] = ["container", "container"]
    return document


def bad_counts() -> dict[str, Any]:
    document = base()
    document["counts"] = {"nodes": 2, "edges": 1, "by_kind": {"host": -1}}
    return document


CASES: dict[str, Callable[[], dict[str, Any]]] = {
    "missing-field__no-oet-version": without("oet_version"),
    "missing-field__no-nodes": without("nodes"),
    "missing-field__node-without-facts": lambda: {
        **base(),
        "nodes": [{k: v for k, v in base()["nodes"][0].items() if k != "facts"}],
    },
    "unknown-version__major-two": lambda: {**base(), "oet_version": "2.0"},
    "bad-value__version-not-a-version": lambda: {**base(), "oet_version": "one"},
    "unknown-kind__not-a-kind": with_node("kind", "sensor"),
    "unknown-layer__not-a-layer": with_node("layer", "datacentre"),
    "unknown-relation__not-a-relation": with_edge("relation", "talks_to"),
    "unknown-field__node-has-extra": with_node("colour", "red"),
    "unknown-field__edge-has-extra": with_edge("weight", 3),
    "bad-pattern__uppercase-id": with_node("id", "host:Lab"),
    "bad-pattern__space-in-id": with_node("id", "host:lab box"),
    "bad-pattern__fingerprint-not-a-digest": lambda: {
        **base(),
        "fingerprint": "not-a-digest",
    },
    "bad-type__site-is-a-number": lambda: {**base(), "site": 7},
    "bad-type__nodes-is-an-object": lambda: {**base(), "nodes": {}},
    "bad-type__nested-fact": nested_fact,
    "bad-value__counts-by-kind-negative": bad_counts,
    "bad-timestamp__not-a-timestamp": lambda: {**base(), "generated_at": "yesterday"},
    "empty__label-is-blank": with_node("label", ""),
    "empty__edge-endpoint-is-blank": with_edge("target", ""),
    "duplicate__same-node-twice": duplicate_node,
    "duplicate__same-edge-twice": duplicate_edge,
    "duplicate__same-tag-twice": duplicate_tags,
    "dangling-edge__points-at-nothing": dangling_edge,
}


def main() -> int:
    TARGET.mkdir(parents=True, exist_ok=True)
    for existing in TARGET.glob("*.json"):
        existing.unlink()
    for name, build in sorted(CASES.items()):
        path = TARGET / f"{name}.json"
        path.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(CASES)} conformance cases to {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
