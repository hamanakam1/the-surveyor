#!/usr/bin/env python3
"""Generate schema/oet-1.0.schema.json from the model.

The schema is the OET contract, so it must not be able to drift away from
the vocabularies the code actually uses. This script builds it from
``surveyor.model`` -- the node kinds, the layers, the relations -- and a
test asserts that the committed file is exactly what this script produces.

Run from the repo root::

    PYTHONPATH=src python3 scripts/make_schema.py

``make schema`` does the same thing.
"""

from __future__ import annotations

import json
from pathlib import Path

from surveyor.model import KINDS, LAYERS, RELATIONS

TARGET = Path(__file__).resolve().parent.parent / "schema" / "oet-1.0.schema.json"


def build() -> dict:
    """The OET 1.x schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://raw.githubusercontent.com/hamanakam1/the-surveyor/main/schema/oet-1.0.schema.json",
        "title": "Open Edge Topology (OET) 1.0",
        "description": (
            "A survey plat: the observed nodes, the observed edges, and the "
            "circumstances of observation. Facts are structural; telemetry is "
            "weather."
        ),
        "type": "object",
        "required": ["oet_version", "site", "generated_at", "nodes", "edges"],
        "additionalProperties": True,
        "properties": {
            "oet_version": {
                "pattern": "^1\\.[0-9]+$",
                "description": (
                    "Schema major.minor. Consumers must reject an unknown "
                    "major and may accept an unknown minor, so this pattern "
                    "covers the whole 1.x family."
                ),
            },
            "generator": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                },
                "required": ["name"],
                "additionalProperties": True,
            },
            "site": {
                "type": "string",
                "minLength": 1,
                "description": "Operator-chosen name for the surveyed location.",
            },
            "generated_at": {
                "type": "string",
                "format": "date-time",
                "description": "UTC timestamp of the survey, second precision.",
            },
            "fingerprint": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
                "description": (
                    "Digest of the structural payload. Ignores timestamps, "
                    "telemetry, and observation notes."
                ),
            },
            "counts": {
                "type": "object",
                "properties": {
                    "nodes": {"type": "integer", "minimum": 0},
                    "edges": {"type": "integer", "minimum": 0},
                    "by_layer": {"type": "object", "additionalProperties": {"type": "integer"}},
                    "by_kind": {"type": "object", "additionalProperties": {"type": "integer"}},
                    "by_relation": {"type": "object", "additionalProperties": {"type": "integer"}},
                },
                "additionalProperties": False,
            },
            "nodes": {"type": "array", "items": {"$ref": "#/$defs/node"}},
            "edges": {"type": "array", "items": {"$ref": "#/$defs/edge"}},
            "observations": {
                "type": "object",
                "description": (
                    "How the survey was taken: scanner outcomes, warnings, "
                    "conflicts, duration. Not part of the fingerprint."
                ),
                "additionalProperties": True,
            },
        },
        "$defs": {
            "scalar": {"type": ["string", "number", "boolean"]},
            "attributeMap": {
                "type": "object",
                "additionalProperties": {
                    "oneOf": [
                        {"$ref": "#/$defs/scalar"},
                        {"type": "array", "items": {"$ref": "#/$defs/scalar"}},
                        {"type": "object", "additionalProperties": {"$ref": "#/$defs/scalar"}},
                    ]
                },
            },
            "node": {
                "type": "object",
                "required": ["id", "kind", "layer", "label", "facts", "telemetry"],
                "additionalProperties": False,
                "properties": {
                    "id": {
                        "type": "string",
                        "pattern": "^[a-z0-9_.:/@+-]+$",
                        "description": (
                            "Stable, human-readable identifier. Same physical "
                            "thing, same id, across surveys."
                        ),
                    },
                    "kind": {"enum": sorted(KINDS)},
                    "layer": {"enum": sorted(LAYERS)},
                    "label": {"type": "string", "minLength": 1},
                    "facts": {
                        "$ref": "#/$defs/attributeMap",
                        "description": (
                            "Structural attributes. Changing one changes the "
                            "fingerprint."
                        ),
                    },
                    "telemetry": {
                        "$ref": "#/$defs/attributeMap",
                        "description": (
                            "Measurements that drift by design. Never part of "
                            "the fingerprint."
                        ),
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "uniqueItems": True,
                    },
                    "source": {
                        "type": "string",
                        "description": "Scanner that observed this node.",
                    },
                },
            },
            "edge": {
                "type": "object",
                "required": ["source", "relation", "target", "facts"],
                "additionalProperties": False,
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "Node id. Must exist in the nodes array.",
                    },
                    "relation": {"enum": sorted(RELATIONS)},
                    "target": {
                        "type": "string",
                        "description": "Node id. Must exist in the nodes array.",
                    },
                    "facts": {"$ref": "#/$defs/attributeMap"},
                },
            },
        },
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    text = render()
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, encoding="utf-8")
    print(f"wrote {TARGET}")
    print(f"kinds {len(KINDS)} · layers {len(LAYERS)} · relations {len(RELATIONS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
