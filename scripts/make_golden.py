#!/usr/bin/env python3
"""Generate the golden plats under ``tests/fixtures/plats``.

A golden plat says, for one scanner and one platform, exactly what the
scanner makes of a recorded command output: which nodes, which edges, which
facts. It is the difference between "the parser still works" and "the
parser still produces the same map".

The command outputs live in ``tests/fixtures/commands``. The goldens are
*generated* from them, so that regenerating one is a deliberate act with a
reviewable diff rather than a copy-and-paste.

Run from the repo root::

    PYTHONPATH=src python3 scripts/make_golden.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from surveyor.config import Config
from surveyor.scanners import (
    host,
    network,
    power,
    services,
    workloads,
)
from surveyor.scanners.base import ScanContext, ScanResult

ROOT = Path(__file__).resolve().parent.parent
COMMANDS = ROOT / "tests" / "fixtures" / "commands"
PLATS = ROOT / "tests" / "fixtures" / "plats"

#: The scanner each fixture belongs to.
SCANNERS = {
    "host": host.scan_host,
    "network": network.scan_network,
    "power": power.scan_power,
    "services": services.scan_services,
    "workloads": workloads.scan_workloads,
}


class _Runner:
    """A stand-in for ``probe.run`` that answers from a table."""

    def __init__(self, table: dict[str, str]) -> None:
        self.table = table

    def __call__(self, argv, timeout: float = 8.0):
        from surveyor.probe import Probe

        vector = tuple(argv)
        command = " ".join(vector)
        best: tuple[int, str] | None = None
        for needle, output in self.table.items():
            if needle in command and (best is None or len(needle) > best[0]):
                best = (len(needle), output)
        if best is not None:
            return Probe(vector, ok=True, stdout=best[1])
        return Probe(vector, ok=False, reason="not installed")


def _scan(name: str, fixture: dict[str, Any]) -> ScanResult:
    module = {
        "host": host,
        "network": network,
        "power": power,
        "services": services,
        "workloads": workloads,
    }[name]
    runner = _Runner(fixture["outputs"])
    # The recorded plats use this synthetic host identity and fallback hardware.
    # Replaying commands alone still lets the runner's hostname, architecture,
    # CPU count, and container markers change the map. Keep those inputs scoped
    # to the replay, including when a scanner raises.
    with (
        patch.object(module, "run", runner),
        patch.object(module, "local_host_id", return_value="host:mac"),
        patch.object(host, "local_hostname", return_value="Mac"),
        patch.object(network, "hostname", return_value="Mac"),
        patch.object(host.platform, "system", return_value=fixture.get("platform", "darwin").title()),
        patch.object(host.platform, "machine", return_value="arm64"),
        patch.object(host.os, "cpu_count", return_value=16),
        patch.object(host, "_virtualisation", return_value=None),
    ):
        context = ScanContext(
            config=Config(),
            site="golden",
            platform=fixture.get("platform", "darwin"),
        )
        return SCANNERS[name](context)


def shape(result: ScanResult) -> dict[str, Any]:
    """The map a scanner produced: its nodes, its edges, and its facts."""

    return {
        "nodes": sorted(
            (
                {
                    "id": node.id,
                    "kind": node.kind,
                    "label": node.label,
                    "facts": dict(sorted(node.facts.items())),
                    "tags": list(node.tags),
                }
                for node in result.nodes
            ),
            key=lambda item: item["id"],
        ),
        "edges": sorted(
            (
                {
                    "source": edge.source,
                    "relation": edge.relation,
                    "target": edge.target,
                }
                for edge in result.edges
            ),
            key=lambda item: (item["source"], item["relation"], item["target"]),
        ),
    }


def main() -> int:
    PLATS.mkdir(parents=True, exist_ok=True)
    written = 0
    for path in sorted(COMMANDS.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        name = fixture["scanner"]
        result = _scan(name, fixture)
        document = {
            "scanner": name,
            "platform": fixture.get("platform", "darwin"),
            "notes": sorted(result.notes),
            **shape(result),
        }
        target = PLATS / path.name
        target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"wrote {target.relative_to(ROOT)} · "
            f"{len(document['nodes'])} nodes · {len(document['edges'])} edges"
        )
        written += 1
    print(f"{written} golden plats")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
