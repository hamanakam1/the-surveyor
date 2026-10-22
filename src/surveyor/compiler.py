"""Topological compilation: run scanners, then fold their findings into one map.

The compiler is deliberately boring. It starts every scanner concurrently,
waits with a hard budget, merges duplicate nodes, drops edges that point at
things nobody observed, and stamps the result with a structural fingerprint.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .config import Config
from .identity import hostname
from .model import LAYER_LABELS, LAYERS, Topology
from .scanners.base import ScanContext, ScanResult, ScannerSpec, resolve

ProgressFn = Callable[[str], None]


@dataclass(slots=True)
class CompilationReport:
    topology: Topology
    results: list[ScanResult] = field(default_factory=list)

    @property
    def failures(self) -> list[ScanResult]:
        return [result for result in self.results if not result.ok]

    @property
    def warnings(self) -> list[str]:
        return [note for result in self.results for note in result.notes]


def execute_scanners(
    config: Config,
    *,
    site: str | None = None,
    progress: ProgressFn | None = None,
    specs: Iterable[ScannerSpec] | None = None,
) -> list[ScanResult]:
    """Run the configured scanners concurrently and return their outcomes."""

    selected = list(specs) if specs is not None else resolve(config.scanners)
    if not selected:
        return []

    ctx = ScanContext(config=config, site=site or config.site)
    results: list[ScanResult] = []
    deadline = config.scanner_timeout + 5.0

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, max(1, len(selected))),
        thread_name_prefix="surveyor",
    ) as pool:
        futures = {pool.submit(spec.run, ctx): spec for spec in selected}
        for future in concurrent.futures.as_completed(futures, timeout=deadline):
            spec = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - a scanner must never kill the survey
                result = ScanResult(
                    scanner=spec.name,
                    layer=spec.layer,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            results.append(result)
            if progress:
                progress(result.summary)
        for future, spec in futures.items():
            if future.done():
                continue
            future.cancel()
            results.append(
                ScanResult(
                    scanner=spec.name,
                    layer=spec.layer,
                    ok=False,
                    error=f"exceeded {deadline:.0f}s scanner budget",
                    notes=["scanner timed out; survey continued without it"],
                )
            )
            if progress:
                progress(f"{spec.name}: timed out")

    order = {spec.name: index for index, spec in enumerate(selected)}
    results.sort(key=lambda item: order.get(item.scanner, 99))
    return results


def compile_topology(
    results: Iterable[ScanResult],
    config: Config,
    *,
    duration_ms: int = 0,
    site: str | None = None,
) -> Topology:
    """Merge scanner results into a single, validated OET document."""

    result_list = list(results)
    topology = Topology(site=(site or config.site).strip() or "edge")
    notes: list[str] = []
    conflicts: list[str] = []

    for result in result_list:
        for node in result.nodes:
            existing = topology.nodes.get(node.id)
            if existing is not None and existing.kind != node.kind:
                conflicts.append(
                    f"{node.id}: kind conflict {existing.kind!r} vs {node.kind!r} from {result.scanner}"
                )
                continue
            topology.add(node)
        topology.edges.extend(result.edges)
        for note in result.notes:
            notes.append(f"{result.scanner}: {note}")

    dangling = topology.prune_dangling()
    for edge in dangling:
        notes.append(f"dropped dangling edge {edge.id}")
    # Normalise ordering once so the document, the fingerprint, and a
    # round-tripped copy all agree byte for byte.
    topology.edges = Topology._dedupe_edges(topology.edges)

    topology.observations = {
        "platform": _platform(),
        "hostname": hostname(),
        "duration_ms": duration_ms,
        "scanners": [result.to_observation() for result in result_list],
        "warnings": notes,
        "conflicts": conflicts,
        "layers": {
            layer: {
                "label": LAYER_LABELS[layer],
                "nodes": len(topology.nodes_in_layer(layer)),
            }
            for layer in LAYERS
        },
        "redacted": bool(config.redact),
    }
    return topology


def survey(
    config: Config,
    *,
    site: str | None = None,
    progress: ProgressFn | None = None,
    salt: str = "",
) -> CompilationReport:
    """Full survey: execute scanners, then compile."""

    started = time.perf_counter()
    results = execute_scanners(config, site=site, progress=progress)
    duration_ms = int((time.perf_counter() - started) * 1000)
    topology = compile_topology(results, config, duration_ms=duration_ms, site=site)
    if config.redact:
        from .redact import redact_topology

        topology = redact_topology(topology, salt=salt)
    return CompilationReport(topology=topology, results=results)


def _platform() -> str:
    import platform

    return f"{platform.system().lower()}/{platform.machine()}"
