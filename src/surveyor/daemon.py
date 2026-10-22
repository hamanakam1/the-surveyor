"""The survey daemon: take bearings on a schedule, record only what moves.

Design notes that matter operationally:

* One instance per ledger, enforced with a non-blocking advisory lock.
* A failed scanner produces a partial plat, not a crash.
* A survey whose structural fingerprint matches HEAD writes no new entry,
  which is what makes a five-minute cadence sustainable.
* SIGINT/SIGTERM finish the current cycle's bookkeeping and exit cleanly.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from .compiler import survey
from .config import Config
from .differ import diff_topologies
from .errors import StoreError
from .scribe import compose_changelog
from .store import Ledger
from .util import short_digest

try:  # pragma: no cover - POSIX only
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


@dataclass(slots=True)
class DaemonStats:
    cycles: int = 0
    recorded: int = 0
    unchanged: int = 0
    structural_changes: int = 0
    failures: int = 0
    started_at: float = field(default_factory=time.time)


class InstanceLock:
    """Non-blocking exclusive lock so two daemons cannot share a ledger."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: TextIO | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+", encoding="utf-8")
        if fcntl is not None:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                handle.close()
                raise StoreError(
                    f"another surveyor daemon already holds {self.path}"
                ) from exc
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        self._handle = handle

    def release(self) -> None:
        if self._handle is None:
            return
        if fcntl is not None:
            try:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            except OSError:  # pragma: no cover
                pass
        self._handle.close()
        self._handle = None


def _install_stop_handlers(stop: threading.Event) -> list[int]:
    installed: list[int] = []

    def handler(_signum: int, _frame: object) -> None:
        stop.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, handler)
            installed.append(signum)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            continue
    return installed


def run_daemon(
    config: Config,
    *,
    interval: int | None = None,
    once: bool = False,
    max_cycles: int | None = None,
    json_lines: bool = False,
    stop: threading.Event | None = None,
    emit: Callable[[str], None] = print,
) -> DaemonStats:
    """Run survey cycles until stopped, ``once``, or ``max_cycles``."""

    ledger = Ledger(config.store)
    lock = InstanceLock(config.store / "daemon.lock")
    lock.acquire()
    stats = DaemonStats()
    stop_event = stop or threading.Event()
    cadence = max(1, interval or config.interval)
    previous_handlers = _install_stop_handlers(stop_event)

    def log(payload: dict[str, object], human: str) -> None:
        if json_lines:
            emit(json.dumps(payload, default=str))
        else:
            emit(human)

    try:
        while not stop_event.is_set():
            cycle_started = time.perf_counter()
            stats.cycles += 1
            report = survey(config)
            topology = report.topology
            head = ledger.head()
            previous = ledger.get(head.digest) if head else None
            diff = diff_topologies(previous, topology)
            commit = ledger.commit(topology)

            payload: dict[str, object] = {
                "cycle": stats.cycles,
                "site": topology.site,
                "nodes": len(topology.nodes),
                "edges": len(topology.edges),
                "fingerprint": topology.fingerprint,
                "recorded": commit.created,
                "structural": diff.structural,
                "changes": len(diff.changes),
                "duration_ms": int((time.perf_counter() - cycle_started) * 1000),
            }

            if commit.created:
                stats.recorded += 1
                if diff.structural:
                    stats.structural_changes += 1
                    output = compose_changelog(diff, topology, previous=previous, config=config)
                    path = ledger.write_change(commit.entry, output.markdown)
                    payload["changelog"] = str(path)
                    if output.warning:
                        payload["scribe_warning"] = output.warning
                human = (
                    f"[{time.strftime('%H:%M:%S')}] #{commit.entry.seq} {diff.headline()} "
                    f"({len(topology.nodes)} nodes, {len(topology.edges)} edges)"
                )
            else:
                stats.unchanged += 1
                human = f"[{time.strftime('%H:%M:%S')}] {topology.fingerprint[:15]} unchanged"

            if report.failures:
                stats.failures += len(report.failures)
                payload["failures"] = [result.scanner for result in report.failures]
                human += f" · {len(report.failures)} scanner failure(s)"
            log(payload, human)

            if once or (max_cycles is not None and stats.cycles >= max_cycles):
                break

            deadline = time.monotonic() + cadence
            while not stop_event.is_set() and time.monotonic() < deadline:
                stop_event.wait(min(0.5, cadence))
    finally:
        for signum in previous_handlers:
            try:
                signal.signal(signum, signal.SIG_DFL)
            except (ValueError, OSError):  # pragma: no cover
                pass
        lock.release()
    return stats


def format_daemon_start(config: Config, *, interval: int, once: bool) -> str:
    mode = "one cycle" if once else f"every {interval}s"
    return (
        f"surveying {config.site} {mode} · store {config.store} · "
        f"scanners {', '.join(config.scanners)} · fingerprint-first idempotence"
    )


def ledger_summary(path: Path) -> str:
    ledger = Ledger(path)
    head = ledger.head()
    if head is None:
        return f"{path}: empty ledger"
    return f"{path}: {head.seq + 1} entries · HEAD {short_digest(head.digest)}"
