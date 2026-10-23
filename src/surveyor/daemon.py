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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from .compiler import survey
from .config import Config
from .differ import diff_topologies
from .errors import ConfigError, StoreError
from .notify import Notifier
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
        # The handle is held for the life of the process on purpose: an
        # flock is released when its descriptor closes.
        handle = open(self.path, "a+", encoding="utf-8")  # noqa: SIM115 - held on purpose
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


def _install_stop_handlers(stop: threading.Event) -> dict[int, Any]:
    previous: dict[int, Any] = {}

    def handler(_signum: int, _frame: object) -> None:
        stop.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.signal(signum, handler)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            continue
    return previous


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

    cadence = config.interval if interval is None else interval
    if type(cadence) is not int or cadence <= 0:
        raise ConfigError("interval must be a positive integer number of seconds")
    if max_cycles is not None and (type(max_cycles) is not int or max_cycles <= 0):
        raise ConfigError("max_cycles must be a positive integer")

    ledger = Ledger(config.store)
    lock = InstanceLock(config.store / "daemon.lock")
    lock.acquire()
    stats = DaemonStats()
    notifier = Notifier(
        config.notify,
        timeout=config.notify_timeout,
        format=config.notify_format,
        on=config.notify_on,
    )
    stop_event = stop or threading.Event()
    previous_handlers = _install_stop_handlers(stop_event)

    def log(payload: dict[str, object], human: str) -> None:
        if json_lines:
            emit(json.dumps(payload, default=str))
        else:
            emit(human)

    def one_cycle() -> None:
        """One survey, one diff, one commit, one line of output."""

        cycle_started = time.perf_counter()
        stats.cycles += 1
        # Use the ledger's redaction key so daemon plats stay comparable
        # with plats produced by `surveyor scan`.
        report = survey(config, salt=(ledger.salt if config.redact else ""))
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

        human_extra = ""
        if commit.created:
            stats.recorded += 1
            if diff.structural:
                stats.structural_changes += 1
                output = compose_changelog(diff, topology, previous=previous, config=config)
                path = ledger.write_change(commit.entry, output.markdown)
                payload["changelog"] = str(path)
                if output.warning:
                    payload["scribe_warning"] = output.warning
                if notifier.enabled:
                    results = notifier.send(diff, topology)
                    if results:
                        payload["notified"] = [
                            {
                                "endpoint": item.endpoint,
                                "ok": item.ok,
                                "status": item.status,
                                "error": item.error,
                            }
                            for item in results
                        ]
                        delivered = sum(1 for item in results if item.ok)
                        if delivered:
                            human_extra = f" · notified {delivered}/{len(results)}"
                        else:
                            human_extra = f" · notify failed ({results[0].error})"
            human = (
                f"[{time.strftime('%H:%M:%S')}] #{commit.entry.seq} {diff.headline()} "
                f"({len(topology.nodes)} nodes, {len(topology.edges)} edges)"
            ) + human_extra
        else:
            stats.unchanged += 1
            human = f"[{time.strftime('%H:%M:%S')}] {topology.fingerprint[:15]} unchanged"

        if report.failures:
            stats.failures += len(report.failures)
            payload["failures"] = [result.scanner for result in report.failures]
            human += f" · {len(report.failures)} scanner failure(s)"
        log(payload, human)

    try:
        while not stop_event.is_set():
            try:
                one_cycle()
            except StoreError:
                # A ledger-level failure is fatal: without a store there is
                # nowhere to record the survey, and a daemon that pretends
                # otherwise is worse than one that stops.
                raise
            except Exception as exc:
                # A bad cycle is not a bad daemon. Record it and go round
                # again: the whole point of running on a timer is to be
                # there when the machine comes back.
                stats.failures += 1
                log(
                    {
                        "cycle": stats.cycles,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                    f"[{time.strftime('%H:%M:%S')}] cycle failed: "
                    f"{type(exc).__name__}: {exc}",
                )

            if once or (max_cycles is not None and stats.cycles >= max_cycles):
                break

            deadline = time.monotonic() + cadence
            while not stop_event.is_set() and time.monotonic() < deadline:
                stop_event.wait(min(0.5, cadence))
    finally:
        for signum, previous in previous_handlers.items():
            try:
                signal.signal(signum, previous)
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
