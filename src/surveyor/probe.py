"""Read-only system probes.

Scanners are allowed to look, never to touch. This module is the single
chokepoint for that promise:

* commands are argument vectors (never shell strings),
* the executable must appear in :data:`ALLOWED_PROGRAMS`,
* the executable is resolved to an absolute path in a directory nobody else
  can write to, so a name in the allowlist cannot be shadowed by a file
  somewhere earlier in ``PATH``,
* ``subprocess`` runs with ``shell=False``, a scrubbed environment, empty
  stdin, and a hard timeout,
* a probe that overruns has its whole process group killed, not just the
  child that was spawned,
* filesystem reads are capped in size and never follow writes.

If a probe is missing, slow, or permission-denied, the caller gets a failed
:class:`Probe` instead of an exception. A survey with three working scanners
is more useful than a survey with zero.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ProbeError

#: Programs The Surveyor is willing to execute. All are introspection tools.
#: Anything not listed here -- including ``sudo``, ``sh``, ``osascript`` -- is
#: rejected before a process is spawned.
#:
#: The list is deliberately short. A program earns its place here when a
#: scanner calls it, and it loses it when the scanner goes away; a test
#: enforces that. The alternative -- a list of tools somebody might want --
#: is an attack surface waiting for a reason.
ALLOWED_PROGRAMS = frozenset(
    {
        "arp",
        "df",
        "docker",
        "ifconfig",
        "ioreg",
        "ip",
        "lsof",
        "networksetup",
        "pmset",
        "ps",
        "route",
        "ss",
        "sw_vers",
        "sysctl",
        "uname",
    }
)

#: Directories searched for allowlisted programs, in order. The inherited
#: ``PATH`` is not trusted: a survey must not run whatever happens to be
#: first in a path nobody curated.
SEARCH_PATH: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/opt/homebrew/sbin",
    "/opt/homebrew/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)

#: Environment variables that must never reach a child process. A survey
#: document is meant to be publishable; a leaked token is not. The match is
#: on the variable *name*, so anything ending in ``_TOKEN`` or containing
#: ``SECRET`` goes, whatever its value.
_SECRET_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "KEY",
    "CREDENTIAL",
    "SESSION",
    "AUTH",
)

_MAX_OUTPUT_BYTES = 2_000_000


@dataclass(slots=True)
class Probe:
    """Outcome of one read-only probe."""

    argv: tuple[str, ...]
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    reason: str = ""
    resolved: str = ""

    @property
    def command(self) -> str:
        return " ".join(self.argv)

    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]

    def first_line(self) -> str:
        lines = self.lines()
        return lines[0].strip() if lines else ""


def _scrubbed_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if any(marker in upper for marker in _SECRET_MARKERS):
            continue
        env[key] = value
    # Keep child tools in the C locale so parsers see stable text.
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return env


def _trusted_directory(path: str) -> bool:
    """Whether nobody but the owner can write into a directory.

    A program in a world-writable directory can be replaced between the
    moment it is found and the moment it runs, which would make the
    allowlist meaningless.
    """

    try:
        info = os.stat(path)
    except OSError:
        return False
    return not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def resolve(program: str) -> str | None:
    """Find an allowlisted program without trusting the inherited ``PATH``.

    The curated :data:`SEARCH_PATH` is tried first. Only then is the
    operator's own ``PATH`` consulted, and only for directories that nobody
    else can write to.
    """

    def usable(candidate: str) -> bool:
        return os.path.isfile(candidate) and os.access(candidate, os.X_OK)

    for directory in SEARCH_PATH:
        candidate = os.path.join(directory, program)
        if usable(candidate):
            return candidate
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory or not _trusted_directory(directory):
            continue
        candidate = os.path.join(directory, program)
        if usable(candidate):
            return candidate
    return None


def _validate(argv: tuple[str, ...]) -> None:
    if not argv:
        raise ProbeError("probe requires at least an executable name")
    if not all(isinstance(part, str) and part for part in argv):
        raise ProbeError("probe arguments must be non-empty strings")
    program = Path(argv[0]).name
    if program not in ALLOWED_PROGRAMS:
        raise ProbeError(
            f"refusing to run {program!r}: only read-only introspection tools are allowlisted"
        )


def _kill_group(process: subprocess.Popen[str]) -> None:
    """Kill the whole process group, not just the child that was spawned."""

    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:  # pragma: no cover - already gone
            pass


def run(argv: list[str] | tuple[str, ...], timeout: float = 8.0) -> Probe:
    """Run an allowlisted read-only command.

    Raises :class:`~surveyor.errors.ProbeError` only for programmer error
    (a non-allowlisted program, an empty vector). Environmental failures are
    returned as an unsuccessful probe so scanners can degrade gracefully.
    """

    vector = tuple(argv)
    _validate(vector)

    program = Path(vector[0]).name
    resolved = resolve(program)
    if resolved is None:
        return Probe(vector, ok=False, reason="not installed")

    # A symlink out of a trusted directory is how an allowlisted name gets
    # pointed at something else.
    if not _trusted_directory(os.path.dirname(os.path.realpath(resolved))):
        return Probe(
            vector,
            ok=False,
            reason="refusing to run a program that resolves into an untrusted directory",
            resolved=resolved,
        )

    try:
        # The argv is fixed, the shell is disabled and the program is
        # allowlisted and resolved to an absolute path above.
        process = subprocess.Popen(  # noqa: S603 - fixed argv, shell disabled, allowlisted
            [resolved, *vector[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.DEVNULL,
            env=_scrubbed_env(),
            start_new_session=True,
        )
    except FileNotFoundError:
        return Probe(vector, ok=False, reason="not installed", resolved=resolved)
    except PermissionError:
        return Probe(vector, ok=False, reason="permission denied", resolved=resolved)
    except OSError as exc:  # pragma: no cover - defensive
        return Probe(vector, ok=False, reason=f"could not execute: {exc}", resolved=resolved)

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(process)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            stdout, stderr = "", ""
        return Probe(
            vector,
            ok=False,
            reason=f"timed out after {timeout:g}s",
            resolved=resolved,
        )

    return Probe(
        vector,
        ok=process.returncode == 0,
        stdout=(stdout or "")[:_MAX_OUTPUT_BYTES],
        stderr=(stderr or "")[:4000],
        returncode=process.returncode,
        reason="" if process.returncode == 0 else f"exited {process.returncode}",
        resolved=resolved,
    )


def read_text(path: str | Path, *, limit: int = 64_000) -> str | None:
    """Read a small text file, returning ``None`` when unreadable.

    Used for ``/proc`` and ``/sys`` on Linux and for the odd plist on macOS.
    """

    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except (OSError, ValueError):
        return None


def read_int(path: str | Path) -> int | None:
    text = read_text(path, limit=64)
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


@dataclass(slots=True)
class ProbeLog:
    """Collects probe outcomes so a report can explain what was unavailable."""

    entries: list[Probe] = field(default_factory=list)

    def add(self, probe: Probe) -> Probe:
        self.entries.append(probe)
        return probe

    @property
    def failures(self) -> list[Probe]:
        return [entry for entry in self.entries if not entry.ok]

    def notes(self) -> list[str]:
        return [
            f"{entry.command}: {entry.reason}" for entry in self.failures if entry.reason
        ]
