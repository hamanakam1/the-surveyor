"""The survey ledger: an immutable, hash-chained record of every plat.

Layout::

    <root>/
      objects/<2>/<sha256>.json   canonical OET documents, content addressed
      journal.jsonl               append-only chain of survey entries
      HEAD                        pointer to the newest entry
      lock                        advisory lock serialising writers
      salt                        the ledger's redaction key, owner-only

Three properties matter:

1. **Content addressing.** An object's filename is the SHA-256 of its bytes.
   Corruption is detectable without trusting the writer.
2. **A hash chain.** Each journal entry names its parent's ``entry_digest``, so
   deleting or editing history breaks ``surveyor verify``.
3. **Idempotence.** ``commit`` refuses to record a survey whose structural
   fingerprint matches HEAD unless explicitly forced.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import StoreError
from .model import Topology
from .util import canonical_json, digest_of, sha256_hex, short_digest

try:  # pragma: no cover - POSIX only, imported for availability
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

GENESIS = "genesis"


def _structural_payload(document: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute the structural payload from a stored document.

    Kept deliberately local so verification does not depend on a live
    ``Topology`` instance (or on the model's normalisation rules).
    """

    from .model import VOLATILE_FACT_KEYS

    nodes = []
    for node in sorted(document.get("nodes") or [], key=lambda item: str(item.get("id", ""))):
        facts = {
            key: value
            for key, value in dict(node.get("facts") or {}).items()
            if key not in VOLATILE_FACT_KEYS
        }
        nodes.append(
            {
                "id": node.get("id"),
                "kind": node.get("kind"),
                "layer": node.get("layer"),
                "label": node.get("label"),
                "facts": facts,
                "tags": list(node.get("tags") or []),
            }
        )
    edges = []
    for edge in sorted(
        document.get("edges") or [],
        key=lambda item: f"{item.get('source')}|{item.get('relation')}|{item.get('target')}",
    ):
        edges.append(
            {
                "source": edge.get("source"),
                "relation": edge.get("relation"),
                "target": edge.get("target"),
                "facts": {
                    key: value
                    for key, value in dict(edge.get("facts") or {}).items()
                    if key not in VOLATILE_FACT_KEYS
                },
            }
        )
    return {
        "oet_version": document.get("oet_version"),
        "site": document.get("site"),
        "nodes": nodes,
        "edges": edges,
    }


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class LedgerEntry:
    """One recorded survey, as it appears in the journal."""

    seq: int
    recorded_at: str
    digest: str
    fingerprint: str
    parent: str
    entry_digest: str = ""
    site: str = ""
    counts: dict[str, Any] = field(default_factory=dict)
    note: str = ""
    #: ``local`` for a survey this host took, ``imported`` for one that
    #: arrived from somewhere else. The chain covers both; only the local
    #: ones are this host's own history.
    origin: str = "local"
    #: The host a plat describes. Empty for a local survey, where it is
    #: this host by definition.
    host: str = ""

    def payload(self) -> dict[str, Any]:
        """The bytes that are hashed into ``entry_digest``."""

        return {
            "seq": self.seq,
            "recorded_at": self.recorded_at,
            "digest": self.digest,
            "fingerprint": self.fingerprint,
            "parent": self.parent,
            "site": self.site,
            "counts": self.counts,
            "note": self.note,
            "origin": self.origin,
            "host": self.host,
        }

    def sign(self) -> LedgerEntry:
        self.entry_digest = digest_of(self.payload())
        return self

    @property
    def short(self) -> str:
        return short_digest(self.digest)

    @property
    def imported(self) -> bool:
        return self.origin != "local"

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "entry_digest": self.entry_digest}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LedgerEntry:
        if not isinstance(data, Mapping):
            raise StoreError("journal entry must be a JSON object")
        try:
            entry = cls(
                seq=int(data["seq"]),
                recorded_at=str(data["recorded_at"]),
                digest=str(data["digest"]),
                fingerprint=str(data["fingerprint"]),
                parent=str(data.get("parent") or GENESIS),
                entry_digest=str(data.get("entry_digest") or ""),
                site=str(data.get("site") or ""),
                counts=dict(data.get("counts") or {}),
                note=str(data.get("note") or ""),
                origin=str(data.get("origin") or "local"),
                host=str(data.get("host") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StoreError(f"journal entry is malformed: {exc}") from exc
        if not entry.entry_digest:
            raise StoreError("journal entry is missing entry_digest")
        return entry


@dataclass(slots=True)
class CommitResult:
    created: bool
    entry: LedgerEntry
    previous: LedgerEntry | None = None
    reason: str = ""

    @property
    def unchanged(self) -> bool:
        return not self.created and self.reason == "structural fingerprint unchanged"


@dataclass(slots=True)
class VerifyReport:
    ok: bool
    entries: int = 0
    objects: int = 0
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "objects": self.objects,
            "problems": self.problems,
        }


class Ledger:
    """Append-only store of OET documents and their signed journal."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser()
        self.objects = self.root / "objects"
        self.journal = self.root / "journal.jsonl"
        self.head_file = self.root / "HEAD"
        self.lock_file = self.root / "lock"
        self.salt_file = self.root / "salt"

    # -- plumbing ---------------------------------------------------------
    def ensure(self) -> Ledger:
        self.objects.mkdir(parents=True, exist_ok=True)
        return self

    @property
    def salt(self) -> str:
        """The ledger's redaction key.

        Aliases in a redacted plat are digests of a name *and this key*. Two
        names that are the same produce the same alias everywhere in this
        ledger, so redacting a plat twice does not churn the map; but an
        unkeyed digest of a hostname can be brute-forced from a word list,
        and that would make redaction a speed bump rather than a protection.

        The key never leaves the ledger directory and is created with owner
        read/write only.
        """

        with self._locked():
            if self.salt_file.exists():
                text = self.salt_file.read_text(encoding="utf-8").strip()
                if text:
                    return text
            value = secrets.token_hex(32)
            self._atomic_write(self.salt_file, value + "\n")
            try:
                os.chmod(self.salt_file, 0o600)
            except OSError:  # pragma: no cover - exotic filesystems
                pass
            return value

    @property
    def exists(self) -> bool:
        return self.journal.exists()

    def _object_path(self, digest: str) -> Path:
        body = digest.split(":", 1)[-1]
        if len(body) < 4:
            raise StoreError(f"malformed digest {digest!r}")
        return self.objects / body[:2] / f"{body}.json"

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.ensure()
        # The handle is held for the life of the context on purpose: an
        # flock is released when its descriptor closes.
        handle = open(self.lock_file, "a+", encoding="utf-8")  # noqa: SIM115 - held on purpose
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:  # pragma: no cover - defensive
                    pass
            handle.close()

    @staticmethod
    def _atomic_write(path: Path, payload: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed in the finally below
            "w", dir=path.parent, prefix=".tmp-", delete=False, encoding="utf-8"
        )
        try:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, path)

    # -- reading ----------------------------------------------------------
    def history(self, limit: int | None = None) -> list[LedgerEntry]:
        if not self.journal.exists():
            return []
        entries: list[LedgerEntry] = []
        with open(self.journal, encoding="utf-8") as handle:
            for number, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entries.append(LedgerEntry.from_dict(json.loads(line)))
                except json.JSONDecodeError as exc:
                    raise StoreError(
                        f"{self.journal}: line {number} is not valid JSON ({exc.msg})"
                    ) from exc
        if limit is not None and limit >= 0:
            return entries[-limit:] if limit else []
        return entries

    def head(self) -> LedgerEntry | None:
        """The newest entry *this host* recorded.

        An imported plat belongs to another host, so it does not become this
        host's HEAD: `surveyor diff HEAD~1 HEAD` has to keep comparing
        this host's own surveys with each other.
        """

        for entry in reversed(self.history()):
            if not entry.imported:
                return entry
        return None

    def imports(self) -> list[LedgerEntry]:
        """The newest imported plat for each host."""

        newest: dict[str, LedgerEntry] = {}
        for entry in self.history():
            if entry.imported:
                newest[entry.host or entry.digest] = entry
        return [newest[key] for key in sorted(newest)]

    def tip(self) -> LedgerEntry | None:
        """The newest entry of any kind -- what the HEAD file points at."""

        entries = self.history()
        return entries[-1] if entries else None

    def import_of(self, host: str) -> LedgerEntry | None:
        """The newest plat imported from a given host."""

        for entry in reversed(self.history()):
            if entry.imported and entry.host == host:
                return entry
        return None

    def fleet_plats(self) -> list[Topology]:
        """Every plat this ledger holds: this host's, and one per import.

        One plat per host — the newest of each — because a site map wants
        the current state of every box, not its history.
        """

        plats: list[Topology] = []
        head = self.head()
        if head is not None:
            plats.append(self.get(head.digest))
        for entry in self.imports():
            plats.append(self.get(entry.digest))
        return plats

    def get(self, digest: str) -> Topology:
        path = self._object_path(digest)
        if not path.exists():
            raise StoreError(f"no survey object for {digest}; the ledger is missing data")
        raw = path.read_text(encoding="utf-8")
        expected = digest.split(":", 1)[-1]
        actual = sha256_hex(raw)
        if actual != expected:
            raise StoreError(
                f"object {digest} failed integrity check (bytes hash to sha256:{actual[:12]})"
            )
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StoreError(f"object {digest} is not valid JSON: {exc.msg}") from exc
        return Topology.from_dict(data)

    def latest(self) -> Topology:
        """The newest plat in the ledger, whoever surveyed it."""

        tip = self.tip()
        if tip is None:
            raise StoreError(f"ledger at {self.root} is empty; run `surveyor scan` first")
        return self.get(tip.digest)

    def entry_at(self, seq: int) -> LedgerEntry:
        for entry in self.history():
            if entry.seq == seq:
                return entry
        raise StoreError(f"no journal entry with seq={seq}")

    def previous_of(self, entry: LedgerEntry) -> LedgerEntry | None:
        if entry.seq <= 0:
            return None
        try:
            return self.entry_at(entry.seq - 1)
        except StoreError:
            return None

    def previous_local(self, entry: LedgerEntry | None) -> LedgerEntry | None:
        """The local entry recorded before this one.

        Imports do not break a host's own history: the survey before this
        one is the previous *local* survey, not the previous entry in the
        journal.
        """

        if entry is None:
            return None
        for candidate in reversed(self.history()):
            if candidate.seq < entry.seq and not candidate.imported:
                return candidate
        return None

    # -- writing ----------------------------------------------------------
    def commit(
        self,
        topology: Topology,
        *,
        note: str = "",
        force: bool = False,
    ) -> CommitResult:
        return self._commit(topology, note=note, force=force, origin="local", host="")

    def commit_import(
        self,
        topology: Topology,
        *,
        host: str,
        note: str = "",
        force: bool = False,
    ) -> CommitResult:
        """Record a plat that came from another host.

        The import is idempotent per host: re-importing the same plat from
        the same host changes nothing, exactly as re-surveying an unchanged
        machine changes nothing.
        """

        return self._commit(
            topology, note=note, force=force, origin="imported", host=host
        )

    def _commit(
        self,
        topology: Topology,
        *,
        note: str,
        force: bool,
        origin: str,
        host: str,
    ) -> CommitResult:
        document = topology.to_dict()
        payload = canonical_json(document)
        digest = "sha256:" + sha256_hex(payload)

        with self._locked():
            history = self.history()
            head = history[-1] if history else None
            if not force:
                # Idempotence is per source: a local survey compares with
                # the last local survey, an import with the last import
                # from the same host.
                if origin == "local":
                    comparable = next(
                        (entry for entry in reversed(history) if not entry.imported),
                        None,
                    )
                else:
                    comparable = next(
                        (
                            entry
                            for entry in reversed(history)
                            if entry.imported and entry.host == host
                        ),
                        None,
                    )
                if comparable is not None and comparable.fingerprint == topology.fingerprint:
                    return CommitResult(
                        created=False,
                        entry=comparable,
                        previous=self.previous_of(comparable),
                        reason="structural fingerprint unchanged",
                    )

            path = self._object_path(digest)
            if not path.exists():
                self._atomic_write(path, payload)

            entry = LedgerEntry(
                seq=(head.seq + 1) if head else 0,
                recorded_at=_now(),
                digest=digest,
                fingerprint=topology.fingerprint,
                parent=head.entry_digest if head else GENESIS,
                site=topology.site,
                counts=topology.counts(),
                note=note,
                origin=origin,
                host=host,
            ).sign()
            with open(self.journal, "a", encoding="utf-8") as handle:
                handle.write(canonical_json(entry.to_dict()) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._atomic_write(self.head_file, json.dumps(entry.to_dict(), indent=2) + "\n")
            return CommitResult(
                created=True,
                entry=entry,
                previous=head,
                reason="recorded new survey",
            )

    def write_change(self, entry: LedgerEntry, markdown: str) -> Path:
        """Persist a changelog entry beside the ledger, one file per survey."""

        directory = self.root / "changes"
        directory.mkdir(parents=True, exist_ok=True)
        filename = f"{entry.seq:04d}-{entry.short}.md"
        path = directory / filename
        self._atomic_write(path, markdown)
        return path

    def changes(self) -> list[tuple[LedgerEntry, Path]]:
        """The recorded changelogs, oldest first.

        A changelog is written only when the structure moved, so this is the
        ledger's own history: what changed, and when.
        """

        directory = self.root / "changes"
        if not directory.is_dir():
            return []
        found: list[tuple[LedgerEntry, Path]] = []
        for path in sorted(directory.glob("*.md")):
            try:
                seq = int(path.name.split("-", 1)[0])
            except ValueError:
                continue
            entry = next((item for item in self.history() if item.seq == seq), None)
            if entry is not None:
                found.append((entry, path))
        return found

    # -- verification -----------------------------------------------------
    def verify(self) -> VerifyReport:
        """Recompute the chain and every object digest."""

        try:
            entries = self.history()
        except StoreError as exc:
            return VerifyReport(ok=False, problems=[str(exc)])
        report = VerifyReport(ok=True, entries=len(entries))
        if not entries:
            report.problems.append("ledger is empty")
            report.ok = False
            return report

        parent = GENESIS
        seen_digests: set[str] = set()
        for index, entry in enumerate(entries):
            if entry.seq != index:
                report.problems.append(
                    f"entry {entry.entry_digest[:15]}: seq {entry.seq} out of order (expected {index})"
                )
                report.ok = False
            if entry.parent != parent:
                report.problems.append(
                    f"entry seq {entry.seq}: parent {entry.parent[:15]} does not match {parent[:15]}"
                )
                report.ok = False
            recomputed = digest_of(entry.payload())
            if recomputed != entry.entry_digest:
                report.problems.append(f"entry seq {entry.seq}: signature mismatch")
                report.ok = False
            path = self._object_path(entry.digest)
            if not path.exists():
                report.problems.append(f"entry seq {entry.seq}: object {entry.short} missing")
                report.ok = False
            else:
                raw = path.read_text(encoding="utf-8")
                if "sha256:" + sha256_hex(raw) != entry.digest:
                    report.problems.append(f"entry seq {entry.seq}: object bytes were altered")
                    report.ok = False
                else:
                    try:
                        document = json.loads(raw)
                    except json.JSONDecodeError:
                        document = None
                    if not isinstance(document, dict):
                        report.problems.append(f"entry seq {entry.seq}: object is not a JSON object")
                        report.ok = False
                    else:
                        recomputed_fp = "sha256:" + sha256_hex(canonical_json(_structural_payload(document)))
                        if recomputed_fp != entry.fingerprint:
                            report.problems.append(
                                f"entry seq {entry.seq}: recorded fingerprint does not match the object"
                            )
                            report.ok = False
                seen_digests.add(entry.digest)
            parent = entry.entry_digest

        report.objects = len(seen_digests)
        try:
            persisted_head = LedgerEntry.from_dict(
                json.loads(self.head_file.read_text(encoding="utf-8"))
            )
        except (OSError, ValueError, StoreError) as exc:
            report.problems.append(f"HEAD is missing, unreadable or malformed: {exc}")
            report.ok = False
        else:
            if persisted_head.to_dict() != entries[-1].to_dict():
                report.problems.append("HEAD does not match the newest journal entry")
                report.ok = False
        return report
