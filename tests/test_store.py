from __future__ import annotations

import json

import pytest

from surveyor.errors import StoreError
from surveyor.store import GENESIS, Ledger


def test_commit_creates_a_chained_entry(tmp_ledger, topology):
    result = tmp_ledger.commit(topology)
    assert result.created is True
    assert result.entry.seq == 0
    assert result.entry.parent == GENESIS
    assert result.entry.entry_digest.startswith("sha256:")
    assert tmp_ledger.head().digest == result.entry.digest
    assert tmp_ledger.latest().fingerprint == topology.fingerprint


def test_second_commit_of_same_structure_is_refused(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    duplicate = type(topology).from_dict(topology.to_dict())
    duplicate.generated_at = "2027-01-01T00:00:00Z"
    result = tmp_ledger.commit(duplicate)
    assert result.created is False
    assert result.unchanged is True
    assert len(tmp_ledger.history()) == 1


def test_force_records_an_unchanged_survey(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    duplicate = type(topology).from_dict(topology.to_dict())
    result = tmp_ledger.commit(duplicate, force=True, note="manual")
    assert result.created is True
    assert result.entry.seq == 1
    assert result.entry.parent == tmp_ledger.entry_at(0).entry_digest
    assert result.previous.seq == 0
    assert result.entry.note == "manual"


@pytest.mark.parametrize("damage", ["truncated", "missing", "malformed", "stale"])
@pytest.mark.parametrize("force", [False, True])
def test_commit_refuses_inconsistent_head_without_repair(tmp_ledger, topology, damage, force):
    first = tmp_ledger.commit(topology).entry
    tmp_ledger.commit(topology, force=True)
    if damage == "truncated":
        tmp_ledger.journal.write_text(json.dumps(first.to_dict()) + "\n")
    elif damage == "missing":
        tmp_ledger.head_file.unlink()
    elif damage == "malformed":
        tmp_ledger.head_file.write_text("not JSON")
    else:
        tmp_ledger.head_file.write_text(json.dumps(first.to_dict()))
    journal_before = tmp_ledger.journal.read_bytes()
    head_before = tmp_ledger.head_file.read_bytes() if tmp_ledger.head_file.exists() else None
    objects_before = {path: path.read_bytes() for path in tmp_ledger.objects.rglob("*.json")}

    with pytest.raises(StoreError, match="HEAD"):
        tmp_ledger.commit(topology, force=force)

    assert tmp_ledger.journal.read_bytes() == journal_before
    assert (tmp_ledger.head_file.read_bytes() if tmp_ledger.head_file.exists() else None) == head_before
    assert {path: path.read_bytes() for path in tmp_ledger.objects.rglob("*.json")} == objects_before


def test_commit_cannot_replace_a_truncated_history_with_a_new_topology(tmp_ledger, topology):
    first = tmp_ledger.commit(topology).entry
    topology.nodes["host:lab"].facts["revision"] = 2
    tmp_ledger.commit(topology)
    tmp_ledger.journal.write_text(json.dumps(first.to_dict()) + "\n")
    journal_before = tmp_ledger.journal.read_bytes()
    head_before = tmp_ledger.head_file.read_bytes()
    topology.nodes["host:lab"].facts["revision"] = 3

    with pytest.raises(StoreError, match="HEAD"):
        tmp_ledger.commit(topology)

    assert tmp_ledger.journal.read_bytes() == journal_before
    assert tmp_ledger.head_file.read_bytes() == head_before
    assert not tmp_ledger._object_path(topology.digest).exists()


def test_commit_refuses_an_empty_journal_with_an_existing_head(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    tmp_ledger.journal.write_text("")
    head_before = tmp_ledger.head_file.read_bytes()

    with pytest.raises(StoreError, match="HEAD"):
        tmp_ledger.commit(topology)

    assert tmp_ledger.journal.read_text() == ""
    assert tmp_ledger.head_file.read_bytes() == head_before


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("corrupt", [None, b"corrupt object", b"\xff"])
def test_commit_refuses_corrupt_reused_objects_without_repair(tmp_ledger, topology, force, corrupt):
    entry = tmp_ledger.commit(topology).entry
    path = tmp_ledger._object_path(entry.digest)
    if corrupt is None:
        path.unlink()
    else:
        path.write_bytes(corrupt)
    journal_before = tmp_ledger.journal.read_bytes()
    head_before = tmp_ledger.head_file.read_bytes()

    with pytest.raises(StoreError, match="object"):
        tmp_ledger.commit(topology, force=force)

    assert (path.read_bytes() if path.exists() else None) == corrupt
    assert tmp_ledger.journal.read_bytes() == journal_before
    assert tmp_ledger.head_file.read_bytes() == head_before


def test_unchanged_commit_checks_the_previous_object_even_when_time_changes(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry
    path = tmp_ledger._object_path(entry.digest)
    path.write_text("corrupt object")
    topology.generated_at = "2027-01-01T00:00:00Z"

    with pytest.raises(StoreError, match="object"):
        tmp_ledger.commit(topology)

    assert len(tmp_ledger.history()) == 1
    assert path.read_text() == "corrupt object"
    assert not tmp_ledger._object_path(topology.digest).exists()


def test_verify_passes_on_a_fresh_chain(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    topology.nodes["workload:docker:web"].facts["image"] = "nginx:1.27"
    tmp_ledger.commit(topology, force=True)
    report = tmp_ledger.verify()
    assert report.ok is True
    assert report.entries == 2
    assert report.problems == []


def test_verify_detects_object_tampering(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry
    path = tmp_ledger._object_path(entry.digest)
    payload = json.loads(path.read_text())
    payload["nodes"][0]["facts"]["role"] = "coal"
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    report = tmp_ledger.verify()
    assert report.ok is False
    assert any("altered" in problem for problem in report.problems)


def test_verify_detects_journal_edits(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    lines = tmp_ledger.journal.read_text().strip().splitlines()
    entry = json.loads(lines[0])
    entry["note"] = "rewritten history"
    tmp_ledger.journal.write_text(json.dumps(entry) + "\n")
    report = tmp_ledger.verify()
    assert report.ok is False
    assert any("signature mismatch" in problem for problem in report.problems)


def test_verify_detects_a_truncated_journal_against_persisted_head(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    tmp_ledger.commit(topology, force=True)
    lines = tmp_ledger.journal.read_text().splitlines()
    tmp_ledger.journal.write_text(lines[0] + "\n")

    report = tmp_ledger.verify()

    assert report.ok is False
    assert any("HEAD" in problem for problem in report.problems)


def test_verify_detects_a_stale_persisted_head(tmp_ledger, topology):
    first = tmp_ledger.commit(topology).entry
    tmp_ledger.commit(topology, force=True)
    tmp_ledger.head_file.write_text(json.dumps(first.to_dict()))

    report = tmp_ledger.verify()

    assert report.ok is False
    assert any("HEAD" in problem for problem in report.problems)


def test_verify_detects_a_missing_head(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    tmp_ledger.head_file.unlink()

    report = tmp_ledger.verify()

    assert report.ok is False
    assert any("HEAD" in problem for problem in report.problems)
    assert not tmp_ledger.head_file.exists()


@pytest.mark.parametrize("head", ["not JSON", "[]", "{}"])
def test_verify_reports_a_malformed_head(tmp_ledger, topology, head):
    tmp_ledger.commit(topology)
    tmp_ledger.head_file.write_text(head)

    report = tmp_ledger.verify()

    assert report.ok is False
    assert any("HEAD" in problem for problem in report.problems)
    assert tmp_ledger.head_file.read_text() == head


def test_verify_checks_head_payload_not_only_its_digest(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry.to_dict()
    entry["note"] = "rewritten HEAD"
    tmp_ledger.head_file.write_text(json.dumps(entry))

    report = tmp_ledger.verify()

    assert report.ok is False
    assert any("HEAD" in problem for problem in report.problems)


@pytest.mark.parametrize("missing_digest", [None, ""])
def test_unsigned_journal_entries_are_rejected_without_repair(
    tmp_ledger, topology, missing_digest
):
    entry = tmp_ledger.commit(topology).entry.to_dict()
    entry["note"] = "rewritten history"
    if missing_digest is None:
        del entry["entry_digest"]
    else:
        entry["entry_digest"] = missing_digest
    unsigned = json.dumps(entry) + "\n"
    tmp_ledger.journal.write_text(unsigned)

    report = tmp_ledger.verify()

    assert report.ok is False
    assert any("entry_digest" in problem for problem in report.problems)
    with pytest.raises(StoreError, match="entry_digest"):
        tmp_ledger.history()
    assert tmp_ledger.journal.read_text() == unsigned


def test_verify_rejects_a_head_with_a_missing_digest(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry.to_dict()
    del entry["entry_digest"]
    tmp_ledger.head_file.write_text(json.dumps(entry))

    report = tmp_ledger.verify()

    assert report.ok is False
    assert any("HEAD" in problem for problem in report.problems)


def test_verify_detects_a_journal_fingerprint_that_contradicts_the_object(tmp_ledger, topology):
    from surveyor.store import LedgerEntry

    entry = tmp_ledger.commit(topology).entry
    forged = LedgerEntry(
        seq=entry.seq,
        recorded_at=entry.recorded_at,
        digest=entry.digest,
        fingerprint="sha256:" + "0" * 64,
        parent=entry.parent,
        site=entry.site,
        counts=entry.counts,
    ).sign()
    tmp_ledger.journal.write_text(json.dumps(forged.to_dict()) + "\n")
    report = tmp_ledger.verify()
    assert report.ok is False
    assert any("fingerprint does not match" in problem for problem in report.problems)


def test_verify_detects_missing_objects(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry
    tmp_ledger._object_path(entry.digest).unlink()
    report = tmp_ledger.verify()
    assert report.ok is False
    assert any("missing" in problem for problem in report.problems)


def test_get_rejects_corrupted_objects(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry
    tmp_ledger._object_path(entry.digest).write_text('{"oet_version":"1.0"}')
    with pytest.raises(StoreError, match="integrity"):
        tmp_ledger.get(entry.digest)


def test_history_reports_corrupt_json_with_a_line_number(tmp_ledger, topology):
    tmp_ledger.commit(topology)
    with open(tmp_ledger.journal, "a", encoding="utf-8") as handle:
        handle.write("{not json}\n")
    with pytest.raises(StoreError, match="line 2"):
        tmp_ledger.history()


def test_write_change_creates_a_markdown_file(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry
    path = tmp_ledger.write_change(entry, "# hello\n")
    assert path.exists()
    assert path.name.startswith("0000-")
    assert path.read_text().startswith("# hello")


def test_previous_of_the_first_entry_is_none(tmp_ledger, topology):
    entry = tmp_ledger.commit(topology).entry
    assert tmp_ledger.previous_of(entry) is None


def test_empty_ledger_semantics(tmp_ledger):
    assert tmp_ledger.head() is None
    assert tmp_ledger.history() == []
    report = tmp_ledger.verify()
    assert report.ok is False
    assert "empty" in report.problems[0]
    with pytest.raises(StoreError, match="empty"):
        tmp_ledger.latest()


def test_two_ledgers_do_not_share_objects(tmp_path, topology):
    first = Ledger(tmp_path / "a")
    second = Ledger(tmp_path / "b")
    first.commit(topology)
    assert second.head() is None
