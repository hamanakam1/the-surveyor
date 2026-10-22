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
