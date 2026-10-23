"""Content references identify objects even when several entries reuse them."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from surveyor import cli
from surveyor.config import Config
from surveyor.errors import StoreError
from surveyor.model import Topology


@pytest.mark.parametrize("imported", [False, True])
@pytest.mark.parametrize("reference", ["full", "bare", "prefix"])
def test_repeated_object_refs_select_the_latest_matching_entry(
    tmp_ledger, topology, imported, reference
):
    first = tmp_ledger.commit(topology).entry
    if imported:
        repeated = tmp_ledger.commit_import(topology, host="host:lab").entry
    else:
        repeated = tmp_ledger.commit(topology, force=True).entry
    other = Topology.from_dict(topology.to_dict())
    other.site = "another-site"
    tmp_ledger.commit(other)
    assert first.digest == repeated.digest
    assert tmp_ledger.verify().ok
    journal_before = tmp_ledger.journal.read_bytes()
    ref = {
        "full": first.digest,
        "bare": first.digest.removeprefix("sha256:"),
        "prefix": "sha256:" + first.short,
    }[reference]

    resolved, label = cli._parse_ref(ref, tmp_ledger)

    assert resolved.to_dict() == topology.to_dict()
    assert label == f"#{repeated.seq}"
    assert tmp_ledger.journal.read_bytes() == journal_before


def test_a_prefix_matching_different_objects_remains_ambiguous(tmp_ledger, topology):
    # Seventeen different objects guarantee two with the same first hex digit.
    # Build candidates in memory; only the colliding pair enters the ledger.
    by_prefix = {}
    for number in range(17):
        candidate = Topology.from_dict(topology.to_dict())
        candidate.observations["sample"] = number
        prefix = candidate.digest.removeprefix("sha256:")[0]
        if prefix in by_prefix:
            first = by_prefix[prefix]
            second = candidate
            break
        by_prefix[prefix] = candidate
    else:
        pytest.fail("expected two objects with the same hexadecimal prefix")

    first_entry = tmp_ledger.commit(first).entry
    tmp_ledger.commit(first, force=True)
    second_entry = tmp_ledger.commit(second, force=True).entry
    assert first_entry.digest != second_entry.digest

    with pytest.raises(StoreError, match="ambiguous"):
        cli._parse_ref("sha256:" + prefix, tmp_ledger)
    for entry in (first_entry, second_entry):
        resolved, _label = cli._parse_ref(entry.digest, tmp_ledger)
        assert resolved.digest == entry.digest


def test_export_accepts_a_repeated_full_digest(tmp_ledger, topology, monkeypatch, capsys):
    entry = tmp_ledger.commit(topology).entry
    tmp_ledger.commit(topology, force=True)
    monkeypatch.setattr(cli.Config, "load", Mock(return_value=Config(store=tmp_ledger.root)))

    assert cli.main(["export", entry.digest]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out) == topology.to_dict()
    assert captured.err == ""
