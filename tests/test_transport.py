"""Plats crossing a ledger boundary.

A plat is a file, and a file can be shipped. The questions these tests
answer are the ones a fleet has to get right: does an import disturb this
host's own history, is re-importing the same plat idempotent, and does the
chain still verify afterwards.
"""

from __future__ import annotations

import json

from conftest import build_topology
from surveyor.model import Node, Topology
from surveyor.store import Ledger


def _plat(site: str = "shed") -> Topology:
    topology = build_topology()
    topology.site = site
    topology.add(
        Node("host:shed", "host", "shed (Raspberry Pi 5)", facts={"hostname": "shed"})
    )
    return topology


def _changed_plat(site: str = "shed") -> Topology:
    """The same plat with something new on it."""

    topology = _plat(site)
    topology.add(
        Node("workload:docker:new", "workload", "new", facts={"runtime": "docker"})
    )
    return topology


def test_a_local_entry_is_local_and_an_import_is_not(tmp_path):
    ledger = Ledger(tmp_path / "ledger")
    local = ledger.commit(_plat())
    imported = ledger.commit_import(_plat("other"), host="host:elsewhere")

    assert local.entry.origin == "local"
    assert imported.entry.origin == "imported"
    assert imported.entry.host == "host:elsewhere"


def test_an_import_does_not_become_this_hosts_head(tmp_path):
    """A diff of two local surveys must not compare them with a stranger."""

    ledger = Ledger(tmp_path / "ledger")
    ledger.commit(_plat())
    ledger.commit_import(_plat("other"), host="host:elsewhere")

    head = ledger.head()
    assert head is not None
    assert not head.imported
    assert head.origin == "local"


def test_the_previous_local_survey_skips_the_import(tmp_path):
    ledger = Ledger(tmp_path / "ledger")
    first = ledger.commit(_plat())
    ledger.commit_import(_plat("other"), host="host:elsewhere")
    second = ledger.commit(_changed_plat())

    previous = ledger.previous_local(second.entry)
    assert previous is not None
    assert previous.seq == first.entry.seq


def test_re_importing_the_same_plat_changes_nothing(tmp_path):
    ledger = Ledger(tmp_path / "ledger")
    ledger.commit_import(_plat("other"), host="host:elsewhere")
    again = ledger.commit_import(_plat("other"), host="host:elsewhere")

    assert again.created is False
    assert again.reason == "structural fingerprint unchanged"
    assert len(ledger.history()) == 1


def test_two_different_plats_from_one_host_are_both_recorded(tmp_path):
    ledger = Ledger(tmp_path / "ledger")
    ledger.commit_import(_plat("other"), host="host:elsewhere")
    changed = _plat("other")
    changed.add(Node("workload:docker:new", "workload", "new", facts={"runtime": "docker"}))
    again = ledger.commit_import(changed, host="host:elsewhere")

    assert again.created is True
    assert len(ledger.history()) == 2


def test_the_chain_still_verifies_after_an_import(tmp_path):
    ledger = Ledger(tmp_path / "ledger")
    ledger.commit(_plat())
    ledger.commit_import(_plat("other"), host="host:elsewhere")
    ledger.commit(_changed_plat())

    report = ledger.verify()
    assert report.ok, report.problems
    assert report.entries == 3


def test_imports_are_listed_per_host(tmp_path):
    ledger = Ledger(tmp_path / "ledger")
    ledger.commit_import(_plat("a"), host="host:one")
    ledger.commit_import(_plat("b"), host="host:two")
    ledger.commit_import(_plat("b2"), host="host:two")

    imports = ledger.imports()
    assert [entry.host for entry in imports] == ["host:one", "host:two"]
    assert imports[1].seq == 2


def test_an_exported_plat_round_trips_through_a_file(tmp_path):
    source = Ledger(tmp_path / "source")
    source.commit(_plat())
    document = source.latest().to_dict()

    path = tmp_path / "plat.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    target = Ledger(tmp_path / "target")
    restored = Topology.from_dict(json.loads(path.read_text(encoding="utf-8")))
    result = target.commit_import(restored, host="host:shed")

    assert result.created is True
    assert target.latest().fingerprint == restored.fingerprint
