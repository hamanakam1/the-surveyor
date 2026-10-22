from __future__ import annotations

import json

import pytest

from conftest import build_topology, change_fact
from surveyor import cli
from surveyor.compiler import CompilationReport
from surveyor.config import Config
from surveyor.model import Topology


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep the CLI away from the operator's real config and ledger."""

    monkeypatch.setenv("SURVEYOR_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SURVEYOR_SITE", raising=False)
    monkeypatch.delenv("SURVEYOR_SCANNERS", raising=False)
    monkeypatch.delenv("SURVEYOR_REDACT", raising=False)
    return tmp_path / "home"


def _stub_survey(monkeypatch, topologies):
    queue = list(topologies)

    def fake_survey(config, *, site=None, progress=None, salt=""):
        from surveyor.redact import redact_topology

        if progress:
            progress("stub scanner: 1 node")
        topology = queue.pop(0) if len(queue) > 1 else queue[0]
        if config.redact:
            topology = redact_topology(topology, salt=salt)
        return CompilationReport(topology=topology)

    monkeypatch.setattr(cli, "survey", fake_survey)


def test_banner_mentions_the_surveyor(capsys):
    assert cli.main(["banner"]) == 0
    out = capsys.readouterr().out
    assert "S U R V E Y O R" in out
    assert "not to scale" in out


def test_no_command_prints_help(capsys):
    assert cli.main([]) == 0
    assert "choose a bearing" in capsys.readouterr().out


def test_scanners_lists_built_ins(capsys):
    assert cli.main(["scanners"]) == 0
    out = capsys.readouterr().out
    for name in ("power", "host", "network", "workloads"):
        assert name in out


def test_scan_records_an_entry_and_writes_a_changelog(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    _stub_survey(monkeypatch, [build_topology()])
    assert cli.main(["--store", str(store), "scan", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["recorded"] is True
    assert payload["seq"] == 0
    assert payload["counts"]["nodes"] == 8
    assert (store / "journal.jsonl").exists()
    changelogs = list((store / "changes").glob("*.md"))
    assert len(changelogs) == 1


def test_scan_is_idempotent(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    _stub_survey(monkeypatch, [build_topology()])
    cli.main(["--store", str(store), "scan", "--json"])
    capsys.readouterr()
    assert cli.main(["--store", str(store), "scan", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["recorded"] is False
    assert payload["unchanged"] is True


def test_scan_can_emit_an_oet_document(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    output = tmp_path / "plat.json"
    _stub_survey(monkeypatch, [build_topology()])
    cli.main(["--store", str(store), "scan", "--no-save", "--output", str(output)])
    capsys.readouterr()
    document = json.loads(output.read_text())
    assert document["oet_version"] == "1.0"
    assert document["counts"]["nodes"] == 8
    assert cli.main(["validate", str(output)]) == 0


def test_scan_reports_scanner_failures(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"

    def failing_survey(config, *, site=None, progress=None, salt=""):
        from surveyor.scanners.base import ScanResult

        topology = build_topology()
        return CompilationReport(
            topology=topology,
            results=[ScanResult("network", "network", ok=False, error="boom")],
        )

    monkeypatch.setattr(cli, "survey", failing_survey)
    assert cli.main(["--store", str(store), "scan"]) == 0
    captured = capsys.readouterr()
    assert "boom" in captured.err


def test_diff_exit_code_reports_structural_change(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    first = build_topology()
    second = change_fact(first, "workload:docker:web", "image", "nginx:1.27")
    _stub_survey(monkeypatch, [first, second])
    cli.main(["--store", str(store), "scan", "--json"])
    cli.main(["--store", str(store), "scan", "--json"])
    capsys.readouterr()
    assert cli.main(["--store", str(store), "diff", "--exit-code"]) == cli.EXIT_CHANGED
    output = capsys.readouterr().out
    assert "nginx:1.25" in output and "nginx:1.27" in output


def test_diff_markdown_format(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    first = build_topology()
    second = change_fact(first, "workload:docker:web", "image", "nginx:1.27")
    _stub_survey(monkeypatch, [first, second])
    cli.main(["--store", str(store), "scan"])
    cli.main(["--store", str(store), "scan"])
    capsys.readouterr()
    assert cli.main(["--store", str(store), "diff", "--format", "markdown"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Survey change log")
    assert "Structural changes" in out


def test_log_and_show_and_verify(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    _stub_survey(monkeypatch, [build_topology()])
    cli.main(["--store", str(store), "scan"])
    capsys.readouterr()

    assert cli.main(["--store", str(store), "log"]) == 0
    log_out = capsys.readouterr().out
    assert "HEAD #0" in log_out

    assert cli.main(["--store", str(store), "show", "--format", "mermaid"]) == 0
    assert "graph TD" in capsys.readouterr().out

    assert cli.main(["--store", str(store), "show", "--format", "markdown"]) == 0
    assert "### Survey plat" in capsys.readouterr().out

    assert cli.main(["--store", str(store), "verify"]) == 0
    assert "chain intact" in capsys.readouterr().out


def test_show_ascii_map_has_layers(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    _stub_survey(monkeypatch, [build_topology()])
    cli.main(["--store", str(store), "scan"])
    capsys.readouterr()
    assert cli.main(["--store", str(store), "show"]) == 0
    out = capsys.readouterr().out
    assert "POWER" in out and "BARE METAL" in out and "WORKLOADS" in out
    assert "EDGES" in out


def test_verify_fails_on_an_empty_ledger(tmp_path, capsys):
    assert cli.main(["--store", str(tmp_path / "empty"), "verify"]) == 1
    assert "failed" in capsys.readouterr().err


def test_init_writes_a_config(tmp_path, capsys):
    config_path = tmp_path / "config.toml"
    store = tmp_path / "ledger"
    assert cli.main(["init", "--path", str(config_path), "--store", str(store), "--site", "lab"]) == 0
    assert config_path.exists()
    loaded = Config.load(config_path)
    assert loaded.site == "lab"
    assert loaded.store == store
    assert cli.main(["init", "--path", str(config_path)]) == 1
    assert "already exists" in capsys.readouterr().err


def test_validate_rejects_dangling_edges(tmp_path, capsys):
    document = build_topology().to_dict()
    document["edges"].append({"source": "host:lab", "relation": "runs", "target": "workload:ghost"})
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(document))
    assert cli.main(["validate", str(path)]) == 1
    assert "dangling" in capsys.readouterr().err


def test_validate_rejects_a_forged_fingerprint(tmp_path, capsys):
    document = build_topology().to_dict()
    document["fingerprint"] = "sha256:" + "0" * 64
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(document))
    assert cli.main(["validate", str(path)]) == 1
    assert "does not match" in capsys.readouterr().err


def test_validate_rejects_unknown_versions(tmp_path, capsys):
    document = build_topology().to_dict()
    document["oet_version"] = "0.1"
    path = tmp_path / "old.json"
    path.write_text(json.dumps(document))
    assert cli.main(["validate", str(path)]) == 1
    assert "unsupported" in capsys.readouterr().err


def test_export_writes_a_plat_and_import_records_it(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    target = tmp_path / "target"
    exported = tmp_path / "plat.json"

    _stub_survey(monkeypatch, [build_topology()])
    assert cli.main(["--store", str(source), "scan", "--quiet"]) == 0
    assert cli.main(["--store", str(source), "export", "HEAD", "--output", str(exported)]) == 0
    assert exported.exists()

    assert cli.main(["--store", str(target), "import", str(exported)]) == 0
    out = capsys.readouterr().out
    assert "imported" in out

    # The imported plat is addressable by the host it describes.
    assert cli.main(["--store", str(target), "show", "host:lab", "--format", "json"]) == 0
    assert "host:lab" in capsys.readouterr().out


def test_importing_the_same_plat_twice_changes_nothing(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    target = tmp_path / "target"
    exported = tmp_path / "plat.json"

    _stub_survey(monkeypatch, [build_topology()])
    cli.main(["--store", str(source), "scan", "--quiet"])
    cli.main(["--store", str(source), "export", "HEAD", "--output", str(exported)])

    assert cli.main(["--store", str(target), "import", str(exported)]) == 0
    capsys.readouterr()
    assert cli.main(["--store", str(target), "import", str(exported)]) == 0
    assert "unchanged" in capsys.readouterr().out


def test_import_refuses_a_broken_document(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text(json.dumps({"oet_version": "1.0"}))
    assert cli.main(["--store", str(tmp_path / "ledger"), "import", str(path)]) == 1
    assert "missing-field" in capsys.readouterr().err


def test_head_can_reach_back_through_the_local_surveys(tmp_path, capsys):
    """``HEAD~N`` is the Nth local survey before this one."""

    from surveyor.model import Node, Topology
    from surveyor.store import Ledger

    ledger = Ledger(tmp_path / "ledger")
    for index in range(4):
        topology = Topology(site="edge")
        topology.add(Node("host:lab", "host", "lab"))
        topology.add(Node(f"workload:w{index}", "workload", f"w{index}"))
        ledger.commit(topology)

    assert cli.main(["--store", str(tmp_path / "ledger"), "show", "HEAD~2", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    labels = {node["label"] for node in document["nodes"]}
    assert labels == {"lab", "w1"}


def test_history_says_what_changed(tmp_path, monkeypatch, capsys):
    _stub_survey(monkeypatch, [build_topology()])
    store = tmp_path / "ledger"
    assert cli.main(["--store", str(store), "scan", "--quiet"]) == 0
    capsys.readouterr()

    assert cli.main(["--store", str(store), "history"]) == 0
    out = capsys.readouterr().out
    assert "#0" in out
    assert "theodolite" in out


def test_history_on_a_quiet_ledger_says_so(tmp_path, capsys):
    assert cli.main(["--store", str(tmp_path / "ledger"), "history"]) == 0
    assert "has not moved" in capsys.readouterr().out


def test_export_into_a_repo_writes_one_file_per_site_and_host(tmp_path, monkeypatch, capsys):
    """A tree of plats, so that what changed is a reviewable diff."""

    _stub_survey(monkeypatch, [build_topology()])
    store = tmp_path / "ledger"
    repo = tmp_path / "repo"
    assert cli.main(["--store", str(store), "scan", "--quiet"]) == 0
    capsys.readouterr()

    assert cli.main(["--store", str(store), "export", "HEAD", "--repo", str(repo)]) == 0
    out = capsys.readouterr().out
    assert "changed" in out

    written = list(repo.glob("plats/*/*.oet.json"))
    assert len(written) == 1
    document = json.loads(written[0].read_text())
    assert document["nodes"]

    # A second export of the same plat changes nothing.
    assert cli.main(["--store", str(store), "export", "HEAD", "--repo", str(repo)]) == 0
    assert "unchanged" in capsys.readouterr().out


def test_fleet_can_be_narrowed_to_one_site(tmp_path, monkeypatch, capsys):
    plat = build_topology()
    plat.site = "alpha"
    _stub_survey(monkeypatch, [plat])
    store = tmp_path / "ledger"
    assert cli.main(["--store", str(store), "scan", "--quiet"]) == 0
    capsys.readouterr()

    assert cli.main(["--store", str(store), "fleet", "--site", "alpha", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hosts"]
    assert set(payload["sites"].values()) == {"alpha"}

    # A site with no surveys is an error, not an empty map.
    assert cli.main(["--store", str(store), "fleet", "--site", "nowhere"]) == 1


def test_show_missing_ledger_is_an_error(tmp_path, capsys):
    assert cli.main(["--store", str(tmp_path / "none"), "show"]) == 1
    assert "no survey available" in capsys.readouterr().err


def test_daemon_once_records_and_stops(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    _stub_survey(monkeypatch, [build_topology()])
    assert cli.main(["--store", str(store), "daemon", "--once"]) == 0
    out = capsys.readouterr().out
    assert "recorded" in out or "#0" in out
    assert (store / "journal.jsonl").exists()


def test_redaction_flag_reaches_the_document(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    _stub_survey(monkeypatch, [build_topology()])
    output = tmp_path / "plat.json"
    cli.main(["--store", str(store), "scan", "--redact", "--no-save", "--output", str(output)])
    capsys.readouterr()
    document = json.loads(output.read_text())
    host = next(node for node in document["nodes"] if node["kind"] == "host")
    assert host["facts"]["mac"] == "f0:18:98:xx:xx:xx"
    assert document["observations"]["redacted"] is True
    assert cli.main(["validate", str(output)]) == 0


def test_topology_from_dict_survives_cli_round_trip(tmp_path, monkeypatch, capsys):
    store = tmp_path / "ledger"
    _stub_survey(monkeypatch, [build_topology()])
    output = tmp_path / "plat.json"
    cli.main(["--store", str(store), "scan", "--no-save", "--output", str(output)])
    capsys.readouterr()
    restored = Topology.from_dict(json.loads(output.read_text()))
    assert restored.fingerprint == build_topology().fingerprint
