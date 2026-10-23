"""Unreadable plat inputs fail cleanly without changing existing artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from surveyor import cli
from surveyor.config import Config


def _arguments(command, source, output):
    if command == "diff":
        return ["diff", "--from", str(source), "--to", "HEAD"]
    if command in {"show", "export", "redact"}:
        return [command, str(source), "--output", str(output)]
    return [command, str(source)]


def _snapshot(root):
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


@pytest.mark.parametrize("command", ["validate", "import", "show", "diff", "export", "redact"])
@pytest.mark.parametrize("failure", ["utf8", "permission", "json"])
def test_unreadable_plats_report_errors_and_preserve_artifacts(
    *, tmp_path, tmp_ledger, topology, monkeypatch, capsys, command, failure
):
    tmp_ledger.commit(topology)
    monkeypatch.setattr(cli, "_config", lambda args: Config(store=tmp_ledger.root))
    source = tmp_path / "input.oet.json"
    source.write_bytes(b"\xff" if failure == "utf8" else b"{\nnot JSON}")
    original_input = source.read_bytes()
    output = tmp_path / "output.json"
    output.write_text("existing output\n")
    before = _snapshot(tmp_ledger.root)
    if failure == "permission":
        original_read = Path.read_text

        def refused(path, *args, **kwargs):
            if path == source:
                raise PermissionError("synthetic read denial")
            return original_read(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", refused)

    assert cli.main(_arguments(command, source, output)) == cli.EXIT_ERROR

    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(source) in captured.err
    expected = {"utf8": "UTF-8", "permission": "cannot read", "json": "invalid JSON at line 2"}
    assert expected[failure] in captured.err
    assert "Traceback" not in captured.err
    assert source.read_bytes() == original_input
    assert output.read_text() == "existing output\n"
    assert _snapshot(tmp_ledger.root) == before


@pytest.mark.parametrize("command", ["validate", "import"])
def test_directory_input_reports_a_read_error_without_creating_a_store(
    tmp_path, monkeypatch, capsys, command
):
    store = tmp_path / "ledger"
    monkeypatch.setattr(cli, "_config", lambda args: Config(store=store))
    source = tmp_path / "input.oet.json"
    source.mkdir()
    assert cli.main([command, str(source)]) == cli.EXIT_ERROR
    assert "cannot read" in capsys.readouterr().err
    assert not store.exists()


def test_a_utf8_plat_with_unicode_labels_can_still_be_imported(
    tmp_path, topology, monkeypatch, capsys
):
    topology.site = "edge🚀"
    topology.nodes["host:lab"].label = "測定🚀"
    source = tmp_path / "input.oet.json"
    source.write_text(json.dumps(topology.to_dict(), ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(cli, "_config", lambda args: Config(store=tmp_path / "ledger"))
    assert cli.main(["validate", str(source)]) == cli.EXIT_OK
    assert cli.main(["import", str(source)]) == cli.EXIT_OK
    assert capsys.readouterr().err == ""
