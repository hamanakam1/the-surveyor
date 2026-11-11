"""One version, declared once.

The distribution metadata, the CLI and the release tag must never disagree
about what version this is, so the version lives in exactly one place: the
package. These tests hold that line.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

import surveyor
from surveyor import cli

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_package_is_the_single_source_of_the_version():
    pyproject = _pyproject()
    assert "version" in pyproject["project"].get("dynamic", [])
    assert "version" not in pyproject["project"]
    hatch_version = pyproject["tool"]["hatch"]["version"]
    assert hatch_version["path"] == "src/surveyor/__init__.py"

    source = (ROOT / "src" / "surveyor" / "__init__.py").read_text(encoding="utf-8")
    declared = re.search(r'^__version__\s*=\s*"([^"]+)"', source, re.MULTILINE).group(1)
    assert declared == surveyor.__version__


def test_the_version_is_a_release_label():
    assert re.match(r"^\d+\.\d+\.\d+", surveyor.__version__)
    assert re.match(r"^\d+\.\d+$", surveyor.OET_VERSION)


def test_the_cli_reports_the_package_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    out = capsys.readouterr().out
    assert f"the-surveyor {surveyor.__version__}" in out
    assert f"OET {surveyor.OET_VERSION}" in out
