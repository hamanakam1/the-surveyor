"""The golden plats.

``tests/fixtures/plats/`` says, for one scanner and one platform, exactly
what the scanner makes of a recorded command output. It is the difference
between "the parser still works" and "the parser still produces the same
map".

A golden is generated from the recorded output by
``scripts/make_golden.py``, so regenerating one is a deliberate act with a
reviewable diff rather than a copy-and-paste.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = ROOT / "tests" / "fixtures" / "commands"
PLATS = ROOT / "tests" / "fixtures" / "plats"


def _fixtures() -> list[tuple[str, dict, dict]]:
    found = []
    for path in sorted(COMMANDS.glob("*.json")):
        golden = PLATS / path.name
        assert golden.exists(), f"{golden.name} is missing; run `make golden`"
        found.append(
            (
                path.stem,
                json.loads(path.read_text(encoding="utf-8")),
                json.loads(golden.read_text(encoding="utf-8")),
            )
        )
    return found


def test_there_are_golden_plats():
    assert len(list(PLATS.glob("*.json"))) >= 5


@pytest.mark.parametrize(
    ("name", "fixture", "golden"),
    _fixtures(),
    ids=[name for name, _, _ in _fixtures()],
)
def test_a_scanner_still_produces_the_same_map(name, fixture, golden):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "make_golden", ROOT / "scripts" / "make_golden.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    result = module._scan(fixture["scanner"], fixture)
    produced = module.shape(result)

    assert produced["nodes"] == golden["nodes"], (
        f"{name}: the nodes changed. If that is intended, run `make golden` "
        "and read the diff."
    )
    assert produced["edges"] == golden["edges"], (
        f"{name}: the edges changed. If that is intended, run `make golden` "
        "and read the diff."
    )


def test_the_goldens_are_not_empty():
    for path in PLATS.glob("*.json"):
        golden = json.loads(path.read_text(encoding="utf-8"))
        assert golden["nodes"], f"{path.name} has no nodes"
        # The host scanner emits no edges of its own, and that is correct.
        assert "edges" in golden


def test_the_goldens_match_the_generator():
    """A golden that has drifted from its generator is a golden nobody trusts."""

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "make_golden", ROOT / "scripts" / "make_golden.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    for path in sorted(COMMANDS.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        golden = json.loads((PLATS / path.name).read_text(encoding="utf-8"))
        result = module._scan(fixture["scanner"], fixture)
        produced = module.shape(result)
        assert produced["nodes"] == golden["nodes"]
        assert produced["edges"] == golden["edges"]
