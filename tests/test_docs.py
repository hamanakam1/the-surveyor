"""Guards against documentation drifting away from the software."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from surveyor.ascii import BANNER
from surveyor.config import Config
from surveyor.model import KINDS, LAYERS, RELATIONS, Topology, kind_layer

ROOT = Path(__file__).resolve().parents[1]


def _enum_values(node: Any) -> set[str]:
    """Every string a schema enumerates, wherever it happens to live."""

    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "enum" and isinstance(value, list):
                found.update(str(item) for item in value)
            else:
                found |= _enum_values(value)
    elif isinstance(node, list):
        for item in node:
            found |= _enum_values(item)
    return found


def _readme_banner() -> list[str]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    block = text.split("```text\n", 1)[1].split("```", 1)[0]
    return block.rstrip("\n").split("\n")


def test_readme_art_is_the_same_art_the_binary_prints():
    assert tuple(_readme_banner()) == BANNER


def test_readme_art_fits_an_eighty_column_terminal():
    assert max(len(line) for line in BANNER) <= 80
    assert all(line == line.rstrip() for line in BANNER)


def test_sample_plat_is_valid_and_self_describing():
    document = json.loads((ROOT / "examples" / "sample.oet.json").read_text())
    topology = Topology.from_dict(document)
    assert not topology.dangling_edges()
    assert document["fingerprint"] == topology.fingerprint
    for node in topology.nodes.values():
        assert node.kind in KINDS
        assert node.layer in LAYERS
        assert node.layer == kind_layer(node.kind)
    for edge in topology.edges:
        assert edge.relation in RELATIONS
        assert edge.source in topology.nodes and edge.target in topology.nodes


def test_example_config_loads_and_names_a_site():
    config = Config.load(ROOT / "examples" / "surveyor.toml")
    assert config.site == "edge-lab"
    assert "workloads" in config.scanners
    assert config.scribe in {"template", "ollama"}


def test_readme_images_exist():
    """A broken image in the README is a broken README."""

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    sources = set(re.findall(r'<img[^>]+src="([^"]+)"', readme))
    sources |= set(re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", readme))
    # Remote badges and links are not files we own.
    local = sorted(source for source in sources if "://" not in source)
    assert local, "the README should show at least one screenshot"
    for source in local:
        assert (ROOT / source).exists(), f"README references a missing image: {source}"


def test_screenshots_are_regenerable():
    """The screenshot set must be produced by a script, not by hand."""

    script = (ROOT / "scripts" / "make_screenshots.py").read_text(encoding="utf-8")
    assert "surveyor" in script
    shots = sorted((ROOT / "docs" / "screenshots").glob("*.png"))
    assert shots, "no screenshots were committed"


def test_docs_reference_the_schema_that_exists():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    spec = (ROOT / "docs" / "oet-1.0.md").read_text(encoding="utf-8")
    assert Path(ROOT / "schema" / "oet-1.0.schema.json").exists()
    assert "schema/oet-1.0.schema.json" in readme
    assert "schema/oet-1.0.schema.json" in spec
    schema = json.loads((ROOT / "schema" / "oet-1.0.schema.json").read_text())
    rule = schema["properties"]["oet_version"]
    if "const" in rule:
        assert rule["const"] == "1.0"
    else:
        assert re.match(rule["pattern"], "1.0")
        assert not re.match(rule["pattern"], "2.0")
    assert set(RELATIONS) <= _enum_values(schema)
