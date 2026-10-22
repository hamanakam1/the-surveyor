"""Guards against documentation drifting away from the software."""

from __future__ import annotations

import json
from pathlib import Path

from surveyor.ascii import BANNER
from surveyor.config import Config
from surveyor.model import KINDS, LAYERS, RELATIONS, Topology, kind_layer

ROOT = Path(__file__).resolve().parents[1]


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


def test_docs_reference_the_schema_that_exists():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    spec = (ROOT / "docs" / "oet-1.0.md").read_text(encoding="utf-8")
    assert Path(ROOT / "schema" / "oet-1.0.schema.json").exists()
    assert "schema/oet-1.0.schema.json" in readme
    assert "schema/oet-1.0.schema.json" in spec
    schema = json.loads((ROOT / "schema" / "oet-1.0.schema.json").read_text())
    assert schema["properties"]["oet_version"]["const"] == "1.0"
    assert set(schema["$defs"]["edge"]["properties"]["relation"]["enum"]) == set(RELATIONS)
