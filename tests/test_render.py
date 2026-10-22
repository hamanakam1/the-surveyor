"""The ASCII map.

A topology map has to survive being big. A modern edge box has hundreds of
scheduled services and a handful of things that actually matter, and a map
that shows the first six alphabetically shows the reader neither.
"""

from __future__ import annotations

from surveyor.model import Edge, Node, Topology
from surveyor.render import ascii_map, markdown_table, mermaid


def _busy_topology() -> Topology:
    """A host with one hub, a few models, and a crowd of daemons."""

    topology = Topology(site="edge", generated_at="2026-01-01T00:00:00Z")
    topology.add(Node("host:lab", "host", "lab"))
    topology.add(
        Node("workload:ollama", "workload", "ollama", facts={"runtime": "ollama"})
    )
    for index in range(3):
        topology.add(
            Node(
                f"model:m{index}",
                "model",
                f"m{index}",
                facts={"name": f"m{index}", "served_by": "http://127.0.0.1:11434"},
                source="workloads",
            )
        )
        topology.connect(Edge("workload:ollama", "serves", f"model:m{index}", {}))
    for index in range(12):
        topology.add(
            Node(
                f"workload:daemon{index}",
                "workload",
                f"daemon{index}",
                facts={"runtime": "systemd"},
                source="services",
            )
        )
        topology.connect(Edge("host:lab", "runs", f"workload:daemon{index}", {}))
    topology.connect(Edge("host:lab", "runs", "workload:ollama", {"runtime": "ollama"}))
    return topology


def test_the_map_shows_the_hub_first():
    """The model server that serves three models matters more than a daemon."""

    rendered = ascii_map(_busy_topology())
    workloads = rendered.split("WORKLOADS", 1)[1]
    box = workloads.split("╰", 1)[0]
    lines = [line for line in box.splitlines() if line.startswith("│ ")]
    assert "ollama" in lines[0]


def test_the_map_says_what_it_left_out():
    rendered = ascii_map(_busy_topology())
    assert "12 systemd" in rendered
    assert "3 model" in rendered
    assert "more" in rendered


def test_the_edge_list_shows_the_interesting_edges_first():
    rendered = ascii_map(_busy_topology())
    serves = rendered.split("serves", 1)[1]
    assert "m0" in serves.splitlines()[0]


def test_a_small_plat_has_no_breakdown_line():
    topology = Topology(site="edge", generated_at="2026-01-01T00:00:00Z")
    topology.add(Node("host:lab", "host", "lab"))
    rendered = ascii_map(topology)
    assert "more" not in rendered
    assert "nothing observed" in rendered


def test_the_markdown_rendering_has_a_table_per_layer():
    rendered = markdown_table(_busy_topology())
    assert "### Survey plat — edge" in rendered
    assert "| Node | Kind | Detail |" in rendered
    assert "#### Workloads" in rendered


def test_the_mermaid_rendering_has_a_graph_per_layer():
    rendered = mermaid(_busy_topology())
    assert rendered.startswith("%%{init:")
    assert "graph TD" in rendered
    assert 'subgraph WORKLOAD["Workloads"]' in rendered
    assert "-->|serves|" in rendered
