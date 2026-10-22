"""Generate examples/sample.oet.json.

Run from the repo root:  PYTHONPATH=src python3 scripts/make_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path

from surveyor.model import Edge, Node, Topology

topology = Topology(site="shed", generated_at="2026-10-22T05:00:00Z")

nodes = [
    Node("power:solar", "power_source", "Solar array",
         facts={"role": "solar", "kw_peak": 1.2, "mppt": "victron-100/30"},
         telemetry={"yield_today_kwh": 0.9}, tags=("renewable",), source="power"),
    Node("power:battery:agm", "power_source", "AGM battery bank",
         facts={"role": "battery", "chemistry": "agm", "capacity_ah": 200},
         telemetry={"charge_percent": 78, "draw_w": 21.4}, tags=("battery",), source="power"),
    Node("power:ac", "power_source", "AC mains",
         facts={"role": "ac", "source": "utility"}, telemetry={"present": True},
         tags=("utility",), source="power"),
    Node("host:shed", "host", "shed (Raspberry Pi 5)",
         facts={"model": "Raspberry Pi 5", "arch": "aarch64", "cpu_model": "Cortex-A76",
                "cpu_cores": 4, "mem_total_gib": 8, "os": "Debian GNU/Linux 13 (trixie)"},
         telemetry={"load_1m": 0.31, "mem_available_gib": 5.4, "temperature_c": 48.2},
         tags=("site-host", "linux"), source="host"),
    Node("device:192.168.7.1", "device", "gateway 192.168.7.1",
         facts={"role": "gateway", "address": "192.168.7.1"},
         tags=("gateway", "unverified"), source="network"),
    Node("network:192.168.7.0/24", "network", "192.168.7.0/24",
         facts={"cidr": "192.168.7.0/24", "family": "ipv4", "private": True, "size": 256},
         tags=("subnet", "private"), source="network"),
    Node("iface:shed:eth0", "interface", "eth0 (ethernet)",
         facts={"name": "eth0", "kind": "ethernet", "address": "192.168.7.42",
                "ipv4": ["192.168.7.42/24"], "default_route": True, "link_state": "up"},
         telemetry={"up": True}, tags=("ethernet", "primary"), source="network"),
    Node("workload:docker:influxdb", "workload", "influxdb",
         facts={"runtime": "docker", "image": "influxdb:2.7", "container_id": "7c1f0a9b2d34",
                "published_ports": ["8086->8086/tcp"]},
         telemetry={"status": "Up 6 days"}, tags=("container", "docker", "database"),
         source="workloads"),
    Node("workload:ollama", "workload", "ollama",
         facts={"runtime": "ollama", "endpoint": "http://127.0.0.1:11434",
                "model_count": 1, "models": ["qwen2.5:3b"]},
         telemetry={"loaded": ["qwen2.5:3b"]}, tags=("model-server", "local-ai"),
         source="workloads"),
    Node("model:qwen2-5-3b", "model", "qwen2.5:3b",
         facts={"name": "qwen2.5:3b", "family": "qwen2", "parameter_size": "3.1B",
                "quantization": "Q4_K_M", "size_gib": 1.9, "digest": "a80c4f17acd5"},
         tags=("model", "ollama", "loaded"), source="workloads"),
    Node("service:tcp:8086", "service", "tcp/8086 (influxdb)",
         facts={"port": 8086, "proto": "tcp", "published": True, "container_port": 8086},
         tags=("published", "docker"), source="workloads"),
    Node("service:tcp:11434", "service", "tcp/11434 (ollama)",
         facts={"port": 11434, "proto": "tcp", "bind": ["0.0.0.0"]},
         tags=("listener", "exposed"), source="workloads"),
]
for node in nodes:
    topology.add(node)

edges = [
    Edge("power:solar", "powers", "host:shed", {"priority": 1, "kind": "solar"}),
    Edge("power:battery:agm", "powers", "host:shed", {"priority": 2, "kind": "battery"}),
    Edge("power:ac", "powers", "host:shed", {"priority": 3, "kind": "ac"}),
    Edge("host:shed", "hosts", "iface:shed:eth0", {"role": "interface"}),
    Edge("iface:shed:eth0", "attaches_to", "network:192.168.7.0/24", {"address": "192.168.7.42"}),
    Edge("host:shed", "routes_via", "device:192.168.7.1", {"role": "default"}),
    Edge("host:shed", "runs", "workload:docker:influxdb", {"runtime": "docker"}),
    Edge("host:shed", "runs", "workload:ollama", {"runtime": "ollama"}),
    Edge("workload:ollama", "serves", "model:qwen2-5-3b", {}),
    Edge("workload:docker:influxdb", "exposes", "service:tcp:8086", {"container_port": 8086}),
    Edge("host:shed", "exposes", "service:tcp:11434", {"source": "listener"}),
]
for edge in edges:
    topology.connect(edge)

topology.observations = {
    "platform": "linux/aarch64",
    "hostname": "shed",
    "duration_ms": 386,
    "scanners": [
        {"scanner": "power", "layer": "power", "ok": True, "nodes": 3, "edges": 3,
         "duration_ms": 41, "notes": [], "error": ""},
        {"scanner": "host", "layer": "metal", "ok": True, "nodes": 1, "edges": 0,
         "duration_ms": 58, "notes": [], "error": ""},
        {"scanner": "network", "layer": "network", "ok": True, "nodes": 3, "edges": 3,
         "duration_ms": 63, "notes": [], "error": ""},
        {"scanner": "workloads", "layer": "workload", "ok": True, "nodes": 5, "edges": 5,
         "duration_ms": 121, "notes": ["1 loopback-only listener(s) omitted"],
         "error": ""},
    ],
    "warnings": [],
    "conflicts": [],
    "layers": {
        "power": {"label": "Power", "nodes": 3},
        "metal": {"label": "Bare metal", "nodes": 1},
        "network": {"label": "Network", "nodes": 3},
        "workload": {"label": "Workloads", "nodes": 5},
    },
    "redacted": False,
}

target = Path(__file__).resolve().parent.parent / "examples" / "sample.oet.json"
target.write_text(json.dumps(topology.to_dict(), indent=2) + "\n", encoding="utf-8")
print(f"wrote {target} · {len(topology.nodes)} nodes · {len(topology.edges)} edges")
print(f"fingerprint {topology.fingerprint}")
