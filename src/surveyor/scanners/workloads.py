"""Workload scanner: containers, local model servers, and listening sockets.

Three independent observations live here because they answer one question:
*what is actually running on this box, and what does it expose?*

Each sub-probe is optional. A laptop with no Docker, no Ollama, and no
permission to see other users' sockets still produces a valid survey.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..identity import host_id as local_host_id
from ..model import (
    KIND_MODEL,
    KIND_SERVICE,
    KIND_VOLUME,
    KIND_WORKLOAD,
    LAYER_WORKLOAD,
    REL_ATTACHES_TO,
    REL_EXPOSES,
    REL_RUNS,
    REL_SERVES,
    Edge,
    Node,
)
from ..probe import Probe, ProbeLog, run
from ..util import human_bytes, slug, to_int
from .base import ScanContext, ScanResult, register

_DOCKER_PORT = re.compile(r"(?P<published>\d{1,5})->(?P<container>\d{1,5})/(?P<proto>tcp|udp)")
_SS_PROCESS = re.compile(r"users:\(\((?P<process>[^,)]+)")
_LOOPBACK_BINDS = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}


def _service_id(port: int, proto: str = "tcp") -> str:
    return f"service:{proto}:{port}"


def _service_node(port: int, proto: str, label: str, facts: dict[str, Any], tags: tuple[str, ...]) -> Node:
    return Node(
        id=_service_id(port, proto),
        kind=KIND_SERVICE,
        label=label,
        layer=LAYER_WORKLOAD,
        facts={"port": port, "proto": proto, **facts},
        tags=tags,
        source="workloads",
    )


def _published_ports(raw: str) -> list[tuple[int, int, str]]:
    ports: list[tuple[int, int, str]] = []
    for match in _DOCKER_PORT.finditer(raw or ""):
        published = int(match.group("published"))
        container = int(match.group("container"))
        proto = match.group("proto")
        if (published, container, proto) not in ports:
            ports.append((published, container, proto))
    return ports


def _parse_labels(raw: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for part in (raw or "").split(","):
        key, sep, value = part.partition("=")
        if sep and key.strip():
            labels[key.strip()] = value.strip()
    return labels


def _mounts(raw: Any) -> list[dict[str, Any]]:
    """The mounts of a container, as the runtime reports them."""

    if not isinstance(raw, list):
        return []
    found: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        found.append({key: str(value) for key, value in item.items() if value is not None})
    return found


#: Container runtimes, in the order they are tried.
_RUNTIMES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("docker", ("docker", "ps", "--no-trunc", "--format", "{{json .}}")),
    ("podman", ("podman", "ps", "--no-trunc", "--format", "json")),
    ("nerdctl", ("nerdctl", "ps", "--no-trunc", "--format", "{{json .}}")),
)


@dataclass(slots=True)
class Container:
    """One container, whichever runtime reported it."""

    name: str
    image: str = ""
    identifier: str = ""
    state: str = ""
    status: str = ""
    created: str = ""
    running_for: str = ""
    networks: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    ports: list[tuple[int, int, str]] = field(default_factory=list)
    mounts: list[dict[str, Any]] = field(default_factory=list)


def _parse_runtime_output(text: str) -> list[dict[str, Any]]:
    """Read a runtime's output, whatever shape it comes in.

    Docker and nerdctl print one JSON object per line; podman prints one
    JSON array.
    """

    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        return [item for item in parsed if isinstance(item, dict)]
    payloads: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            payloads.append(parsed)
    return payloads


def _first(value: Any) -> str:
    """The first name, whether the runtime gave a string or a list."""

    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _label_map(value: Any) -> dict[str, str]:
    """Docker gives labels as a string; podman gives them as a mapping."""

    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    return _parse_labels(str(value or ""))


def _port_list(value: Any) -> list[tuple[int, int, str]]:
    """Published ports, from either a docker string or a podman list."""

    if isinstance(value, list):
        ports: list[tuple[int, int, str]] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            published = to_int(item.get("host_port"))
            container = to_int(item.get("container_port"))
            if published and container:
                ports.append((published, container, str(item.get("protocol") or "tcp")))
        return ports
    return _published_ports(str(value or ""))


def _container(payload: dict[str, Any], runtime: str) -> Container | None:
    """Normalise one container from either runtime's JSON shape."""

    name = _first(payload.get("Names") or payload.get("Name"))[:120]
    identifier = str(payload.get("ID") or payload.get("Id") or "")
    if not name:
        name = identifier[:120]
    if not name:
        return None
    networks = payload.get("Networks")
    if isinstance(networks, list):
        network_text = ",".join(str(item) for item in networks)
    else:
        network_text = str(networks or "")
    return Container(
        name=name,
        image=str(payload.get("Image") or ""),
        identifier=identifier,
        state=str(payload.get("State") or "").strip(),
        status=str(payload.get("Status") or "").strip(),
        created=str(payload.get("CreatedAt") or "").strip(),
        running_for=str(payload.get("RunningFor") or "").strip(),
        networks=",".join(part.strip() for part in network_text.split(",") if part.strip()),
        labels=_label_map(payload.get("Labels")),
        ports=_port_list(payload.get("Ports")),
        mounts=_mounts(payload.get("Mounts")),
    )


def _volume_node(mount: dict[str, Any]) -> Node | None:
    """A volume or bind mount, as a node of its own.

    The name of a named volume is its identity. A bind mount has no name on
    the host that anyone chose deliberately, so it is named by where it
    lands inside the container -- and the path it comes *from* is recorded
    as a fact, because that path is where the data actually lives and is
    the operator's own directory.
    """

    kind = mount.get("Type", "volume")
    destination = mount.get("Destination", "")
    name = mount.get("Name", "")
    if kind == "volume" and name:
        volume_id = f"volume:{slug(name)}"
        label = name
        facts: dict[str, Any] = {"type": "volume", "name": name}
        if mount.get("Driver"):
            facts["driver"] = mount["Driver"]
    elif destination:
        volume_id = f"volume:{slug(destination)}"
        label = destination
        facts = {"type": "bind", "destination": destination}
        if mount.get("Source"):
            facts["host_path"] = mount["Source"]
    else:
        return None
    if destination:
        facts.setdefault("destination", destination)
    facts["read_only"] = str(mount.get("RW", "true")).lower() == "false"
    return Node(
        id=volume_id,
        kind=KIND_VOLUME,
        label=label,
        layer=LAYER_WORKLOAD,
        facts=facts,
        tags=("volume", kind),
        source="workloads",
    )


def scan_docker(ctx: ScanContext, result: ScanResult, log: ProbeLog) -> None:
    """The containers running on this machine, whichever runtime runs them.

    Docker first because it is what most machines have; podman and nerdctl
    because a box that dropped Docker for one of them is not unusual, and a
    box running nothing but Docker is not the only shape of an edge.
    """

    runtime = ""
    payloads: list[dict[str, Any]] = []
    attempts: list[str] = []
    # The runtime probes get their own log: a box with no container runtime
    # should hear about it once, not once per runtime tried.
    runtime_log = ProbeLog()
    for name, argv in _RUNTIMES:
        probe = runtime_log.add(run(list(argv), timeout=min(ctx.timeout, 8.0)))
        if not probe.ok:
            lines = probe.stderr.strip().splitlines()
            reason = probe.reason or "unavailable"
            attempts.append(f"{name}: {reason}" + (f" ({lines[0][:80]})" if lines else ""))
            continue
        payloads = _parse_runtime_output(probe.stdout)
        runtime = name
        break

    if not runtime:
        summary = "; ".join(attempts) or "no runtime found"
        result.warn(f"container runtime: {summary}; container layer not observed")
        return

    host = local_host_id()
    count = 0
    for payload in payloads:
        if count >= ctx.config.max_workloads:
            result.warn(f"{runtime}: stopped at max_workloads={ctx.config.max_workloads}")
            break
        container = _container(payload, runtime)
        if container is None:
            continue
        count += 1
        name = container.name
        labels = container.labels
        ports = container.ports
        workload_id = f"workload:{runtime}:{slug(name)}"

        facts: dict[str, Any] = {
            "runtime": runtime,
            "image": container.image or "unknown",
            "network_mode": container.networks or "default",
        }
        if container.identifier:
            facts["container_id"] = container.identifier[:12]
        if container.created:
            facts["created_at"] = container.created
        if labels.get("com.docker.compose.project"):
            facts["compose_project"] = labels["com.docker.compose.project"]
        if labels.get("com.docker.compose.service"):
            facts["compose_service"] = labels["com.docker.compose.service"]
        if ports:
            facts["published_ports"] = [f"{published}->{container_port}/{proto}" for published, container_port, proto in ports]

        for mount in container.mounts:
            volume = _volume_node(mount)
            if volume is None:
                continue
            result.nodes.append(volume)
            result.edges.append(
                Edge(workload_id, REL_ATTACHES_TO, volume.id, {"destination": volume.facts.get("destination", "")})
            )

        telemetry: dict[str, Any] = {
            key: value
            for key, value in (
                ("state", container.state),
                ("status", container.status),
                ("running_for", container.running_for),
            )
            if value
        }

        result.nodes.append(
            Node(
                id=workload_id,
                kind=KIND_WORKLOAD,
                label=name,
                facts=facts,
                telemetry=telemetry,
                tags=("container", runtime) + (("compose",) if "compose_project" in facts else ()),
                source="workloads",
            )
        )
        result.edges.append(Edge(host, REL_RUNS, workload_id, {"runtime": runtime}))

        for published, container_port, proto in ports:
            facts_for_service = {
                "published": True,
                "container_port": container_port,
                "workload": name,
            }
            service = _service_node(
                published,
                proto,
                f"{proto}/{published} ({name})",
                facts_for_service,
                ("published", runtime),
            )
            result.nodes.append(service)
            result.edges.append(Edge(workload_id, REL_EXPOSES, service.id, {"container_port": container_port}))


def _http_json(url: str, timeout: float) -> Any:
    request = urllib.request.Request(  # noqa: S310 - loopback endpoint
        url, headers={"User-Agent": "the-surveyor/1.0"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - loopback endpoint
        body = response.read(2_000_000)
    return json.loads(body.decode("utf-8", errors="replace"))


def scan_ollama(ctx: ScanContext, result: ScanResult, log: ProbeLog) -> None:
    endpoint = ctx.config.ollama_endpoint.rstrip("/")
    timeout = min(3.0, ctx.timeout)
    try:
        tags = _http_json(f"{endpoint}/api/tags", timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        result.warn(f"ollama: {type(exc).__name__}; local model server not observed")
        return

    running: Any = {}
    try:
        running = _http_json(f"{endpoint}/api/ps", timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        result.warn("ollama: /api/ps unavailable; resident models not observed")

    models = tags.get("models") if isinstance(tags, dict) else None
    if not isinstance(models, list):
        result.warn("ollama: /api/tags returned an unexpected shape")
        return

    host = local_host_id()
    loaded: list[str] = []
    if isinstance(running, dict) and isinstance(running.get("models"), list):
        loaded = sorted(str(item.get("name") or "") for item in running["models"] if isinstance(item, dict))

    ollama_id = "workload:ollama"
    names = sorted(str(item.get("name") or "") for item in models if isinstance(item, dict) and item.get("name"))
    result.nodes.append(
        Node(
            id=ollama_id,
            kind=KIND_WORKLOAD,
            label="ollama",
            facts={
                "runtime": "ollama",
                "endpoint": endpoint,
                "model_count": len(names),
                "models": names[:50],
            },
            telemetry={"loaded": loaded},
            tags=("model-server", "local-ai"),
            source="workloads",
        )
    )
    result.edges.append(Edge(host, REL_RUNS, ollama_id, {"runtime": "ollama"}))

    for item in models[: ctx.config.max_workloads]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        facts: dict[str, Any] = {"name": name, "served_by": endpoint}
        for source, target in (
            ("family", "family"),
            ("parameter_size", "parameter_size"),
            ("quantization_level", "quantization"),
            ("format", "format"),
        ):
            value = details.get(source) if details else None
            if value:
                facts[target] = str(value)
        size = to_int(item.get("size"))
        if size:
            facts["size_gib"] = round(size / (1024**3), 2)
            facts["size_human"] = human_bytes(size)
        digest = str(item.get("digest") or "")
        if digest:
            facts["digest"] = digest[:12]
        model_id = f"model:{slug(name)}"
        result.nodes.append(
            Node(
                id=model_id,
                kind=KIND_MODEL,
                label=name,
                facts=facts,
                telemetry={"modified_at": str(item.get("modified_at") or "")},
                tags=("model", "ollama") + (("loaded",) if name in loaded else ()),
                source="workloads",
            )
        )
        result.edges.append(Edge(ollama_id, REL_SERVES, model_id, {}))

    if loaded:
        result.warn(f"ollama: {len(loaded)} model(s) resident in memory")


def _bind_of(name: str) -> tuple[str, int | None]:
    trimmed = name.strip()
    if "->" in trimmed:
        trimmed = trimmed.split("->", 1)[0]
    if trimmed.startswith("["):
        host, _, port = trimmed.rpartition("]:")
        return host.lstrip("["), to_int(port)
    if ":" in trimmed:
        host, _, port = trimmed.rpartition(":")
        return host, to_int(port)
    return trimmed, None


def scan_listeners(ctx: ScanContext, result: ScanResult, log: ProbeLog) -> None:
    probe: Probe = log.add(run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=min(ctx.timeout, 8.0)))
    entries: list[tuple[str, str, int]] = []
    if probe.ok:
        for raw in probe.lines():
            # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            fields = raw.split(None, 8)
            if len(fields) < 9 or not fields[1].isdigit():
                continue
            command = _unescape_lsof(fields[0])
            name = fields[8].replace(" (LISTEN)", "").strip()
            bind, port = _bind_of(name)
            if port is None:
                continue
            entries.append((command, bind, port))
    else:
        fallback = log.add(run(["ss", "-ltn"], timeout=min(ctx.timeout, 8.0)))
        if fallback.ok:
            for raw in fallback.lines():
                fields = raw.split()
                if len(fields) < 4 or fields[0] != "LISTEN":
                    continue
                bind, port = _bind_of(fields[3])
                if port is None:
                    continue
                process = _SS_PROCESS.search(raw)
                command = process.group("process").strip('"') if process else "unknown"
                entries.append((command, bind, port))
        else:
            result.warn("no listener table available (lsof/ss); socket exposure not observed")
            return

    services: dict[int, dict[str, Any]] = {}
    for command, bind, port in entries:
        record = services.setdefault(port, {"processes": set(), "binds": set()})
        record["processes"].add(command)
        record["binds"].add(bind)

    host = local_host_id()
    skipped_loopback = 0
    for port in sorted(services)[: ctx.config.max_workloads]:
        record = services[port]
        binds = sorted(record["binds"])
        processes = sorted(record["processes"])
        local_only = bool(binds) and all(bind in _LOOPBACK_BINDS or bind.startswith("127.") for bind in binds)
        if local_only and not ctx.config.include_local_services:
            # A socket that cannot leave the machine is not part of the edge
            # topology. Recording them by default makes diffs noisy without
            # telling the operator anything about reachability.
            skipped_loopback += 1
            continue
        tags = ("listener", "local-only" if local_only else "exposed")
        label = f"tcp/{port} ({processes[0]})" if processes else f"tcp/{port}"
        node = _service_node(
            port,
            "tcp",
            label,
            {"bind": binds, "processes": processes},
            tags,
        )
        result.nodes.append(node)
        result.edges.append(Edge(host, REL_EXPOSES, node.id, {"source": "listener"}))

    if skipped_loopback:
        result.warn(
            f"{skipped_loopback} loopback-only listener(s) omitted; "
            "set include_local_services = true to record them"
        )


#: ``lsof -nP -iUDP``: "rapportd 681 user 19u IPv6 0x... 0t0 UDP *:3722"
_LSOF_UDP = re.compile(
    r"^(?P<command>\S+)\s+(?P<pid>\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+UDP\s+(?P<endpoint>\S+)\s*$"
)

#: ``ss -lun``: "UNCONN 0 0 0.0.0.0:68 0.0.0.0:*"
_SS_UDP = re.compile(
    r"^(?P<state>\S+)\s+(?P<recv>\d+)\s+(?P<send>\d+)\s+(?P<local>\S+)\s+(?P<peer>\S+)"
)


#: lsof escapes unusual characters in the command column as ``\xNN``.
_LSOF_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _unescape_lsof(text: str) -> str:
    """Decode lsof's ``\\xNN`` escapes in a command name."""

    return _LSOF_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), text)


def parse_lsof_udp(text: str) -> list[tuple[str, str, int]]:
    """Parse ``lsof -nP -iUDP`` into (command, bind, port).

    Only sockets that are *bound* to a port count. A connected UDP socket
    is a conversation in progress, not a service, and a socket bound to an
    ephemeral port (``*:*``) is an outgoing client.
    """

    found: list[tuple[str, str, int]] = []
    for raw in text.splitlines():
        match = _LSOF_UDP.match(raw.strip())
        if not match:
            continue
        endpoint = match.group("endpoint")
        if "->" in endpoint:
            continue
        bind, port = _bind_of(endpoint)
        if port is None:
            continue
        found.append((_unescape_lsof(match.group("command")), bind, port))
    return found


def parse_ss_udp(text: str) -> list[tuple[str, str, int]]:
    """Parse ``ss -lun`` into (command, bind, port)."""

    found: list[tuple[str, str, int]] = []
    for raw in text.splitlines():
        match = _SS_UDP.match(raw.strip())
        if not match:
            continue
        local = match.group("local")
        bind, port = _bind_of(local)
        if port is None:
            continue
        process = _SS_PROCESS.search(raw)
        command = process.group("process").strip('"') if process else "unknown"
        found.append((command, bind, port))
    return found


def scan_udp_listeners(ctx: ScanContext, result: ScanResult, log: ProbeLog) -> None:
    """The UDP services the machine offers.

    A UDP server is a service exactly as much as a TCP one is, and it was
    invisible: a box answering DNS or discovery requests over UDP showed a
    map with nothing listening.
    """

    entries: list[tuple[str, str, int]] = []
    if ctx.platform == "darwin":
        probe = log.add(run(["lsof", "-nP", "-iUDP"], timeout=min(ctx.timeout, 8.0)))
        if probe.ok:
            entries = parse_lsof_udp(probe.stdout)
    elif ctx.platform.startswith("linux"):
        probe = log.add(run(["ss", "-lun"], timeout=min(ctx.timeout, 8.0)))
        if probe.ok:
            entries = parse_ss_udp(probe.stdout)
    if not entries:
        return

    services: dict[int, dict[str, Any]] = {}
    for command, bind, port in entries:
        record = services.setdefault(port, {"processes": set(), "binds": set()})
        record["processes"].add(command)
        record["binds"].add(bind)

    host = local_host_id()
    skipped_loopback = 0
    for port in sorted(services)[: ctx.config.max_workloads]:
        record = services[port]
        binds = sorted(record["binds"])
        processes = sorted(record["processes"])
        local_only = bool(binds) and all(
            bind in _LOOPBACK_BINDS or bind.startswith("127.") for bind in binds
        )
        if local_only and not ctx.config.include_local_services:
            skipped_loopback += 1
            continue
        tags = ("listener", "udp", "local-only" if local_only else "exposed")
        label = f"udp/{port} ({processes[0]})" if processes else f"udp/{port}"
        node = _service_node(
            port,
            "udp",
            label,
            {"bind": binds, "processes": processes},
            tags,
        )
        result.nodes.append(node)
        result.edges.append(Edge(host, REL_EXPOSES, node.id, {"source": "listener"}))

    if skipped_loopback:
        result.warn(
            f"{skipped_loopback} loopback-only UDP service(s) omitted; "
            "set include_local_services = true to record them"
        )


@register(
    "workloads",
    LAYER_WORKLOAD,
    "Docker containers, a local Ollama server with its models, and listening sockets",
    tools={
        "any": ("docker", "podman", "nerdctl", "lsof", "ss"),
    },
)
def scan_workloads(ctx: ScanContext) -> ScanResult:
    result = ScanResult(scanner="workloads", layer=LAYER_WORKLOAD)
    log = ProbeLog()
    scan_docker(ctx, result, log)
    scan_ollama(ctx, result, log)
    scan_listeners(ctx, result, log)
    scan_udp_listeners(ctx, result, log)

    for note in log.notes():
        result.warn(note)
    if not result.nodes:
        result.warn("no containers, model servers, or listeners observed")
    return result
