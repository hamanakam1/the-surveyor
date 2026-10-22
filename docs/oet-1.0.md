# Open Edge Topology (OET) 1.0

OET is the document format The Surveyor emits. It is deliberately small: four
layers, nine node kinds, nine relations. Anything richer belongs in `facts`,
not in a new noun.

The formal contract lives in [`schema/oet-1.0.schema.json`](../schema/oet-1.0.schema.json).
This document explains the semantics the schema cannot express.

## 1. The one rule

**A plat records what was observed, not what was intended.**

There is no `desired_state`, no `expected_image`, no `should_be_running`. If a
scanner could not see something, the node is absent and the reason is recorded
in `observations.warnings`. Absence is a fact; invention is not.

## 2. Layers

The map is read top-down, from the wall socket to the listening socket.

| Layer | Key | Holds |
| --- | --- | --- |
| Power | `power` | utility feeds, batteries, UPS, solar where the OS reports it |
| Bare metal | `metal` | the surveyed host itself: CPU, memory, storage, thermals, accelerator, board |
| Network | `network` | interfaces, IPv4 and IPv6 subnets, unverified devices such as the default gateway |
| Workloads | `workload` | containers, model servers, models, listening services, volumes, scheduled services |

Layer is a presentation and diffing affordance. It never changes the identity
of a node.

## 3. Node kinds

| Kind | Layer | Identity convention | Example |
| --- | --- | --- | --- |
| `power_source` | power | `power:<slug>` | `power:ac`, `power:battery:internal-0` |
| `host` | metal | `host:<hostname-slug>` | `host:studio` |
| `device` | network | `device:<hardware-address>` | `device:f0-18-98-11-22-33` |
| `network` | network | `network:<cidr>` | `network:192.168.53.0/24` |
| `interface` | network | `iface:<host>:<ifname>` | `iface:studio:en0` |
| `workload` | workload | `workload:<runtime>:<name>` | `workload:docker:web`, `workload:systemd:nginx.service` |
| `model` | workload | `model:<slug>` | `model:llama3.2:3b` |
| `service` | workload | `service:<proto>:<port>` | `service:tcp:8080`, `service:udp:5353` |
| `volume` | workload | `volume:<name>` | `volume:pgdata` |
Identity is the hard part of any topology format. Three rules keep it stable:

1. **Prefer names over generated identifiers.** Container name, interface name,
   subnet CIDR, port number. A container recreated with the same name is the
   same node with a new `container_id` fact -- and that fact changing is exactly
   the structural event an operator wants to hear about.
2. **Never encode telemetry in an id.** No timestamps, no load averages, no
   percentages.
3. **A device is named by its hardware address, not its IP.** An address is
   not an identity: a DHCP lease moves and the device does not. A device
   observed on the wire is `device:f0-18-98-11-22-33`, and that id survives
   the lease changing. A device that was *not* observed — a default gateway
   that never answered — is `device:192.168.53.1` and carries the tag
   `unverified`, because its identity is a guess. `observed` means the device
   answered.

   Redaction aliases the hardware-address form of a device id rather than
   masking it to its vendor prefix, so two peers from the same vendor do not
   collapse into one node.

## 4. Relations

| Relation | Meaning | Typical pair |
| --- | --- | --- |
| `powers` | supplies electrical power | `power_source` → `host` |
| `hosts` | contains or terminates | `host` → `interface` |
| `runs` | executes | `host` → `workload` |
| `serves` | makes available | `workload` → `model` |
| `attaches_to` | is bound to | `interface` → `network` |
| `routes_via` | sends traffic through | `host` → `device` (gateway) |
| `exposes` | makes reachable | `workload`/`host` → `service` |
| `depends_on` | requires, without owning | any → any |
| `member_of` | participates in | device → subnet |

Edges are directed, deduplicated by `(source, relation, target)`, and may carry
`facts` (for example `{"priority": 1}` on a power edge).

An edge whose endpoints do not both exist is invalid. The compiler drops such
edges and records why; `surveyor validate` reports them.

## 5. Facts and telemetry

Every node carries two attribute maps.

**`facts` -- the shape of the thing.** Image, CPU model, MAC address, subnet,
port, design capacity, container id. Changing a fact changes the map.

**`telemetry` -- the weather.** Load average, available memory, charge
percentage, uptime, container status string, model expiry. Changing telemetry
changes the document, but not the map.

The distinction is enforced, not advisory. See
[`src/surveyor/model.py`](../src/surveyor/model.py) `VOLATILE_FACT_KEYS`: even a
scanner that misfiles `load_1m` under `facts` cannot cause a false structural
change.

## 6. Two digests

A plat has two identities, and confusing them is how idempotence dies.

**Structural fingerprint** -- `sha256` of the canonical JSON of:

```json
{
  "oet_version": "1.0",
  "site": "edge-lab",
  "nodes": [{"id": "...", "kind": "...", "layer": "...", "label": "...", "facts": {}, "tags": []}],
  "edges": [{"source": "...", "relation": "...", "target": "...", "facts": {}}]
}
```

Nodes are sorted by id, edges by `(source, relation, target)`, keys are sorted,
separators are `,` and `:`, and non-JSON scalars fall back to `str`. Excluded:
`generated_at`, `observations`, all `telemetry`, and any key in
`VOLATILE_FACT_KEYS`.

Two surveys with the same fingerprint describe the same infrastructure, however
much the machine has been breathing in between. The ledger uses this to decide
whether a survey is worth recording.

**Content digest** -- `sha256` of the canonical JSON of the *entire* document,
including `generated_at` and telemetry. It addresses the immutable object in
the ledger. Object files are stored as exactly those canonical bytes, so
`sha256(file) == digest` is a real integrity check, not a convention.

## 7. Observations

`observations` is the surveyor's field book, and is explicitly outside the
fingerprint:

```json
{
  "platform": "darwin/arm64",
  "hostname": "studio",
  "duration_ms": 412,
  "scanners": [
    {"scanner": "power", "layer": "power", "ok": true, "nodes": 2, "edges": 2,
     "duration_ms": 71, "notes": [], "error": ""}
  ],
  "warnings": ["network: 3 interface(s) without an IPv4 address omitted from the plat"],
  "conflicts": [],
  "layers": {"power": {"label": "Power", "nodes": 2}},
  "redacted": false
}
```

A failed scanner sets `ok: false` and an `error`, and the rest of the plat still
stands. Consumers must treat a partial plat as partial: check `scanners[].ok`
before concluding that a workload is gone.

## 8. Redaction

`surveyor scan --redact` (or `redact = true`) produces a plat safe to publish.

| Value | Treatment |
| --- | --- |
| Hostname | `sha256:<10 hex>` alias, in facts, labels, observations, **and node ids** |
| Container name, compose project, compose service | `sha256:<10 hex>` alias |
| Model name (the local model, not the hardware model) | `sha256:<10 hex>` alias |
| Image registry owner (`ghcr.io/acme/app`) | owner aliased, application name kept |
| Serial, UUID, machine id, container id, digest | `sha256:<10 hex>` alias |
| Wi-Fi SSID | `sha256:<10 hex>` alias |
| Listener process names | `sha256:<10 hex>` alias |
| MAC address | vendor prefix kept, host bits replaced: `f0:18:98:xx:xx:xx` |
| Public IPv4 | host bits masked: `93.184.x.x` |
| Public IPv6 | routing prefix kept: `2606:2800:220:1::` |
| Link-local, unique-local, loopback addresses | preserved -- a topology map needs them |
| Private, loopback, link-local addresses | preserved -- a topology map needs them |
| Hardware model, CPU model, ports, versions, counts | preserved -- this is the shape |
| Telemetry values | treated like any other value |

### 8.1 Aliases are keyed

An alias is `sha256(salt + slug(value))`, where the salt is a 256-bit secret
stored beside the ledger it protects, in `salt`, readable only by its owner.

The key matters. An unkeyed digest of a low-entropy value -- a hostname, a
container name, a Wi-Fi network -- can be reversed by hashing a word list, at
which point redaction is a speed bump rather than a protection. With a key,
the same name always produces the same alias *within one ledger* (so
redacting twice does not churn the map) and a different alias in every other
ledger (so two redacted plats cannot be correlated by their aliases).

The alias is derived from the *slug* of the value, so the raw name
(`qwen3.8:32b`) and the name as it appears in a node id (`qwen3-8-32b`)
collapse to one alias rather than two.

### 8.2 Redacted node ids

Because a hostname is part of a node id, redaction rewrites ids:

```text
host:studio                      ->  host:sha256:5c2e856b3f
iface:studio:en0                 ->  iface:sha256:5c2e856b3f:en0
workload:docker:payments         ->  workload:docker:sha256:9f1c02ab34
```

Edges are rewritten to match, so a redacted plat has no dangling edges and
the same graph as the plat it came from.

### 8.3 Fingerprints and cross-referencing

Redaction changes the fingerprint (facts and ids changed), which is correct:
it is a different, less identifiable plat. **Do not cross-reference redacted
and unredacted plats by node id** -- the ids have been rewritten.

The redacted id is a keyed digest of the original id, so an operator holding
both plats can still match them: the mapping is deterministic, and the
redacted plat records `observations.redaction_keyed`.

### 8.4 Auditing

`surveyor redact FILE --audit` reports every identifier that survived
redaction: a declared identifier that failed to be removed (a bug), and a
value that merely *looks* like an identifier -- an email address, a home
directory, a long hex digest. The second kind is a question for the operator,
not a defect; the command exits non-zero so it can be used in CI.


## 9. Versioning and extension

`oet_version` is `MAJOR.MINOR`. Consumers must reject unknown majors and may
accept unknown minors, ignoring unrecognised fields. Within 1.x:

- new node kinds require a minor bump and a schema update,
- new relations require a minor bump,
- new fact keys require nothing at all -- facts are open.

Producers that need private nouns should encode them as `facts` and `tags`
rather than inventing a parallel document shape.

## 10. Minimal valid plat

```json
{
  "oet_version": "1.0",
  "site": "shed",
  "generated_at": "2026-10-22T00:00:00Z",
  "nodes": [
    {
      "id": "host:shed",
      "kind": "host",
      "layer": "metal",
      "label": "shed (Raspberry Pi 5)",
      "facts": {"arch": "aarch64", "cpu_cores": 4},
      "telemetry": {"load_1m": 0.4},
      "tags": [],
      "source": "host"
    }
  ],
  "edges": []
}
```
