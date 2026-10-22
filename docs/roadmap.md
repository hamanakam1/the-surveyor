# The Long-Term Plan

How The Surveyor should be built from 1.0 to the thing it is meant to become.

This is a plan, not a wish list. Every item names the module it lands in, the
reason it exists, and the evidence that it is done. Items that cannot be
justified by an observation of the current code are not in here.

The plan is written against the 1.0.0 tree: four scanners, a content-addressed
ledger, a hash-chained journal, a deterministic scribe, and a CLI that reads
its own host and writes down what it found.

---

## 1. The invariant

Everything below is downstream of one sentence:

> **The Surveyor reports what a machine is, never what it should be, and never
> what someone inferred.**

That single rule produces most of the design decisions already made, and it
should produce most of the ones still to come:

- **Read-only** — the tool observes; it never configures, restarts, or repairs.
  It will not grow a "fix this for me" button in any horizon below.
- **Facts are structure, telemetry is weather** — a node's shape changes the
  fingerprint; its mood does not. A five-minute daemon must not write 288
  entries a day.
- **Absence is a fact** — if a scanner could not see something, the node is
  absent and the reason is in `observations.warnings`. Never invent a node to
  fill a layer.
- **The record is verifiable** — content addressing plus a parent-linked hash
  chain means a tampered ledger is detectable without trusting the writer.
- **Local-first** — no account, no cloud, no telemetry. The optional model is
  local and may only rewrite prose, never facts.

When a horizon item below seems to strain against this invariant, the
invariant wins and the item is rewritten or dropped.

### The problem this solves, restated

Infrastructure tools fail in one of two ways. They either report so much that
nobody reads them, or they report so little that they cannot answer a
question at 3am. The Surveyor's answer is: **survey the whole host, then
throw away everything that has not changed shape.** The long-term work is
about widening "the whole host" and about making the narrowing provable.

---

## 2. Shape of the plan

Four horizons, roughly in order. They are not strictly sequential — Horizons A
and B run in parallel, and Horizon D is mostly a consequence of Horizon C
succeeding.

| Horizon | Releases | Question it answers | Roughly |
| --- | --- | --- | --- |
| **A — Trustworthy** | 1.1, 1.2 | "Can I believe what it says and publish it?" | 3 months |
| **B — Complete** | 1.3 – 2.0 | "Can it see everything that actually runs here?" | 6–12 months |
| **C — Fleet** | 2.x | "Can it describe twenty boxes and a site?" | 12–24 months |
| **D — Standard** | 3.x | "Can another tool rely on what it emits?" | 24 months+ |

Horizons are ordered by *risk*, not by excitement. A is boring and
load-bearing. B is the bulk of the user-visible value. C is what turns a
single-host tool into infrastructure. D is what turns an implementation into
a standard.

---

## 3. Horizon A — Trustworthy (1.1, 1.2)

The 1.0 code works. The gaps in this horizon are all cases where it works
*almost* correctly: prose that can contradict the record, redaction that
misses identifiers, validation that does not use the schema that ships with it.

### A1. The prose may never contradict the record

**Problem.** `scribe.narrative()` grouped only `critical` changes and
node-level `warning` changes. A diff whose changes were all `notice`-level —
adding a container, a model, a socket — produced an empty sentence list and
fell through to *"Only the weather changed: 1 telemetry series drifted."*
while the changelog body underneath listed 28 structural changes. The
README's promise that narration is creative but the record is not was being
broken by the template itself.

**Done in this release.** The narrative now partitions structural changes by
polarity, names node changes before edge changes, ranks by significance
(`host` > `power` > `workload` > `model` > `service` > network kinds), and
only says the weather moved when there is genuinely nothing structural.
Regression tests in `tests/test_scribe.py`.

**Still to do.** The same discipline must be applied to the *counting* prose:
`_bullets()` truncates at 10 per layer and the summary line counts only
`critical`/`warning`/`notice`. When bullets are elided, the summary should
say how many were elided, so a reader can tell a short changelog from a
truncated one.

### A2. Redaction that is actually safe

**Problem.** `--redact` was advertised as producing "a plat safe to publish".
It did not. Auditing `redact.py` against what the scanners actually collect
found these leaks:

| Leaked | Where |
| --- | --- |
| **Hostname** | node ids (`host:studio`, `iface:studio:en0`), `facts["hostname"]`, `observations["hostname"]`, and every label that embeds it |
| **Container names** | node ids (`workload:docker:web`), labels, `facts["compose_project"]`, and the `workload` fact of every service they publish |
| **Model names** | node ids (`model:llama3.2:3b`), labels |
| **Process names** | `facts["processes"]`, and the service label that embeds them |
| **Edge facts** | `redact.py` copied edges with a shallow copy — `{"workload": "web"}` survived untouched |
| **MAC addresses** | the regex only matched colon form; dash form was missed |
| **IPv6** | never masked, because it is never parsed either |
| **Container ids, Ollama digests** | 12 hex characters of a stable identifier |
| **Aliases** | `alias_secret` was unsalted SHA-256 truncated to 40 bits — brute-forceable for low-entropy values like `ssid` |

**Done in this release.**

1. **A declared inventory of identifiers** (`sensitivity.py`) — what counts as
   an identifier is stated in one reviewable place instead of guessed by the
   redactor. The policy covers fact keys, kind-specific keys (`name` is an
   interface name on an interface and a model name on a model), and the
   name-bearing component of a node id.
2. **Names are aliased throughout the document** — in facts, in labels, in
   observations, and in **node ids**, with edges rewritten to match so a
   redacted plat has no dangling edges and the same graph.
3. **Edge facts are redacted** like node facts.
4. **Aliases are keyed** — `sha256(salt + slug(value))` against a 256-bit
   secret in `salt` beside the ledger. Stable within a ledger, different in
   every other one, and not reversible with a word list. Deriving the alias
   from the *slug* means the raw name (`qwen3.8:32b`) and the name in the
   node id (`qwen3-8-32b`) collapse to one alias rather than two.
5. **Dash-form MACs and globally routable IPv6** are masked. Private
   addresses are still preserved, by design.
6. **An audit command**: `surveyor redact FILE --audit` reports every
   identifier that survived, and exits non-zero so it can gate a publish in
   CI. It distinguishes a declared identifier that failed to be removed (a
   bug) from a value that merely looks like one — an email address, a home
   directory, a long hex digest — which is a question for the operator.

**Deliberately kept.** Hardware model and CPU model describe the *class* of
machine, not the machine; a map that cannot say what kind of box it is
describing is not a map. Ports, versions and counts are the shape. Private
addresses are the map.

**Still to do.** The inventory is a single table rather than being declared
by the scanner that emits each identifier. That is deliberate for now — a
scanner-declared registry would make redaction depend on import order — but
it should move into the scanner interface once the plugin story (D4) exists
and the registry can be loaded deterministically.


### A3. The schema becomes executable

**Problem.** `schema/oet-1.0.schema.json` ships with the project and
`surveyor validate` does not use it. Validation currently checks exactly two
things: that no edge dangles, and that the declared fingerprint matches the
recomputed one. A document with a malformed node kind, a missing `id`, or an
illegal `oet_version` passes.

**Work.**

1. Implement the schema's rules directly in `model.py` — a hand-written
   validator with no dependency, mirroring the schema exactly.
2. Make `surveyor validate` check: required fields, enums for `kind`,
   `layer`, `relation` and `oet_version`, id-syntax rules, fingerprint
   agreement, dangling edges, and the `facts`/`telemetry` split.
3. Add a **conformance suite**: a directory of deliberately broken plats, each
   with the exact rule it breaks, and a test that every one of them is
   rejected. The schema and the validator must agree, and the test is how
   they are kept honest.
4. `surveyor validate` should be able to validate a *stream* (`--stdin`) and
   emit machine-readable problems with a code, not just prose.

**Exit criteria.** The JSON Schema, the validator, and the conformance suite
cannot disagree; a CI job regenerates the schema from the model definitions
and fails if the committed schema is stale.

### A4. Determinism, reproducibility, golden plats

**Problem.** The suite is fast and hermetic, but the *platform* is not
pinned. A scanner's output can change with a macOS point release, a Docker
version, or a kernel, and nothing catches it.

**Work.**

1. **Golden plats.** Record the output of each scanner against a corpus of
   recorded command output (`tests/fixtures/<os>/<tool>.txt`), and assert the
   parsed nodes and edges match a committed golden plat. This turns "the
   parser still works" into "the parser still works on macOS 15.4".
2. **A determinism check**: scanning the same recorded fixtures twice must
   produce byte-identical canonical JSON.
3. **A fingerprint stability suite**: reordering nodes or edges must not change
   the fingerprint; changing any structural fact must.
4. **CI matrix expansion**: add a pinned-latest job per OS in addition to the
   floating one, so a platform change is caught at the point it lands rather
   than by a user.

### A5. Release and repository hygiene

**Problem.** There is one workflow (tests), and it does not build a release.

**Work.**

- `ruff` (lint + format) and `mypy --strict` on `src/`, wired into CI. The
  codebase is already typed; this makes the annotations load-bearing.
- Coverage measurement with a ratcheting floor (never lower than today).
- A `release.yml`: tag-triggered build, `twine` publish to PyPI, signed
  attestations, and a GitHub Release with the changelog section.
- A `CHANGELOG` gate: the release notes must be generated from the changelog
  file, and the version in `pyproject.toml` must match the changelog's
  newest heading.
- Fix the classifier drift (`Development Status :: 4 - Beta` on a 1.0.0
  release).
- `docs/roadmap.md` (this file) is reviewed each quarter and amended in
  place, so it stays a record of decisions rather than a snapshot.

### A6. Harden the probe boundary

**Problem.** `probe.py` is the security boundary and it is good — argv only,
no shell, allowlist, timeouts, scrubbed environment. Three edges remained:

1. **The allowlist matched on basename only.** `/tmp/attacker/docker` passed,
   because `Path(argv[0]).name` is `docker`. Combined with an inherited
   `PATH`, a writable directory earlier in `PATH` could shadow an allowlisted
   binary.
2. **Environment scrubbing was name-based and incomplete.** `AWS_ACCESS_KEY_ID`
   and `SSH_AUTH_SOCK` both survived it. `SSH_AUTH_SOCK` in particular hands
   a child process the ability to use the operator's SSH agent.
3. **Timeouts killed the child, not the process group.** A probe that spawned
   grandchildren could leave them running.

**Done in this release.** Programs are resolved to an absolute path through a
curated search path; the inherited `PATH` is consulted only for directories
nobody else can write to; a program resolving into a world-writable
directory is refused. The environment marker list now covers `KEY` and
`AUTH`. Probes start in their own session and the whole process group is
killed on timeout.

**Also done — least privilege.** Eight programs were allowlisted with no
caller: `arp`, `df`, `launchctl`, `netstat`, `nvidia-smi`, `powermetrics`,
`system_profiler`, `uptime`. An allowlisted program is an attack surface with
no upside, so they are gone, and a test now fails if an allowlisted program
has no caller. The scanners planned for Horizon B will add their tools back
when they need them — the allowlist grows on demand, which is the only way it
should ever grow.

**Still to do.** `SECURITY.md` now states plainly what this is *not*
designed for: a hostile host that can lie about `sysctl` output, or replace
`/usr/bin/sysctl`, will fool the Surveyor. The hardening above is about
accidents, shadowing and credential leakage, not adversaries. That sentence
belongs in the threat model rather than implied by omission.


---

## 4. Horizon B — Complete (1.3 – 2.0)

The Surveyor currently sees a slice of a modern edge box. This horizon
widens the slice without ever inventing what it cannot see.

The organising principle: **one scanner per layer, one dimension per
scanner**, and every new observation must be able to answer "does this change
the map?" — a fact, yes; a mood, no.

### B1. IPv6, first class

**Problem.** The network scanner parses only `inet` records. Every IPv6
address, prefix, and route is invisible, and IPv6-only interfaces are
dropped entirely as "interfaces without an IPv4 address". For an edge box
that is dual-stacked, half the addressing story is missing.

**Work.** Parse `inet6` on macOS (`ifconfig`) and `ip -6` on Linux; emit
IPv6 interface addresses and IPv6 prefixes as `network:` nodes with
`family: "ipv6"`; model IPv6 default routes as `routes_via` to an IPv6
gateway; and extend redaction (A2) to mask IPv6 host bits the way it masks
public IPv4. Add `family` to the identity of a subnet node so `192.168.1.0/24`
and `2001:db8::/32` cannot collide.

### B2. Storage, volumes and filesystems

**Problem.** `KIND_VOLUME` is defined in the model, documented in the OET
spec, and emitted by no scanner. The `df` and `mount` commands are on the
probe allowlist and unused. A box whose disk filled up looks unchanged.

**Work.** A `storage` dimension, either a new scanner or an extension of
`host`: filesystems, mount points, total and free space (free space is
telemetry, total and mount topology are facts), read-only mounts, and bind
mounts for containers. Emit `volume:` nodes and `mounts` edges.

### B3. Containers beyond Docker

**Problem.** `workloads` shells out to `docker ps` only. A box running
Podman, `nerdctl`, `containerd`, or Kubernetes is invisible; stopped
containers are invisible because `--all` is not used.

**Work.** Detect the available runtime rather than assuming Docker. Prefer
the Docker socket's API over the CLI where the API is more stable and
cheaper. Add `nerdctl` and `podman ps` support behind the same allowlist
rules, and use `--all` so a stopped container is recorded with its state as
telemetry. A container that stopped is a structural event worth a line in the
changelog.

### B4. Schedulers and the things that run on a timer

**Problem.** `launchctl` and `netstat` are allowlisted and unused. A service
scheduled by systemd, launchd, or cron is part of the topology and currently
does not appear.

**Work.** Read systemd unit files and `systemctl list-units` on Linux, and
`launchctl list` on macOS. Emit `workload:` nodes for units with a distinct
identity convention, and a `scheduled_by`/`member_of` relation. This is where
`REL_DEPENDS_ON` and `REL_MEMBER_OF` — currently defined and never emitted —
earn their place.

### B5. GPU and accelerators

**Problem.** `nvidia-smi` is allowlisted and unused. On a box running local
models, the accelerator is often the most load-bearing fact on the machine.

**Work.** Detect the accelerator, its driver version, its memory (total is a
fact, used is telemetry), and which model server is using it. On Apple
silicon, expose the unified-memory split. Consider a fifth layer, `compute`,
between `metal` and `workload` — but only if the evidence supports it; the
four-layer model is a feature and should not be extended for tidiness.

### B6. Peers, and a gateway that is not a guess

**Problem.** The default gateway becomes a `device:` node whose id is its raw
IP address. It is tagged `unverified` because nothing ever verified it, and
under DHCP its id changes, so the map churns for no reason. The rest of the
LAN is invisible; `arp` is allowlisted and unused.

**Work.** Read the neighbour/ARP table and record discovered peers as
`device:` nodes with a MAC-derived, stable, opaque identity — a device id
should survive an address change, exactly like a container id survives a
recreate. Distinguish *observed* devices (seen in the neighbour table) from
*inferred* ones (the default route), and put the distinction in the tags,
not in a footnote. This is the single largest fidelity win available for a
LAN-shaped edge.

### B7. Power beyond AC and battery

**Problem.** The power scanner reports AC and internal batteries, and little
else. A UPS is invisible; a solar array is invisible; on macOS, a laptop
running on battery reports no AC node at all.

**Work.** Linux already sees `/sys/class/power_supply`; the gap is on macOS,
where `pmset -g batt` and IOKit are the only sources. Add `ioreg` parsing for
UPS and for external power, and treat "AC absent" as an absent node with a
warning rather than as "no power layer". A power layer that empties because
the supply changed is a critical event and must be diffable.

### B8. Identity stability

**Problem.** Three identity rules produce churn:

- `device:<raw-ip>` for the gateway — unstable under DHCP.
- `network:<cidr>` for subnets — two interfaces in the same `/24` produce the
  *same* node id, so the second observation is silently merged and its facts
  are lost.
- `util.slug()` truncates at 80 characters — long container and model names
  can collide.

**Work.** Introduce a stable-identity rule per kind, documented in the OET
spec: prefer a durable attribute (MAC for a peer, container name for a
container, mount point for a volume) and fall back to an address only when
nothing durable exists. Make subnet ids include the interface when two
interfaces share a prefix, or make the merge rule "union of facts" instead of
"first writer wins". Resolve `slug()` collisions with a short hash suffix
rather than a truncation.

### B9. Sockets, in full

**Problem.** Only TCP listeners are seen. UDP endpoints, Unix domain sockets,
and process-level services are not.

**Work.** Add UDP listeners, and Unix sockets as a `service:` node with a
filesystem-path identity. Keep the "loopback-only is not topology" rule — it
is a good rule — but make it configurable per operator, not global.

### B10. OET 2.0

**Problem.** Nine node kinds and nine relations will not cover the edge once
B1–B9 land. Every new noun currently wants a new kind, and the spec's own
rule ("anything richer belongs in `facts`, not a new noun") will be tested
hard.

**Work.** Write OET 2.0 as a deliberate, versioned change:

- New kinds only where the *identity* differs, not where the facts differ.
  A peer device, a volume, a scheduled unit, an accelerator, and a peer
  container are candidates; a "temperature sensor" is not.
- New relations where the *semantics* differ: `observed_by`, `scheduled_by`,
  `mounts`, `peers_with`.
- The facts/telemetry split stays exactly as it is. It is the best idea in
  the format and it is not changing.
- A compatibility window: 2.0 consumers reject 1.x majors and accept 1.x
  minors; a 2.x producer may emit a 1.x-compatible plat when asked.

### B11. Performance

**Problem.** Scanners run concurrently in threads and each probe is a
subprocess; a survey of a busy box takes 300–600ms, which is fine, but the
`lsof` call dominates and the whole fan-out is bounded by a single deadline.

**Work.** Cache invocations within a survey (several scanners want the same
`ifconfig` output), prefer `sysctl` and `/proc` reads over subprocesses
wherever possible, and make the fan-out deadline adaptive rather than fixed.
Target: a full four-layer survey of a busy Linux box in under 150ms, and a
`surveyor scan` that costs less than one percent of a core.

---

## 5. Horizon C — Fleet (2.x)

A single-host tool answers "what is this box". An infrastructure tool answers
"what is this site". That is the next horizon, and it is where the OET
format either earns the word *standard* or does not.

### C1. Moving plats between ledgers

**Problem.** There is no way to take a plat from one ledger to another.
`surveyor show --format json` writes a document, but there is no
corresponding import, and the ledger has no way to accept a plat it did not
itself produce.

**Work.** `surveyor export REF --output plat.json` and
`surveyor import plat.json`, where an imported plat is validated, recorded as
a normal journal entry, and *linked* to the local plat for the same host. The
import must not break the chain, so imports get their own entry type with a
`source` field.

### C2. One map for many hosts

**Problem.** A fleet is a graph of graphs, and there is no way to hold one.

**Work.** A fleet ledger holds plats from many hosts, keyed by site and host.
`surveyor fleet --site shed` renders a composed map: the same OET node model,
with edges *between* hosts where one host can see another (a neighbour
table entry, a route, a published port). The composed map is itself a plat,
with its own fingerprint, so a fleet diff works exactly like a host diff.

This is the moment the OET layer model either holds up or does not. The test
is whether "power → bare metal → network → workload" survives a cross-host
edge, and whether a composed fingerprint is meaningful when two hosts
contribute.

### C3. Sites

**Problem.** `site` is a free-text label on every plat. It has no structure,
no hierarchy, and no meaning beyond whatever the operator typed.

**Work.** A site is a directory of hosts with its own metadata: a name, a
description, an optional address range, and optional tags. A plat belongs to
a site. Site-level diffs ("which host in the site changed?") become a
first-class query.

### C4. Telling someone

**Problem.** The Surveyor writes to a ledger and stops. An operator who wants
to know about a change has to look at the ledger.

**Work.** Notifications on structural change, through a small set of
transports: a webhook (for `ntfy`, `Gotify`, or a Slack-compatible
endpoint), and a local `systemd` unit that mails. The rules stay strict:
notifications fire only on *structural* changes, never on telemetry, and the
notification body is the redacted changelog by default. An operator who wants
to be told about a container upgrade should not have to configure what counts
as a container upgrade — the severity classifier already knows.

### C5. GitOps

**Problem.** A plat is a file. A repository of plats is a history of
infrastructure. Nothing connects the two.

**Work.** `surveyor publish --repo <path>` writes the current plat as a
committed file and opens a pull request when the structure has changed. This
turns "what changed on this box" into a reviewable diff, which is how
infrastructure is actually reviewed. The hash chain and the git history are
different guarantees, and both are useful: git gives review, the chain gives
tamper-evidence.

### C6. Attestation

**Problem.** The hash chain proves the ledger has not been edited. It does
not prove *who* wrote it, or that the plat describes a real machine.

**Work.** Optional signing of journal entries with an SSH or GPG key, so a
plat can be verified as "written by this host, by this operator" and not just
"internally consistent". The chain remains the default; signing is opt-in,
because most operators do not need it and it should never be a tax on the
common case.

---

## 6. Horizon D — Standard (3.x)

### D1. OET as a published specification

**Problem.** OET 1.0 is a document in this repository, described as a
"standard". It is not one: there is no registry, no independent schema
authority, no versioning policy outside this repository, and no conformance
process.

**Work.** Move the specification to its own home with its own lifecycle:
a stable URL, a semantic version, a published JSON Schema, a changelog, and
a conformance suite that any implementation can run against. The Surveyor
becomes the reference implementation, not the owner of the format. If the
format is genuinely useful, other tools will emit it; that is the test.

### D2. A local, read-only interface

**Problem.** The ASCII map is good. It is also the only way to look at a
plat, and it cannot answer "show me every container that has changed image
since January".

**Work.** A local HTTP server (`surveyor serve --read-only`) that renders the
ledger as browsable plats, diffs, and changelogs. Read-only, bound to
loopback by default, no telemetry, no accounts, no cloud. The same rule as
everything else: it observes and it displays; it does not act. This is the
single most-requested capability, and it is deliberately built *on top of*
the ledger rather than replacing it.

### D3. A terminal UI

**Problem.** `surveyor show --format ascii` is a static map. It cannot be
navigated.

**Work.** A TUI for browsing the ledger: layer by layer, diff two plats
side by side, follow an edge from a host to the socket it exposes. Deferred
until the ledger can be read without a CLI, because a TUI over a single-host
ledger is a toy.

### D4. Third-party scanners

**Problem.** The scanner registry is internal. Every new dimension requires a
change to this repository, which caps the rate of coverage growth at one
person's throughput.

**Work.** A documented scanner interface — the same contract `ScannerSpec`
already implies — discoverable through Python entry points, so a scanner can
live in its own package. The probe allowlist stays a hard boundary: a
third-party scanner may only run allowlisted programs, so the security
posture does not change when the code does not live here.

### D5. Ecosystem

**Problem.** Nothing else reads OET.

**Work.** Prove the format by building at least one non-trivial consumer that
does not live here: a Terraform/Ansible provider that reconciles a plat
against reality, or an inventory exporter. The point is not the consumer; it
is the discipline of writing a specification that someone else can implement
without reading this repository's source.

---

## 7. Cross-cutting workstreams

These run across every horizon.

**Testing.** The current suite is fast, hermetic, and good. It needs to
grow in three directions: platform corpora (A4), a fault-injection suite that
kills probes mid-flight and asserts the survey still completes, and
property-based testing for the identity and fingerprint rules, where
round-trip and reorder-invariance are the properties to pin down.

**Performance.** A budget, measured in CI: a full survey under 150ms, a
`verify` over a 10,000-entry ledger under one second, and no single scan
consuming more than one core-second.

**Security.** A threat model that says what the tool is *not* designed to
survive (a hostile host) and what it *is* (a local, read-only observer).
Periodic review of the allowlist: every entry must have a caller, and every
caller must have an entry. `SECURITY.md` is updated with each horizon's
changes to the data-handling story.

**Documentation.** The README, the OET spec, and the architecture note are
part of the product, not an afterthought. Each release ships with a
regenerated screenshot set (`scripts/make_screenshots.py`), a refreshed
architecture note, and an updated data-handling section.

**Community.** The repository is public and MIT-licensed. That means issues
and pull requests are expected. The response is: a documented contribution
path, a `CODE_OF_CONDUCT`, a `CONTRIBUTING.md` with the test and lint
commands, and a clear statement of what a good scanner patch looks like
(one dimension, one layer, pure parsers, tests that need no host).

**Governance.** One maintainer means every decision is one person's decision.
The mitigation is written decisions: this roadmap, the OET spec's versioning
policy, and an ADR-style directory for choices that a future contributor
would otherwise have to reverse-engineer.

---

## 8. Sequencing

```text
A1 scribe truth ──────────────┐
A2 redaction ─────────────────┤
A3 executable schema ─────────┤
A4 determinism ───────────────┼──► 1.1  (trustworthy)
A5 release hygiene ───────────┤
A6 probe boundary ────────────┘

B1 IPv6 ───────────┐
B8 identity ───────┤
B9 sockets ────────┤
B6 peers ──────────┼──► 1.3  (wider)
B2 storage ────────┤
B3 containers ─────┤
B4 schedulers ─────┤
B5 accelerators ───┤
B7 power ──────────┘
B10 OET 2.0 ────────────────► 2.0  (complete)

C1 import/export ─┐
C3 sites ─────────┼──► 2.1  (transport)
C2 fleet ─────────┘
C6 attestation ──────────────► 2.2  (trust across hosts)
C4 notifications ─────────────► 2.3
C5 GitOps ────────────────────► 2.4

D1 spec ──────────────────────► 3.0  (standard)
D2 local interface ───────────► 3.1
D3 TUI ───────────────────────► 3.2
D4 plugin scanners ───────────► 3.3
D5 ecosystem ──────────────────► 3.4
```

Dependencies worth stating explicitly:

- **A2 before any publishing feature.** C5 (GitOps) and C4 (notifications)
  both publish plats. Shipping either before redaction is safe means shipping
  a leak.
- **B8 before B6.** Peer devices need stable identities to be worth
  diffing; identity rules first, peers second.
- **C1 before C2.** A fleet cannot exist before a plat can cross a ledger
  boundary.
- **B10 before C2.** Composing a fleet map is what forces the last of the
  format's rough edges out. The format should be settled by the time it is
  used at scale, not after.

---

## 9. Non-goals

Stated so that they are not quietly re-litigated.

- **No remediation.** The Surveyor never changes the machine. It is an
  instrument, not an actuator.
- **No cloud, no account, no telemetry.** There will be no hosted version, no
  sign-up, and no data leaving the machine.
- **No agent to install on every host.** A Python file tree and a standard
  library are the deployment. The fleet model in Horizon C works because
  plats are files that can be shipped any number of ways.
- **No desired state.** OET records what is. A separate tool may compare a
  plat to a desired state; that tool is not this one.
- **No Windows.** The scanners depend on `sysctl`, `/proc`, `sysfs`, `pmset`,
  and `lsof`. Supporting Windows honestly would mean a different tool.
- **No multi-tenancy, ever.** One operator, one host, one ledger.

---

## 10. How progress is measured

A plan that cannot be checked is a wish. These are the signals:

| Signal | Target |
| --- | --- |
| Layers observed on a typical edge box | 4 of 4 today; 4 of 4 *plus* peers and storage by 2.0 |
| Unclassified values in a redacted plat | zero, by the audit command |
| Golden-plat coverage per scanner | 100% of scanners, both platforms |
| Survey wall time, busy Linux box | under 150ms by 2.0 |
| Conformance suite pass rate for the reference implementation | 100% |
| Independent implementations of OET | at least one, by 3.x |
| Time from a good-faith issue to a first response | under a week |

And one qualitative check, applied to every release: **would a reader of this
release's changelog believe it?** If the prose can overstate what the data
supports, the release is not ready.

---

## 11. Open questions

Decisions that this plan does not make yet, and the trigger that will force
each one.

1. **Does OET need a fifth layer?** `compute` for accelerators, or does the
   accelerator belong in `metal` with a `compute` tag? Trigger: when the
   first accelerator scanner is written.
2. **Is a fleet plat one document or many?** A composed map is convenient; a
   set of per-host plats plus a manifest is more honest about staleness.
   Trigger: the first multi-host deployment.
3. **Does the ledger need compaction?** The journal grows forever and
   `verify` is linear. Trigger: a ledger past ~10,000 entries.
4. **Should the scribe be allowed to write more than the opening paragraph?**
   Currently it may not. If the local model can be trusted with per-change
   bullets, the changelog gets better. Trigger: evidence that a local model
   can be *verified* against the diff facts, not merely trusted.
5. **Is OET the right name?** "Open" implies a governance model this project
   does not yet have. Trigger: Horizon D, when the specification gets its own
   home and needs a name that survives that.

---

*Last reviewed: 2026-10-22, against v1.0.0. Amended in place as decisions
are made; see the changelog for what moved.*
