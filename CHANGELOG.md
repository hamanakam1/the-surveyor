# Changelog

All notable changes to The Surveyor. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **A long-term plan** (`docs/roadmap.md`): four horizons — *Trustworthy*,
  *Complete*, *Fleet*, *Standard* — with the work, the reason, the module it
  lands in, and the evidence that it is done. Includes the sequencing
  dependencies, the explicit non-goals, and the signals that measure
  progress.
- **Screenshots** (`docs/screenshots/*.png`): the survey, the diff, the
  changelog, and the ledger, rendered from live CLI output by
  `scripts/make_screenshots.py`. `make screenshots` regenerates the set;
  nothing in it is hand-drawn.
- **`surveyor redact FILE [--audit]`**: mask a plat's identifiers, and report
  every identifier that survived. The audit distinguishes a declared
  identifier that failed to be removed (a defect) from a value that merely
  looks like one — an email address, a home directory, a long hex digest — and
  exits non-zero so it can gate a publish in CI.
- **A declared inventory of identifiers** (`sensitivity.py`): what counts as
  an identifier is now stated in one reviewable place rather than guessed by
  the redactor, and a scanner that starts emitting a new kind of identifier
  adds a line there.
- **Keyed redaction aliases**: a 256-bit secret in `salt` beside the ledger.
  The same name always produces the same alias within one ledger, so redacting
  twice does not churn the map, and a different alias in every other ledger,
  so two redacted plats cannot be correlated.

### Security

- **`--redact` no longer leaks the identifiers it claimed to remove.** The
  old redactor masked MAC addresses and serials and left everything else in
  the clear. A redacted plat still carried:
  - the **hostname**, in node ids (`host:studio`), in labels, in
    `facts["hostname"]`, and in `observations["hostname"]`;
  - **container names**, in node ids, labels, and the `workload` fact of every
    service they publish;
  - **model names**, in node ids and labels;
  - **listener process names**, in service facts and labels;
  - **every edge fact**, which were copied without redaction at all;
  - MAC addresses in the dash form, and IPv6, which was never parsed.

  Redaction now aliases names throughout the document — including node ids,
  with edges rewritten to match, so a redacted plat has no dangling edges and
  the same graph — masks dash-form MACs, and truncates globally routable IPv6
  addresses. The policy is documented in `docs/oet-1.0.md` §8 and in
  `SECURITY.md`.
- **Aliases are keyed.** An unkeyed digest of a hostname or container name can
  be reversed by hashing a word list, which made the old redaction a speed
  bump rather than a protection. Aliases are now
  `sha256(salt + slug(value))` against a per-ledger secret.

### Fixed

- **The scribe can no longer contradict its own changelog.** A diff whose
  changes were all `notice`-level — a container, a model, a socket appearing
  — produced an empty narrative and fell through to *"Only the weather
  changed: 1 telemetry series drifted."* while the changelog body underneath
  listed the structural changes in full. The narrative now partitions
  structural changes by polarity, names node changes before edge changes,
  ranks by significance (`host` > `power` > `workload` > `model` > `service` >
  network kinds), and only reports weather when there is genuinely nothing
  structural to report.
- **Edge changes are no longer filed under "Unaligned".** An edge change
  inherited no layer, so every one of them grouped into a separate heading
  that meant nothing. An edge now belongs to the layer of the node that
  initiates it.

## [1.0.0] — 2026-10-22

The scaffold becomes software. Everything below is new; the previous state of
this repository was a README describing the intent.

### Added

- **OET 1.0 object model** (`model.py`): four layers, nine node kinds, nine
  relations, and a hard split between structural `facts` and drifting
  `telemetry`. Structural fingerprint and content digest are separate identities.
- **Four scanners**, each independently failable:
  - `power` — `pmset`/IOKit on macOS, `/sys/class/power_supply` on Linux,
    including battery chemistry, design capacity, charge, cycle count.
  - `host` — CPU, memory, board model, kernel, boot mode, load, thermals.
  - `network` — interfaces, MACs, IPv4 subnets, default gateway, Wi-Fi SSID,
    with loopback and tunnel interfaces excluded by default.
  - `workloads` — Docker containers, a local Ollama server with its models, and
    externally reachable listening sockets.
- **Read-only probe layer** (`probe.py`): command allowlist, argument vectors
  only (never a shell), scrubbed environment, empty stdin, hard timeouts.
- **Compiler** with concurrent fan-out, a total time budget, duplicate merging,
  dangling-edge pruning, and per-scanner observation records.
- **Severity-classified differ**: `critical`, `warning`, `notice`, `info`, with
  telemetry drift explicitly non-structural.
- **Scribe**: deterministic Markdown changelogs, plus optional Ollama rewrite of
  the opening paragraph only, with graceful fallback.
- **Ledger**: content-addressed objects (name == SHA-256 of canonical bytes),
  append-only journal, parent-linked hash chain, HEAD pointer, writer lock, and
  `verify` that catches tampering, reordering, and missing objects.
- **Idempotent commits**: an unchanged structural fingerprint writes nothing.
- **Redaction** for publishable plats: MAC vendor prefixes kept, serials and
  SSIDs aliased, public IPv4 truncated, private addresses preserved.
- **Daemon** with interval cadence, single-instance lock, and clean SIGINT and
  SIGTERM handling.
- **Rendering**: layered ASCII plat, Markdown tables, and a Mermaid graph.
- **CLI**: `scan`, `diff`, `log`, `show`, `verify`, `daemon`, `scanners`,
  `init`, `validate`, `banner`, with `--json`, `--redact`, `--output`,
  `--exit-code` (3 = structure changed), and `--no-save`.
- **Configuration**: TOML (default), JSON, optional YAML, environment overrides,
  and a `surveyor init` writer. Zero runtime dependencies.
- **Documentation**: the OET 1.0 specification, a JSON Schema, an architecture
  note covering the failure model and ledger internals, a sample plat, example
  config, systemd and launchd units, and CI on macOS and Linux.
- **A new banner.** The old block-letter wordmark is replaced by a levelled
  theodolite on a tripod, sighting a four-node graph: *plat no. 007, not to
  scale*.

### Changed

- README rewritten around what the software actually does, with real output,
  the core loop, and the guarantees (read-only, idempotent, verifiable).
- Field parsers are pure functions so they can be tested without a host.

### Fixed

- Fingerprints are independent of edge insertion order; previously a document
  could fail its own validation after a round trip.
- Scanner bootstrap no longer hides built-ins when a single scanner module is
  imported first.
