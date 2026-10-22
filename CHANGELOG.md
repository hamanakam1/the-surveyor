# Changelog

All notable changes to The Surveyor. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

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
