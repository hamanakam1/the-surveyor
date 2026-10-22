# Architecture

The Surveyor is a pipeline with one mutable side effect (the ledger) and no
authority over the machine it surveys. Everything else is a pure function over
observed facts, which is why the tests are fast and why a broken probe cannot
corrupt a recorded plat.

## Data flow

```text
                      surveyor scan ── surveyor diff ── surveyor daemon
                                    │
                     ┌──────────────▼───────────────┐
                     │ compiler.survey()            │
                     │  · run scanners concurrently │
                     │  · per-scanner time budget   │
                     │  · merge, prune, stamp       │
                     └───┬──────────────────────┬───┘
                         │                      │
        ┌────────────────▼──────┐        ┌──────▼─────────┐
        │ scanners/             │        │ redact.py      │
        │  power    host        │        │ (optional)     │
        │  network  workloads   │        └──────┬─────────┘
        │  services             │               │
        └────────────┬──────────┘               │
                     │                          │
              ┌──────▼──────┐                   │
              │ probe.py    │                   │
              │ allowlist   │                   │
              │ timeouts    │                   │
              │ scrubbed env│                   │
              └─────────────┘                   │
                                                ▼
                                     ┌────────────────────┐
                                     │ model.Topology     │
                                     │  fingerprint (shape)│
                                     │  digest (document) │
                                     └───┬────────────┬───┘
                                         │            │
                            differ.py ◄──┘            └──► store.Ledger
                            │                              (objects + chain)
                            ▼
                    scribe.py ──► changes/NNNN-<digest>.md
                    │
                    ├──► notify.py ──► Slack / Discord / ntfy / JSON webhook
                    │
                    └──► render.py (ASCII / Markdown / Mermaid)

        fleet.py composes many plats into one map; doctor.py says what this
        machine lets the Surveyor see. Neither writes anything.
```

## Modules

| Module | Responsibility | Writes anything? |
| --- | --- | --- |
| `probe.py` | run allowlisted read-only commands, capped and timed out | no |
| `scanners/*` | observe one dimension, emit nodes and edges | no |
| `compiler.py` | run scanners, merge, validate, stamp observations | no |
| `model.py` | OET objects, identity, fingerprint, canonical serialisation | no |
| `differ.py` | severity-classified structural diff | no |
| `redact.py` | identifier masking for publishable plats | no |
| `sensitivity.py` | the declared inventory of what an identifier is | no |
| `validation.py` | the OET contract, enforced in code | no |
| `scribe.py` | deterministic changelog, optional local-model rewrite | no |
| `render.py` | ASCII map, Markdown tables, Mermaid graph | no |
| `fleet.py` | compose many hosts into one map | no |
| `doctor.py` | diagnose what this machine lets the Surveyor see | no |
| `store.py` | content-addressed objects, hash-chained journal, redaction key | **yes** (ledger only) |
| `daemon.py` | schedule, instance lock, signal handling | **yes** (via store) |
| `cli.py` | argument parsing, exit codes, output | **yes** (via store) |

## Failure model

Three concentric promises:

1. **A scanner never kills a survey.** Each scanner runs in its own thread and
   is wrapped by `ScannerSpec.run`; exceptions become a failed `ScanResult`
   with `ok: false`. The plat still gets everything the other scanners saw.
2. **A probe never kills a scanner.** `probe.run` converts missing binaries,
   permission errors, and timeouts into failed probes. Scanners translate those
   into `notes`, which land in `observations.warnings`.
3. **A daemon never dies on a bad cycle.** The loop records the cycle's result
   and continues; only a ledger-level failure (unwritable store) is fatal.

The one thing that is not best-effort is **integrity**: if an object's bytes do
not hash to its name, `get` and `verify` refuse it rather than serving a
plausible lie.

## Ledger layout

```text
~/.surveyor/ledger/
├── objects/
│   └── 94/94f4b2e6….json     canonical OET document; name == sha256(bytes)
├── journal.jsonl             append-only entries; each names its parent digest
├── HEAD                      pointer to the newest entry
├── changes/
│   └── 0000-94f4b2e6037a.md  scribe output for that survey
├── daemon.lock               non-blocking instance lock
├── salt                      the ledger's redaction key, owner-read only
└── lock                      writer lock for commits
```

An entry is:

```json
{
  "seq": 0,
  "recorded_at": "2026-10-22T06:56:59Z",
  "digest": "sha256:94f4…",
  "fingerprint": "sha256:3d27…",
  "parent": "genesis",
  "site": "edge",
  "counts": {"nodes": 20, "edges": 19},
  "note": "",
  "entry_digest": "sha256:1f0c…"
}
```

`entry_digest` is the digest of the entry *without* it. Editing any field, or
deleting an entry, breaks the chain and `surveyor verify` says so. `parent`
being the previous `entry_digest` (not seq) means entries cannot be reordered
either.

## Concurrency

- Scanners fan out through `ThreadPoolExecutor` at eight workers; the whole fan
  out has a `scanner_timeout + 5s` deadline. Scanners that overrun are recorded
  as timed out and the survey proceeds.
- Commits take an exclusive `flock` on the ledger's `lock` file, so two
  processes cannot interleave a HEAD read and a journal append.
- Notifications are sent after the journal entry is written, never before, so a
  webhook failure cannot lose a survey. Delivery failures are reported and
  dropped; they never propagate into the survey path.
- The daemon takes a non-blocking `flock` on `daemon.lock`; a second daemon
  exits with a clear message instead of doubling the cadence.

## Why facts and telemetry are separate types

Idempotence is not a nicety here. At a five-minute cadence, a naive
"hash the whole snapshot" design commits 288 entries a day and narrates load
averages forever. Splitting structure from weather makes the interesting signal
survive:

```text
19:00  nginx:1.25 -> nginx:1.27        ← structural, recorded, narrated
19:05  load 1.7 -> 2.4                 ← telemetry, recorded as drift only
19:10  nothing moved                   ← no journal entry at all
```

## Testing strategy

| Layer | How it is tested |
| --- | --- |
| Parsers | recorded command output, no host access |
| Scanner output | the *complete* node and edge set, so a changed OS output cannot add or drop a node unnoticed |
| Diff/scribe | fabricated plats, deterministic assertions |
| Redaction | one plat carrying every identifier shape the scanners emit, and an assertion that none survives |
| Schema | a conformance suite: one broken document per rule, each rejected for its own reason |
| Ledger | real filesystem in `tmp_path`, including tamper cases |
| Daemon | a bad cycle and an unwritable ledger, in a temp directory |
| CLI | stubbed `survey()` and a temporary `SURVEYOR_HOME` |
| CI | a real survey on macOS and Linux runners, validated against the schema |

The suite needs no network and sleeps only where a timeout is the thing
under test, so it runs in well under half a minute.

Three things are checked in CI that a unit test cannot do: the whole survey
of a real runner must be a valid plat, the committed schema must match the
one the model generates, and the code must pass `ruff` and `mypy`.
