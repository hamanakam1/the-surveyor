# Security

## Posture

The Surveyor is a **read-only observer**. It does not configure, restart,
install, or delete anything on the machine it surveys. It writes only inside its
own ledger directory (`~/.surveyor` by default, or `--store`).

That promise is enforced in code, not just documented:

- **Command allowlist.** `probe.ALLOWED_PROGRAMS` names every executable the
  scanners may run (`sysctl`, `pmset`, `ioreg`, `ifconfig`, `ip`, `route`,
  `lsof`, `ss`, `docker ps`, `sw_vers`, `uname`, `ps`, `networksetup`, …).
  Shells, `sudo`, and scripting bridges are rejected before a process is
  created. The list is *least privilege*: a program is on it because a
  scanner calls it, and a test fails if an allowlisted program has no caller.
- **Absolute paths, not names.** The allowlist is matched on the program's
  basename, but the program that actually runs is resolved to an absolute
  path in a curated search path (`/usr/local/bin`, `/usr/sbin`, `/usr/bin`,
  `/sbin`, `/bin`, and the Homebrew prefixes). The inherited `PATH` is only
  consulted for directories nobody else can write to. A program that
  resolves into a world-writable directory is refused.
- **No shell.** Commands are argument vectors passed with `shell=False`.
- **Scrubbed environment.** Variables whose names contain `TOKEN`, `SECRET`,
  `PASSWORD`, `PASSWD`, `KEY`, `CREDENTIAL`, `SESSION`, or `AUTH` are removed
  from child processes, so a survey cannot leak credentials into logs or
  subprocesses. This covers `AWS_ACCESS_KEY_ID` and `SSH_AUTH_SOCK`, which
  the previous marker list missed.
- **Bounded execution.** Every probe has a timeout, output is capped at 2 MB,
  and each scanner runs inside a total time budget. A probe that overruns
  has its **whole process group** killed, so it cannot leave grandchildren
  behind.

### What this is not designed for

The Surveyor reads a machine the operator already controls. It is not built
to survive a *hostile* host — a rootkit that can lie about `sysctl` output
will fool it, and a rootkit that can replace `/usr/bin/sysctl` will fool it
too. The hardening above is about accidents, shadowing, and credential
leakage, not about adversary-controlled machines.


## Data handling

A plat can contain hostnames, MAC addresses, serial numbers, IP addresses,
interface names, container images, container names, model names, and the names
of local models and listening processes. Treat an unredacted plat as
**internal** data.

Use `--redact` (or `redact = true`) before publishing a plat. Redaction is
driven by a declared inventory of identifiers
(`src/surveyor/sensitivity.py`), not by guesswork, and it covers:

- hostnames — in facts, in labels, in observations, **and in node ids**,
- container names, compose project and service names,
- local model names, image registry owners, container ids, model digests,
- serial numbers, UUIDs, machine ids, board ids, Wi-Fi SSIDs,
- listener process names,
- MAC addresses (vendor prefix kept) and globally routable IPv4 and IPv6
  addresses (host bits removed).

Private, loopback and link-local addresses are preserved because the map is
useless without them. Hardware model, CPU model, ports, versions and counts
are preserved because they describe the class of machine rather than the
machine.

### Aliases are keyed

An alias is a digest of the name **and a secret key** stored in `salt` beside
the ledger, readable only by its owner. This matters: an unkeyed digest of a
low-entropy value such as a hostname or a container name can be reversed by
hashing a word list, which would make redaction a speed bump rather than a
protection. With a key, the same name always produces the same alias within
one ledger — so redacting twice does not churn the map — and a different alias
in every other ledger, so two redacted plats cannot be correlated by their
aliases.

Because redaction rewrites node ids (a hostname is part of a node id), do
**not** cross-reference a redacted plat and an unredacted plat by node id.
The mapping is deterministic but it is not the identity.

### Audit before publishing

`surveyor redact FILE --audit` reports every identifier that survived
redaction: a declared identifier that failed to be removed (a defect), and a
value that merely looks like an identifier — an email address, a home
directory, a long hex digest. The second kind is a question for the operator.
The command exits non-zero when it finds anything, so it can gate a publish.

Ledger objects are stored unencrypted. Protect the directory with filesystem
permissions; the bundled systemd unit runs as an unprivileged user with a
read-only view of the rest of the system. The `salt` file is created with
owner read/write only.


## Webhooks are credentials

A webhook URL is a bearer token: anyone holding it can post to your chat. The
Surveyor therefore masks endpoints everywhere they might be printed -- output,
logs, error messages -- showing only the host, never the path.

Prefer the environment over the config file:

```bash
export SURVEYOR_NOTIFY="https://hooks.slack.com/services/T00/B00/xxxx"
```

rather than writing the URL into `config.toml`, which is a file you will
eventually commit. `surveyor notify --dry-run` prints the payload without
sending anything, so you can confirm the shape without exposing the endpoint.

Notifications carry the same facts as a changelog: site name, severity, the
changed nodes, and the plat fingerprint. With `redact = true` the identifiers
in those notifications are masked exactly as they are in the recorded plat.

## Optional local model

`scribe = "ollama"` sends the diff's *facts* and the deterministic draft to the
configured endpoint (loopback by default) so a local model can rewrite the
opening paragraph. No other data leaves the machine, and the deterministic
changelog is written even when the model is unavailable. Pointing
`ollama_endpoint` at a remote host is an explicit operator choice and should be
treated as data egress.

## Reporting

Open a private security advisory on the repository, or email the maintainer
listed in `pyproject.toml`. Please include the version (`surveyor --version`),
the platform, and the smallest reproduction you can manage. Do not attach a real
unredacted plat.
