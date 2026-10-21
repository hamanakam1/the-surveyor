# The Surveyor

```text
SSSSS U   U RRRR   V   V EEEEE Y   Y  OOO  RRRR
S     U   U R   R  V   V E     Y   Y O   O R   R
SSSSS U   U RRRR   V   V EEE    Y Y  O   O RRRR
    S U   U R  R    V V  E       Y   O   O R  R
SSSSS  UUU  R   R     V   EEEEE   Y    OOO  R   R
```

**Autonomous systems analyst for the Open Edge Topology (OET) standard.**

> *Infrastructure is empirical. The Surveyor reverse-engineers the truth.*

## Purpose

The Surveyor abandons manual documentation in favor of autonomous discovery. It constantly polls the live physical environment, reverse-engineers the true state into a mathematically perfect OET map, uses a local LLM to translate changes into human-readable documentation, and commits everything to EdgeRecord.

## The Open Edge Topology (OET) Standard

OET is an open-source, multi-dimensional JSON/YAML standard that maps the exact DAG of:
- **Power** - Solar charge controllers, batteries, UPS, discharge rates
- **Bare Metal** - CPUs, RAM, thermals, architecture
- **Network** - UniFi topology, VLANs, switch ports, congestion
- **Workloads** - Docker containers, images, ports, volumes, Ollama endpoints
- **Relationships** - Edges connecting all of the above

## Core Loop

1. **Multi-Vector Discovery** - Poll power/thermals, bare metal, network, and workloads concurrently
2. **Topological Compilation** - Aggregate into LiveTopologyGraph, diff against last known state
3. **Autonomous Scribe** - Local LLM generates changelog entries for structural shifts
4. **Cryptographic Commit** - Hash and push to EdgeRecord

## Design Principles

- **Empirical, not declarative** - Maps what *is*, not what we *want*
- **Local-first** - All AI via Ollama, no cloud SDKs
- **Idempotent** - Only acts on structural changes
- **Strategy pattern** - Pluggable scanners for new hardware
- **Read-only observer** - Never modifies infrastructure, only documents it

## Status

Early scaffolding - architecture design phase.
