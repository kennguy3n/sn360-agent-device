# SN360 Desktop Agent — Development Progress

Tracks the implementation status of `sn360-agent-device` against the
roadmap in
[`docs/device-agent-proposal.md`](./docs/device-agent-proposal.md) §12.

Status legend:

- **Done** — merged to `main` and covered by tests / benchmarks below.
- **In Progress** — branch exists, code is being written / reviewed.
- **Not Started** — no implementation work started yet.

## Current Status

Phases 1–6 are complete. `cargo test --all` shows
**433 passing / 0 failed**, the base E2E harness passes
**14/14** assertions against a local reference SIEM manager, and
the security E2E suite passes **10/10** attack-scenario checks.
All four proposal benchmark targets (idle RSS, idle CPU, binary
size, FIM scan peak CPU) continue to be met — see
[`docs/benchmark-results.md`](./docs/benchmark-results.md).

Server-side SN360 Control Plane microservices (TRDS, IOCFS, SIS,
Agent Gateway) are **out of scope** for this repository and are
implemented in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
Future work (Phases 7–9) is tracked in
[`docs/revised-phase-plan.md`](./docs/revised-phase-plan.md);
high-level phase status is summarized in the table below.

The only Phase 6 items not drivable from this repo are the beta
tag (`v0.9.0-beta.1`) and signed-binary publication, which need
release credentials and signing keys outside this session.

## Phase 1 — Core Plumbing (7/7) — Done

Workspace + crate skeleton, structured YAML config loading, legacy
SIEM enrollment + transport adapter (TCP/UDP + Blowfish), keepalive
loop, event bus with priority queues, and clean shutdown signalling
are all on `main`.

## Phase 2 — Detection Modules (9/9) — Done

FIM (inotify / `ReadDirectoryChangesW` / FSEvents), log collection
(file tailing, journald, Windows EventLog, OSLog), syscollector-
compatible inventory, active response, SCA YAML policy evaluation,
and rootcheck signatures / hidden-process / binary-integrity drift
are all on `main`.

## Phase 3 — Gap-fill (3/3) — Done

Server message receive loop parses `#!-execd` / `#!-req` /
`#!-up_file` tags, SCA module is wired into the agent main loop
with periodic policy evaluation, and rootcheck detection logic is
wired into `RootcheckModule::start()`.

## Phase 4 — Edge Detection, Software Inventory & Tenant Rule Distribution — Done (agent-side)

LDE rule store + mmap loader, Aho-Corasick + IOC bloom matcher,
behavioural rule state machines, local response dispatcher, YARA
scanner, offline detection queue + server sync, and enhanced
inventory (running software, browser extensions, CycloneDX SBOM)
are all on `main`. Companion microservices (TRDS / IOCFS / SIS /
Agent Gateway) and the agent ↔ TRDS rule pull are tracked in
[`docs/revised-phase-plan.md`](./docs/revised-phase-plan.md) §
Phase 7 and live in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

## Phase 5 — Platform Hardening (4/4) — Done

| Deliverable | PR |
|---|---|
| Self-update module (signed manifest + rollback) | [#49](https://github.com/kennguy3n/sn360-agent-device/pull/49) |
| Privilege separation (drop-privileges, minimal caps per module) | [#50](https://github.com/kennguy3n/sn360-agent-device/pull/50) |
| Tamper protection (binary / config / keys integrity + watchdog) | [#50](https://github.com/kennguy3n/sn360-agent-device/pull/50) |
| Installers — `.deb`, `.rpm`, `.pkg`, `.msi`, hardened systemd unit | [#48](https://github.com/kennguy3n/sn360-agent-device/pull/48) |

## Phase 5.6 — Enhanced Protocol (5/5) — Done

TLS 1.3 transport (`sda_comms::transport::tls`), MessagePack
serialisation (`MessagePackSerializer`), HTTP/2 transport with ALPN
`h2`, `server.enhanced.{tls,serialization,transport,...}` config
surface, and unit tests covering MessagePack round-trip, TLS
construction + pinning, HTTP/2 ALPN, and legacy-protocol fallback.
Initial PR [#55](https://github.com/kennguy3n/sn360-agent-device/pull/55);
review fixes PR
[#56](https://github.com/kennguy3n/sn360-agent-device/pull/56).

## Phase 6 — Testing & Release (6/6) — Done

| # | Task | Status |
|---|------|--------|
| 6.1 | E2E vs a reference SIEM manager (`make e2e` v4.9.2; `make e2e-compat` v4.7.5) | Done |
| 6.2 | Platform testing — CI matrix on `ubuntu-22.04` / `24.04`, `macos-13` / `14`, `windows-2022` | Done |
| 6.3 | Performance regression — `tests/scripts/benchmark-regression.sh` + hard thresholds | Done |
| 6.4 | `cargo audit --deny warnings` + `cargo-fuzz` harness | Done |
| 6.5 | User / admin / architecture / config-reference docs | Done |
| 6.6 | Release workflow + nightly fuzz + runbook (tag push + artefact signing remain credentialed) | Done |

## Tests & Benchmarks

`cargo test --all` — **433 passing / 0 failed**. Base E2E harness
14/14, security E2E 10/10. Latest test environment, raw output,
and historical runs live in
[`TEST_RESULTS.md`](./TEST_RESULTS.md). Headline benchmark numbers
vs. proposal targets live in
[`docs/benchmark-results.md`](./docs/benchmark-results.md); all
four metrics (idle RAM, idle CPU, binary size, FIM scan peak CPU)
are within target.

## Continuous Integration

The CI matrix runs `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all`, `cargo audit --deny warnings`, and the
benchmark regression script on every PR across the five OS / arch
combinations above. The `nightly-fuzz` job runs each of the four
`cargo-fuzz` targets (`protocol_decode`, `protocol_decompress`,
`msgpack_event_decode`, `rule_store_msgpack`) for 5 minutes on
every cron tick.

## Known Gaps

1. **macOS FIM burst test permanently skipped on CI** — mitigated,
   not fixed. The runtime-starvation bug is fixed (multi-thread
   runtime + `spawn_blocking`) but the underlying kqueue drop on
   GitHub-hosted `macos-latest` runners persists, so the test
   keeps its `#[cfg_attr(target_os = "macos", ignore)]`
   annotation. It can still be forced locally with
   `cargo test -p sda-fim --test burst_workload -- --include-ignored`.
   See
   [`docs/known-issues/fim-burst-workload-macos-ci.md`](./docs/known-issues/fim-burst-workload-macos-ci.md).
2. **Server-side microservices excluded from this repo** — TRDS,
   IOCFS, SIS, and the Agent Gateway live in
   [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform),
   not this repository. Phase 4.10–4.14 are marked Out of Scope.

## Next Steps

1. Finalise `[Unreleased]` in
   [`CHANGELOG.md`](./CHANGELOG.md) under a fresh version
   section in the release PR.
2. `git tag -s v0.9.0-beta.1 -m "Beta 1 release"` and push; the
   release workflow runs automatically.
3. Sign / notarise the artefacts per
   [`docs/release-process.md`](./docs/release-process.md)
   (macOS Developer ID + notarisation, Windows EV code-sign,
   Linux `.deb` / `.rpm` repo key).
4. Replace the unsigned artefacts on the draft release with the
   signed ones, regenerate `SHA256SUMS`, and promote the draft to
   a published release.
5. Begin Phase 7 (SN360 native protocol promotion + Control Plane
   MVP) per
   [`docs/revised-phase-plan.md`](./docs/revised-phase-plan.md).
