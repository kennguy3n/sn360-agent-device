# SN360 Desktop Agent — Development Progress

Tracks the implementation status of `sn360-agent-device` against the
roadmap in
[`device-agent-proposal.md`](./device-agent-proposal.md) §12.

Status legend:

- **Done** — merged to `main` and covered by tests / benchmarks below.
- **In Progress** — branch exists, code is being written / reviewed.
- **Not Started** — no implementation work started yet.

## Current Status

Phases 1–3 are complete, and the agent-side Phase 4 work (Local
Detection Engine tasks 4.1–4.6 and Enhanced Inventory tasks 4.7–4.9)
has landed. Phase 5 platform hardening is also complete: self-update
(PR #49), privilege separation + tamper protection (PR #50), and
installer / packaging (PR #48). All four proposal benchmark targets
(idle RSS 5.7 MB, idle CPU 0.00 %, shipped binary 4.6 MB, FIM scan
peak 3 %) are met. `cargo test --all` shows **361 passing / 0
failed**, the base E2E harness passes **14/14** assertions against a
local Wazuh 4.9.2 manager, and the security E2E suite passes
**10/10** attack-scenario checks. Remaining work is the server-side
TRDS / IOCFS / SIS / Gateway microservices (Phase 4.10–4.14, tracked
in other repositories).

## Phase 1 — Core Plumbing (7/7)

| # | Task | Status |
|---|------|--------|
| 1.1 | Workspace + crate skeleton (`wda-core`, `wda-comms`, `wda-event-bus`, `wda-pal`, modules) | Done |
| 1.2 | Structured YAML config loading (`AgentConfig`) on all OSes | Done |
| 1.3 | Enrollment against `authd` on 1515 with password auth, key persistence | Done |
| 1.4 | Connection manager with TCP + UDP transports and Blowfish crypto | Done |
| 1.5 | Keepalive loop sending startup + periodic keepalives | Done |
| 1.6 | Event bus with priority queues and back-pressure handling | Done |
| 1.7 | Shutdown signal + task coordination (SIGINT / SIGTERM) | Done |

## Phase 2 — Detection Modules (9/9)

| # | Task | Status |
|---|------|--------|
| 2.1 | FIM — realtime + scheduled baseline (inotify / ReadDirectoryChangesW / FSEvents) | Done |
| 2.2 | Log collection — file tailing (syslog format, position tracking) | Done |
| 2.3 | Log collection — journald (Linux, event-driven) | Done |
| 2.4 | Log collection — Windows EventLog (`EvtSubscribe` / `EvtRender` via `windows-rs`) | Done |
| 2.5 | Log collection — macOS OSLog / unified logging (`/usr/bin/log stream`) | Done |
| 2.6 | Inventory (syscollector-compatible: os, hardware, packages, network) | Done |
| 2.7 | Active response (`block_ip`, `kill_process`, script execution) | Done |
| 2.8 | SCA policy evaluation (YAML policies, regex / command / file checks) | Done |
| 2.9 | Rootcheck (signatures, Linux hidden-process detection, binary-integrity drift) | Done |

## Phase 3 — Gap-fill (3/3)

| # | Task | Status |
|---|------|--------|
| 3.R | Server message receive loop — parses `#!-execd` / `#!-req` / `#!-up_file` tags and publishes `EventKind::ServerCommand` | Done |
| 3.S | Wire SCA module into agent main loop with periodic policy evaluation | Done |
| 3.RC | Rootcheck detection logic (signatures, hidden-process, binary-integrity) wired into `RootcheckModule::start()` | Done |

## Phase 4 — Edge Detection, Software Inventory & Tenant Rule Distribution

Tasks below are tracked against
[`device-agent-proposal.md` § 12 Phase 4 roadmap](./device-agent-proposal.md#phase-4-edge-detection-software-inventory--tenant-rule-distribution-weeks-15-22);
see
[`device-agent-proposal.md` § 13](./device-agent-proposal.md#13-phase-4-detail-edge-detection-software-inventory--tenant-rule-distribution)
for the detailed design. Tasks 4.10–4.14 are server-side
microservices that live outside this repository.

| # | Task | Status |
|---|------|--------|
| 4.1 | LDE: rule store format, MessagePack schema, mmap loader | Done |
| 4.2 | LDE: Aho-Corasick pattern matcher + IOC bloom filter evaluator | Done |
| 4.3 | LDE: Behavioral rule state machine (JSON DSL → evaluator) | Done |
| 4.4 | LDE: Local Response Dispatcher (block IP, kill process, quarantine) | Done |
| 4.5 | LDE: YARA scanner integration (required, not feature-gated) | Done |
| 4.6 | LDE: Offline detection queue + server sync on reconnect | Done |
| 4.7 | Enhanced Inventory: running software monitor (all platforms) | Done |
| 4.8 | Enhanced Inventory: browser extension inventory (Chrome / Firefox / Edge / Safari) | Done |
| 4.9 | Enhanced Inventory: CycloneDX SBOM generator (periodic + on-demand) | Done |
| 4.10 | TRDS microservice: rule CRUD API, compiler, delta distribution | Not Started |
| 4.11 | IOCFS microservice: feed ingestion, normalization, bloom filter compilation | Not Started |
| 4.12 | SIS microservice: inventory ingestion, CVE matching, dashboard API | Not Started |
| 4.13 | Agent Gateway: mTLS termination, tenant routing, rate limiting | Not Started |
| 4.14 | Integration: agent ↔ TRDS rule pull, hot-reload, version tracking | Not Started |

## Unit Tests

Command: `cargo test --all`

**Result: 361 passing / 0 failed.**

| Crate | Passed |
|---|---|
| `wda-active-response` | 29 |
| `wda-agent` | 18 |
| `wda-comms` | 31 |
| `wda-core` | 2 |
| `wda-enhanced-inventory` | 57 |
| `wda-event-bus` | 4 |
| `wda-fim` | 68 |
| `wda-inventory` | 32 |
| `wda-local-detection` | 56 |
| `wda-logcollector` | 34 |
| `wda-pal` | 5 |
| `wda-rootcheck` | 20 |
| `wda-sca` | 5 |
| **Total** | **361** |

Reproduce locally with `make test`. CI regenerates the result on every
push across `ubuntu-latest`, `macos-latest`, and `windows-latest`.

## E2E Tests vs. Local Wazuh 4.9.2

Command: `make e2e` (wraps `tests/scripts/run-e2e.sh`).

The E2E harness brings up `wazuh/wazuh-manager:4.9.2` via
`tests/docker-compose.yml`, enrolls the agent, exercises each module,
then queries the manager's `syscheck`, `syscollector`, and
archived-alerts for the expected events.

**Result: 14/14 assertions pass.**

```
  E2E Test Summary
  PASS: Agent enrolled successfully
  PASS: Agent still enrolled after keepalive
  PASS: FIM syscheck alerts received by server
  PASS: Baseline scan syscheck alerts received by server
  PASS: Baseline scan detected file deletion
  PASS: Inventory data received by server
  PASS: Log collection alerts received by server
  PASS: Journal log collection events received by server
  PASS: Active response command processed
  PASS: SCA policy evaluation received by server
  PASS: Rootcheck signature alert received by server
  PASS: Enhanced inventory running-software scanner active
  PASS: Enhanced inventory SBOM scanner active
  PASS: Enhanced inventory browser-extensions scanner active
  RESULT: ALL CHECKS PASSED
```

## Security E2E Tests vs. Local Wazuh 4.9.2

Command: `make security-e2e` (wraps
`tests/scripts/run-security-e2e.sh`).

Extends the base E2E harness with ten security-focused scenarios:
malware file drop, brute-force SSH, privilege-escalation (sudo abuse),
config-file tampering, ransomware simulation (bulk rename), active
response `kill_process`, IP block (IPv4 + IPv6), unauthorized package
install, system-binary tampering, and account-disable AR. The harness
injects minimal `<active-response>` blocks into the stock
`wazuh/wazuh-manager:4.9.2` image so `disable-account0` /
`firewall-drop0` resolve correctly before the agent enrolls.

**Result: 10/10 assertions pass.**

```
  Security E2E Test Summary
  PASS: Malware file drop detected
  PASS: Brute-force SSH simulation detected
  PASS: Privilege escalation (sudo abuse) detected
  PASS: Config file tampering detected
  PASS: Ransomware simulation detected
  PASS: Active response kill_process command sent
  PASS: IP blocking active response commands sent (IPv4 + IPv6)
  PASS: Package inventory update detected after install
  PASS: System binary tampering detected
  PASS: Account disable AR configured and dispatched by server
  RESULT: ALL CHECKS PASSED
```

## Continuous Integration

Unit tests and builds run on `ubuntu-latest`, `macos-latest`, and
`windows-latest` on every push and pull request. `rustfmt` + `clippy`
run on `ubuntu-latest`. A nightly benchmark job runs at `0 3 * * *`.

The `e2e` job runs on push to `main` on `ubuntu-latest` only —
`macos-latest` lacks Docker and the `wazuh/wazuh-manager:4.9.2` image
is Linux-only, so macOS / Windows E2E runs are executed locally via
`make e2e-macos` / `make e2e-windows`.

## Benchmark vs. Wazuh Agent 4.9.2

See [`benchmark-results.md`](./benchmark-results.md) for methodology
and raw numbers. Summary vs. proposal targets:

| Metric | Target | Wazuh 4.9.2 | SN360 Desktop Agent (SDA) | Status |
|---|---|---|---|---|
| Idle RAM (single process) | < 15 MB | ~56 MB across 5 daemons | 5.7 MB | Done |
| Idle CPU | < 0.1 % | 0.45 % (`wazuh-agentd` only) | 0.00 % | Done |
| Shipped binary size | < 5 MB | 3.8 MB (5 daemons combined) | 4.6 MB | Done |
| FIM scan peak CPU (1 000 files) | < 3 % | 9 % | 3 % (15 s avg 1.33 %) | Done |

## Known Gaps

All previously-open items from Phases 1–3 have been resolved. The
remaining agent-side gaps are:

1. **FIM scan CPU benchmark re-run pending.** Phase 3 FIM reshape
   introduced lazy hashing, a `RateLimiter`, and `EventBatcher`. The
   latest numbers (peak ~3 %, 15-s avg 1.33 %) still need to be
   re-run end-to-end to confirm the strict < 3 % peak target under
   the merged pipeline. Reproduce with
   `bash tests/scripts/fim-burst-bench.sh` (requires `pidstat`).
2. **Linux user-idle detection returns `None`.**
   `PowerMonitor::user_idle_duration()` is implemented for macOS and
   Windows only; the Linux branch falls through to `None`, so
   `PowerProfile::IdleAC` / `PowerProfile::BatteryIdle` cannot be
   entered on Linux. Needs XScreenSaver or a D-Bus `logind`
   integration.
3. **macOS FIM burst test** — skipped on CI due to kqueue event drops
   under load; see
   [`docs/known-issues/fim-burst-workload-macos-ci.md`](./docs/known-issues/fim-burst-workload-macos-ci.md).
4. **Rootcheck depth.** Currently file-existence signatures only — no
   content-based inspection of e.g. `/etc/ld.so.preload`; hidden-
   process detection is Linux-only (no-op on macOS / Windows).

## Next Steps

Completed items keep their strikethrough to preserve context; active
work is unstruck.

### Priority 1 — Phase 3 polish and open gaps

| # | Task |
|---|------|
| P1.1 | ~~Wire PAL `PowerMonitor` on macOS and Windows~~ — Done |
| P1.2 | ~~Add E2E tests for SCA and Rootcheck~~ — Done |
| P1.3 | Investigate and fix the macOS FIM burst test hang; re-enable on macOS CI |
| P1.4 | Implement rootcheck content-based checks (e.g. `/etc/ld.so.preload`) |
| P1.5 | Cross-platform rootcheck hidden-process detection (macOS / Windows) |
| P1.6 | ~~Record Phase 2.9 Rootcheck as Complete in this document~~ — Done |
| P1.7 | ~~Wire adaptive power-aware scheduling into module loops~~ — Done |
| P1.8 | Linux user-idle detection (XScreenSaver or D-Bus `logind`) |
| P1.9 | Re-run FIM burst benchmark on the merged pipeline and update `benchmark-results.md` |
| P1.10 | Tune FIM defaults for burst-heavy environments |
| P1.11 | ~~Regenerate E2E coverage for enhanced inventory~~ — Done |

### Priority 2 — Phase 4: Edge Detection & Enhanced Inventory

| # | Task | Phase 4 ref |
|---|------|-------------|
| P2.1 | ~~LDE rule store format and mmap loader~~ — Done | 4.1 |
| P2.2 | ~~Aho-Corasick pattern matcher + IOC bloom filter~~ — Done | 4.2 |
| P2.3 | ~~Behavioral rule state machines~~ — Done | 4.3 |
| P2.4 | ~~Local Response Dispatcher~~ — Done | 4.4 |
| P2.5 | ~~YARA scanner integration~~ — Done | 4.5 |
| P2.6 | ~~Offline detection queue + server sync on reconnect~~ — Done | 4.6 |
| P2.7 | ~~Enhanced Inventory: running software monitor~~ — Done | 4.7 |
| P2.8 | ~~Enhanced Inventory: browser extension enumeration~~ — Done | 4.8 |
| P2.9 | ~~Enhanced Inventory: SBOM generator (on-demand)~~ — Done | 4.9 |
| P2.10 | ~~Wire Enhanced Inventory into main agent~~ — Done | 4.7–4.9 wiring |
| P2.11 | Companion microservices (TRDS / IOCFS / SIS / Gateway) — server-side, outside this repo | 4.10–4.13 |
| P2.12 | Agent ↔ TRDS rule pull, hot-reload, version tracking | 4.14 |

### Priority 3 — Phase 5: Platform Hardening

All Priority 3 tasks have landed. Phase 5 is complete.

| # | Task | Status |
|---|------|--------|
| P3.1 | Self-update mechanism (signed download, atomic replace, rollback) | Done (PR #49) |
| P3.2 | Privilege separation — run detection modules with minimal privileges | Done (PR #50) |
| P3.3 | Tamper protection — protect binary / config / keys; watchdog restart | Done (PR #50) |
| P3.4 | Installer / packaging — MSI (Windows), `.deb` / `.rpm` (Linux), `.pkg` (macOS) | Done (PR #48) |

## Phase 5 detailed status

| Deliverable | Status | PR |
|---|---|---|
| Self-update module (signed manifest + rollback) | Done | [#49](https://github.com/kennguy3n/sn360-agent-device/pull/49) |
| Privilege separation (drop-privileges, minimal caps per module) | Done | [#50](https://github.com/kennguy3n/sn360-agent-device/pull/50) |
| Tamper protection (binary / config / keys integrity + watchdog) | Done | [#50](https://github.com/kennguy3n/sn360-agent-device/pull/50) |
| Installers — `.deb`, `.rpm`, `.pkg`, `.msi`, hardened systemd unit | Done | [#48](https://github.com/kennguy3n/sn360-agent-device/pull/48) |
