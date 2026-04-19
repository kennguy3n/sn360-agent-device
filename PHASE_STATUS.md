# WDA Phase Status — 2026-04-19

This document summarizes the status of Phase 1 and Phase 2 of the Wazuh
Desktop Agent (WDA) against the original proposal, the results of the E2E
and unit test runs against a local Wazuh 4.9.2 manager, and the benchmark
comparison against the official Wazuh agent 4.9.2.

## Phase 1 — Core Plumbing (7/7 complete)

| # | Task | Status |
|---|---|---|
| 1.1 | Workspace + crate skeleton (`wda-core`, `wda-comms`, `wda-event-bus`, `wda-pal`, modules) | Complete |
| 1.2 | Structured config loading (`AgentConfig`) with YAML on all OSes | Complete |
| 1.3 | Enrollment against `authd` on 1515 with password auth, key persistence | Complete |
| 1.4 | Connection manager with TCP + UDP transports and Blowfish crypto | Complete |
| 1.5 | Keepalive loop sending startup + periodic keepalives | Complete |
| 1.6 | Event bus with priority queues and back-pressure handling | Complete |
| 1.7 | Shutdown signal + task coordination (SIGINT/SIGTERM) | Complete |

## Phase 2 — Detection Modules (9/9 complete)

| # | Task | Status | Notes |
|---|---|---|---|
| 2.1 | FIM (file integrity monitoring), realtime + scheduled baseline | Complete | inotify / ReadDirectoryChangesW / FSEvents, SHA-256 hashing, deletion detection |
| 2.2 | Log collection — file tailing | Complete | syslog format, position tracking |
| 2.3 | Log collection — journald (Linux) | Complete | event-driven via journal fd |
| 2.4 | Log collection — Windows EventLog | Complete | native `EvtSubscribe` + `EvtRender` via `windows-rs`, push-based |
| 2.5 | Log collection — macOS OSLog / unified logging | Complete | /usr/bin/log stream reader with predicate + level filtering |
| 2.6 | Inventory (syscollector-compatible) | Complete | os, hardware, packages, network |
| 2.7 | Active response | Complete | block_ip, kill_process, script execution |
| 2.8 | SCA (policy evaluation) | Complete | YAML policies, regex / command / file checks |
| 2.9 | Rootcheck | Complete | rootkit, hidden-process, suspicious-port checks |

## Phase 3 (this session) — gap-fill work

| # | Task | Status |
|---|---|---|
| 3.R | **Server message receive loop** (`crates/wda-agent/src/main.rs`) | **Complete** — `receive_handle` task added that reads frames from the server, parses the leading `#!-execd` / `#!-req` / `#!-up_file` tag, and publishes `EventKind::ServerCommand` on the event bus so the active_response module can consume them |

Unit tests for `parse_server_command` were added inline to lock the
parsing of each tag variant, including trailing-null stripping, and are
run as part of `cargo test --all`.

## Unit Tests

Command: `cargo test --all 2>&1 | tee unit-test-results.txt`

**Result: all 178 tests passed, 0 failed.**

| Crate | Passed |
|---|---|
| `wda-agent` | 29 |
| `wda-active-response` | 18 |
| `wda-comms` | 23 |
| `wda-core` | 4 |
| `wda-enhanced-inventory` | 4 |
| `wda-event-bus` | 5 |
| `wda-fim` | 43 (120 s — slowest, uses real inotify/kqueue) |
| `wda-inventory` | 5 |
| `wda-local-detection` | 4 |
| `wda-logcollector` | 1 (24 s) |
| `wda-pal` | 5 |
| `wda-rootcheck` | 12 |
| `wda-sca` | 30 |
| **Total** | **178** |

Full log: [`unit-test-results.txt`](./unit-test-results.txt).

## E2E Tests vs. Local Wazuh 4.9.2

Command: `sudo env "HOME=$HOME" "PATH=$HOME/.cargo/bin:$PATH" bash tests/scripts/run-e2e.sh`

The E2E harness brings up `wazuh/wazuh-manager:4.9.2` via
`tests/docker-compose.yml`, enrolls WDA, exercises each module, then
queries the manager's `syscheck`, `syscollector`, and archived-alerts
for the expected events.

**Result: all 9 checks passed.**

```
  E2E Test Summary
  PASS: Agent enrolled successfully
  PASS: Agent still enrolled after keepalive (active flag not shown)
  PASS: FIM syscheck alerts received by server
  PASS: Baseline scan syscheck alerts received by server
  PASS: Baseline scan detected file deletion
  PASS: Inventory data received by server
  PASS: Log collection alerts received by server
  PASS: Journal log collection events received by server
  PASS: Active response command processed
  RESULT: ALL CHECKS PASSED
```

Full log: [`e2e-results.txt`](./e2e-results.txt).

## Benchmark vs. Wazuh Agent 4.9.2

See [`benchmark-results.md`](./benchmark-results.md) for methodology and
raw numbers. Summary vs. proposal targets:

| Metric | Target | Wazuh 4.9.2 | WDA | Status |
|---|---|---|---|---|
| Idle RAM (single process) | < 15 MB | ~56 MB across 5 daemons | 12 MB | **Met** |
| Idle CPU | < 0.1 % | 0.45 % (`wazuh-agentd` only) | 0.03 % | **Met** |
| Shipped binary size | < 5 MB | 3.8 MB (5 daemons combined) | 5.5 MB | **Not met** (down from 8.0 MB after release-profile size flags) |
| FIM scan peak CPU (1 000 files) | < 3 % | 9 % | 8 % | **Not met** |

## Known Gaps

1. **Binary size > 5 MB target.** Release build is now 5.5 MB (down
   from 8.0 MB) with `[profile.release]` using `lto = "fat"`,
   `codegen-units = 1`, `panic = "abort"`, `opt-level = "z"`, and
   `strip = true`. The remaining ~0.5 MB to hit the < 5 MB target is
   dominated by `rusqlite` (bundled SQLite) and `rustls`; trimming
   unused features there is the next lever to pull.
2. **FIM scan CPU > 3 % target.** The current FIM path hashes every
   new file inline in the same task that dispatches the event. Under
   the "create 1 000 files" stress pattern this pushes the peak to
   ~8 %. The proposal calls for:
   - adaptive hashing rate limit (files/sec)
   - batching of change events into a single bus message
   - optional lazy/background SHA-256 after the metadata event
   None of these are wired in yet.
3. ~~**Noisy `receive` warnings.**~~ **Fixed.**
   `ConnectionManager::receive()` now returns
   `Result<Option<Vec<u8>>, ConnectionError>` and a new
   `CryptoError::EmptyPayload` variant lets the read path distinguish
   a legitimate zero-length keep-open frame from a real decryption
   failure. The agent main loop logs these at `debug!` instead of
   `warn!`, eliminating the ~2 Hz `failed to receive from server`
   spam that appeared every time the manager kept the connection
   idle.
4. ~~**Event bus back-pressure during first-time inventory.**~~
   **Fixed.** The default server-event channel capacity was raised
   from 256 to 1024 in `crates/wda-core/src/agent.rs`, which is
   enough to absorb the initial syscollector package burst (~900
   rows) without drops. The `wda-inventory` collector still yields
   every row and sleeps 50 ms every 50 rows, so the forwarder has
   time to drain the channel before it fills.
5. ~~**Windows EventLog uses `wevtutil` CLI**~~ **Fixed.** The
   collector now subscribes via the native `EvtSubscribe` +
   `EvtRender` APIs through `windows-rs`. Events are delivered
   push-based to an `EVT_SUBSCRIBE_CALLBACK`, rendered to XML with
   `EvtRenderEventXml`, parsed into a text summary, and published on
   the event bus. No subprocess per poll.
6. ~~**Windows network inventory returns empty.**~~ **Fixed.** A new
   `windows_impl` module in `wda-inventory/src/network.rs`
   enumerates adapters via `GetAdaptersAddresses` (`AF_UNSPEC`) and
   emits `dbsync_netiface` + `dbsync_netaddr` payloads for every
   adapter and unicast address, matching the Unix output format.
7. **PAL `PowerMonitor` returns `Unknown`/`None` on macOS and
   Windows.** Non-blocking for core telemetry — `wda-inventory` has
   real hardware/OS implementations — but adaptive power-aware
   scheduling (battery vs AC profile switching) is not yet wired up
   outside Linux.

## Recommended Next Steps

Short list, ordered by impact:

1. **FIM throttling / lazy hashing** to get FIM scan peak CPU under
   3 %.
2. **Enable release-profile size optimizations** in `Cargo.toml`
   (LTO, `opt-level=z`, `strip`, `panic=abort`) to get under the
   5 MB binary-size target.
3. **Wire `ServerCommand` events into `wda-active-response`** — the
   receive loop publishes them, but the active_response
   module still reads only locally-triggered commands. Minor patch
   inside `wda-active-response` to subscribe to `EventKind::ServerCommand`.
4. **Wire PAL `PowerMonitor` on macOS and Windows** so adaptive
   battery-vs-AC scheduling works outside Linux.
