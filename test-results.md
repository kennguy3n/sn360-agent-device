# SN360 Desktop Agent — Test Results

Date: 2026-04-21
Platform: Linux 5.15.200, x86_64 (Ubuntu)
Rust version: rustc 1.95.0 (59807616e 2026-04-14)
Cargo version: cargo 1.95.0 (f2d3ce0bd 2026-03-21)
Docker version: Docker 27.4.1 / Compose v2.32.1
Wazuh Manager: `wazuh/wazuh-manager:4.9.2`

## Unit & Integration Tests

Command: `cargo test --all`

**Result: 391 passing / 0 failed.**

Per-crate breakdown (unit + integration test binaries):

| Crate | Passed | Failed |
|---|---|---|
| `sda-active-response` (unit) | 29 | 0 |
| `sda-agent` (unit) | 29 | 0 |
| `sda-comms` (unit) | 31 | 0 |
| `sda-core` (unit) | 2 | 0 |
| `sda-enhanced-inventory` (unit) | 50 | 0 |
| `sda-enhanced-inventory` (integration: `browser_extensions_integration`) | 3 | 0 |
| `sda-enhanced-inventory` (integration: `sbom_integration`) | 3 | 0 |
| `sda-event-bus` (unit) | 4 | 0 |
| `sda-fim` (unit) | 57 | 0 |
| `sda-fim` (integration: `baseline_scan_integration`) | 1 | 0 |
| `sda-fim` (integration: `burst_workload`) | 2 | 0 |
| `sda-fim` (integration: `fim_integration`) | 5 | 0 |
| `sda-fim` (integration: `integration`) | 4 | 0 |
| `sda-inventory` (unit) | 32 | 0 |
| `sda-local-detection` (unit) | 56 | 0 |
| `sda-logcollector` (unit) | 34 | 0 |
| `sda-pal` (unit) | 5 | 0 |
| `sda-rootcheck` (unit) | 20 | 0 |
| `sda-sca` (unit) | 5 | 0 |
| `sda-updater` (unit) | 16 | 0 |
| `sda-updater` (integration: `checker_http`) | 3 | 0 |
| **Total** | **391** | **0** |

Rolled up by crate (matching the shape of the table in `PROGRESS.md`):

| Crate | Passed |
|---|---|
| `sda-active-response` | 29 |
| `sda-agent` | 29 |
| `sda-comms` | 31 |
| `sda-core` | 2 |
| `sda-enhanced-inventory` | 56 |
| `sda-event-bus` | 4 |
| `sda-fim` | 69 |
| `sda-inventory` | 32 |
| `sda-local-detection` | 56 |
| `sda-logcollector` | 34 |
| `sda-pal` | 5 |
| `sda-rootcheck` | 20 |
| `sda-sca` | 5 |
| `sda-updater` | 19 |
| **Total** | **391** |

Notes on deltas vs. the previously recorded `PROGRESS.md` table (361 total):

- `sda-agent`: 18 → 29 (+11 new agent-level unit tests).
- `sda-enhanced-inventory`: 57 → 56 (one unit test was refactored into the integration test binaries; total across unit + integration is 56 here vs 57 previously, i.e. net –1).
- `sda-fim`: 68 → 69 (+1 unit test).
- `sda-updater`: (absent) → 19. This crate is not listed in the old PROGRESS.md table at all; 16 unit tests + 3 `checker_http` integration tests.
- All other crates are unchanged.

No tests failed, so no fixes were required. `PROGRESS.md` has been updated
to reflect the new 391/0 count and the added `sda-updater` row.

## Base E2E Tests (vs. Local Wazuh 4.9.2)

Command: `make e2e`

**Result: 14/14 assertions pass.**

```
==============================
  E2E Test Summary
==============================
  PASS: Agent enrolled successfully
  PASS: Agent still enrolled after keepalive (active flag not shown)
  PASS: FIM syscheck alerts received by server
  PASS: Baseline scan syscheck alerts received by server
  PASS: Baseline scan detected file deletion
  PASS: Inventory data received by server
  PASS: Log collection alerts received by server
  PASS: Journal log collection events received by server
  PASS: Active response command processed
  PASS: SCA policy evaluation received by server (generic match)
  PASS: Rootcheck signature alert received by server
  PASS: Enhanced inventory running-software scanner active (agent log oracle)
  PASS: Enhanced inventory SBOM scanner active (agent log oracle)
  PASS: Enhanced inventory browser-extensions scanner active (agent log oracle)
==============================
  RESULT: ALL CHECKS PASSED
==============================
```

Per-assertion counters observed by the harness:

- Syscheck alerts: 2 (FIM testfile.txt creation)
- Baseline-scan syscheck alerts: 6 (scan-test-1/2/3)
- Deletion alerts: 3 (scan-test-2.txt removed)
- Inventory (syscollector) events in archives: 1088
- Log-collection alerts: 1 ("Failed password" tailed from `/tmp/sda-e2e-logs/test.log`)
- Journal log events in archives: 1 (`sda-e2e-test` via `logger`)
- Rootcheck marker events in archives: 18 (hits on `/tmp/sda-e2e-rootkit-marker`)
- Enhanced-inventory log-oracle hits: running_software=1, SBOM=2, browser-extensions=2

## Security E2E Tests (vs. Local Wazuh 4.9.2)

Command: `make security-e2e`

**Result: 10/10 assertions pass.**

```
==============================
  Security E2E Test Summary
==============================
  PASS: Malware file drop detected (syscheck alert for malware.exe)
  PASS: Brute-force SSH simulation detected (10 alert(s))
  PASS: Privilege escalation (sudo abuse) detected (5 alert(s))
  PASS: Config file tampering detected (hash change alert)
  PASS: Ransomware simulation detected (208 FIM alerts for .encrypted files)
  PASS: Active response kill_process command sent (process still alive — expected without server-side rule)
  PASS: IP blocking active response commands sent (IPv4 + IPv6)
  PASS: Package inventory update detected after install
  PASS: System binary tampering detected (SHA-256 change alert)
  PASS: Account disable AR configured and dispatched by server
==============================
  RESULT: ALL CHECKS PASSED
==============================
```

## Issues Found & Fixes Applied

None. All 391 unit/integration tests, 14 base E2E assertions, and 10
security E2E assertions passed on the first attempt.

## Notes

- The E2E and security E2E harnesses both hung during the `trap cleanup`
  step after printing `ALL CHECKS PASSED`. Root cause: the harnesses
  launch the agent via `timeout 300 sudo ./target/release/sda-agent …`
  and then run `kill "$AGENT_PID"; wait "$AGENT_PID"` from an
  unprivileged shell. `$AGENT_PID` is the non-privileged `timeout`
  wrapper, so the unprivileged SIGTERM never reaches the root
  `sda-agent` process. Issuing `sudo pkill -f sda-agent` unblocked the
  `wait` in both runs. All assertion results above were already
  recorded before the hang, so the test outcomes are not affected, but
  the harness cleanup path is worth hardening (e.g.
  `sudo kill "$AGENT_PID"` or prefixing the launch with
  `setsid --wait`). This is a test-infrastructure issue only; no agent
  code change is required.
- `ossec.log` reported 1 "Decrypt the message fail, socket 28" warning
  during the base E2E run. This is the expected first-frame re-enroll
  race that the Wazuh manager logs when the previous run's client key
  was cleared and a new enrollment is in flight; no subsequent decrypt
  errors were observed and all 14 downstream assertions passed.
- Test step 10 in the base E2E harness logs
  `** Selected active response does not exist.` from
  `agent_control -f restart-wazuh0`. The harness intentionally treats
  this as the "command processed" oracle (the manager dispatched the
  AR, there is no matching `<active-response>` block for
  `restart-wazuh` in the stock image), and the assertion passes. The
  security E2E harness, which injects `<active-response>` blocks for
  `disable-account` and `firewall-drop` before starting the agent,
  exercises the full round-trip end-to-end in tests 7 and 10.
- Prerequisites confirmed on this host: Docker 27.4.1 running,
  Compose v2.32.1, Rust 1.95.0, `sudo` available (passwordless), and
  `/usr/bin/pidstat` present.
