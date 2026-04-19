# WDA Development Progress

## Last Updated: 2026-04-19

## Completed Phases

### Phase 1 — Core Plumbing (7/7 complete)
- Workspace + crate skeleton
- Structured config loading (AgentConfig) with YAML
- Enrollment against authd (port 1615) with password auth
- Connection manager with TCP + UDP + Blowfish crypto
- Keepalive loop
- Event bus with priority queues and back-pressure
- Shutdown signal + task coordination

### Phase 2 — Detection Modules (9/9 complete)
- FIM (realtime + baseline, inotify/FSEvents/ReadDirectoryChangesW)
- Log collection — file tailing, journald, Windows EventLog, macOS OSLog
- Inventory (syscollector-compatible: os, hardware, packages, network)
- Active response (block_ip, kill_process, script execution)
- SCA (YAML policies, regex/command/file checks)
- Rootcheck (signatures, hidden-process on Linux, binary-integrity)

### Phase 3 — Gap-fill (3/3 complete)
- Server message receive loop
- Wire SCA module into agent main loop
- Implement rootcheck detection logic

## Benchmark Targets (all met as of 2026-04-19)
| Metric | Target | Actual |
|---|---|---|
| Idle RAM | < 15 MB | 5.7 MB |
| Idle CPU | < 0.1% | 0.00% |
| Binary size | < 5 MB | 4.6 MB |
| FIM scan CPU peak | < 3% | 3% |

## Test Results
- 186 unit tests passing
- 9/9 E2E tests passing vs Wazuh 4.9.2

## Current Sprint: Phase 3 Polish

### In Progress
- [ ] P1.1: Wire PAL PowerMonitor on macOS and Windows

### Up Next
- [ ] P1.2: Add E2E tests for SCA and Rootcheck
- [ ] P1.3: Investigate and fix macOS FIM burst test hang
- [ ] P1.4: Implement rootcheck content-based checks
- [ ] P1.5: Cross-platform rootcheck hidden-process detection

## Phase 4 Backlog (Edge Detection & Enhanced Inventory)
- [ ] P2.1: LDE rule store format and mmap loader
- [ ] P2.2: Aho-Corasick pattern matcher + IOC bloom filter
- [ ] P2.3: Behavioral rule state machines
- [ ] P2.4: Enhanced Software Inventory — running software monitor
- [ ] P2.5: Enhanced Software Inventory — browser extension enumeration
- [ ] P2.6: Wire LDE and Enhanced Inventory into main agent

## Phase 5 Backlog (Platform Hardening)
- [ ] P3.1: Self-update mechanism
- [ ] P3.2: Privilege separation
- [ ] P3.3: Tamper protection
- [ ] P3.4: Installer / packaging (MSI, deb, rpm, pkg)

## Known Issues
- macOS FIM burst test skipped due to kqueue event drops on CI
- Rootcheck hidden-process detection is Linux-only (no-op on macOS/Windows)
- Rootcheck only does file-existence checks, not content-based inspection
- wda-local-detection and wda-enhanced-inventory are empty skeletons
