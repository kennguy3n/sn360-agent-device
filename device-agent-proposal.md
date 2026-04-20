# SN360 Device Agent (WDA): Architecture & Implementation Proposal

> **Version:** 1.0 | **Date:** April 2026 | **Status:** Draft Proposal
> **Target Platforms:** Windows 10/11, macOS 12+, Linux (Ubuntu/Fedora/Arch)
> **Goal:** Sub-20 MB RAM idle, <0.5% CPU baseline, unnoticeable to end users

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Analysis of Existing Wazuh Agent](#2-analysis-of-existing-wazuh-agent)
3. [Problem Statement & Design Goals](#3-problem-statement--design-goals)
4. [Proposed Architecture](#4-proposed-architecture)
5. [Core Module Design](#5-core-module-design)
6. [Cross-Platform Abstraction Layer](#6-cross-platform-abstraction-layer)
7. [Technology Stack & Justification](#7-technology-stack--justification)
8. [Communication Protocol](#8-communication-protocol)
9. [Resource Management Strategy](#9-resource-management-strategy)
10. [Security Architecture](#10-security-architecture)
11. [Configuration & Deployment](#11-configuration--deployment)
12. [Implementation Roadmap](#12-implementation-roadmap)
13. [Phase 4 Detail: Edge Detection, Software Inventory & Tenant Rule Distribution](#13-phase-4-detail-edge-detection-software-inventory--tenant-rule-distribution)
    - 13.1 [Local Detection Engine (LDE) Module](#131-local-detection-engine-lde-module)
    - 13.2 [Enhanced Software Inventory Module](#132-enhanced-software-inventory-module)
    - 13.3 [Companion Microservices](#133-companion-microservices)
      - 13.3.1 [Tenant Rule Distribution Service (TRDS)](#1331-tenant-rule-distribution-service-trds)
      - 13.3.2 [IOC Feed Aggregator Service (IOCFS)](#1332-ioc-feed-aggregator-service-iocfs)
      - 13.3.3 [Software Inventory Service (SIS)](#1333-software-inventory-service-sis)
    - 13.4 [Agent Gateway](#134-agent-gateway)
    - 13.5 [Updated Resource Budget](#135-updated-resource-budget)
    - 13.6 [Updated Configuration](#136-updated-configuration)
    - 13.7 [New Crate Structure](#137-new-crate-structure)
14. [Risk Assessment](#14-risk-assessment)
15. [Appendix: Wazuh Source Analysis](#15-appendix-wazuh-source-analysis)
16. [Local Wazuh Server Test Environment](#16-local-wazuh-server-test-environment)
17. [Summary](#17-summary)

---

## 1. Executive Summary

The current Wazuh agent (v5.0.0-beta1) is a comprehensive, monolithic C/C++ application totaling ~247,000 lines of source code across agent modules. It was designed to serve all deployment contexts (servers, containers, endpoints, cloud) with a single binary. While feature-complete, this architecture carries unnecessary overhead for desktop/laptop/VM endpoints where user experience is paramount.

This proposal describes **Wazuh Desktop Agent (WDA)** -- a purpose-built, modular rewrite optimized exclusively for end-user devices. The design targets:

| Metric | Current Wazuh Agent | WDA Target |
|---|---|---|
| Idle RAM | 60-120 MB | **< 15 MB** |
| Idle CPU | 1-3% | **< 0.1%** |
| FIM scan CPU spike | 10-30% | **< 3%** |
| Binary size (stripped) | ~25 MB + deps | **< 5 MB** |
| Startup time | 3-8 seconds | **< 500 ms** |
| Disk I/O during idle | Continuous | **Near-zero** |

The key architectural decisions enabling these targets are:

1. **Rust as the primary language** -- zero-cost abstractions, no GC pauses, fearless concurrency, and first-class cross-platform support.
2. **Event-driven, async-first architecture** -- using `tokio` with a single-threaded runtime by default, scaling only when work demands it.
3. **Modular plugin system** -- load only the modules the endpoint needs; unload when idle.
4. **OS-native notification APIs** -- replace polling with kernel-level filesystem/process watchers (inotify/fanotify, FSEvents, ReadDirectoryChangesW).
5. **Adaptive scheduling** -- back off scans when the user is active; run intensive work during idle/sleep transitions.

---

## 2. Analysis of Existing Wazuh Agent

### 2.1 Repository Structure (wazuh/wazuh @ main)

The Wazuh codebase is organized as follows (agent-relevant paths):

```
src/
  client-agent/       # Core agent daemon (4,236 LoC in C)
    src/main.c        # Entry point, config loading, daemonization
    src/start_agent.c # Server handshake, key exchange, enrollment
    src/agcom.c       # Agent communication dispatcher
    src/buffer.c      # Anti-flooding circular message buffer
    src/receiver.c    # Message receiver from server
    src/sendmsg.c     # Message sender to server
    src/notify.c      # Keepalive/notification to server
    src/event-forward.c  # Event forwarding logic
    src/state.c       # Agent state tracking

  syscheckd/          # File Integrity Monitoring (6,033 LoC)
    src/fim_scan.c    # Full disk scanning
    src/run_realtime.c # Real-time monitoring (inotify/ReadDirectoryChanges)
    src/whodata/      # Who-changed-it tracking (audit/Windows)
    src/ebpf/         # eBPF-based monitoring (Linux)
    src/db/           # SQLite-based FIM database

  logcollector/       # Log Collection (10,818 LoC)
    src/logcollector.c    # Main log collection loop
    src/read_syslog.c     # Syslog reader
    src/read_journald.c   # systemd journal reader
    src/read_macos.c      # macOS unified log reader
    src/read_win_event_channel.c  # Windows Event Log reader
    src/read_json.c       # JSON log reader
    # + 15 more format-specific readers

  rootcheck/          # Rootkit Detection (4,503 LoC)
    src/               # Anti-rootkit checks

  data_provider/      # System Inventory (24,252 LoC)
    src/sysInfoLinux.cpp  # Linux system info
    src/sysInfoMac.cpp    # macOS system info
    src/sysInfoWin.cpp    # Windows system info
    src/packages/         # Package enumeration (APK, DEB, RPM, Brew, MSI, etc.)
    src/network/          # Network interface enumeration
    src/hardware/         # Hardware info collection

  wazuh_modules/      # High-level feature modules (74,724 LoC)
    syscollector/     # System inventory collection
    vulnerability_scanner/  # CVE matching (server-side, not needed on agent)
    sca/              # Security Configuration Assessment

  shared/             # Shared utilities library (26,806 LoC)
    src/              # Crypto, string ops, file ops, networking, JSON, etc.
    include/          # ~70 header files

  shared_modules/     # Shared C++ modules (106,544 LoC)
    dbsync/           # Database synchronization
    http-request/     # HTTP client
    utils/            # C++ utilities
    content_manager/  # Content/update management
    router/           # Internal message routing

  config/             # Configuration parsing
    src/              # Per-module config readers (client, syscheck, localfile, etc.)

  active-response/    # Active response scripts
  os_execd/           # Active response execution daemon
  win32/              # Windows service wrapper, installer scripts
```

### 2.2 Identified Resource Overhead Sources

| Source | Impact | Root Cause |
|---|---|---|
| **Embedded Python (cPython 3.12)** | +30-40 MB RAM, +15 MB disk | Framework/API uses Python; wodles (AWS, Azure, GCP, Docker) are Python scripts |
| **RocksDB** | +10-15 MB RAM | Used for state storage; heavy for endpoint use |
| **SQLite FIM database** | +5-15 MB RAM | Full scan results stored in-memory SQLite |
| **Polling-based log collection** | Continuous CPU | Logcollector polls files on configurable intervals |
| **Full-disk FIM scans** | CPU spikes to 10-30% | Scheduled full hash scans of monitored directories |
| **Monolithic process** | All modules always loaded | No way to unload unused modules |
| **Thread-per-module model** | Thread overhead | Each module spawns 1-3 threads regardless of workload |
| **Shared library chain** | 25+ external deps compiled in | OpenSSL, cURL, libarchive, PCRE2, msgpack, cJSON, etc. |
| **Anti-flooding buffer** | Fixed memory allocation | Circular buffer pre-allocates regardless of event rate |

### 2.3 Communication Protocol Analysis

The current agent communicates with the Wazuh server using:

- **UDP or TCP** (configurable) on port 1514
- **Custom binary protocol** with AES-256 encryption using pre-shared keys
- **Handshake** includes server-pushed module limits (FIM file counts, syscollector limits)
- **Keepalive** notifications every 10-600 seconds (configurable `notify_time`)
- **Event forwarding** via a buffered queue with anti-flooding controls
- **Enrollment** via SSL/TLS connection to the server's authd (port 1515)

### 2.4 Cross-Platform Implementation

The existing agent handles cross-platform via:

- **C preprocessor `#ifdef WIN32` / `#ifdef __APPLE__`** scattered throughout code
- **Separate source files** for platform-specific implementations (e.g., `sysInfoLinux.cpp`, `sysInfoMac.cpp`, `sysInfoWin.cpp`)
- **Makefile-level target selection**: `make TARGET=agent` (Linux/macOS) vs `make TARGET=winagent` (cross-compiled with MinGW)
- **Win32 service wrapper** (`win32/win_agent.c`) manages Windows service lifecycle
- **No unified platform abstraction layer** -- each module handles its own platform differences

---

## 3. Problem Statement & Design Goals

### 3.1 Problem

Desktop/laptop users experience:
- Noticeable CPU spikes during FIM scans and inventory collection
- Memory footprint inappropriate for 8-16 GB RAM devices running user workloads
- Battery drain on laptops from continuous polling and periodic scans
- Occasional I/O contention with user applications during disk-heavy scans

### 3.2 Design Goals

| Priority | Goal | Metric |
|---|---|---|
| P0 | **Invisible to the user** | <0.1% idle CPU, <15 MB RAM, no perceptible disk I/O |
| P0 | **Security parity** | FIM, log collection, SCA, inventory, active response all functional |
| P0 | **Cross-platform** | Single codebase, native builds for Windows/macOS/Linux |
| P1 | **Battery-aware** | Defer scans on battery; adaptive scheduling |
| P1 | **Fast startup** | <500 ms cold start |
| P1 | **Small footprint** | <5 MB binary, <10 MB installed |
| P1 | **Edge detection capability** | Local IOC matching + behavioral rules, <1% CPU during event evaluation |
| P2 | **Backward-compatible protocol** | Communicate with existing Wazuh servers (v4.x/v5.x) |
| P2 | **Graceful degradation** | Reduce functionality under resource pressure rather than crash |
| P2 | **Auto-update** | Self-updating agent with rollback capability |

### 3.3 Non-Goals

- **Server/manager functionality** -- this agent is endpoint-only
- **Container monitoring** -- separate container-optimized agent
- **Cloud API integration** -- wodles for AWS/Azure/GCP remain server-side
- **Full vulnerability scanning** -- CVE matching remains server-side (in the SIS microservice); the agent now performs local IOC matching and behavioral detection but does not run full CVE analysis locally

---

## 4. Proposed Architecture

### 4.1 High-Level Architecture

```
+------------------------------------------------------------------+
|                    Wazuh Desktop Agent (WDA)                      |
+------------------------------------------------------------------+
|                                                                    |
|  +--------------------+    +-------------------+                   |
|  |   Agent Core       |    |  Module Manager   |                   |
|  |  - Lifecycle mgmt  |    |  - Load/unload    |                   |
|  |  - Config engine   |    |  - Health checks  |                   |
|  |  - Signal handling |    |  - Scheduling     |                   |
|  +--------+-----------+    +--------+----------+                   |
|           |                         |                              |
|  +--------v-------------------------v----------+                   |
|  |            Event Bus (async channels)        |                  |
|  |  - Zero-copy message passing                 |                  |
|  |  - Backpressure support                      |                  |
|  |  - Priority queues                           |                  |
|  +----+--------+--------+--------+--------+----+                  |
|       |        |        |        |        |                        |
|  +----v--+ +---v---+ +--v---+ +-v----+ +-v-------+               |
|  |  FIM  | | Log   | | SCA  | | Inv  | | Active  |               |
|  |Module | |Collect | |Module| |Module| |Response |               |
|  +-------+ +-------+ +------+ +------+ +---------+               |
|                                                                    |
|  +-------------------------------------------------------------+  |
|  |          Platform Abstraction Layer (PAL)                     | |
|  |  +----------+  +----------+  +-----------+  +----------+    | |
|  |  |Filesystem|  |  Process |  |  Network  |  |  System  |    | |
|  |  | Watcher  |  |  Monitor |  |  Monitor  |  |   Info   |    | |
|  |  +----------+  +----------+  +-----------+  +----------+    | |
|  +-------------------------------------------------------------+  |
|                                                                    |
|  +-------------------------------------------------------------+  |
|  |              Communication Layer                              | |
|  |  - TLS 1.3 transport (rustls)                                | |
|  |  - Wazuh protocol compatibility                              | |
|  |  - Automatic reconnection with exponential backoff           | |
|  |  - Message batching & compression                            | |
|  +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### 4.2 Core Design Principles

#### 4.2.1 Event-Driven, Not Polling

Every module that can use OS-native notification APIs must do so:

| Function | Current (Polling) | WDA (Event-Driven) |
|---|---|---|
| File changes | Scheduled full-disk hash scans | `inotify`/`fanotify` (Linux), `FSEvents` (macOS), `ReadDirectoryChangesW` (Windows) |
| Log collection | Periodic file reads with seek tracking | `inotify` on log files + systemd journal subscription + macOS OSLog streaming |
| Process monitoring | Periodic `/proc` enumeration | `netlink` proc connector (Linux), `kqueue` (macOS), ETW (Windows) |
| Network changes | Periodic interface enumeration | `netlink` RTNL (Linux), `SCNetworkReachability` (macOS), `NotifyIpInterfaceChange` (Windows) |

Full-disk scans are retained only as a **fallback verification** mechanism, running during system idle periods.

#### 4.2.2 Lazy Module Loading

Modules are compiled as separate Rust crates but linked into a single binary. At runtime, each module's main loop is spawned as an async task only when enabled in configuration. Disabled modules consume zero CPU and near-zero RAM.

```rust
// Pseudocode for module lifecycle
trait AgentModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn init(&mut self, config: &ModuleConfig) -> Result<()>;
    async fn run(&mut self, bus: EventBus) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    fn health_check(&self) -> ModuleHealth;
}
```

#### 4.2.3 Adaptive Resource Budgeting

The agent monitors system state and adjusts its behavior:

```
System State         | FIM Scan Rate | Log Batch Size | Inventory Interval
---------------------|---------------|----------------|-------------------
User active + AC     | Normal        | Normal         | Normal (1h)
User active + Battery| Reduced 50%   | Increased 2x   | Extended (4h)
User idle + AC       | Accelerated   | Normal         | Normal (1h)
User idle + Battery  | Reduced 25%   | Increased 4x   | Extended (8h)
High CPU (>80%)      | Paused        | Increased 4x   | Deferred
Low memory (<500MB)  | Paused        | Minimal        | Deferred
```

#### 4.2.4 Single-Threaded Async by Default

The agent uses a **single-threaded tokio runtime** for all async I/O. CPU-intensive work (hashing, compression) is offloaded to a small (2-thread) blocking pool via `spawn_blocking`. This eliminates thread synchronization overhead for the common path.

```
Threads at idle:
  1x  Main async runtime (event loop + all modules)
  0x  Blocking pool threads (spawned on demand, reaped after timeout)

Threads during FIM scan:
  1x  Main async runtime
  1-2x Blocking pool (hash computation)
```

---

## 5. Core Module Design

### 5.1 File Integrity Monitoring (FIM)

**Current issues:** Full-disk scans hash every monitored file, causing CPU spikes up to 30%. The SQLite FIM database keeps full state in memory.

**WDA Design:**

```
FIM Module
  |
  +-- Real-time Watcher (primary)
  |     Linux:   fanotify (FAN_MARK_FILESYSTEM) or inotify
  |     macOS:   FSEvents with kFSEventStreamCreateFlagFileEvents
  |     Windows: ReadDirectoryChangesW with FILE_NOTIFY_CHANGE_*
  |
  +-- Change Processor
  |     - Debounce rapid changes (100ms window)
  |     - Hash only changed files (SHA-256 via ring crate)
  |     - Compare against on-disk state DB
  |     - Emit change events to Event Bus
  |
  +-- State Store
  |     - Memory-mapped SQLite (WAL mode, mmap_size=4MB)
  |     - Schema: path, hash, size, perms, uid, gid, mtime, inode
  |     - Bloom filter for fast "is this path monitored?" checks
  |
  +-- Baseline Scanner (secondary)
        - Runs only during detected system idle
        - Rate-limited: max 100 files/sec, yields every 10ms
        - Verifies real-time watcher hasn't missed changes
        - Incremental: only re-hashes files with changed mtime/size
```

**Memory budget:** ~2 MB for state DB + bloom filter for 500K monitored paths.

### 5.2 Log Collection

**Current issues:** 10,818 LoC with 17+ format-specific readers. Polling-based file reading. All readers always compiled in.

**WDA Design:**

```
Log Collector Module
  |
  +-- Source Registry
  |     - Tracks monitored log sources with seek positions
  |     - Persisted to disk on graceful shutdown
  |
  +-- Watcher (event-driven)
  |     Linux:   inotify IN_MODIFY on log files
  |     macOS:   FSEvents / kqueue EVFILT_VNODE
  |     Windows: ReadDirectoryChangesW on log directories
  |
  +-- Readers (feature-gated at compile time)
  |     - Syslog (plain text line reader)
  |     - JSON (streaming JSON parser via simd-json)
  |     - Windows Event Log (via windows-rs EvtSubscribe)
  |     - macOS Unified Log (via OSLog streaming API)
  |     - systemd Journal (via libsystemd sd_journal_* FFI)
  |
  +-- Output Buffer
        - Ring buffer with configurable capacity (default: 1000 events)
        - Backpressure: drops oldest events when full (configurable)
        - Batches events for transmission (default: every 5s or 100 events)
```

**Key optimization:** Instead of polling log files every N seconds, we receive OS-level notifications when files are modified, then read only the new data from the last seek position.

### 5.3 System Inventory (Syscollector)

**Current issues:** Enumerates all packages, processes, ports, network interfaces, and hardware on every scan cycle. The data_provider module is 24K+ LoC with heavy platform-specific code.

**WDA Design:**

```
Inventory Module
  |
  +-- Hardware Info (collected once at startup, cached)
  |     - CPU model, cores, RAM total
  |     - OS version, hostname, architecture
  |
  +-- Package Inventory
  |     Linux:   dpkg/rpm DB inotify watch + incremental diff
  |     macOS:   FSEvents on /Applications + receipts + Homebrew
  |     Windows: Registry watcher on Uninstall keys + AppX catalog
  |
  +-- Network Interfaces
  |     Linux:   netlink RTNL subscription
  |     macOS:   SCNetworkReachability callbacks
  |     Windows: NotifyIpInterfaceChange callbacks
  |
  +-- Process List
  |     - Snapshot only on demand or server request
  |     - NOT continuously monitored (high cost, low value for desktops)
  |
  +-- Open Ports
        - Snapshot only on demand or on network change events
```

**Key optimization:** Event-driven package tracking. Instead of scanning all packages every hour, watch the package database files for changes and only re-enumerate when something actually changed.

### 5.4 Security Configuration Assessment (SCA)

**Current issues:** Lua-based policy evaluation engine. Runs all checks sequentially.

**WDA Design:**

```
SCA Module
  |
  +-- Policy Engine
  |     - YAML policy files (Wazuh SCA format compatible)
  |     - Compiled to a check tree at load time
  |     - Checks are pure functions: (SystemState) -> CheckResult
  |
  +-- Check Executor
  |     - Runs during system idle only
  |     - Rate-limited: max 50 checks/sec
  |     - Results cached until relevant system state changes
  |     - Delta reporting: only send changed results to server
  |
  +-- Check Types
        - File existence/content/permissions
        - Registry keys (Windows)
        - Process running checks
        - Command output evaluation
        - System configuration values
```

### 5.5 Active Response

**Current issues:** Separate daemon (os_execd) that forks processes to run scripts.

**WDA Design:**

```
Active Response Module
  |
  +-- Command Registry
  |     - Pre-registered response actions with allowed parameters
  |     - Sandboxed: actions run with dropped privileges
  |
  +-- Executor
  |     - Async process spawning via tokio::process
  |     - Timeout enforcement (default: 30s)
  |     - Output capture and event reporting
  |
  +-- Built-in Actions
        - IP blocking (platform-native firewall APIs)
        - Process termination
        - User session disconnect
        - Custom script execution (configurable, off by default)
```

### 5.6 Rootkit Detection (Rootcheck)

**Current issues:** Scans for known rootkit files/directories, checks `/dev`, verifies system binaries.

**WDA Design:**

This module is retained but significantly simplified for desktops:

```
Rootcheck Module
  |
  +-- File-based checks (known rootkit signatures)
  |     - Run during system idle, once per day
  |
  +-- Process hiding detection
  |     - Compare /proc enumeration vs kill(pid, 0) sweep
  |     - Run once per hour during idle
  |
  +-- System binary integrity
        - Verify critical binaries against known hashes
        - Triggered by FIM changes to /usr/bin, /usr/sbin, etc.
```

---

## 6. Cross-Platform Abstraction Layer

### 6.1 PAL Architecture

The Platform Abstraction Layer is a set of Rust traits with platform-specific implementations selected at compile time via `cfg` attributes:

```rust
// Core PAL traits

pub trait FileSystemWatcher: Send + Sync {
    async fn watch(&self, paths: &[PathBuf], recursive: bool) -> Result<()>;
    async fn unwatch(&self, paths: &[PathBuf]) -> Result<()>;
    fn events(&self) -> &mpsc::Receiver<FsEvent>;
}

pub trait LogSource: Send + Sync {
    async fn open(&mut self, config: &LogSourceConfig) -> Result<()>;
    async fn read_new(&mut self) -> Result<Vec<LogEntry>>;
    async fn seek_to_end(&mut self) -> Result<()>;
}

pub trait SystemInfo: Send + Sync {
    fn os_info(&self) -> OsInfo;
    fn hardware_info(&self) -> HardwareInfo;
    fn network_interfaces(&self) -> Vec<NetworkInterface>;
    fn installed_packages(&self) -> Vec<Package>;
    fn running_processes(&self) -> Vec<Process>;
}

pub trait PowerStatus: Send + Sync {
    fn is_on_battery(&self) -> bool;
    fn battery_percentage(&self) -> Option<u8>;
    fn is_user_idle(&self) -> bool;
    fn idle_duration(&self) -> Duration;
}

pub trait ServiceManager: Send + Sync {
    fn install(&self) -> Result<()>;
    fn uninstall(&self) -> Result<()>;
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn status(&self) -> ServiceStatus;
}
```

### 6.2 Platform Implementations

| PAL Trait | Linux | macOS | Windows |
|---|---|---|---|
| `FileSystemWatcher` | `fanotify` (root) / `inotify` (user) | `FSEvents` framework | `ReadDirectoryChangesW` |
| `LogSource` (system) | `sd_journal` (systemd) | `OSLog` streaming | `EvtSubscribe` (Event Log) |
| `LogSource` (file) | `inotify` + read | `kqueue` + read | `ReadDirectoryChangesW` + read |
| `SystemInfo` | `/proc`, `/sys`, `uname`, dpkg/rpm | `sysctl`, `IOKit`, `system_profiler` | WMI, Registry, `GetSystemInfo` |
| `PowerStatus` | `/sys/class/power_supply`, D-Bus `UPower` | `IOPSCopyPowerSourcesInfo` | `GetSystemPowerStatus` |
| `ServiceManager` | systemd unit file | `launchd` plist | Windows Service API (SCM) |
| `FirewallControl` | `iptables`/`nftables` | `pfctl` | Windows Firewall API (COM) |

### 6.3 Compile-Time Feature Gates

```toml
# Cargo.toml feature configuration
[features]
default = ["fim", "logcollector", "sca", "inventory", "active-response"]

# Core modules (can be individually disabled)
fim = []
logcollector = []
sca = []
inventory = []
active-response = []
rootcheck = []

# Platform-specific features (auto-detected)
linux-ebpf = []          # eBPF-based FIM (requires kernel 5.8+)
linux-fanotify = []      # fanotify FIM (requires CAP_SYS_ADMIN)
linux-journal = ["dep:libsystemd"]
macos-endpoint-security = []  # macOS Endpoint Security Framework
windows-etw = []         # Event Tracing for Windows

# Optional capabilities
self-update = ["dep:reqwest"]
tls-native = ["dep:native-tls"]  # Use OS TLS stack
tls-rustls = ["dep:rustls"]      # Use rustls (default, smaller)
```

---

## 7. Technology Stack & Justification

### 7.1 Primary Language: Rust

| Criterion | C (current) | C++ (current shared_modules) | Go | Rust (proposed) |
|---|---|---|---|---|
| Memory safety | Manual | Manual (RAII helps) | GC | Compile-time ownership |
| Runtime overhead | None | Minimal | GC pauses, goroutine stack | None |
| Cross-compilation | Complex (MinGW) | Complex | Easy | Easy (rustup target) |
| Async I/O | Manual (select/epoll) | Manual / Boost.Asio | Built-in (goroutines) | tokio (mature, production-proven) |
| Binary size (hello world) | ~15 KB | ~25 KB | ~2 MB (static) | ~300 KB (stripped, static) |
| Dependency management | Manual/CMake | Manual/CMake | go mod | Cargo (excellent) |
| FFI for OS APIs | Native | Native | cgo (overhead) | Direct (no overhead) |
| Security | Buffer overflows common | Use-after-free possible | Safe | Memory safe by default |

**Why Rust over Go:** Go's garbage collector introduces unpredictable latency spikes (1-3 ms) and its minimum runtime memory (~5 MB) is too high for our targets. Rust's zero-cost abstractions and lack of GC make it possible to achieve truly minimal resource usage while maintaining safety.

**Why Rust over C/C++ (rewriting):** The current C codebase has 70+ header files in shared/include with complex manual memory management. A Rust rewrite eliminates entire classes of security bugs (buffer overflows, use-after-free, data races) that are critical in a security agent running with elevated privileges.

### 7.2 Key Dependencies

| Crate | Purpose | Size Impact | Justification |
|---|---|---|---|
| `tokio` (rt, io, net, time, process) | Async runtime | ~500 KB | Industry standard, single-threaded mode available |
| `rustls` + `ring` | TLS 1.3 + crypto | ~400 KB | No OpenSSL dependency, smaller, auditable |
| `serde` + `serde_json` | Serialization | ~200 KB | Zero-copy deserialization, compile-time code generation |
| `notify` | Cross-platform fs watching | ~50 KB | Wraps inotify/FSEvents/ReadDirectoryChanges |
| `rusqlite` (bundled) | SQLite for state storage | ~800 KB | Mature, WAL mode, memory-mapped I/O |
| `tracing` | Structured logging | ~100 KB | Zero-overhead when disabled, async-aware |
| `windows-rs` | Windows API bindings | Build-time | Official Microsoft crate, zero-overhead |
| `nix` | Unix API bindings | ~150 KB | Safe wrappers for Linux/macOS syscalls |
| `simd-json` | High-perf JSON parsing | ~100 KB | 2-4x faster than serde_json for log parsing |

**Estimated binary size (stripped, release):** ~3.5 MB (single static binary, all modules enabled)

### 7.3 Build & Distribution

```
Build Targets:
  x86_64-unknown-linux-gnu       # Linux x86_64
  aarch64-unknown-linux-gnu      # Linux ARM64
  x86_64-apple-darwin            # macOS Intel
  aarch64-apple-darwin           # macOS Apple Silicon
  x86_64-pc-windows-msvc         # Windows x86_64

Distribution:
  Linux:   .deb, .rpm, static binary, systemd unit
  macOS:   .pkg installer, launchd plist
  Windows: .msi installer, Windows Service
```

---

## 8. Communication Protocol

### 8.1 Wazuh Protocol Compatibility

The WDA maintains backward compatibility with Wazuh server protocol:

```
+---+---+---+---+---+---+---+---+---+---+---+---+
| Agent ID | : | Message Type | : | Payload     |
+---+---+---+---+---+---+---+---+---+---+---+---+
              |
              v
    AES-256-CBC encrypted (existing key exchange)
              |
              v
    Compressed (zlib, optional)
              |
              v
    TCP/UDP transport to port 1514
```

### 8.2 Enhanced Mode (opt-in)

When communicating with WDA-aware servers, an enhanced protocol is available:

- **TLS 1.3** transport (replacing custom AES-CBC wrapping)
- **MessagePack** serialization (50-70% smaller than JSON for events)
- **HTTP/2** for multiplexed bidirectional communication
- **Batched events** with delta compression
- **Server-sent configuration updates** (push model vs. polling)

### 8.3 Connection Management

```rust
// Connection strategy pseudocode
struct ConnectionManager {
    primary_server: ServerEndpoint,
    failover_servers: Vec<ServerEndpoint>,
    reconnect_strategy: ExponentialBackoff {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(60),
        multiplier: 2.0,
        jitter: 0.1,
    },
    keepalive_interval: Duration::from_secs(600),
    batch_window: Duration::from_secs(5),
    max_batch_size: 100,
}
```

---

## 9. Resource Management Strategy

### 9.1 Memory Management

| Component | Budget | Strategy |
|---|---|---|
| Agent core + event bus | 2 MB | Static allocation, bounded channels |
| FIM state database | 2-4 MB | Memory-mapped SQLite, 4 MB mmap window |
| Log collector buffers | 1-2 MB | Ring buffer, bounded, backpressure |
| SCA policy cache | 0.5 MB | Loaded on demand, freed after scan |
| Inventory cache | 1-2 MB | Cached, refreshed on change events |
| Network buffers | 0.5 MB | Reusable buffer pool |
| **Total idle** | **~8-12 MB** | |

**Key techniques:**
- `jemalloc` replaced by system allocator (smaller, adequate for low-alloc workload)
- Zero-copy message passing between modules via `bytes::Bytes`
- String interning for repeated paths/log sources
- Bounded collections everywhere (no unbounded growth)

### 9.2 CPU Management

```
Priority Scheduling:

  IDLE TASKS (run only when system CPU < 20%):
    - FIM baseline scan
    - SCA policy evaluation
    - Rootkit detection scans
    - Full inventory refresh

  NORMAL TASKS (always run, rate-limited):
    - Real-time FIM event processing
    - Log collection (event-driven)
    - Server communication

  CRITICAL TASKS (never deferred):
    - Active response execution
    - Agent keepalive
    - Configuration updates
```

**CPU throttling implementation:**
```rust
async fn throttled_scan(scanner: &mut Scanner, budget: &ResourceBudget) {
    for entry in scanner.next_batch(100) {
        process_entry(entry).await;

        // Yield to other tasks
        tokio::task::yield_now().await;

        // Check if we should pause
        if budget.cpu_usage() > 0.03 {  // 3% threshold
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
```

### 9.3 Disk I/O Management

- **WAL mode SQLite** -- writes don't block reads, auto-checkpointing
- **Buffered, batched writes** -- accumulate events and write in batches
- **Log rotation awareness** -- detect rotated files, don't re-read
- **No continuous disk activity at idle** -- state persisted on events, not on timer

### 9.4 Battery & Power Awareness

```rust
enum PowerProfile {
    /// AC power, user active: normal operation
    Normal,
    /// AC power, user idle: run deferred scans
    IdleAC,
    /// Battery, user active: minimal scans, larger batches
    BatteryActive,
    /// Battery, user idle: reduced scans, extended intervals
    BatteryIdle,
    /// Critical battery (<10%): essential only
    CriticalBattery,
}

impl PowerProfile {
    fn fim_scan_rate(&self) -> f64 { /* multiplier */ }
    fn log_batch_interval(&self) -> Duration { /* ... */ }
    fn inventory_interval(&self) -> Duration { /* ... */ }
    fn sca_enabled(&self) -> bool { /* ... */ }
}
```

---

## 10. Security Architecture

### 10.1 Privilege Model

```
Linux:
  - Main process runs as unprivileged user (wazuh)
  - CAP_DAC_READ_SEARCH for FIM (read any file)
  - CAP_NET_ADMIN for active response (firewall)
  - fanotify requires CAP_SYS_ADMIN (optional, fallback to inotify)

macOS:
  - LaunchDaemon runs as root (required for Endpoint Security Framework)
  - Privilege separation via sandbox profiles where possible

Windows:
  - Windows Service runs as LOCAL SYSTEM (required for Event Log, Registry)
  - Active responses use constrained process tokens
```

### 10.2 Secure Communication

- **Key storage:** Platform keychain integration (Linux: kernel keyring, macOS: Keychain, Windows: DPAPI)
- **Certificate pinning:** Server certificate fingerprint cached and verified
- **Forward secrecy:** TLS 1.3 with ephemeral keys (in enhanced mode)
- **Anti-tampering:** Binary signature verification, config file integrity checks

### 10.3 Self-Protection

- **Binary signing** on all platforms (code signing certificates)
- **Config file permissions** enforced at startup (0640 on Unix, ACL on Windows)
- **Memory protection:** Stack canaries, ASLR, DEP (enabled by default in Rust)
- **Secure deletion** of temporary files and key material

---

## 11. Configuration & Deployment

### 11.1 Configuration Format

WDA uses YAML configuration (with backward-compatible XML config reader):

```yaml
# /etc/wazuh-desktop-agent/config.yaml
agent:
  server:
    address: "wazuh-server.example.com"
    port: 1514
    protocol: tcp  # tcp | udp
  enrollment:
    server: "wazuh-server.example.com"
    port: 1515
    auto_enroll: true
  keepalive_interval: 600  # seconds

modules:
  fim:
    enabled: true
    directories:
      - path: /etc
        recursive: true
        realtime: true
      - path: /usr/bin
        recursive: false
        check_sha256: true
      - path: /home
        recursive: true
        realtime: true
        exclude:
          - "*.tmp"
          - ".cache/**"
    scan_interval: 43200  # 12h baseline scan (idle only)

  logcollector:
    enabled: true
    sources:
      - type: journald
        units: ["sshd", "sudo", "systemd-logind"]
      - type: file
        path: /var/log/auth.log
        format: syslog

  sca:
    enabled: true
    policies:
      - cis_ubuntu_22_04.yaml
    scan_on_idle: true

  inventory:
    enabled: true
    collect:
      - packages
      - network
      - hardware
      - os
    interval: 3600  # 1h

  active_response:
    enabled: true
    actions:
      - block_ip
      - kill_process

resource_limits:
  max_cpu_percent: 3
  max_memory_mb: 50
  battery_mode: adaptive  # adaptive | minimal | normal
  idle_detection: true
```

### 11.2 Deployment Automation

```
Packaging:
  - Linux: .deb (apt), .rpm (yum/dnf), static binary tarball
  - macOS: .pkg with installer scripts, Homebrew cask
  - Windows: .msi with WiX, winget manifest

Enrollment:
  - Automatic enrollment with pre-shared key or certificate
  - Group-based auto-assignment via agent labels
  - Supports Wazuh server enrollment API (port 1515)

Management:
  - Server-pushed configuration updates
  - Remote module enable/disable
  - Centralized policy deployment
```

---

## 12. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

| Task | Description | Est. Effort |
|---|---|---|
| **1.1** | Project scaffolding: Cargo workspace, CI/CD pipeline, cross-compilation targets | 3 days |
| **1.2** | Platform Abstraction Layer: `FileSystemWatcher` trait + Linux inotify impl | 5 days |
| **1.3** | Platform Abstraction Layer: macOS FSEvents + Windows ReadDirectoryChangesW | 5 days |
| **1.4** | Agent core: lifecycle management, signal handling, config engine (YAML + XML compat) | 5 days |
| **1.5** | Event bus: async channel-based inter-module communication | 3 days |
| **1.6** | Communication layer: Wazuh protocol v5 compatibility (AES-256, TCP/UDP) | 5 days |
| **1.7** | Enrollment: agent registration with Wazuh server (authd protocol) | 3 days |

**Milestone:** Agent can start, enroll with a Wazuh server, send keepalives, and receive messages.

### Phase 2: Core Modules (Weeks 5-10)

| Task | Description | Est. Effort |
|---|---|---|
| **2.1** | FIM module: real-time watcher (all platforms) + state database | 8 days |
| **2.2** | FIM module: baseline scanner with idle-aware scheduling | 4 days |
| **2.3** | FIM module: change event formatting (Wazuh syscheck compatible) | 3 days |
| **2.4** | Log collector: file-based collection with seek tracking | 5 days |
| **2.5** | Log collector: systemd journal (Linux) | 3 days |
| **2.6** | Log collector: Windows Event Log (EvtSubscribe) | 4 days |
| **2.7** | Log collector: macOS Unified Log (OSLog) | 3 days |
| **2.8** | Inventory module: packages, network, hardware, OS info (all platforms) | 8 days |
| **2.9** | Active response module: command execution with sandboxing | 4 days |

**Milestone:** All core modules operational. Agent can collect FIM events, logs, and inventory and forward to Wazuh server.

### Phase 3: Optimization & Polish (Weeks 11-14)

| Task | Description | Est. Effort |
|---|---|---|
| **3.1** | Resource budgeting system: CPU/RAM monitoring and adaptive throttling | 5 days |
| **3.2** | Power awareness: battery detection, idle detection, profile switching | 4 days |
| **3.3** | SCA module: policy engine with YAML policy support | 5 days |
| **3.4** | Rootcheck module: basic rootkit detection checks | 3 days |
| **3.5** | Performance benchmarking: memory profiling, CPU profiling, I/O profiling | 3 days |
| **3.6** | Binary size optimization: LTO, panic=abort, strip, feature gating | 2 days |

**Milestone:** Agent meets all resource targets. Benchmarked and profiled.

### Phase 4: Edge Detection, Software Inventory & Tenant Rule Distribution (Weeks 15-22)

| Task | Description | Est. Effort |
|---|---|---|
| **4.1** | Local Detection Engine: rule store format, MessagePack schema, mmap loader | 4 days |
| **4.2** | LDE: Aho-Corasick pattern matcher + IOC bloom filter evaluator | 5 days |
| **4.3** | LDE: Behavioral rule state machine (JSON DSL → evaluator) | 5 days |
| **4.4** | LDE: Local Response Dispatcher (block IP, kill process, quarantine) | 4 days |
| **4.5** | LDE: YARA scanner integration (feature-gated, yara-rust) | 4 days |
| **4.6** | LDE: Offline detection queue + server sync on reconnect | 3 days |
| **4.7** | Enhanced Inventory: running software monitor (all platforms) | 5 days |
| **4.8** | Enhanced Inventory: browser extension inventory (Chrome/Firefox/Edge/Safari) | 3 days |
| **4.9** | Enhanced Inventory: SBOM generator (CycloneDX, on-demand) | 4 days |
| **4.10** | TRDS microservice: rule CRUD API, compiler, delta distribution | 8 days |
| **4.11** | IOCFS microservice: feed ingestion, normalization, bloom filter compilation | 6 days |
| **4.12** | SIS microservice: inventory ingestion, CVE matching, dashboard API | 8 days |
| **4.13** | Agent Gateway: mTLS termination, tenant routing, rate limiting | 5 days |
| **4.14** | Integration: agent ↔ TRDS rule pull, hot-reload, version tracking | 4 days |

**Milestone:** Agent performs local detection with tenant-specific rules, collects comprehensive software inventory, and companion microservices manage rule distribution and vulnerability analysis.

### Phase 5: Platform Hardening (Weeks 23-26)

| Task | Description | Est. Effort |
|---|---|---|
| **5.1** | Windows service integration: SCM, installer (.msi), Event Log integration | 5 days |
| **5.2** | macOS launchd integration: plist, .pkg installer, Endpoint Security entitlements | 5 days |
| **5.3** | Linux packaging: .deb, .rpm, systemd unit, capability setup | 4 days |
| **5.4** | Self-update mechanism: download, verify, replace, rollback | 5 days |
| **5.5** | Security hardening: binary signing, config protection, anti-tampering | 4 days |
| **5.6** | Enhanced protocol: TLS 1.3, MessagePack, HTTP/2 (opt-in) | 5 days |

**Milestone:** Production-ready agent with installers for all platforms.

### Phase 6: Testing & Release (Weeks 27-30)

| Task | Description | Est. Effort |
|---|---|---|
| **6.1** | Integration testing: agent <-> Wazuh server (v4.x, v5.x compatibility) | 5 days |
| **6.2** | Platform testing: Windows 10/11, macOS 12-15, Ubuntu/Fedora/Arch | 5 days |
| **6.3** | Performance regression testing: automated benchmarks in CI | 3 days |
| **6.4** | Security audit: fuzzing (cargo-fuzz), dependency audit (cargo-audit) | 4 days |
| **6.5** | Documentation: user guide, admin guide, architecture docs | 3 days |
| **6.6** | Beta release and feedback cycle | 5 days |

**Milestone:** v1.0 release candidate.

---

## 13. Phase 4 Detail: Edge Detection, Software Inventory & Tenant Rule Distribution

This section expands on Phase 4 of the implementation roadmap, detailing the Local Detection Engine, Enhanced Software Inventory module, and the companion microservices that support them.

### 13.1 Local Detection Engine (LDE) Module

The LDE enables the agent to evaluate detection rules locally — without a round-trip to the server — for low-latency threat response at the edge. It consumes events from the Event Bus, matches them against a tenant-specific rule store, and dispatches local responses when a rule fires.

```
Local Detection Engine (LDE)
  |
  +-- Rule Store (mmap, read-only)
  |     - MessagePack-encoded rule bundles
  |     - Versioned: pulled from TRDS, hot-reloaded on update
  |     - Sections: IOC lists, behavioral rules, YARA rule refs
  |
  +-- Micro Rule Evaluator
  |     +-- Aho-Corasick Pattern Matcher
  |     |     - Multi-pattern string search across event fields
  |     |     - Used for IOC domain/hash/IP matching
  |     |
  |     +-- IOC Bloom Filter Evaluator
  |     |     - Pre-compiled bloom filters from IOCFS
  |     |     - O(1) negative lookups for hashes, IPs, domains
  |     |
  |     +-- Behavioral Rule State Machine
  |           - JSON DSL rules compiled to state machines
  |           - Tracks sequences (e.g., "process A spawns B within 5 min")
  |           - Sliding-window counters for threshold rules
  |
  +-- Local Response Dispatcher
  |     - block_ip: platform-native firewall rule insertion
  |     - kill_process: terminate matching PID
  |     - quarantine: move file to quarantine directory + strip execute bits
  |     - notify: emit high-priority alert to Event Bus → server
  |
  +-- YARA Scanner (feature-gated: `yara`)
  |     - On-demand file scanning triggered by FIM events
  |     - Uses yara-rust crate (links libyara)
  |     - Rule files pulled alongside detection rules from TRDS
  |     - Scans rate-limited to 1 file/sec to stay within CPU budget
  |
  +-- Telemetry Forwarder
  |     - All detection events (hit or miss stats) batched to server
  |     - Offline detection queue: SQLite WAL table
  |     - Syncs queued detections on server reconnect
  |
  +-- Offline Detection Queue
        - SQLite WAL-mode table for detections generated while offline
        - Bounded: max 10,000 entries, FIFO eviction
        - Synced to server on reconnect via batched upload
```

**LDE Resource Budget:**

| Component | Memory | CPU | Notes |
|---|---|---|---|
| Rule store (mmap) | 1-2 MB | — | Memory-mapped, OS paging handles eviction |
| Aho-Corasick automaton | 0.5 MB | <0.5% per event batch | Built once per rule reload |
| Bloom filters | 0.25 MB | O(1) per lookup | ~2 MB on disk, partial mmap |
| Behavioral state machines | 0.5 MB | <0.1% | Sliding windows bounded by rule count |
| YARA scanner (optional) | 2 MB | <2% during scan | Only loaded when `yara` feature enabled |
| Offline queue (SQLite) | 0.25 MB | Negligible | Shared WAL with agent state DB |
| **Total (without YARA)** | **~2.5 MB** | **<1%** | |
| **Total (with YARA)** | **~4.5 MB** | **<3% during scan** | |

### 13.2 Enhanced Software Inventory Module

The Enhanced Software Inventory module extends the existing Inventory module with running-software monitoring, browser extension enumeration, and on-demand SBOM generation.

```
Enhanced Software Inventory Module
  |
  +-- Installed Software Tracker (existing, enhanced)
  |     - Package DB watchers (dpkg/rpm/Homebrew/MSI/AppX)
  |     - Event-driven: re-enumerates only on DB change
  |
  +-- Running Software Monitor
  |     Linux:   /proc polling (idle-only, 60s interval) + netlink proc events
  |     macOS:   NSWorkspace notifications + kqueue EVFILT_PROC
  |     Windows: WMI Win32_Process event subscription + ETW process events
  |     Output:  { name, version, pid, path, sha256, started_at, publisher }
  |
  +-- Browser Extension Inventory
  |     Chrome:   ~/.config/google-chrome/*/Extensions/*/manifest.json
  |     Firefox:  ~/.mozilla/firefox/*/extensions.json
  |     Edge:     ~/.config/microsoft-edge/*/Extensions/*/manifest.json
  |     Safari:   ~/Library/Safari/Extensions/ (macOS)
  |     Output:  { browser, ext_id, name, version, permissions[], store_url }
  |     Trigger: FSEvents / inotify on profile directories, plus scheduled (4h)
  |
  +-- SBOM Generator (on-demand)
  |     - Generates CycloneDX 1.5 JSON BOM
  |     - Sources: installed packages + running software + browser extensions
  |     - Triggered by server request or local schedule
  |     - Output written to local file + forwarded to SIS
  |
  +-- Normalized Output Format
        - All inventory sources emit unified JSON schema:
          { source: "installed"|"running"|"browser_ext",
            name, version, publisher, platform_id,
            sha256?, install_path?, detected_at }
        - Batched to server every inventory interval (default: 1h)
        - Delta reporting: only changed entries sent after initial baseline
```

**Enhanced Inventory Resource Budget:**

| Component | Memory | CPU | Notes |
|---|---|---|---|
| Running software monitor | 0.5 MB | <0.1% idle | Event-driven where possible |
| Browser extension cache | 0.25 MB | Negligible | Re-scanned on FS change events |
| SBOM generator | 1 MB (transient) | <2% during generation | On-demand only, freed after output |
| **Total additional** | **~0.75 MB steady** | **<0.2%** | |

### 13.3 Companion Microservices

The Phase 4 companion microservices run server-side within the SN360 Control Plane. They manage rule lifecycle, IOC feeds, and software inventory analysis.

```
+-----------------------------------------------------------------------+
|                        SN360 Control Plane                             |
+-----------------------------------------------------------------------+
|                                                                        |
|  +------------------+  +------------------+  +------------------+      |
|  | Tenant Rule      |  | IOC Feed         |  | Software         |      |
|  | Distribution     |  | Aggregator       |  | Inventory        |      |
|  | Service (TRDS)   |  | Service (IOCFS)  |  | Service (SIS)    |      |
|  +--------+---------+  +--------+---------+  +--------+---------+      |
|           |                      |                      |              |
|  +--------v----------------------v----------------------v---------+    |
|  |                       Message Queue                             |   |
|  |           (rule updates, IOC deltas, inventory batches)         |   |
|  +----------------------------+------------------------------------+   |
|                               |                                        |
|  +----------------------------v------------------------------------+   |
|  |                      Agent Gateway                               |  |
|  |  - mTLS termination          - Tenant routing                    |  |
|  |  - Rate limiting              - Protocol translation             |  |
|  +----------------------------+------------------------------------+   |
|                               |                                        |
+-----------------------------------------------------------------------+
                                |
                    +-----------v-----------+
                    |   WDA Agents (edge)    |
                    +-----------------------+
```

#### 13.3.1 Tenant Rule Distribution Service (TRDS)

The TRDS manages the lifecycle of detection rules across tenants, compiles them into agent-consumable bundles, and distributes delta updates.

**API Endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/tenants/{tid}/rules` | Create a new rule |
| GET | `/api/v1/tenants/{tid}/rules` | List rules (filterable by type, status) |
| PUT | `/api/v1/tenants/{tid}/rules/{rid}` | Update a rule |
| DELETE | `/api/v1/tenants/{tid}/rules/{rid}` | Soft-delete a rule |
| POST | `/api/v1/tenants/{tid}/rules/compile` | Trigger bundle compilation |
| GET | `/api/v1/tenants/{tid}/bundles/latest` | Get latest compiled bundle metadata |
| GET | `/api/v1/tenants/{tid}/bundles/{version}/delta?from={prev}` | Get delta update |

**Rule Types:**

| Type | Format | Agent Evaluation |
|---|---|---|
| IOC list | CSV/STIX → bloom filter + Aho-Corasick | Pattern match on event fields |
| Behavioral | JSON DSL (sequence, threshold, boolean) | State machine evaluation |
| YARA | `.yar` files | File content scanning (feature-gated) |
| Exclusion | Allowlist entries (hash, path, signer) | Skip matching entries |

**Workflow:**

1. Analyst creates/updates rules via API or dashboard
2. TRDS validates rule syntax and compiles to agent-native format
3. Compiled bundle is versioned and stored (S3/MinIO)
4. Delta diff computed against previous bundle version
5. Agents poll for updates (or receive push notification via gateway)
6. Agent downloads delta, applies to local rule store, hot-reloads LDE

**Storage:** PostgreSQL (rule metadata, tenant config) + S3-compatible object store (compiled bundles).

**Footprint:** 2 vCPU, 2 GB RAM per instance. Horizontally scalable behind load balancer.

#### 13.3.2 IOC Feed Aggregator Service (IOCFS)

The IOCFS ingests threat intelligence feeds, normalizes IOCs, and compiles them into optimized data structures for agent consumption.

**Sources:**

| Feed | Format | Refresh Interval |
|---|---|---|
| MISP (self-hosted or community) | MISP JSON | 15 min |
| Abuse.ch (URLhaus, MalBazaar, ThreatFox) | CSV | 1 hour |
| AlienVault OTX | STIX/TAXII 2.1 | 1 hour |
| Custom tenant feeds | CSV/STIX upload | On upload |

**Processing Pipeline:**

1. Ingest: pull/receive IOCs from configured feeds
2. Normalize: map to unified schema `{ type, value, confidence, source, expires_at }`
3. Deduplicate: merge across feeds, keep highest confidence
4. Compile:
   - Bloom filters (one per IOC type: hash, domain, IP, URL) — target FPR: 0.01%
   - Aho-Corasick automaton for string-matchable IOCs
5. Package: MessagePack bundle with version metadata
6. Publish: push to TRDS for inclusion in tenant rule bundles

**Output Size Targets:**

| IOC Type | Typical Count | Bloom Filter Size | Aho-Corasick Size |
|---|---|---|---|
| File hashes (SHA-256) | 500K | ~1.2 MB | N/A (bloom only) |
| Domains | 100K | ~240 KB | ~400 KB |
| IPv4 addresses | 50K | ~120 KB | N/A (bloom only) |
| URLs | 200K | ~480 KB | ~800 KB |
| **Total** | **~850K IOCs** | **~2 MB** | **~1.2 MB** |

**Footprint:** 2 vCPU, 4 GB RAM (bloom filter compilation is memory-intensive). Single instance with HA failover.

#### 13.3.3 Software Inventory Service (SIS)

The SIS ingests software inventory from agents, matches against CVE databases, and provides dashboard APIs for vulnerability visibility.

**Ingest:**

- Receives normalized inventory batches from agents via Agent Gateway
- Stores per-agent inventory snapshots in PostgreSQL (partitioned by tenant)
- Computes diffs: tracks install/uninstall/upgrade events over time

**CVE Matching:**

- NVD CPE dictionary + known exploited vulnerabilities (CISA KEV)
- CPE matching: software name + version → CVE lookup
- Refresh: NVD feed pulled every 2 hours
- Results stored per-agent: `{ cve_id, severity, software_name, version, fix_available }`

**Dashboard Integration:**

| Endpoint | Description |
|---|---|
| `GET /api/v1/tenants/{tid}/inventory` | Aggregated software inventory |
| `GET /api/v1/tenants/{tid}/inventory/{agent_id}` | Per-agent inventory |
| `GET /api/v1/tenants/{tid}/vulnerabilities` | All matched CVEs |
| `GET /api/v1/tenants/{tid}/vulnerabilities/critical` | Critical/high severity CVEs |
| `GET /api/v1/tenants/{tid}/sbom/{agent_id}` | Download agent SBOM (CycloneDX) |

**Storage:** PostgreSQL (inventory + CVE matches, partitioned by tenant). NVD mirror in local cache (~2 GB).

**Footprint:** 2 vCPU, 4 GB RAM per instance. Horizontally scalable for large deployments.

### 13.4 Agent Gateway

The Agent Gateway is the single entry point for all agent-to-server communication in the SN360 control plane.

**Responsibilities:**

- **mTLS termination:** Validates agent client certificates, extracts tenant ID from cert subject
- **Tenant routing:** Routes requests to the correct tenant-scoped backend services
- **Rate limiting:** Per-agent and per-tenant rate limits to prevent abuse
- **Protocol translation:** Accepts agent binary protocol, translates to internal gRPC/HTTP
- **Connection pooling:** Maintains persistent connections to backend services

**Configuration:**

| Parameter | Default | Description |
|---|---|---|
| `listen_address` | `0.0.0.0:8443` | mTLS listener |
| `max_connections` | 50,000 | Per-instance connection limit |
| `rate_limit_per_agent` | 100 req/min | Per-agent request rate limit |
| `rate_limit_per_tenant` | 10,000 req/min | Per-tenant aggregate limit |
| `backend_pool_size` | 64 | Connection pool to each backend service |

**Footprint:** 2 vCPU, 1 GB RAM per instance. Horizontally scalable behind L4 load balancer.

### 13.5 Updated Resource Budget

With the LDE and Enhanced Inventory modules, the WDA memory projection is updated:

```
WDA (projected, with Phase 4 modules):
  RSS: ~15 MB (without YARA), ~17 MB (with YARA)
    - Agent core + runtime:       2.0 MB
    - SQLite FIM DB (mmap):       3.0 MB
    - Log collector buffers:      1.0 MB
    - Inventory cache:            1.0 MB
    - Enhanced inventory:         0.75 MB  (running sw + browser ext)
    - Network/TLS buffers:        1.0 MB
    - SCA policy cache:           0.5 MB
    - LDE rule store (mmap):     1.5 MB
    - LDE Aho-Corasick + bloom:  0.75 MB
    - LDE behavioral state:      0.5 MB
    - LDE offline queue:         0.25 MB
    - Stack (2-3 threads):       1.5 MB
    - Other:                     1.25 MB
    - YARA scanner (optional):  +2.0 MB
```

### 13.6 Updated Configuration

The following sections are added to `config.yaml` for the new Phase 4 modules:

```yaml
modules:
  # ... existing modules ...

  local_detection:
    enabled: true
    rule_pull_interval: 300      # seconds, poll TRDS for rule updates
    offline_queue_max: 10000     # max queued detections while offline
    response_actions:
      block_ip: true
      kill_process: true
      quarantine: true
    yara:
      enabled: false             # feature-gated, requires 'yara' build feature
      scan_rate_limit: 1         # files per second
      max_file_size_mb: 50       # skip files larger than this
    bloom_filter:
      false_positive_rate: 0.01
    behavioral:
      max_window_sec: 300        # max sliding window for sequence rules
      max_tracked_entities: 5000 # max concurrent entity state machines

  enhanced_inventory:
    enabled: true
    running_software:
      enabled: true
      interval: 60               # seconds between running-sw snapshots
    browser_extensions:
      enabled: true
      browsers:
        - chrome
        - firefox
        - edge
        - safari
      interval: 14400            # seconds (4h) scheduled re-scan
    sbom:
      enabled: true
      format: cyclonedx          # cyclonedx | spdx (future)
      on_demand: true            # allow server-triggered generation
      scheduled_interval: 86400  # seconds (24h), 0 to disable scheduled
```

### 13.7 New Crate Structure

Two new crates are added to the workspace:

- **`wda-local-detection`** — Local Detection Engine: rule store, pattern matching, behavioral evaluation, response dispatch, YARA integration (feature-gated).
- **`wda-enhanced-inventory`** — Enhanced Software Inventory: running software monitor, browser extension inventory, SBOM generator.

**New workspace dependencies:**

| Crate | Version | Purpose |
|---|---|---|
| `aho-corasick` | 1 | Multi-pattern string matching for IOC detection |
| `bloomfilter` | 1 | Bloom filter data structure for O(1) IOC lookups |
| `yara` | 0.28 (optional) | YARA rule scanning via yara-rust bindings |
| `cyclonedx-bom` | 0.7 | CycloneDX SBOM generation |

---

## 14. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Wazuh server protocol changes in v5.x | Medium | High | Maintain protocol compatibility layer; engage with Wazuh community |
| macOS Endpoint Security Framework restrictions | Medium | Medium | Fallback to FSEvents; apply for Apple developer entitlements early |
| Windows SmartScreen / AV false positives | Medium | Medium | EV code signing certificate; submit to Microsoft for whitelisting |
| Rust async ecosystem maturity gaps | Low | Medium | tokio is battle-tested; fallback to synchronous I/O for edge cases |
| Performance regression in specific modules | Medium | Low | Automated benchmarks in CI; per-module resource budgets |
| SQLite performance under high event rates | Low | Medium | WAL mode + batched writes; consider redb as alternative |
| Binary size exceeding target | Low | Low | Feature gates, LTO, `panic=abort`, `opt-level=z` for size |

---

## 15. Appendix: Wazuh Source Analysis

### A. Module Dependency Graph (Agent Build)

```
CMakeLists.txt agent target dependencies:

  client-agent  (core daemon)
    -> shared (26K LoC utility library)
    -> config (configuration parsing)
    -> shared_modules/utils
    -> shared_modules/http-request
    -> shared_modules/agent_metadata

  syscheckd (FIM)
    -> shared
    -> shared_modules/dbsync (database sync)
    -> shared_modules/sync_protocol
    -> shared_modules/file_helper

  logcollector (log collection)
    -> shared
    -> config

  rootcheck (rootkit detection)
    -> shared

  data_provider (system inventory)
    -> shared
    -> shared_modules/utils

  wazuh_modules (SCA, syscollector)
    -> shared
    -> shared_modules/* (multiple)
    -> data_provider

  active-response
    -> shared

  os_execd (active response daemon)
    -> shared
    -> config

  External dependencies (all compiled from source):
    cJSON, zlib, OpenSSL, cURL, libYAML, SQLite, msgpack,
    RocksDB, PCRE2, Flatbuffers, audit-userspace, etc.
```

### B. Lines of Code Summary

| Component | LoC (C/C++) | WDA Estimate (Rust) | Reduction |
|---|---|---|---|
| client-agent | 4,236 | ~2,000 | 53% |
| syscheckd | 6,033 | ~3,000 | 50% |
| logcollector | 10,818 | ~3,500 | 68% |
| rootcheck | 4,503 | ~1,500 | 67% |
| data_provider | 24,252 | ~6,000 | 75% |
| wazuh_modules | 74,724 | ~4,000 | 95% (server features removed) |
| shared | 26,806 | ~3,000 | 89% (Rust stdlib + crates) |
| shared_modules | 106,544 | ~2,000 | 98% (replaced by Rust crates) |
| config | ~8,000 | ~1,500 | 81% |
| os_execd / active-response | ~3,000 | ~1,000 | 67% |
| **Total** | **~269,000** | **~27,500** | **~90%** |

The dramatic reduction comes from: (1) Rust's standard library and ecosystem replacing custom C utility code, (2) removing server-only features, (3) replacing custom crypto/HTTP/JSON with well-maintained crates, and (4) Rust's expressiveness reducing boilerplate.

### C. Memory Usage Comparison (Projected)

```
Current Wazuh Agent (typical Linux endpoint):
  RSS: ~85 MB
    - Python runtime:     35 MB
    - RocksDB:            12 MB
    - SQLite FIM DB:      10 MB
    - Shared libraries:    8 MB
    - Thread stacks:       6 MB (10+ threads x ~512 KB)
    - Event buffers:       5 MB
    - Other:               9 MB

WDA (projected same endpoint):
  RSS: ~12 MB
    - Agent core + runtime:  2 MB
    - SQLite FIM DB (mmap):  3 MB
    - Log collector buffers: 1 MB
    - Inventory cache:       1 MB
    - Network/TLS buffers:   1 MB
    - SCA policy cache:      0.5 MB
    - Stack (2-3 threads):   1.5 MB
    - Other:                 2 MB
```

---

## 16. Local Wazuh Server Test Environment

This section describes how to stand up a **local Wazuh server** for development and integration testing of the WDA agent. The recommended approach uses the official Wazuh Docker deployment — it is the fastest way to get the full stack (manager, indexer, dashboard) running on a single machine.

### 16.1 Prerequisites

- **Docker Engine 24+** and **Docker Compose v2**
- At least **4 GB RAM** available for the server stack
- The following ports must be available on the host:
  | Port | Service |
  |---|---|
  | 1514 | Agent communication (events) |
  | 1515 | Agent enrollment (authd) |
  | 443 | Wazuh dashboard (web UI) |
  | 55000 | Wazuh manager API |

### 16.2 Download & Start the Wazuh Server (Docker)

```bash
# Clone the official Wazuh Docker deployment
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node

# Generate self-signed certificates for the stack
docker compose -f generate-indexer-certs.yml run --rm generator

# Start the Wazuh server stack (manager + indexer + dashboard)
docker compose up -d
```

> **Note:** The stack includes three containers — `wazuh.manager`, `wazuh.indexer`, and `wazuh.dashboard`. The manager is the component the WDA agent communicates with.
>
> **Default credentials:** `admin` / `SecretPassword` (for the dashboard at https://localhost:443).

### 16.3 Verify the Server Is Running

```bash
# Check all containers are healthy
docker compose ps

# Verify the manager API is responding
curl -k -u admin:SecretPassword https://localhost:55000/?pretty
```

### 16.4 Configure the Server for WDA Testing

**Retrieve the enrollment password** from the manager container:

```bash
docker exec -it single-node-wazuh.manager-1 cat /var/ossec/etc/authd.pass
```

**Optionally set a known enrollment password** (easier for automated testing):

```bash
docker exec -it single-node-wazuh.manager-1 bash -c \
  'echo "MyTestPassword" > /var/ossec/etc/authd.pass && /var/ossec/bin/wazuh-control restart'
```

**Ensure the manager is listening** on ports 1514 (events) and 1515 (enrollment):

```bash
docker exec -it single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-control status
```

### 16.5 Enroll & Connect the WDA Agent

Create a test configuration file (`test-config.yaml`) pointing at the local Docker server:

```yaml
agent:
  server:
    address: "127.0.0.1"
    port: 1514
    protocol: tcp
  enrollment:
    server: "127.0.0.1"
    port: 1515
    password: "MyTestPassword"
    auto_enroll: true
  keepalive_interval: 30   # shorter for testing

modules:
  fim:
    enabled: true
    directories:
      - path: /tmp/wda-test-fim
        recursive: true
        realtime: true
    scan_interval: 60
  logcollector:
    enabled: true
    sources:
      - type: file
        path: /tmp/wda-test-logs/test.log
        format: syslog
  sca:
    enabled: true
    scan_on_idle: false     # run immediately for testing
  inventory:
    enabled: true
    interval: 60
  active_response:
    enabled: true
    actions:
      - block_ip

resource_limits:
  max_cpu_percent: 10
  max_memory_mb: 100
  battery_mode: normal
  idle_detection: false
```

Build and run the agent against the local server:

```bash
# Build the agent
cargo build

# Run with the test config
RUST_LOG=debug cargo run --bin wda-agent -- --config ./test-config.yaml
```

### 16.6 Functional Verification Checklist

Use the following checklist to verify each module works against the local test server:

| Module | Test Procedure | Expected Server-Side Result |
|---|---|---|
| **Enrollment** | Start the agent; it should auto-enroll | Agent appears in `docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -l` |
| **Keepalive** | Agent stays running | Agent shows as "Active" in the Wazuh dashboard (Agents page) |
| **FIM** | `mkdir -p /tmp/wda-test-fim && echo "test" > /tmp/wda-test-fim/hello.txt` | FIM alert in Dashboard → Security Events with rule.groups containing "syscheck" |
| **Log Collection** | `mkdir -p /tmp/wda-test-logs && echo "Apr 17 12:00:00 localhost sshd[1234]: Failed password for root" >> /tmp/wda-test-logs/test.log` | Log event visible in Dashboard → Security Events |
| **Inventory** | Agent sends inventory on startup | Dashboard → Agents → (agent) → Inventory shows packages, network, OS info |
| **SCA** | Agent runs SCA policies | Dashboard → Agents → (agent) → SCA shows policy results |
| **Active Response** | Trigger from server: `/var/ossec/bin/agent_control -b 10.0.0.99 -f firewall-drop0 -u <AGENT_ID>` | Agent logs show active response execution |

### 16.7 Teardown

```bash
cd wazuh-docker/single-node
docker compose down -v   # -v removes volumes (all data)
```

### 16.8 Alternative: Bare-Metal / VM Server Install

For longer-lived test environments, you can install the Wazuh server directly on a Linux VM using the official quickstart:

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && \
  sudo bash ./wazuh-install.sh -a
```

This installs the full stack (manager + indexer + dashboard) on a single machine. Refer to the official docs at https://documentation.wazuh.com/current/quickstart.html for details.

---

## 17. Summary

The Wazuh Desktop Agent (WDA) is a ground-up reimagining of the Wazuh endpoint agent for user-facing devices. By leveraging Rust's zero-cost abstractions, event-driven OS APIs, adaptive resource management, and a modular architecture that loads only what's needed, WDA achieves a 7-10x reduction in memory usage and near-invisible CPU impact compared to the current agent.

The 30-week implementation roadmap breaks the work into six clear phases, each with concrete milestones and deliverables. The architecture maintains protocol compatibility with existing Wazuh servers while providing an upgrade path to enhanced communication modes.

**Key differentiators from the current Wazuh agent:**
1. **Event-driven everywhere** -- no polling loops for file/log monitoring
2. **Single-threaded async** -- minimal thread overhead
3. **Adaptive scheduling** -- respects user activity and power state
4. **90% code reduction** -- leveraging Rust ecosystem and removing server features
5. **Cross-platform from day one** -- unified PAL instead of scattered `#ifdef`s
6. **Memory-bounded** -- every component has a hard memory budget
7. **Edge detection** -- local rule evaluation and response without server dependency
8. **Comprehensive software inventory** -- running apps, browser extensions, SBOM generation with event-driven tracking

---

*This document is a living proposal. Implementation details may evolve as development progresses and real-world benchmarking data becomes available.*
