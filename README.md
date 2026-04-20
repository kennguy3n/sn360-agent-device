# Wazuh Desktop Agent (WDA)

A lightweight, cross-platform security agent for desktop/laptop endpoints, built in Rust. WDA is a modular rewrite of the Wazuh agent optimized for end-user devices — targeting sub-15 MB RAM, <0.1% idle CPU, and invisible operation.

## Features

- **File Integrity Monitoring (FIM)** — real-time filesystem watching via inotify/FSEvents/ReadDirectoryChangesW
- **Log Collection** — file tailing, systemd journal, Windows Event Log, macOS unified logging
- **System Inventory** — packages, network interfaces, hardware, OS info (syscollector-compatible)
- **Security Configuration Assessment (SCA)** — YAML policy evaluation
- **Active Response** — IP blocking, process termination, script execution
- **Rootkit Detection** — signature scanning, hidden process detection, binary integrity checks
- **Local Detection Engine** — edge IOC matching, behavioral rules, YARA scanning (Phase 4)
- **Enhanced Inventory** — running software, browser extensions, SBOM generation (Phase 4)

## Prerequisites

- **Rust 1.75+** (install via [rustup](https://rustup.rs/))
- **Linux:** `pkg-config`, `libssl-dev` (or equivalent for your distro)
- **macOS:** Xcode Command Line Tools
- **Windows:** Visual Studio Build Tools (MSVC)
- **Cross-compilation:** [cross](https://github.com/cross-rs/cross) (`cargo install cross`)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/kennguy3n/sn360-agent-device.git
cd sn360-agent-device

# Debug build
make build

# Run the agent with a config file
cargo run --bin wda-agent -- --config ./tests/wazuh-test-config.yaml

# Release build (optimized for size)
make release
```

## Testing

```bash
# Run all unit tests (237 tests)
make test

# Run linting (format check + clippy)
make lint

# Run E2E tests against a local Wazuh 4.9.2 server (requires Docker)
make e2e

# Run security-focused E2E scenarios (malware drop, brute-force, ransomware,
# IP block, etc.) against a local Wazuh 4.9.2 server
make security-e2e

# Platform-specific E2E
make e2e-macos
make e2e-windows
```

See [PROGRESS.md](./PROGRESS.md) for current test results and benchmarks.

## Cross-Compilation

Build for all supported targets using `cross`:

```bash
make all-targets
```

| Target | Platform |
|---|---|
| `x86_64-unknown-linux-gnu` | Linux x86_64 (glibc) |
| `x86_64-unknown-linux-musl` | Linux x86_64 (static, musl) |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |
| `x86_64-apple-darwin` | macOS Intel |
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows x86_64 |

## Project Structure

```
├── crates/
│   ├── wda-agent/              # Main binary — agent entry point and orchestration
│   ├── wda-core/               # Shared types, config loading, agent lifecycle
│   ├── wda-pal/                # Platform Abstraction Layer (filesystem, power, service)
│   ├── wda-event-bus/          # Async event bus with priority queues and backpressure
│   ├── wda-comms/              # Wazuh protocol communication (enrollment, transport, crypto)
│   ├── wda-fim/                # File Integrity Monitoring module
│   ├── wda-logcollector/       # Log collection module
│   ├── wda-inventory/          # System inventory module (syscollector-compatible)
│   ├── wda-sca/                # Security Configuration Assessment module
│   ├── wda-active-response/    # Active response module
│   ├── wda-rootcheck/          # Rootkit detection module
│   ├── wda-local-detection/    # Local Detection Engine (Phase 4)
│   └── wda-enhanced-inventory/ # Enhanced software inventory (Phase 4)
├── tests/                      # E2E test scripts and configs
├── docs/                       # Additional documentation
├── PROPOSAL.md                 # Architecture & implementation proposal
├── PROGRESS.md                 # Phase completion status, test results, benchmarks
├── benchmark-results.md        # Detailed benchmark data vs. Wazuh 4.9.2
├── Cargo.toml                  # Workspace configuration
├── Cross.toml                  # Cross-compilation targets
├── Makefile                    # Build convenience targets
└── LICENSE                     # GPL-2.0-only
```

## Configuration

WDA uses YAML configuration files. See the test configs for examples:

- [`tests/wazuh-test-config.yaml`](./tests/wazuh-test-config.yaml) — Linux
- [`tests/wazuh-test-config-macos.yaml`](./tests/wazuh-test-config-macos.yaml) — macOS
- [`tests/wazuh-test-config-windows.yaml`](./tests/wazuh-test-config-windows.yaml) — Windows

For a full configuration reference, see the [Configuration section in PROPOSAL.md](./PROPOSAL.md#11-configuration--deployment).

## Local Wazuh Server for Testing

To test against a real Wazuh server, see the [Local Wazuh Server Test Environment section in PROPOSAL.md](./PROPOSAL.md#16-local-wazuh-server-test-environment).

## Documentation

- [**PROPOSAL.md**](./PROPOSAL.md) — Full architecture & implementation proposal
- [**PROGRESS.md**](./PROGRESS.md) — Phase status, test results, known gaps, and next steps
- [**benchmark-results.md**](./benchmark-results.md) — Performance benchmarks vs. Wazuh 4.9.2

## License

GPL-2.0-only — see [LICENSE](./LICENSE).
