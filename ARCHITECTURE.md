# SN360 Desktop Agent — Architecture (At a Glance)

Quick orientation for the SDA codebase. For the full reference —
PAL design, protocol details, testing layers, resource budgeting
— see [`docs/architecture.md`](./docs/architecture.md). For the
original design rationale see
[`device-agent-proposal.md`](./device-agent-proposal.md).

## Crate map

| Crate | Responsibility |
|---|---|
| `sda-agent` | Main binary — entry point, module orchestration, wire-format mapping |
| `sda-core` | Shared types, YAML config loading, agent lifecycle, power broadcast |
| `sda-pal` | Platform Abstraction Layer (filesystem, power, service, firewall) |
| `sda-event-bus` | Async event bus with priority queues and back-pressure |
| `sda-comms` | Communication layer — SN360 native protocol (TLS 1.3, MessagePack, HTTP/2) and optional legacy SIEM protocol adapter |
| `sda-fim` | File Integrity Monitoring module |
| `sda-logcollector` | Log collection module (file, journald, Event Log, OSLog) |
| `sda-inventory` | System inventory module (syscollector-compatible) |
| `sda-sca` | Security Configuration Assessment module |
| `sda-active-response` | Active response module |
| `sda-rootcheck` | Rootkit detection module |
| `sda-local-detection` | Local Detection Engine (Aho-Corasick + IOC bloom + YARA + offline queue) |
| `sda-enhanced-inventory` | Running software, browser extensions, CycloneDX SBOM |

## Event flow

```
+-------------------------------------------------------------+
|                       sda-agent (bin)                       |
+-------------------------------------------------------------+
|                        sda-core                             |
|   lifecycle | config | signals | module manager | power     |
+-------------------------------------------------------------+
|                     sda-event-bus                           |
|     bounded broadcast + server-bound mpsc + priorities      |
+-------------------------------------------------------------+
|  sda-fim  | sda-logcollector | sda-inventory | sda-sca   |  |
|  sda-active-response | sda-rootcheck | sda-local-detection |
|  sda-enhanced-inventory | sda-comms                        |
+-------------------------------------------------------------+
|                        sda-pal                              |
|   FS watcher | log source | sysinfo | service | firewall    |
|                  | power monitor |                          |
+-------------------------------------------------------------+
|     Linux (inotify, journald, nftables, netlink)            |
|     macOS (FSEvents, OSLog, pfctl, IOKit)                   |
|     Windows (ReadDirectoryChangesW, Event Log, SCM)         |
+-------------------------------------------------------------+
```

See [`docs/architecture.md`](./docs/architecture.md) for the full reference.
