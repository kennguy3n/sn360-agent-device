# SN360 Desktop Agent — Phase Overview

At-a-glance summary of the agent-side delivery phases. For the
detailed delivery log (per-task tables, test counts, PR
references, known gaps) see [`PROGRESS.md`](./PROGRESS.md). For
the design reference for future phases see
[`docs/revised-phase-plan.md`](./docs/revised-phase-plan.md).

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Core plumbing — workspace, config, enrolment, transport, event bus, lifecycle | Done — see [PROGRESS.md § Phase 1](./PROGRESS.md#phase-1--core-plumbing-77) |
| 2 | Detection modules — FIM, log collection, inventory, AR, SCA, rootcheck | Done — see [PROGRESS.md § Phase 2](./PROGRESS.md#phase-2--detection-modules-99) |
| 3 | Gap-fill — server-message receive loop, SCA wiring, rootcheck wiring | Done — see [PROGRESS.md § Phase 3](./PROGRESS.md#phase-3--gap-fill-33) |
| 4 | Edge detection (LDE), enhanced inventory; server-side TRDS/IOCFS/SIS/Gateway are out of scope here | Done (agent-side) — see [PROGRESS.md § Phase 4](./PROGRESS.md#phase-4--edge-detection-software-inventory--tenant-rule-distribution) |
| 5 | Platform hardening — self-update, privilege separation, tamper protection, installers | Done — see [PROGRESS.md § Priority 3 — Phase 5](./PROGRESS.md#priority-3--phase-5-platform-hardening) |
| 5.6 | Enhanced protocol — TLS 1.3 + MessagePack + HTTP/2 (opt-in) | Done — see [PROGRESS.md § Phase 5.6 detail](./PROGRESS.md#phase-56-detail--enhanced-protocol) |
| 6 | Testing & release — E2E + compat harness, perf gate, `cargo audit`, fuzzing, release workflow, docs | Done (publication gated on maintainer action) — see [PROGRESS.md § Phase 6](./PROGRESS.md#phase-6--testing--release) |
| 7 | SN360 native protocol promotion & Control Plane MVP | Not Started — see [revised-phase-plan.md § Phase 7](./docs/revised-phase-plan.md#phase-7--sn360-native-protocol-promotion--control-plane-mvp) |
| 8 | Full Control Plane (TRDS / IOCFS / SIS / Gateway hardening, server-side) | Not Started — see [revised-phase-plan.md § Phase 8](./docs/revised-phase-plan.md#phase-8--full-control-plane) |
| 9 | Legacy SIEM adapter deprecation | Not Started — see [revised-phase-plan.md § Phase 9](./docs/revised-phase-plan.md#phase-9--legacy-deprecation) |

> [`PROGRESS.md`](./PROGRESS.md) is the **delivery log** —
> per-task tables, test counts, PR references, and known gaps for
> phases that have shipped.
> [`docs/revised-phase-plan.md`](./docs/revised-phase-plan.md) is
> the **design reference** for future phases (7–9).
