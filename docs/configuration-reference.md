# SDA Configuration Reference

Canonical reference for every field understood by
`AgentConfig` in [`crates/sda-core/src/config.rs`](../crates/sda-core/src/config.rs).
Defaults shown here are what the agent uses when the field is
absent from `config.yaml`; see `tests/sda-test-config.yaml` for
an end-to-end working example.

---

## Top-level shape

```yaml
server:            # required — connection to the SN360 Control Plane
enrollment:        # required if auto-enrolling
modules:           # optional — per-module toggles, defaults enable all
updater:           # optional — self-update configuration
resource_limits:   # optional — per-host budget overrides
logging:           # optional — RUST_LOG-style filter override
legacy_adapter:    # optional — only relevant when built with the `legacy-siem` Cargo feature
```

## `server`

```yaml
server:
  address: "sn360.example.com"     # hostname or IP of the SN360 Agent Gateway
  port: 443                         # default: 1514 (override for native HTTP/2)
  protocol: "http2"                 # "http2" (default) | "tcp" | "udp" (legacy adapter only)
  keepalive_interval: 600           # seconds, default: 600
  enhanced:                         # SN360 native protocol knobs (all default on)
    tls: true                        # TLS 1.3 transport, default: true
    serialization: "msgpack"         # "msgpack" (default) | "json"
    tls_ca_bundle_path: null         # optional path to PEM bundle
    tls_pinned_sha256: null          # optional 64-char hex leaf fingerprint
```

- `enhanced.tls = true` is the default and switches the comms
  layer onto `rustls` with TLS 1.3 enforced
  (`rustls::version::TLS13`). Flip this off only when the optional
  legacy SIEM adapter is compiled in and you need to talk to a
  legacy manager that does not offer TLS on port 1514.
- `enhanced.serialization = "msgpack"` is the default and encodes
  events with `rmp-serde`; 50–70 % smaller on inventory-heavy
  payloads. Use `"json"` only when talking to a legacy SIEM
  manager through the adapter.
- `protocol = "http2"` is the default and switches to the native
  HTTP/2 transport. It requires `enhanced.tls = true` — HTTP/2 is
  only spoken over TLS with ALPN `h2`; plain-text h2c is not
  supported. `"tcp"` and `"udp"` are accepted only for the legacy
  SIEM adapter path.

## `enrollment`

```yaml
enrollment:
  server: "sn360.example.com"     # SN360 Agent Gateway; defaults to server.address
  port: 1515                        # default: 1515 (legacy adapter only)
  password_file: "/etc/sn360-desktop-agent/enrollment.password"
  auto_enroll: true                 # default: true
  agent_name: null                  # defaults to hostname
  agent_groups: []                  # agent group tags
```

On the SN360 native protocol, enrolment is mTLS against the Agent
Gateway and the issued native identity is persisted alongside the
config. On the legacy SIEM adapter path, enrolment talks to the
legacy `authd`-compatible daemon on port 1515 and writes
`client.keys` into the same directory as `config.yaml`. Either
way, the systemd unit's `ReadWritePaths=` must include this
directory or enrolment will fail with `EACCES`.

## `modules`

Each module has an `enabled: bool` and a module-specific subsection.
Omitting a module leaves it on with defaults.

### `modules.fim`

```yaml
modules:
  fim:
    enabled: true                   # default
    directories:
      - path: /etc
        recursive: true
        realtime: true
        check_sha256: true
      - path: /home
        recursive: true
        exclude: ["*.tmp", ".cache/**"]
    scan_interval: 43200             # seconds between idle baseline scans (12 h)
    batch_size: 500                  # max files per hash burst
```

### `modules.logcollector`

```yaml
modules:
  logcollector:
    enabled: true
    sources:
      - type: file                   # file | journald | eventlog | oslog
        path: /var/log/auth.log
        format: syslog
      - type: journald
        units: [sshd, sudo]
    max_lines_per_batch: 100
```

### `modules.inventory`

```yaml
modules:
  inventory:
    enabled: true
    collect: [packages, network, hardware, os, processes]
    interval: 3600                   # seconds between full refreshes
```

### `modules.sca`

```yaml
modules:
  sca:
    enabled: true
    policies:
      - /etc/sn360-desktop-agent/policies/cis_ubuntu_22_04.yaml
    scan_interval: 900
    scan_on_idle: true
```

### `modules.rootcheck`

```yaml
modules:
  rootcheck:
    enabled: true
    signature_paths: [/etc/rootcheck/signatures.json]
    scan_interval_secs: 86400
```

### `modules.active_response`

```yaml
modules:
  active_response:
    enabled: true
    allowed_commands: [block_ip, kill_process]
    command_timeout_secs: 30
```

### `modules.local_detection`

```yaml
modules:
  local_detection:
    enabled: true
    rule_bundle_path: /var/lib/sn360-desktop-agent/rules.mp
    yara_rules_dir: /var/lib/sn360-desktop-agent/yara
    offline_queue_capacity: 10000
```

### `modules.enhanced_inventory`

```yaml
modules:
  enhanced_inventory:
    running_software_enabled: true
    browser_extensions_enabled: true
    sbom_enabled: true
    scan_interval_secs: 10           # tick cadence per scanner
```

## `updater`

```yaml
updater:
  enabled: false
  manifest_url: "https://updates.sn360.example.com/desktop-agent/manifest.json"
  public_key_pem: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
  poll_interval_secs: 21600           # 6 h
```

## `resource_limits`

```yaml
resource_limits:
  max_cpu_percent: 3
  max_memory_mb: 50
  battery_mode: adaptive             # adaptive | minimal | normal
  idle_detection: true
```

## `logging`

```yaml
logging:
  filter: "info,sda_fim=debug"
```

The filter string uses the `tracing-subscriber` env-filter grammar
and overrides `RUST_LOG` if both are set.

---

## `legacy_adapter`

The legacy SIEM protocol adapter is **optional** and compiled in
only when `sda-comms` is built with the `legacy-siem` Cargo
feature. When that feature is off, this stanza is ignored with a
warning. When it is on, use this block to pin a deployment to the
legacy path while migrating off a legacy SIEM manager:

```yaml
legacy_adapter:
  enabled: false                    # default: false
  manager_address: "siem.example.com"
  manager_port: 1514                # legacy TCP/UDP port
  transport: "tcp"                  # "tcp" | "udp"
  enrollment_port: 1515             # authd-compatible enrolment port
```

Switching `legacy_adapter.enabled: true` implies
`server.enhanced.tls = false`, `server.enhanced.serialization =
"json"`, and `server.protocol = "tcp"` for that deployment’s
session — the adapter cannot negotiate the SN360 native protocol
knobs. See
[`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md)
for the clean-room interoperability statement and the
[revised phase plan](./revised-phase-plan.md) for the deprecation
timeline.

---

## Migration notes

- `server.protocol` replaces the legacy `server.transport` field.
- Old configs referencing `wazuh-desktop-agent` paths
  (`/etc/wazuh-desktop-agent/`) are read at startup and a warning
  is logged; move them to `/etc/sn360-desktop-agent/` before the
  next major release.
- The `server.enhanced` stanza is now the **default** path — omit
  it to keep the SN360 native protocol. Explicitly set its fields
  to `false` / `"json"` / `"tcp"` only when routing a specific
  deployment through the optional legacy SIEM adapter.
