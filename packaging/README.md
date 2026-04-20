# Packaging

Installer recipes for the Wazuh Desktop Agent across Linux, macOS, and
Windows. Each platform has a build script that takes an
already-compiled release binary (`cargo build --release -p wda-agent`)
and emits a ready-to-install package into `dist/`.

```
packaging/
├── config/
│   └── config.yaml              # Default /etc/wazuh-desktop-agent/config.yaml
├── systemd/
│   └── wda-agent.service        # systemd unit (Type=simple, User=wda)
├── debian/
│   ├── control, conffiles, postinst, prerm, postrm
│   └── build-deb.sh             # dpkg-deb driver
├── rpm/
│   ├── wda-agent.spec
│   └── build-rpm.sh             # rpmbuild driver
├── macos/
│   ├── com.wazuh.desktop-agent.plist
│   ├── scripts/{preinstall,postinstall}
│   └── build-pkg.sh             # pkgbuild + productbuild driver
└── windows/
    ├── wda-agent.wxs            # WiX 3.x manifest, registers Windows Service
    └── build-msi.ps1            # candle + light driver
```

## Install layout

| Path                                      | Purpose                                  | Platform |
|-------------------------------------------|------------------------------------------|----------|
| `/usr/bin/wda-agent`                      | Agent binary                             | Linux    |
| `/usr/local/bin/wda-agent`                | Agent binary                             | macOS    |
| `C:\Program Files\WazuhDesktopAgent\wda-agent.exe` | Agent binary                  | Windows  |
| `/etc/wazuh-desktop-agent/config.yaml`    | Main config (conffile, preserved on upgrade) | Linux/macOS |
| `/etc/wazuh-desktop-agent/client.keys`    | Enrollment key, 0600 root:wda            | Linux/macOS |
| `/etc/wazuh-desktop-agent/sca/`           | SCA policies                             | Linux/macOS |
| `/var/lib/wazuh-desktop-agent/`           | State (FIM DB, rootcheck baseline, LDE)  | Linux/macOS |
| `/var/log/wazuh-desktop-agent/`           | Log files                                | Linux/macOS |
| `C:\ProgramData\WazuhDesktopAgent\`       | State                                    | Windows  |

## Service registration

- **Linux** — `systemctl enable --now wda-agent.service` (installed by
  `postinst`/`%post`). Unit runs as user `wda`, `Restart=on-failure`,
  `RestartSec=5`, hardened via `ProtectSystem=strict` and
  `NoNewPrivileges=true`.
- **macOS** — launchd daemon `com.wazuh.desktop-agent`, loaded by the
  `.pkg` postinstall script. `KeepAlive.Crashed=true` so launchd
  restarts the agent on unexpected exit.
- **Windows** — Windows Service `WazuhDesktopAgent` registered by the
  MSI (`ServiceInstall`). Recovery configured to restart on first,
  second, and third failures with a 5-second delay (matches
  `RestartSec=5` on Linux).

## Building

```bash
# All platforms share the same release binary for their native arch:
cargo build --release -p wda-agent

# Linux .deb (run on Debian/Ubuntu with dpkg-dev installed)
make deb

# Linux .rpm (run on Fedora/RHEL-family with rpm-build installed)
make rpm

# macOS .pkg (run on macOS)
make pkg

# Windows .msi (run on Windows with WiX Toolset 3.x on PATH)
make msi
```

The underlying scripts accept `BIN=...`, `VERSION=...`, and
`OUT_DIR=...` environment overrides so release jobs that compile
binaries via cross-compilation can point at the right target
directory (e.g. `BIN=target/x86_64-unknown-linux-gnu/release/wda-agent`).
