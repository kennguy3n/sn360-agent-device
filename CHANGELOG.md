# Changelog

All notable changes to SN360 Desktop Agent (SDA) are documented
here. This project follows
[Semantic Versioning](https://semver.org) once it reaches 1.0;
pre-1.0 releases may introduce breaking config changes at each
minor bump.

## [Unreleased]

### Added

- **Phase 5.6 enhanced protocol (opt-in).** TLS 1.3 transport
  (`rustls`, TLS 1.3 only, optional CA bundle + SHA-256 cert
  pinning), MessagePack event serialisation (`rmp-serde`), and
  HTTP/2 transport with ALPN `h2`. All three are individually
  toggleable under `server.enhanced` and default **off** to stay
  compatible with Wazuh 4.x managers.
  (`crates/sda-comms/src/transport/tls.rs`,
   `crates/sda-comms/src/transport/http2.rs`,
   `crates/sda-comms/src/msgpack.rs`)
- **E2E compatibility harness against Wazuh 4.7.5.**
  `tests/docker-compose-v4.7.yml` +
  `tests/scripts/run-compat-e2e.sh` + `make e2e-compat` run the
  standard 14-assertion suite against an older v4.x manager to
  catch protocol drift.
- **Platform CI matrix expansion.** `ubuntu-22.04`,
  `ubuntu-24.04`, `macos-13`, `macos-14`, `windows-2022`. Fedora
  and Arch are covered by the manual checks in
  `docs/platform-testing.md`.
- **Performance regression gate.**
  `tests/scripts/benchmark-regression.sh` + `make benchmark-ci`
  fails CI if idle RSS > 15 MB, idle CPU > 0.1 %, binary > 5 MB,
  or FIM burst peak > 3 %. Runs nightly on CI with artifact
  upload.
- **Dependency audit gate.** `cargo audit --deny warnings` is
  now a required CI check.
- **Fuzzing harness.** Standalone `fuzz/` crate with cargo-fuzz
  targets for `WazuhMessage::decode`, `decompress_payload`,
  `MessagePackSerializer::decode_event`, and
  `RuleBundle::from_msgpack`. Setup and coverage goals documented
  in `docs/security-audit.md`.
- **Documentation set.** `docs/user-guide.md`,
  `docs/admin-guide.md`, `docs/architecture.md`,
  `docs/configuration-reference.md`,
  `docs/platform-testing.md`, `docs/security-audit.md`.

### Fixed

- **Updater re-download loop (A1, PR #49 review).**
  `sda_updater::run_once` now returns `Option<String>` and
  `sda_updater::run` updates its in-memory `current_version`
  after each install so the next manifest fetch does not retry
  the same version forever.
- **Version comparison trailing-zero bug (A2, PR #49 review).**
  `sda_updater::checker::is_newer` pads both parsed versions to
  the same length before comparing, so `is_newer("0.2.0",
  "0.2") == false` and `is_newer("0.2.1", "0.2") == true`.
- **Linux abstract socket handling in tamper-watchdog (A3, PR
  #50 review).** `sda_agent::tamper::notify` detects
  `@`-prefixed paths and uses
  `std::os::linux::net::SocketAddrExt::from_abstract_name`;
  non-Linux callers fall through to the filesystem socket path.
- **32-bit Linux ioctl constants (A4, PR #50 review).**
  `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS` are derived from
  `std::mem::size_of::<libc::c_long>()` so 32-bit builds encode
  the correct size field.
- **Windows MSI default binary path (A5, PR #48 review).**
  `packaging/windows/build-msi.ps1` defaults to
  `target\release\sda-agent.exe` instead of the target-triple
  path, matching `make release`.
- **WiX NeverOverwrite on config component (A6, PR #48 review).**
  `packaging/windows/sda-agent.wxs` now carries
  `NeverOverwrite="yes"` so operator edits to `config.yaml`
  survive upgrades.
- **systemd ReadOnlyPaths dead code (A7, PR #48 review).** The
  misleading `ReadOnlyPaths=/etc/sn360-desktop-agent` was removed
  from `packaging/systemd/sda-agent.service`; a comment explains
  that the config directory is intentionally writable so
  enrolment can persist `client.keys`.

### Changed

- `ServerConfig::default` now includes
  `enhanced: EnhancedProtocolConfig::default()` so older configs
  round-trip through serde without a "missing field" error.

## [0.1.0] – prior work

Earlier merged milestones (pre-beta). The roadmap-level summary
lives in `PROGRESS.md`; representative PRs:

- PR #48 — Installer/packaging work (`.deb`, `.rpm`, `.pkg`,
  `.msi`, hardened systemd unit).
- PR #49 — Self-update: signed manifest fetch, atomic swap, rollback.
- PR #50 — Privilege separation and tamper protection with
  watchdog restart.
- PR #54 — Rename wda- → sda- and fix E2E cleanup hang.

---

## Release preparation status (Phase 6 task 6.6)

Code, documentation, and CI infrastructure for the beta release
live in this branch. The remaining release-infrastructure items
(signed binary builds for Linux x86_64, macOS x86_64/aarch64,
Windows x86_64; `.deb`, `.rpm`, `.pkg`, `.msi` publishing; GitHub
Release creation via the release API; tag `v0.9.0-beta.1`) require
release credentials and signing keys that are not available from
this agent session. Maintainers should:

1. Create and push the tag locally:
   `git tag -s v0.9.0-beta.1 -m "Beta 1 release"`.
2. Run `make deb rpm pkg msi` on the appropriate build host(s).
3. Sign artefacts per the org signing policy.
4. Publish via the GitHub Release API with the `CHANGELOG.md`
   entries above as the release notes body.
