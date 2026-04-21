# Security Audit

SDA runs with elevated privileges on end-user devices, so every
byte that enters an agent process is an attacker-reachable input.
Phase 6 task 6.4 adds two continuous audit surfaces to the repo:

1. **Dependency auditing** via `cargo audit` in CI.
2. **Differential fuzzing** of the highest-risk parsers via
   `cargo-fuzz` + libFuzzer.

## `cargo audit`

A `cargo-audit` job in `.github/workflows/ci.yml` installs the
latest `cargo-audit` from crates.io and runs:

```sh
cargo audit --deny warnings
```

This fails CI on any unpatched advisory against a direct or
transitive dependency. Warnings-only advisories (e.g. unmaintained
crates) also fail so they cannot silently accumulate. To reproduce
locally:

```sh
cargo install --locked cargo-audit
cargo audit
```

If an advisory is acceptable (e.g. unreachable code path), document
the decision inline via `deny.toml` or the RustSec ignore key rather
than disabling the gate globally.

## Fuzzing harness

The `fuzz/` directory at the repo root is a standalone cargo-fuzz
crate (its own `[workspace]`) so it does not participate in the
main stable build. Setup:

```sh
rustup toolchain install nightly
cargo +nightly install --locked cargo-fuzz
```

Run a target for one minute:

```sh
cd fuzz
cargo +nightly fuzz run protocol_decode -- -max_total_time=60
```

### Targets

| Target                     | Function under fuzz                                              | Rationale                                                              |
|----------------------------|------------------------------------------------------------------|------------------------------------------------------------------------|
| `protocol_decode`          | `sda_comms::protocol::WazuhMessage::decode`                      | First parser on every TCP frame from `remoted`; a panic = crash loop.  |
| `protocol_decompress`      | `sda_comms::protocol::decompress_payload`                        | zlib payloads are attacker-controlled; must fail gracefully.            |
| `msgpack_event_decode`     | `sda_comms::msgpack::MessagePackSerializer::{decode_event,decode_kind}` | Phase 5.6 enhanced protocol decoder; rmp-serde panics on bad input.   |
| `rule_store_msgpack`       | `sda_local_detection::rule_store::RuleBundle::from_msgpack`      | TRDS bundle decoder runs before signature verification.                |

### Corpus management

Each target owns a corpus directory at `fuzz/corpus/<target>/`
and a crashes directory at `fuzz/artifacts/<target>/`. These are
git-ignored by default — regenerate the corpus after a parser
change so libFuzzer's mutation engine has diverse seeds to work
from. Seed corpora can be committed under
`fuzz/seeds/<target>/` for reproducibility.

### Coverage goals

The Phase 6 exit criteria for fuzzing are:

- Each target runs in CI nightly for at least 5 minutes with
  `-max_total_time=300` and 0 crashes.
- Coverage (`cargo +nightly fuzz coverage`) for each parser module
  is ≥ 80 % of lines.

Nightly CI wiring for the fuzz targets is tracked as a follow-up
(release infrastructure item) in PROGRESS.md § Phase 6 6.4.

## Reporting a vulnerability

Confirmed vulnerabilities should be emailed to
`security@uney.com` with `[sda]` in the subject line. Do **not**
open public GitHub issues for unpatched security reports.
