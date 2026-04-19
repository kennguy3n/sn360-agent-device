# FIM burst workload test hangs on macOS CI

- **Status:** open, needs investigation
- **Affected test:** `wda_fim::tests::burst_workload::test_burst_does_not_block_event_loop`
- **Source:** `crates/wda-fim/tests/burst_workload.rs`
- **Environments:** GitHub-hosted `macos-latest` (Apple Silicon, macOS 15). Passes on `ubuntu-latest` and `windows-latest`.
- **First observed:** CI for PR #26 (`perf(ci,build): shrink binary <5MB and fix macOS CI runner slowness`), after the new `timeout-minutes: 30` guardrail made the hang visible instead of letting the job run for hours.

## Symptom

On macOS CI the sibling test `test_two_phase_emission_metadata_then_hash` finishes in under a second, then `test_burst_does_not_block_event_loop` prints

```
test test_burst_does_not_block_event_loop has been running for over 60 seconds
```

and never completes. The 30-minute job timeout cancels it. An orphan `burst_workload-*` process is reaped by the runner during cleanup.

## What we know

- The test creates 1000 files in a `tempfile::TempDir`, expects the real-time FIM pipeline to deliver at least 500 events (and 100+ with `hash_sha256` populated) within a 30-second drain window, and asserts that a 100ms tokio interval keepalive keeps ticking throughout.
- A sibling test in the same crate, `baseline_scan_integration::test_baseline_scan_lifecycle`, is already marked `#[ignore]` with the note `"kqueue does not reliably deliver file deletion events on macOS CI"`. The FIM pipeline on macOS is built on `notify` (kqueue-backed on Apple Silicon here), so a similar class of issue is plausible.
- The test was introduced by commit `935e578 perf(fim): lazy hashing, rate limiting, and event batching`. It has never been stable on macOS CI; it was simply invisible before the timeout was added.
- Build (macos-latest) itself passes, so the macOS Rust toolchain and the agent binary compile fine — this is runtime/test-only.

## Suspected causes (not yet verified)

1. **kqueue / `notify` drop events on bursty creates on this runner.** If the crate's event channel fills faster than it is drained, the `notify` backend may coalesce or drop, leaving `events < 500` and the drain loop waiting out its 30s window on every iteration with `hashed == 0`, which should exit, so this alone probably doesn't explain the hang — but combined with (2) it might.
2. **`create_files_burst` happens on the current-thread tokio runtime.** `#[tokio::test]` defaults to the current-thread flavor. The synchronous `std::fs::write` loop runs on the same thread as the async scheduler, starving the keepalive task and the watcher bridge for seconds at a time. Linux/Windows CI is evidently fast enough that the bridge catches up; macOS CI (single Apple-Silicon VM with slow-ish disk) may not be.
3. **The `max_hashes_per_sec = 100` rate limiter** means hashing 1000 files takes ~10s of wall time by design. If the drain loop starts before events arrive and the keepalive stalls slip past 750ms, the assertion on line 125 could be the first failure — but the observed behaviour is a hang, not a panic, which points away from a failing assertion and toward a channel/runtime stall.

## Suggested next steps

- [ ] Reproduce on a local Apple-Silicon macOS machine with `cargo test -p wda-fim --test burst_workload -- --nocapture`.
- [ ] Add `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` and see if the symptom clears. If it does, the root cause is synchronous file I/O starving the current-thread executor and the test should be changed (not ignored).
- [ ] Instrument the drain loop to print `events` / `hashed` periodically so the macOS CI log tells us whether events are arriving at all or whether we're stuck behind `server_rx.recv()`.
- [ ] If the issue is truly `notify`/kqueue flakiness on the runner, follow the existing convention in `baseline_scan_integration.rs` and mark this test `#[cfg_attr(target_os = "macos", ignore = "...")]` with a link to this document.
- [ ] Once resolved, re-add `macos-latest` to any Test matrix entries that had to be dropped because of this test.

## Related PR

- #26 — original macOS CI slowness fix; explicitly chose **not** to modify this test and instead open this follow-up.
