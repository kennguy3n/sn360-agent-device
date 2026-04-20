//! Enhanced Software Inventory module for the Wazuh Desktop Agent.
//!
//! Extends the base inventory ([`wda-inventory`]) with:
//!
//! * **Running software monitor** (task 4.7) — periodically snapshots
//!   the process list on Linux, macOS and Windows and emits deltas on
//!   the event bus (see [`running_software`]).
//! * **Browser extensions** (task 4.8) — not yet implemented.
//! * **CycloneDX SBOM** (task 4.9) — not yet implemented.
//!
//! The module publishes
//! [`EventKind::EnhancedInventoryUpdate`](wda_event_bus::EventKind::EnhancedInventoryUpdate)
//! events, which the agent maps to a `MessageType::Syscollector`
//! queue on the Wazuh manager so the new categories land alongside
//! the existing inventory indices.

pub mod running_software;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tracing::{debug, error, info, warn};

use wda_core::config::{AgentConfig, EnhancedInventoryConfig};
use wda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use wda_core::signal::ShutdownSignal;
use wda_event_bus::{Event, EventBus, EventKind, Priority};

use crate::running_software::{enumerate_processes, ProcessEntry};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Enhanced inventory module handle.
pub struct EnhancedInventoryModule {
    status: Arc<AtomicU8>,
}

impl EnhancedInventoryModule {
    /// Spawn the enhanced-inventory run loop and return a [`ModuleHandle`].
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let ei_config = config.modules.enhanced_inventory.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(ei_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "enhanced inventory module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("enhanced_inventory", task)
    }
}

impl Default for EnhancedInventoryModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl AgentModule for EnhancedInventoryModule {
    fn name(&self) -> &'static str {
        "enhanced_inventory"
    }

    fn status(&self) -> ModuleStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleStatus::Running,
            STATUS_STOPPED => ModuleStatus::Stopped,
            STATUS_FAILED => ModuleStatus::Failed,
            _ => ModuleStatus::Initialized,
        }
    }

    fn health(&self) -> ModuleHealth {
        match self.status.load(Ordering::Relaxed) {
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

/// Tracks the previous running-software snapshot so the module can
/// emit deltas instead of a full process list on every tick.
#[derive(Default)]
struct RunningSoftwareState {
    /// Whether we've emitted the baseline (full) snapshot yet.
    baseline_sent: bool,
    /// Last observed processes keyed by PID.
    previous: HashMap<u32, ProcessEntry>,
}

/// Two [`ProcessEntry`] values refer to the same running process when
/// they agree on the fields the OS would actually preserve across PID
/// reuse — i.e. the resolved image name and, when known, the absolute
/// executable path. `started_at` is deliberately ignored because Linux
/// derives it from `clock_ticks_per_sec()` and short-lived processes
/// can round-trip to the same tick boundary; PID reuse is always
/// detectable via a different image name or binary path.
fn same_process(a: &ProcessEntry, b: &ProcessEntry) -> bool {
    a.name == b.name && a.path == b.path
}

/// Publish a single enhanced-inventory event on the shared bus.
///
/// Returns `true` on success; logs a warning and returns `false` if the
/// event bus rejected the event (e.g. the server queue is at capacity).
/// Callers that track delivery (such as the running-software baseline)
/// should only advance their state when this returns `true`.
async fn publish_update(bus: &EventBus, category: &str, data: serde_json::Value) -> bool {
    let event = Event::new(
        "enhanced_inventory",
        // Match `wda-inventory::publish_inventory_event` — inventory
        // snapshots are background telemetry and should queue behind
        // latency-sensitive events once the bus starts scheduling by
        // priority.
        Priority::Low,
        EventKind::EnhancedInventoryUpdate {
            category: category.to_string(),
            data,
        },
    );
    match bus.publish_to_server(event).await {
        Ok(()) => true,
        Err(e) => {
            warn!(error = %e, category, "failed to publish enhanced inventory event");
            false
        }
    }
}

/// Take one running-software snapshot, diff it against the previous
/// state, and emit any changes on the bus.
async fn run_running_software_tick(bus: &EventBus, state: &mut RunningSoftwareState) {
    let processes = match tokio::task::spawn_blocking(enumerate_processes).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "running-software enumeration task panicked");
            return;
        }
    };

    let current: HashMap<u32, ProcessEntry> = processes.into_iter().map(|p| (p.pid, p)).collect();

    if !state.baseline_sent {
        let entries: Vec<&ProcessEntry> = current.values().collect();
        let published = publish_update(
            bus,
            "running_software",
            json!({
                "type": "baseline",
                "count": entries.len(),
                "processes": entries,
            }),
        )
        .await;
        if published {
            state.baseline_sent = true;
            state.previous = current;
        } else {
            // Leave `baseline_sent` false so the next tick retries the
            // full baseline instead of jumping straight to deltas that
            // the manager cannot reconcile.
            debug!("baseline publish failed; will retry on next tick");
        }
        return;
    }

    let mut added: Vec<&ProcessEntry> = Vec::new();
    let mut removed: Vec<&ProcessEntry> = Vec::new();

    for (pid, entry) in &current {
        match state.previous.get(pid) {
            None => added.push(entry),
            Some(prev) if !same_process(prev, entry) => {
                // PID reuse — the kernel handed the same pid to a new
                // process between ticks. Report it as a remove + add so
                // the manager updates its view of that slot instead of
                // silently keeping stale process metadata.
                removed.push(prev);
                added.push(entry);
            }
            Some(_) => {}
        }
    }
    for (pid, entry) in &state.previous {
        if !current.contains_key(pid) {
            removed.push(entry);
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        debug!(
            added = added.len(),
            removed = removed.len(),
            "running-software delta"
        );
        let published = publish_update(
            bus,
            "running_software",
            json!({
                "type": "delta",
                "added": added,
                "removed": removed,
            }),
        )
        .await;
        if !published {
            // Keep the previous snapshot so the next tick re-computes
            // the same delta (plus anything new) instead of silently
            // dropping these process changes.
            debug!("delta publish failed; keeping previous snapshot for retry");
            return;
        }
    }

    state.previous = current;
}

/// Main enhanced-inventory run loop.
async fn run(
    ei_config: EnhancedInventoryConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        running_software_enabled = ei_config.running_software.enabled,
        running_software_interval = ei_config.running_software.interval,
        "enhanced inventory module starting"
    );

    status.store(STATUS_RUNNING, Ordering::Relaxed);

    let mut rs_state = RunningSoftwareState::default();
    let rs_enabled = ei_config.running_software.enabled;
    let rs_interval = Duration::from_secs(ei_config.running_software.interval.max(1));

    if rs_enabled {
        // Emit the baseline snapshot immediately on startup so the
        // manager has a fresh inventory without waiting a full cycle.
        run_running_software_tick(&bus, &mut rs_state).await;
    }

    let mut rs_timer = tokio::time::interval(rs_interval);
    // Consume the immediate first tick — handled above for the baseline.
    rs_timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("enhanced inventory module received shutdown signal");
                break;
            }

            _ = rs_timer.tick(), if rs_enabled => {
                debug!("running-software scan timer fired");
                run_running_software_tick(&bus, &mut rs_state).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("enhanced inventory module stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wda_core::config::RunningSoftwareConfig;
    use wda_event_bus::EventBus;

    fn test_agent_config() -> AgentConfig {
        let mut cfg = AgentConfig::default();
        cfg.modules.enhanced_inventory = EnhancedInventoryConfig {
            enabled: true,
            running_software: RunningSoftwareConfig {
                enabled: true,
                interval: 3600,
            },
        };
        cfg
    }

    #[tokio::test]
    async fn test_publishes_inventory_event() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();
        run_running_software_tick(&bus, &mut state).await;

        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a running-software baseline event")
            .expect("server_rx closed");

        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "baseline");
                assert!(
                    data["count"].as_u64().unwrap() > 0,
                    "baseline must include at least one process, got: {:?}",
                    data
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert!(state.baseline_sent);
        assert!(!state.previous.is_empty());
    }

    #[tokio::test]
    async fn test_delta_emits_only_on_change() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();

        run_running_software_tick(&bus, &mut state).await;
        let _ = tokio::time::timeout(Duration::from_millis(200), server_rx.recv()).await;

        // Force a synthetic entry into the previous snapshot so the
        // next tick sees it as terminated.
        let phantom_pid = u32::MAX;
        state.previous.insert(
            phantom_pid,
            ProcessEntry {
                pid: phantom_pid,
                name: "phantom".into(),
                path: None,
                started_at: None,
                publisher: None,
            },
        );

        run_running_software_tick(&bus, &mut state).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a delta event")
            .expect("server_rx closed");

        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "delta");
                let removed = data["removed"].as_array().expect("removed must be array");
                assert!(
                    removed.iter().any(|p| p["pid"] == phantom_pid),
                    "phantom pid must appear in the removed list: {:?}",
                    removed
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_delta_detects_pid_reuse() {
        // Seed `previous` with an entry that claims to be a different
        // process at a PID we KNOW the current snapshot will also hold
        // (our own test process). The next tick must see the same PID
        // in both maps but detect that the name/path differ and emit
        // both a remove (of the synthetic entry) and an add (of the
        // real entry) for that slot.
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();

        let me = std::process::id();
        state.baseline_sent = true;
        state.previous.insert(
            me,
            ProcessEntry {
                pid: me,
                name: "impostor".into(),
                path: Some("/definitely/not/this/binary".into()),
                started_at: None,
                publisher: None,
            },
        );

        run_running_software_tick(&bus, &mut state).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a delta event")
            .expect("server_rx closed");

        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "delta");
                let removed = data["removed"].as_array().expect("removed must be array");
                let added = data["added"].as_array().expect("added must be array");
                assert!(
                    removed
                        .iter()
                        .any(|p| p["pid"] == me && p["name"] == "impostor"),
                    "PID-reused slot must appear in the removed list: {:?}",
                    removed
                );
                assert!(
                    added
                        .iter()
                        .any(|p| p["pid"] == me && p["name"] != "impostor"),
                    "new process at the reused PID must appear in the added list: {:?}",
                    added
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn test_same_process_treats_matching_name_and_path_as_equal() {
        let a = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/usr/bin/foo".into()),
            started_at: Some("2026-04-20T06:30:00Z".into()),
            publisher: None,
        };
        let b = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/usr/bin/foo".into()),
            // Intentionally different started_at — we ignore it.
            started_at: Some("2026-04-20T07:00:00Z".into()),
            publisher: None,
        };
        assert!(same_process(&a, &b));
    }

    #[test]
    fn test_same_process_rejects_differing_name() {
        let a = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: None,
            started_at: None,
            publisher: None,
        };
        let b = ProcessEntry {
            pid: 1,
            name: "bar".into(),
            path: None,
            started_at: None,
            publisher: None,
        };
        assert!(!same_process(&a, &b));
    }

    #[test]
    fn test_same_process_rejects_differing_path() {
        let a = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/usr/bin/foo".into()),
            started_at: None,
            publisher: None,
        };
        let b = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/tmp/foo".into()),
            started_at: None,
            publisher: None,
        };
        assert!(!same_process(&a, &b));
    }

    #[tokio::test]
    async fn test_baseline_retries_when_publish_fails() {
        // Capacity-1 server queue + a pre-seeded entry means the next
        // `publish_to_server` call will hit `ChannelFull` and the baseline
        // must NOT mark itself sent.
        let (bus, mut server_rx) = EventBus::new(16, 1);
        bus.publish_to_server(Event::new("test", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seeding the server queue to saturate it");

        let mut state = RunningSoftwareState::default();
        run_running_software_tick(&bus, &mut state).await;

        assert!(
            !state.baseline_sent,
            "baseline_sent must stay false when publish fails, so the next tick retries the full snapshot instead of sending orphan deltas"
        );
        assert!(
            state.previous.is_empty(),
            "previous snapshot must not be populated when the baseline was dropped"
        );

        // Drain the saturating keepalive and re-run the tick; the baseline
        // should now go through and flip the flag.
        let _seeded = server_rx.recv().await.expect("seeded event");
        run_running_software_tick(&bus, &mut state).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a baseline event on retry")
            .expect("server_rx closed");
        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "baseline");
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert!(state.baseline_sent);
        assert!(!state.previous.is_empty());
    }

    #[tokio::test]
    async fn test_delta_retries_when_publish_fails() {
        // Saturate the server queue AFTER the baseline has gone through,
        // so the next tick's delta publish will fail. The `previous`
        // snapshot must be retained so the phantom PID reappears in the
        // delta on the next successful tick.
        let (bus, mut server_rx) = EventBus::new(16, 2);
        let mut state = RunningSoftwareState::default();

        // Send the baseline.
        run_running_software_tick(&bus, &mut state).await;
        let _baseline = server_rx
            .recv()
            .await
            .expect("expected baseline on server queue");
        assert!(state.baseline_sent);

        // Inject a phantom entry so the next tick wants to emit a delta.
        let phantom_pid = u32::MAX;
        state.previous.insert(
            phantom_pid,
            ProcessEntry {
                pid: phantom_pid,
                name: "phantom".into(),
                path: None,
                started_at: None,
                publisher: None,
            },
        );

        // Fill the server queue so the delta publish fails.
        bus.publish_to_server(Event::new("x", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed 1/2");
        bus.publish_to_server(Event::new("y", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed 2/2");

        run_running_software_tick(&bus, &mut state).await;
        assert!(
            state.previous.contains_key(&phantom_pid),
            "previous snapshot must still contain the phantom pid so the delta can be re-emitted; got {:?}",
            state.previous.keys().collect::<Vec<_>>()
        );

        // Drain the seeded events and retry. The phantom must appear in
        // the removed list on this tick.
        let _ = server_rx.recv().await;
        let _ = server_rx.recv().await;
        run_running_software_tick(&bus, &mut state).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a delta event on retry")
            .expect("server_rx closed");
        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "delta");
                let removed = data["removed"].as_array().expect("removed must be array");
                assert!(
                    removed.iter().any(|p| p["pid"] == phantom_pid),
                    "phantom pid must reappear in the retried delta: {:?}",
                    removed
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert!(!state.previous.contains_key(&phantom_pid));
    }

    #[tokio::test]
    async fn test_module_lifecycle_starts_and_stops() {
        let agent_config = test_agent_config();
        let (controller, signal) = wda_core::signal::ShutdownController::new();
        let (bus, _server_rx) = EventBus::new(16, 16);

        let handle = EnhancedInventoryModule::start(&agent_config, bus, signal);

        tokio::time::sleep(Duration::from_millis(50)).await;
        controller.shutdown();

        tokio::time::timeout(Duration::from_secs(2), handle.task)
            .await
            .expect("enhanced inventory task did not stop within 2s")
            .expect("join error")
            .expect("enhanced inventory run returned Err");
    }

    #[tokio::test]
    async fn test_module_lifecycle_with_running_software_disabled() {
        let mut agent_config = test_agent_config();
        agent_config
            .modules
            .enhanced_inventory
            .running_software
            .enabled = false;

        let (controller, signal) = wda_core::signal::ShutdownController::new();
        let (bus, mut server_rx) = EventBus::new(16, 16);

        let handle = EnhancedInventoryModule::start(&agent_config, bus, signal);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            server_rx.try_recv().is_err(),
            "no events should be published when running_software is disabled"
        );

        controller.shutdown();
        tokio::time::timeout(Duration::from_secs(2), handle.task)
            .await
            .expect("task did not stop within 2s")
            .expect("join error")
            .expect("run returned Err");
    }
}
