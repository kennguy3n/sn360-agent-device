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

/// Publish a single enhanced-inventory event on the shared bus.
async fn publish_update(bus: &EventBus, category: &str, data: serde_json::Value) {
    let event = Event::new(
        "enhanced_inventory",
        Priority::Normal,
        EventKind::EnhancedInventoryUpdate {
            category: category.to_string(),
            data,
        },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, category, "failed to publish enhanced inventory event");
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
        publish_update(
            bus,
            "running_software",
            json!({
                "type": "baseline",
                "count": entries.len(),
                "processes": entries,
            }),
        )
        .await;
        state.baseline_sent = true;
        state.previous = current;
        return;
    }

    let mut added: Vec<&ProcessEntry> = Vec::new();
    let mut removed: Vec<&ProcessEntry> = Vec::new();

    for (pid, entry) in &current {
        if !state.previous.contains_key(pid) {
            added.push(entry);
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
        publish_update(
            bus,
            "running_software",
            json!({
                "type": "delta",
                "added": added,
                "removed": removed,
            }),
        )
        .await;
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
