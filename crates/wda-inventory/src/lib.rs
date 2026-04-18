//! System inventory collection module for the Wazuh Desktop Agent.
//!
//! Collects hardware, OS, package, network information and publishes
//! `EventKind::InventoryUpdate` events to the event bus for each category.
//! Data is collected on startup and then periodically at a configurable interval.

pub mod hardware;
pub mod network;
pub mod os_info;
pub mod packages;
pub mod syscollector_format;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use wda_core::config::AgentConfig;
use wda_core::module::ModuleHandle;
use wda_core::signal::ShutdownSignal;
use wda_event_bus::{Event, EventBus, EventKind, Priority};

use crate::syscollector_format::wrap_syscollector;

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// System inventory collection module.
pub struct InventoryModule;

impl InventoryModule {
    /// Start the inventory module, returning a `ModuleHandle` that owns the spawned task.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let inv_config = config.modules.inventory.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(inv_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "inventory module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("inventory", task)
    }
}

impl wda_core::module::AgentModule for InventoryModule {
    fn name(&self) -> &'static str {
        "inventory"
    }

    fn status(&self) -> wda_core::module::ModuleStatus {
        wda_core::module::ModuleStatus::Initialized
    }

    fn health(&self) -> wda_core::module::ModuleHealth {
        wda_core::module::ModuleHealth::Healthy
    }
}

/// The main inventory run loop.
async fn run(
    inv_config: wda_core::config::InventoryConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("inventory module starting");

    let interval = Duration::from_secs(inv_config.interval);
    let categories = inv_config.collect.clone();

    status.store(STATUS_RUNNING, Ordering::Relaxed);
    info!(interval_secs = inv_config.interval, "inventory module running");

    // Collect immediately on startup.
    collect_and_publish(&categories, &bus).await;

    // Then collect periodically.
    let mut timer = tokio::time::interval(interval);
    // First tick fires immediately; we already collected above, so consume it.
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("inventory module received shutdown signal");
                break;
            }

            _ = timer.tick() => {
                debug!("inventory collection timer fired");
                collect_and_publish(&categories, &bus).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("inventory module stopped");
    Ok(())
}

/// Collect all enabled inventory categories and publish events to the bus.
async fn collect_and_publish(categories: &[String], bus: &EventBus) {
    info!("starting inventory collection");

    for category in categories {
        match category.as_str() {
            "os" => {
                let payload = tokio::task::spawn_blocking(os_info::collect_os_info)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "os info collection task panicked");
                        serde_json::json!({})
                    });

                let wire = wrap_syscollector(&payload);
                publish_inventory_event(bus, "os", &wire).await;
            }
            "hardware" => {
                let payload = tokio::task::spawn_blocking(hardware::collect_hardware_info)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "hardware info collection task panicked");
                        serde_json::json!({})
                    });

                let wire = wrap_syscollector(&payload);
                publish_inventory_event(bus, "hardware", &wire).await;
            }
            "network" => {
                let payloads = tokio::task::spawn_blocking(network::collect_network_info)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "network info collection task panicked");
                        Vec::new()
                    });

                for payload in &payloads {
                    let wire = wrap_syscollector(payload);
                    publish_inventory_event(bus, "network", &wire).await;
                }
            }
            "packages" => {
                let payloads = packages::collect_packages().await;

                for payload in &payloads {
                    let wire = wrap_syscollector(payload);
                    publish_inventory_event(bus, "packages", &wire).await;
                }
            }
            other => {
                warn!(category = %other, "unknown inventory category, skipping");
            }
        }
    }

    info!("inventory collection complete");
}

/// Publish a single inventory event to the event bus.
async fn publish_inventory_event(bus: &EventBus, category: &str, wire_payload: &str) {
    let event = Event::new(
        "inventory",
        Priority::Low,
        EventKind::InventoryUpdate {
            category: category.to_string(),
            data: serde_json::Value::String(wire_payload.to_string()),
        },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, category = %category, "failed to publish inventory event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wda_core::config::{InventoryConfig, ModulesConfig};
    use wda_core::signal::ShutdownController;

    fn test_config() -> AgentConfig {
        AgentConfig {
            modules: ModulesConfig {
                inventory: InventoryConfig {
                    enabled: true,
                    interval: 5,
                    collect: vec![
                        "os".to_string(),
                        "hardware".to_string(),
                        "network".to_string(),
                    ],
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_inventory_module_lifecycle() {
        let config = test_config();
        let (bus, mut server_rx) = EventBus::new(256, 256);
        let (controller, signal) = ShutdownController::new();

        let _handle = InventoryModule::start(&config, bus, signal);

        // Wait for the initial collection to publish events.
        let event = tokio::time::timeout(Duration::from_secs(10), server_rx.recv())
            .await
            .expect("timed out waiting for inventory event")
            .expect("server_rx closed");

        match &event.kind {
            EventKind::InventoryUpdate { category, data } => {
                assert!(
                    ["os", "hardware", "network", "packages"].contains(&category.as_str()),
                    "unexpected category: {category}"
                );
                assert!(data.is_string(), "data should be a wire-format string");
                let wire = data.as_str().unwrap();
                assert!(
                    wire.starts_with("d:syscollector:"),
                    "payload should start with d:syscollector:"
                );
            }
            other => panic!("expected InventoryUpdate, got: {other:?}"),
        }

        controller.shutdown();
    }

    #[tokio::test]
    async fn test_collect_and_publish_os_only() {
        let (bus, mut server_rx) = EventBus::new(256, 256);
        let categories = vec!["os".to_string()];

        collect_and_publish(&categories, &bus).await;

        let event = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
            .await
            .expect("timed out waiting for OS inventory event")
            .expect("server_rx closed");

        match &event.kind {
            EventKind::InventoryUpdate { category, .. } => {
                assert_eq!(category, "os");
            }
            other => panic!("expected InventoryUpdate, got: {other:?}"),
        }
    }
}
