//! Log collection module for the Wazuh Desktop Agent.
//!
//! Collects logs from file-based sources using event-driven APIs
//! (inotify/notify) with seek position tracking, and forwards them
//! to the event bus for server delivery.

pub mod file_reader;
pub mod state;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use tracing::{error, info, warn};

use wda_core::config::AgentConfig;
use wda_core::module::ModuleHandle;
use wda_core::signal::ShutdownSignal;
use wda_event_bus::EventBus;

use crate::file_reader::FileReader;
use crate::state::SeekState;

const STATUS_INITIALIZED: u8 = 0;
const _STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Log collector module.
pub struct LogCollectorModule;

impl LogCollectorModule {
    /// Start the log collector module, returning a `ModuleHandle`.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let lc_config = config.modules.logcollector.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(lc_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "logcollector module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("logcollector", task)
    }
}

impl wda_core::module::AgentModule for LogCollectorModule {
    fn name(&self) -> &'static str {
        "logcollector"
    }

    fn status(&self) -> wda_core::module::ModuleStatus {
        wda_core::module::ModuleStatus::Initialized
    }

    fn health(&self) -> wda_core::module::ModuleHealth {
        wda_core::module::ModuleHealth::Healthy
    }
}

/// The main log collector run loop.
async fn run(
    lc_config: wda_core::config::LogCollectorConfig,
    bus: EventBus,
    shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("logcollector module starting");

    // Collect file-based sources.
    let mut paths = Vec::new();
    let mut formats = Vec::new();

    for source in &lc_config.sources {
        if source.source_type == "file" {
            if let Some(ref path) = source.path {
                let p = PathBuf::from(path);
                if !p.exists() {
                    warn!(path = %path, "log source file does not exist yet, will watch for creation");
                }
                paths.push(p);
                formats.push(source.format.clone());
            } else {
                warn!("file log source missing path, skipping");
            }
        } else {
            info!(source_type = %source.source_type, "non-file source type not yet implemented, skipping");
        }
    }

    // Load seek state.
    let state_path = SeekState::default_path();
    let state = SeekState::load(state_path);

    let reader = FileReader::new(paths, formats, state, bus);

    status.store(_STATUS_RUNNING, Ordering::Relaxed);
    info!("logcollector module running");

    reader.run(shutdown).await?;

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("logcollector module stopped");
    Ok(())
}
