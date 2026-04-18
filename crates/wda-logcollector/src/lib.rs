//! Log collection module for the Wazuh Desktop Agent.
//!
//! Collects logs from file-based sources using event-driven APIs
//! (inotify/notify) with seek position tracking, and forwards them
//! to the event bus for server delivery.

pub mod file_reader;
#[cfg(all(target_os = "linux", feature = "linux-journal"))]
pub mod journal_reader;
#[cfg(target_os = "macos")]
pub mod oslog_reader;
pub mod state;
#[cfg(target_os = "windows")]
pub mod windows_eventlog;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use tracing::{error, info, warn};

use wda_core::config::AgentConfig;
use wda_core::module::ModuleHandle;
use wda_core::signal::ShutdownSignal;
use wda_event_bus::EventBus;

use crate::file_reader::FileReader;
#[cfg(all(target_os = "linux", feature = "linux-journal"))]
use crate::journal_reader::JournalReader;
#[cfg(target_os = "macos")]
use crate::oslog_reader::{OsLogConfig, OsLogReader};
use crate::state::SeekState;
#[cfg(target_os = "windows")]
use crate::windows_eventlog::{EventLogChannelConfig, WindowsEventLogReader};

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

    // Collect file-based sources and journal sources.
    let mut paths = Vec::new();
    let mut formats = Vec::new();
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    let mut journal_sources = Vec::new();
    #[cfg(target_os = "windows")]
    let mut eventlog_channels: Vec<EventLogChannelConfig> = Vec::new();
    #[cfg(target_os = "macos")]
    let mut oslog_configs: Vec<OsLogConfig> = Vec::new();

    for source in &lc_config.sources {
        match source.source_type.as_str() {
            "file" => {
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
            }
            "journald" | "journal" => {
                #[cfg(all(target_os = "linux", feature = "linux-journal"))]
                {
                    journal_sources.push(source.clone());
                }
                #[cfg(not(all(target_os = "linux", feature = "linux-journal")))]
                {
                    warn!(
                        source_type = %source.source_type,
                        "journal source requires linux-journal feature, skipping"
                    );
                }
            }
            "eventlog" | "windows" => {
                #[cfg(target_os = "windows")]
                {
                    let channel = source
                        .path
                        .clone()
                        .unwrap_or_else(|| "Security".to_string());
                    eventlog_channels.push(EventLogChannelConfig {
                        channel,
                        query: None,
                    });
                }
                #[cfg(not(target_os = "windows"))]
                {
                    warn!(
                        source_type = %source.source_type,
                        "eventlog source requires Windows, skipping"
                    );
                }
            }
            "oslog" | "unified" => {
                #[cfg(target_os = "macos")]
                {
                    oslog_configs.push(OsLogConfig {
                        predicate: source.path.clone(),
                        level: None,
                    });
                }
                #[cfg(not(target_os = "macos"))]
                {
                    warn!(
                        source_type = %source.source_type,
                        "oslog source requires macOS, skipping"
                    );
                }
            }
            _ => {
                info!(
                    source_type = %source.source_type,
                    "unknown source type, skipping"
                );
            }
        }
    }

    // Load seek state.
    let state_path = SeekState::default_path();
    let state = SeekState::load(state_path);

    let file_reader = FileReader::new(paths, formats, state, bus.clone());

    status.store(_STATUS_RUNNING, Ordering::Relaxed);
    info!("logcollector module running");

    // Spawn journal readers as separate tasks alongside the file reader.
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    let mut journal_handles = Vec::new();
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    for source in journal_sources {
        let journal_bus = bus.clone();
        let journal_shutdown = shutdown.clone();
        let reader = JournalReader::new(source, journal_bus);
        let handle = tokio::spawn(async move {
            if let Err(e) = reader.run(journal_shutdown).await {
                error!(error = %e, "journal reader failed");
            }
        });
        journal_handles.push(handle);
    }

    // Spawn Windows Event Log reader.
    #[cfg(target_os = "windows")]
    let eventlog_handle = if !eventlog_channels.is_empty() {
        let el_bus = bus.clone();
        let el_shutdown = shutdown.clone();
        let reader = WindowsEventLogReader::new(eventlog_channels, el_bus);
        Some(tokio::spawn(async move {
            if let Err(e) = reader.run(el_shutdown).await {
                error!(error = %e, "Windows Event Log reader failed");
            }
        }))
    } else {
        None
    };

    // Spawn macOS Unified Log readers.
    #[cfg(target_os = "macos")]
    let mut oslog_handles = Vec::new();
    #[cfg(target_os = "macos")]
    for config in oslog_configs {
        let ol_bus = bus.clone();
        let ol_shutdown = shutdown.clone();
        let reader = OsLogReader::new(config, ol_bus);
        let handle = tokio::spawn(async move {
            if let Err(e) = reader.run(ol_shutdown).await {
                error!(error = %e, "macOS Unified Log reader failed");
            }
        });
        oslog_handles.push(handle);
    }

    file_reader.run(shutdown).await?;

    // Wait for journal readers to finish.
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    for handle in journal_handles {
        let _ = handle.await;
    }

    // Wait for Windows Event Log reader to finish.
    #[cfg(target_os = "windows")]
    if let Some(handle) = eventlog_handle {
        let _ = handle.await;
    }

    // Wait for macOS Unified Log readers to finish.
    #[cfg(target_os = "macos")]
    for handle in oslog_handles {
        let _ = handle.await;
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("logcollector module stopped");
    Ok(())
}
