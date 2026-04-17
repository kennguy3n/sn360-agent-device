//! File Integrity Monitoring (FIM) module for the Wazuh Desktop Agent.
//!
//! Monitors filesystem changes using OS-native notification APIs
//! (inotify/FSEvents/ReadDirectoryChangesW) and reports changes
//! to the event bus for server delivery.

pub mod config;
pub mod db;
pub mod debounce;
pub mod event_format;
pub mod hasher;
pub mod watcher;

use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use tracing::{debug, error, info, warn};

use wda_core::config::AgentConfig;
use wda_core::module::{ModuleHandle, ModuleHealth, ModuleStatus};
use wda_core::signal::ShutdownSignal;
use wda_event_bus::{Event, EventBus, EventKind, Priority};

use crate::db::{FimEntry, StateDb};
use crate::event_format::{format_syscheck_event, ChangeType};
use crate::watcher::DebouncedWatcher;

use wda_pal::types::FsEventKind;

// Encode ModuleStatus as a u8 for atomic access.
const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// File Integrity Monitoring module.
pub struct FimModule {
    status: AtomicU8,
}

impl FimModule {
    /// Start the FIM module, returning a `ModuleHandle` that owns the spawned task.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let fim_config = config.modules.fim.clone();
        let status = std::sync::Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = std::sync::Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(fim_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "FIM module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("fim", task)
    }
}

impl wda_core::module::AgentModule for FimModule {
    fn name(&self) -> &'static str {
        "fim"
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
            STATUS_RUNNING => ModuleHealth::Healthy,
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

/// Collect file metadata into a `FimEntry`.
fn collect_metadata(path: &Path, check_sha256: bool) -> anyhow::Result<FimEntry> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("failed to stat {}: {}", path.display(), e))?;

    let sha256 = if check_sha256 && meta.is_file() {
        Some(hasher::hash_file(path)?)
    } else {
        None
    };

    let size = meta.len() as i64;

    #[cfg(unix)]
    let (permissions, uid, gid, mtime, inode) = {
        use std::os::unix::fs::MetadataExt;
        (
            meta.mode() as i64,
            meta.uid() as i64,
            meta.gid() as i64,
            meta.mtime(),
            meta.ino() as i64,
        )
    };

    #[cfg(not(unix))]
    let (permissions, uid, gid, mtime, inode) = {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        (0i64, 0i64, 0i64, mtime, 0i64)
    };

    Ok(FimEntry {
        path: path.to_string_lossy().to_string(),
        sha256,
        size,
        permissions,
        uid,
        gid,
        mtime,
        inode,
        last_scan: chrono::Utc::now().to_rfc3339(),
    })
}

/// Determine whether a path should be hashed based on FIM directory configs.
fn should_check_sha256(path: &Path, directories: &[wda_core::config::FimDirectory]) -> bool {
    for dir in directories {
        let dir_path = Path::new(&dir.path);
        if path.starts_with(dir_path) {
            return dir.check_sha256;
        }
    }
    true // default to hashing
}

/// The main FIM run loop.
async fn run(
    fim_config: wda_core::config::FimConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: std::sync::Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("FIM module starting");

    // Open (or create) the state database.
    let db_path = config::default_db_path();
    let db = match StateDb::open(&db_path) {
        Ok(db) => {
            info!(path = %db_path.display(), "opened FIM state database");
            db
        }
        Err(e) => {
            warn!(error = %e, "failed to open FIM DB at default path, using in-memory fallback");
            StateDb::open_in_memory()?
        }
    };

    // Initialize the debounced watcher.
    let mut watcher = DebouncedWatcher::new(fim_config.debounce_ms)?;

    // Watch all configured directories.
    for dir in &fim_config.directories {
        let path = Path::new(&dir.path);
        if !path.exists() {
            warn!(path = %dir.path, "FIM directory does not exist, skipping");
            continue;
        }
        if let Err(e) = watcher.watch(path, dir.recursive) {
            error!(path = %dir.path, error = %e, "failed to watch directory");
        } else {
            info!(path = %dir.path, recursive = dir.recursive, "watching directory");
        }
    }

    status.store(STATUS_RUNNING, Ordering::Relaxed);
    info!("FIM module running");

    // Main event loop.
    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("FIM module received shutdown signal");
                break;
            }

            event = watcher.next_event() => {
                let event = match event {
                    Some(ev) => ev,
                    None => {
                        warn!("FIM watcher channel closed");
                        break;
                    }
                };

                let path = event.path.clone();
                let kind = event.kind;
                let check_sha256 = should_check_sha256(&path, &fim_config.directories);

                debug!(path = %path.display(), kind = ?kind, "processing FIM event");

                match kind {
                    FsEventKind::Created => {
                        let path_clone = path.clone();
                        let new_entry = match tokio::task::spawn_blocking(move || {
                            collect_metadata(&path_clone, check_sha256)
                        })
                        .await?
                        {
                            Ok(entry) => entry,
                            Err(e) => {
                                debug!(error = %e, path = %path.display(), "file disappeared before stat");
                                continue;
                            }
                        };

                        let syscheck_json = format_syscheck_event(
                            ChangeType::Added,
                            &new_entry.path,
                            None,
                            Some(&new_entry),
                        );

                        db.upsert_entry(&new_entry)?;

                        let bus_event = Event::new(
                            "fim",
                            Priority::Normal,
                            EventKind::FileCreated {
                                path: path.to_string_lossy().to_string(),
                            },
                        );
                        if let Err(e) = bus.publish_to_server(bus_event).await {
                            warn!(error = %e, "failed to publish FIM event");
                        }
                        debug!(payload = %syscheck_json, "FIM created event");
                    }

                    FsEventKind::Modified | FsEventKind::MetadataChanged => {
                        let path_str = path.to_string_lossy().to_string();
                        let old_entry = db.get_entry(&path_str)?;

                        let path_clone = path.clone();
                        let new_entry = match tokio::task::spawn_blocking(move || {
                            collect_metadata(&path_clone, check_sha256)
                        })
                        .await?
                        {
                            Ok(entry) => entry,
                            Err(e) => {
                                debug!(error = %e, path = %path_str, "file disappeared before stat");
                                continue;
                            }
                        };

                        // Only emit an event if something actually changed.
                        let changed = match &old_entry {
                            Some(old) => {
                                old.sha256 != new_entry.sha256
                                    || old.size != new_entry.size
                                    || old.permissions != new_entry.permissions
                                    || old.uid != new_entry.uid
                                    || old.gid != new_entry.gid
                                    || old.mtime != new_entry.mtime
                            }
                            None => true,
                        };

                        if changed {
                            let syscheck_json = format_syscheck_event(
                                ChangeType::Modified,
                                &new_entry.path,
                                old_entry.as_ref(),
                                Some(&new_entry),
                            );

                            db.upsert_entry(&new_entry)?;

                            let event_kind = if kind == FsEventKind::MetadataChanged {
                                EventKind::FileMetadataChanged {
                                    path: path_str.clone(),
                                }
                            } else {
                                EventKind::FileModified {
                                    path: path_str.clone(),
                                }
                            };

                            let bus_event = Event::new("fim", Priority::Normal, event_kind);
                            if let Err(e) = bus.publish_to_server(bus_event).await {
                                warn!(error = %e, "failed to publish FIM event");
                            }
                            debug!(payload = %syscheck_json, "FIM modified event");
                        }
                    }

                    FsEventKind::Deleted => {
                        let path_str = path.to_string_lossy().to_string();
                        let old_entry = db.get_entry(&path_str)?;

                        let syscheck_json = format_syscheck_event(
                            ChangeType::Deleted,
                            &path_str,
                            old_entry.as_ref(),
                            None,
                        );

                        db.delete_entry(&path_str)?;

                        let bus_event = Event::new(
                            "fim",
                            Priority::Normal,
                            EventKind::FileDeleted {
                                path: path_str,
                            },
                        );
                        if let Err(e) = bus.publish_to_server(bus_event).await {
                            warn!(error = %e, "failed to publish FIM event");
                        }
                        debug!(payload = %syscheck_json, "FIM deleted event");
                    }

                    FsEventKind::Renamed => {
                        let path_str = path.to_string_lossy().to_string();
                        let old_entry = db.get_entry(&path_str)?;

                        if old_entry.is_some() {
                            db.delete_entry(&path_str)?;
                            let bus_event = Event::new(
                                "fim",
                                Priority::Normal,
                                EventKind::FileDeleted {
                                    path: path_str.clone(),
                                },
                            );
                            let _ = bus.publish_to_server(bus_event).await;
                        }

                        if path.exists() {
                            let path_clone = path.clone();
                            if let Ok(new_entry) = tokio::task::spawn_blocking(move || {
                                collect_metadata(&path_clone, check_sha256)
                            })
                            .await?
                            {
                                db.upsert_entry(&new_entry)?;
                                let bus_event = Event::new(
                                    "fim",
                                    Priority::Normal,
                                    EventKind::FileCreated {
                                        path: path_str,
                                    },
                                );
                                let _ = bus.publish_to_server(bus_event).await;
                            }
                        }
                    }
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("FIM module stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;
    use wda_core::config::{FimConfig, FimDirectory, ModulesConfig};
    use wda_core::signal::ShutdownController;

    /// Build a minimal `AgentConfig` that watches `dir`.
    fn test_config(dir: &str) -> wda_core::config::AgentConfig {
        wda_core::config::AgentConfig {
            modules: ModulesConfig {
                fim: FimConfig {
                    enabled: true,
                    directories: vec![FimDirectory {
                        path: dir.to_string(),
                        recursive: true,
                        realtime: true,
                        check_sha256: true,
                        exclude: Vec::new(),
                    }],
                    scan_interval: 86400,
                    debounce_ms: 50,
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_fim_module_detects_file_creation_and_publishes_event() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path().to_str().unwrap());

        let (bus, mut server_rx) = EventBus::new(256, 256);
        let (controller, signal) = ShutdownController::new();

        let _handle = FimModule::start(&config, bus, signal);

        // Wait for the watcher to register.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create a file.
        let file_path = tmp.path().join("unit_test.txt");
        std::fs::write(&file_path, "unit test content").unwrap();

        // Wait for a FileCreated event on the server channel.
        let event = tokio::time::timeout(Duration::from_secs(10), server_rx.recv())
            .await
            .expect("timed out waiting for FIM event")
            .expect("server_rx closed");

        match &event.kind {
            EventKind::FileCreated { path }
            | EventKind::FileModified { path }
            | EventKind::FileMetadataChanged { path } => {
                assert!(
                    path.contains("unit_test.txt"),
                    "event path should contain file name, got: {path}"
                );
            }
            other => panic!("expected FileCreated/FileModified, got: {other:?}"),
        }

        controller.shutdown();
    }
}
