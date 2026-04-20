//! Self-update module for the Wazuh Desktop Agent (task P3.1).
//!
//! The updater periodically polls a configured update-server URL for a
//! signed manifest describing the latest agent build. When a newer
//! version is advertised it downloads the binary, verifies its
//! SHA-256 + Ed25519 signature against a pinned verifying key, and
//! atomically swaps the running binary — keeping a `.bak` copy so a
//! failed start can be rolled back.
//!
//! The module is off by default — operators opt in by setting
//! `modules.updater.enabled: true` and configuring a
//! `modules.updater.server_url` in the agent config.
//!
//! See [`device-agent-proposal.md`](../../../device-agent-proposal.md) § 12 / Phase 5 for the
//! full design.

pub mod checker;
pub mod installer;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use wda_core::config::{AgentConfig, UpdateConfig};
use wda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use wda_core::signal::ShutdownSignal;

pub use checker::{check_for_update, UpdateManifest};
pub use installer::{install_update, InstallOutcome};

/// Minimum permitted update-check interval. A runaway timer hammering
/// the update server would be both impolite and a reliable foot-gun
/// for the bandwidth-budgeting logic elsewhere in the agent, so we
/// floor the configured value at one minute.
pub const MIN_CHECK_INTERVAL: Duration = Duration::from_secs(60);

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Updater module handle.
pub struct UpdaterModule {
    status: Arc<AtomicU8>,
}

impl UpdaterModule {
    /// Spawn the updater run loop and return a [`ModuleHandle`].
    pub fn start(config: &AgentConfig, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.updater.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            if let Err(e) = run(cfg, shutdown, Arc::clone(&task_status)).await {
                error!(error = %e, "updater module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("updater", task)
    }
}

impl Default for UpdaterModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl AgentModule for UpdaterModule {
    fn name(&self) -> &'static str {
        "updater"
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

/// Effective check interval: configured value floored at
/// [`MIN_CHECK_INTERVAL`].
fn effective_check_interval(cfg: &UpdateConfig) -> Duration {
    Duration::from_secs(cfg.check_interval.max(MIN_CHECK_INTERVAL.as_secs()))
}

/// Run one complete update cycle: check, download-and-verify, install.
///
/// Logs and swallows all errors — a failed update attempt should never
/// take the agent down.
async fn run_once(cfg: &UpdateConfig, current_version: &str) {
    let manifest = match check_for_update(cfg, current_version).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            debug!(current = current_version, "no update available");
            return;
        }
        Err(e) => {
            warn!(error = %e, "update check failed");
            return;
        }
    };

    info!(
        current = current_version,
        available = %manifest.version,
        "new version available, downloading"
    );

    let current_binary = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "could not resolve current_exe(); skipping install");
            return;
        }
    };

    match install_update(cfg, &manifest, &current_binary).await {
        Ok(InstallOutcome::Installed) => {
            info!(version = %manifest.version, "update installed successfully");
        }
        Ok(InstallOutcome::RolledBack) => {
            warn!(
                version = %manifest.version,
                "update installed but failed smoke test; rolled back"
            );
        }
        Err(e) => warn!(error = %e, "update installation failed"),
    }
}

/// Main updater run loop.
async fn run(
    cfg: UpdateConfig,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        server_url = %cfg.server_url,
        check_interval = cfg.check_interval,
        "updater module starting"
    );

    status.store(STATUS_RUNNING, Ordering::Relaxed);

    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let mut timer = tokio::time::interval(effective_check_interval(&cfg));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("updater module received shutdown signal");
                break;
            }

            _ = timer.tick() => {
                run_once(&cfg, &current_version).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("updater module stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_interval_floors_at_min() {
        let cfg = UpdateConfig {
            enabled: true,
            server_url: "https://example.invalid/wda/latest.json".into(),
            check_interval: 1, // caller asks for 1 s
            public_key: String::new(),
            smoke_test_timeout: 10,
        };
        assert_eq!(effective_check_interval(&cfg), MIN_CHECK_INTERVAL);
    }

    #[test]
    fn effective_interval_respects_higher_values() {
        let cfg = UpdateConfig {
            enabled: true,
            server_url: "https://example.invalid/wda/latest.json".into(),
            check_interval: 7200,
            public_key: String::new(),
            smoke_test_timeout: 10,
        };
        assert_eq!(effective_check_interval(&cfg), Duration::from_secs(7200));
    }
}
