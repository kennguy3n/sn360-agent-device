//! Windows Event Log collector.
//!
//! Uses `wevtutil` to subscribe to Windows Event Log channels (Security,
//! System, Application) and forwards events to the event bus.
//!
//! Gated behind `#[cfg(target_os = "windows")]`.

#![cfg(target_os = "windows")]

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use wda_core::signal::ShutdownSignal;
use wda_event_bus::{Event, EventBus, EventKind, Priority};

/// Configuration for a single Windows Event Log channel subscription.
#[derive(Debug, Clone)]
pub struct EventLogChannelConfig {
    /// Channel name (e.g. "Security", "System", "Application").
    pub channel: String,
    /// Optional XPath query filter.
    pub query: Option<String>,
}

/// Reads events from Windows Event Log channels via `wevtutil`.
pub struct WindowsEventLogReader {
    channels: Vec<EventLogChannelConfig>,
    bus: EventBus,
}

impl WindowsEventLogReader {
    pub fn new(channels: Vec<EventLogChannelConfig>, bus: EventBus) -> Self {
        Self { channels, bus }
    }

    /// Run the event log reader until shutdown.
    pub async fn run(self, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        info!(
            channels = self.channels.len(),
            "starting Windows Event Log reader"
        );

        let mut handles = Vec::new();

        for channel_cfg in &self.channels {
            let channel = channel_cfg.channel.clone();
            let query = channel_cfg.query.clone().unwrap_or_else(|| "*".to_string());
            let bus = self.bus.clone();
            let shutdown = shutdown.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = subscribe_channel(&channel, &query, bus, shutdown).await {
                    error!(channel = %channel, error = %e, "event log channel reader failed");
                }
            });
            handles.push(handle);
        }

        // Wait for all channel readers to finish.
        for handle in handles {
            let _ = handle.await;
        }

        info!("Windows Event Log reader stopped");
        Ok(())
    }
}

/// Subscribe to a single Windows Event Log channel using `wevtutil`.
async fn subscribe_channel(
    channel: &str,
    query: &str,
    bus: EventBus,
    shutdown: ShutdownSignal,
) -> anyhow::Result<()> {
    info!(channel = %channel, "subscribing to event log channel");

    // Use wevtutil to query events. In a production implementation this would
    // use the Windows `EvtSubscribe` API via `windows-rs`, but for now we use
    // the CLI tool as a portable starting point.
    let mut child = Command::new("wevtutil")
        .args(["qe", channel, "/q:*", "/f:text", "/rd:true", "/c:100"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture stdout from wevtutil"))?;

    let mut reader = BufReader::new(stdout).lines();
    let mut event_buf = String::new();

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                debug!(channel = %channel, "shutdown signal received");
                child.kill().await.ok();
                break;
            }
            line = reader.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        if line.trim().is_empty() && !event_buf.is_empty() {
                            let event = Event::new(
                                "logcollector",
                                Priority::Normal,
                                EventKind::LogCollected {
                                    source: format!("eventlog:{}", channel),
                                    message: std::mem::take(&mut event_buf),
                                    format: "eventlog".to_string(),
                                },
                            );
                            if let Err(e) = bus.publish_to_server(event).await {
                                warn!(error = %e, "failed to publish event log event");
                            }
                        } else {
                            if !event_buf.is_empty() {
                                event_buf.push('\n');
                            }
                            event_buf.push_str(&line);
                        }
                    }
                    Ok(None) => {
                        // EOF
                        if !event_buf.is_empty() {
                            let event = Event::new(
                                "logcollector",
                                Priority::Normal,
                                EventKind::LogCollected {
                                    source: format!("eventlog:{}", channel),
                                    message: std::mem::take(&mut event_buf),
                                    format: "eventlog".to_string(),
                                },
                            );
                            if let Err(e) = bus.publish_to_server(event).await {
                                warn!(error = %e, "failed to publish event log event");
                            }
                        }
                        break;
                    }
                    Err(e) => {
                        warn!(channel = %channel, error = %e, "error reading event log");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
