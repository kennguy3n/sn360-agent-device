//! Wazuh Desktop Agent — binary entry point.
//!
//! Orchestrates startup, enrollment, server connection, keepalive,
//! and graceful shutdown of the agent.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tracing::{error, info};

use wda_comms::connection::{ConnectionConfig, ConnectionManager, TransportProtocol};
use wda_comms::crypto::WazuhCipher;
use wda_comms::enrollment::{load_agent_key, save_agent_key, EnrollmentClient};
use wda_comms::keepalive::run_keepalive_loop;
use wda_comms::protocol::{MessageType, WazuhMessage};
use wda_core::config::AgentConfig;
use wda_core::Agent;
use wda_event_bus::EventKind;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("wazuh desktop agent starting");

    // 2. Load configuration (from CLI arg or default path)
    let config = match std::env::args().nth(1) {
        Some(path) => AgentConfig::from_yaml_file(std::path::Path::new(&path))
            .context("failed to load config from provided path")?,
        None => AgentConfig::load_default().context("failed to load default config")?,
    };

    // 3. Create the agent
    let mut agent = Agent::new(config.clone());

    // 4. Check for existing agent key; enroll if missing
    let agent_key = match load_agent_key() {
        Some(key) => {
            info!(agent_id = %key.id, "loaded existing agent key");
            key
        }
        None => {
            info!("no agent key found, enrolling with server");
            let agent_name = config
                .enrollment
                .agent_name
                .clone()
                .unwrap_or_else(gethostname);

            let mut client = EnrollmentClient::new(
                config.enrollment_address(),
                config.enrollment.port,
                &agent_name,
            );

            if let Some(ref password) = config.enrollment.key {
                client = client.with_password(password);
            }
            if let Some(ref groups) = config.enrollment.groups {
                client = client.with_groups(groups.clone());
            }

            let key = client.enroll().await.context("enrollment failed")?;

            // 5. Save the key
            save_agent_key(&key).context("failed to save agent key")?;
            info!(agent_id = %key.id, "enrollment complete, key saved");
            key
        }
    };

    agent.set_agent_id(agent_key.id.clone());
    agent.set_agent_key(agent_key.key.clone());

    // 6. Create ConnectionManager and WazuhCipher from the agent key
    let protocol = match config.server.protocol.as_str() {
        "udp" => TransportProtocol::Udp,
        _ => TransportProtocol::Tcp,
    };

    let conn_config = ConnectionConfig {
        server_address: config.server.address.clone(),
        server_port: config.server.port,
        protocol,
        keepalive_interval: Duration::from_secs(config.server.keepalive_interval),
        ..ConnectionConfig::default()
    };

    let cipher = WazuhCipher::new(&agent_key.key);
    let mut conn = ConnectionManager::new(conn_config);
    conn.set_cipher(cipher);

    // 7. Connect to server with retry
    info!("connecting to server");
    conn.connect_with_retry()
        .await
        .context("failed to connect to server")?;

    // 8. Send startup message
    let startup_msg = WazuhMessage::startup(&agent_key.id);
    conn.send(&startup_msg)
        .await
        .context("failed to send startup message")?;
    info!("startup message sent");

    // Wrap connection in Arc<Mutex> for shared access
    let conn = Arc::new(Mutex::new(conn));

    // 9. Spawn keepalive loop
    let keepalive_interval = Duration::from_secs(config.server.keepalive_interval);
    let keepalive_shutdown = agent.shutdown_signal();
    let keepalive_conn = Arc::clone(&conn);
    let keepalive_agent_id = agent_key.id.clone();

    let keepalive_handle = tokio::spawn(async move {
        run_keepalive_loop(
            keepalive_conn,
            keepalive_agent_id,
            keepalive_interval,
            keepalive_shutdown,
        )
        .await;
    });

    // 10. Spawn event forwarding loop
    let forward_conn = Arc::clone(&conn);
    let forward_agent_id = agent_key.id.clone();
    let mut forward_shutdown = agent.shutdown_signal();
    let mut server_rx = agent.take_server_rx().expect("server_rx already taken");

    let forward_handle = tokio::spawn(async move {
        info!("event forwarding loop started");
        loop {
            tokio::select! {
                biased;

                _ = forward_shutdown.wait() => {
                    info!("event forwarding loop shutting down");
                    break;
                }

                event = server_rx.recv() => {
                    let event = match event {
                        Some(ev) => ev,
                        None => {
                            info!("server event channel closed, stopping forward loop");
                            break;
                        }
                    };

                    let msg = match map_event_to_message(&forward_agent_id, &event.kind) {
                        Some(m) => m,
                        None => continue,
                    };

                    let mut guard = forward_conn.lock().await;
                    if let Err(e) = guard.send(&msg).await {
                        error!(error = %e, "failed to forward event to server");
                    }
                }
            }
        }
        info!("event forwarding loop stopped");
    });

    // 11. Start FIM module if enabled
    if config.modules.fim.enabled {
        info!("starting FIM module");
        let fim_handle =
            wda_fim::FimModule::start(&config, agent.event_bus(), agent.shutdown_signal());
        agent.register_module(fim_handle);
    }

    // 12. Start agent and wait for shutdown signal
    agent.start().await;
    agent.wait_for_shutdown().await;

    // 13. Send shutdown message, disconnect, shut down agent
    info!("sending shutdown message");
    {
        let shutdown_msg = WazuhMessage::new(
            &agent_key.id,
            wda_comms::protocol::MessageType::Shutdown,
            "#!-agent shutdown",
        );
        let mut guard = conn.lock().await;
        if let Err(e) = guard.send(&shutdown_msg).await {
            error!(error = %e, "failed to send shutdown message");
        }
        guard.disconnect().await;
    }

    // Wait for keepalive and forwarding tasks to finish
    let _ = keepalive_handle.await;
    let _ = forward_handle.await;

    agent.shutdown().await;
    info!("wazuh desktop agent stopped");

    Ok(())
}

/// Map an `EventKind` to a `WazuhMessage` ready for server delivery.
///
/// Returns `None` for event kinds that should not be forwarded (e.g.
/// lifecycle events that are handled separately).
fn map_event_to_message(agent_id: &str, kind: &EventKind) -> Option<WazuhMessage> {
    let (msg_type, payload) = match kind {
        EventKind::FileCreated { .. }
        | EventKind::FileModified { .. }
        | EventKind::FileDeleted { .. }
        | EventKind::FileMetadataChanged { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::Syscheck, json)
        }
        EventKind::LogCollected { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::Log, json)
        }
        EventKind::InventoryUpdate { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::Syscollector, json)
        }
        EventKind::ScaResult { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::Sca, json)
        }
        EventKind::ActiveResponseResult { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::ActiveResponse, json)
        }
        EventKind::ServerMessage { payload } => (MessageType::Generic, payload.clone()),
        // Lifecycle / internal events are not forwarded.
        _ => return None,
    };

    Some(WazuhMessage::new(agent_id, msg_type, payload))
}

/// Get the system hostname as a fallback agent name.
fn gethostname() -> String {
    ::gethostname::gethostname().to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wda_comms::protocol::MessageType;
    use wda_event_bus::{Event, EventKind, Priority};

    #[test]
    fn test_file_created_maps_to_syscheck() {
        let kind = EventKind::FileCreated {
            path: "/etc/passwd".to_string(),
        };
        let msg = map_event_to_message("001", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.agent_id, "001");
        assert!(msg.payload.contains("/etc/passwd"));
    }

    #[test]
    fn test_file_modified_maps_to_syscheck() {
        let kind = EventKind::FileModified {
            path: "/etc/shadow".to_string(),
        };
        let msg = map_event_to_message("002", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert!(msg.payload.contains("/etc/shadow"));
    }

    #[test]
    fn test_file_deleted_maps_to_syscheck() {
        let kind = EventKind::FileDeleted {
            path: "/tmp/gone.txt".to_string(),
        };
        let msg = map_event_to_message("003", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert!(msg.payload.contains("/tmp/gone.txt"));
    }

    #[test]
    fn test_file_metadata_changed_maps_to_syscheck() {
        let kind = EventKind::FileMetadataChanged {
            path: "/usr/bin/test".to_string(),
        };
        let msg = map_event_to_message("004", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
    }

    #[test]
    fn test_log_collected_maps_to_log() {
        let kind = EventKind::LogCollected {
            source: "syslog".to_string(),
            message: "test log line".to_string(),
            format: "syslog".to_string(),
        };
        let msg = map_event_to_message("005", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Log);
        assert!(msg.payload.contains("test log line"));
    }

    #[test]
    fn test_inventory_maps_to_syscollector() {
        let kind = EventKind::InventoryUpdate {
            category: "packages".to_string(),
            data: serde_json::json!({"name": "vim"}),
        };
        let msg = map_event_to_message("006", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscollector);
    }

    #[test]
    fn test_sca_maps_to_sca() {
        let kind = EventKind::ScaResult {
            policy_id: "cis_ubuntu".to_string(),
            check_id: "1001".to_string(),
            result: "passed".to_string(),
        };
        let msg = map_event_to_message("007", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Sca);
    }

    #[test]
    fn test_active_response_maps_to_active_response() {
        let kind = EventKind::ActiveResponseResult {
            action: "block_ip".to_string(),
            success: true,
            output: "blocked".to_string(),
        };
        let msg = map_event_to_message("008", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::ActiveResponse);
    }

    #[test]
    fn test_server_message_maps_to_generic() {
        let kind = EventKind::ServerMessage {
            payload: "raw payload".to_string(),
        };
        let msg = map_event_to_message("009", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Generic);
        assert_eq!(msg.payload, "raw payload");
    }

    #[test]
    fn test_keepalive_not_forwarded() {
        let kind = EventKind::Keepalive;
        assert!(map_event_to_message("010", &kind).is_none());
    }

    #[test]
    fn test_shutdown_not_forwarded() {
        let kind = EventKind::Shutdown;
        assert!(map_event_to_message("010", &kind).is_none());
    }

    #[test]
    fn test_config_reloaded_not_forwarded() {
        let kind = EventKind::ConfigReloaded;
        assert!(map_event_to_message("010", &kind).is_none());
    }

    #[tokio::test]
    async fn test_event_forwarding_via_bus() {
        // Verify events published via publish_to_server appear on server_rx
        // and can be correctly mapped to WazuhMessages.
        let (bus, mut server_rx) = wda_event_bus::EventBus::new(64, 64);

        let event = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/etc/test.conf".to_string(),
            },
        );
        bus.publish_to_server(event).await.unwrap();

        let received = server_rx.recv().await.unwrap();
        let msg = map_event_to_message("001", &received.kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.agent_id, "001");
        assert!(msg.payload.contains("/etc/test.conf"));

        // Verify the message encodes to the expected wire format.
        let encoded = String::from_utf8(msg.encode()).unwrap();
        assert!(encoded.starts_with("001:syscheck:"));
    }
}
