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
use wda_comms::protocol::WazuhMessage;
use wda_core::config::AgentConfig;
use wda_core::Agent;

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

    // 10. Start agent and wait for shutdown signal
    agent.start().await;
    agent.wait_for_shutdown().await;

    // 11. Send shutdown message, disconnect, shut down agent
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

    // Wait for keepalive task to finish
    let _ = keepalive_handle.await;

    agent.shutdown().await;
    info!("wazuh desktop agent stopped");

    Ok(())
}

/// Get the system hostname as a fallback agent name.
fn gethostname() -> String {
    ::gethostname::gethostname().to_string_lossy().into_owned()
}
