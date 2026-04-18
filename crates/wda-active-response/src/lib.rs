//! Active response execution module for the Wazuh Desktop Agent.
//!
//! Receives and executes response actions from the Wazuh server
//! (e.g., IP blocking, process termination) with sandboxing and
//! timeout enforcement.

pub mod actions;
pub mod executor;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use wda_core::config::AgentConfig;
use wda_core::module::{ModuleHandle, ModuleHealth, ModuleStatus};
use wda_core::signal::ShutdownSignal;
use wda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};

use crate::actions::{ActionParams, ActionRegistry};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Active response module.
pub struct ActiveResponseModule {
    status: AtomicU8,
}

impl ActiveResponseModule {
    /// Start the active response module, returning a `ModuleHandle` that owns the spawned task.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let ar_config = config.modules.active_response.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(ar_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "active response module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("active_response", task)
    }
}

impl Default for ActiveResponseModule {
    fn default() -> Self {
        Self {
            status: AtomicU8::new(STATUS_INITIALIZED),
        }
    }
}

impl wda_core::module::AgentModule for ActiveResponseModule {
    fn name(&self) -> &'static str {
        "active_response"
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

/// Parse an active response command from a Wazuh server message.
///
/// Wazuh AR commands can arrive in several formats:
/// 1. `#!-execd <json>` — JSON-encoded command
/// 2. Plain JSON with "command" and "parameters" fields
/// 3. Legacy format: `<action_name> - <arg1> - <arg2> - <timeout>`
fn parse_ar_command(payload: &str) -> Option<(String, ActionParams)> {
    let payload = payload.trim();

    // Try stripping #!-execd prefix
    let json_str = if payload.starts_with("#!-execd") {
        payload.trim_start_matches("#!-execd").trim()
    } else {
        payload
    };

    // Try JSON parsing first
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(command) = value.get("command").and_then(|v| v.as_str()) {
            let action = extract_action_name(command);
            let params = if let Some(p) = value.get("parameters") {
                let ip = p
                    .get("alert")
                    .and_then(|a| a.get("data"))
                    .and_then(|d| d.get("srcip"))
                    .and_then(|v| v.as_str())
                    .or_else(|| p.get("ip").and_then(|v| v.as_str()))
                    .map(String::from);
                let pid = p.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
                let user = p.get("user").and_then(|v| v.as_str()).map(String::from);
                let timeout = p.get("timeout").and_then(|v| v.as_u64()).unwrap_or(0);

                ActionParams {
                    ip,
                    pid,
                    user,
                    timeout,
                    extra: std::collections::HashMap::new(),
                }
            } else {
                ActionParams {
                    ip: None,
                    pid: None,
                    user: None,
                    timeout: 0,
                    extra: std::collections::HashMap::new(),
                }
            };
            return Some((action, params));
        }
    }

    // Try legacy format: "action_name - user - ip timeout"
    // Use json_str which has the #!-execd prefix already stripped
    let tokens: Vec<&str> = json_str.split_whitespace().collect();
    if !tokens.is_empty() {
        let raw_action = tokens[0];
        let action = extract_action_name(raw_action);

        // Collect non-separator tokens after the action name
        let args: Vec<&str> = tokens[1..].iter().filter(|t| **t != "-").copied().collect();

        let mut ip = None;
        let mut user = None;
        let mut timeout = 0u64;

        for arg in &args {
            if arg.parse::<std::net::IpAddr>().is_ok() {
                ip = Some(arg.to_string());
            } else if let Ok(t) = arg.parse::<u64>() {
                timeout = t;
            } else if user.is_none() {
                // First non-IP, non-numeric token is treated as a username
                user = Some(arg.to_string());
            }
        }

        let params = ActionParams {
            ip,
            pid: None,
            user,
            timeout,
            extra: std::collections::HashMap::new(),
        };
        return Some((action, params));
    }

    None
}

/// Extract the base action name, stripping trailing '0' or '1' (Wazuh convention).
fn extract_action_name(raw: &str) -> String {
    let name = raw.trim();
    let name = name
        .strip_suffix('0')
        .or_else(|| name.strip_suffix('1'))
        .unwrap_or(name);
    match name {
        "firewall-drop" => "block_ip".to_string(),
        "disable-account" => "disable_account".to_string(),
        "host-deny" => "block_ip".to_string(),
        _ => name.replace('-', "_"),
    }
}

/// The main active response run loop.
async fn run(
    ar_config: wda_core::config::ActiveResponseConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("active response module starting");

    let timeout = if ar_config.timeout == 0 {
        Duration::from_secs(300)
    } else {
        Duration::from_secs(ar_config.timeout)
    };
    let registry = ActionRegistry::new(&ar_config.actions);
    let mut rx: EventReceiver = bus.subscribe();

    status.store(STATUS_RUNNING, Ordering::Relaxed);
    info!("active response module running");

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("active response module received shutdown signal");
                break;
            }

            event = rx.recv() => {
                let event = match event {
                    Some(ev) => ev,
                    None => {
                        warn!("event bus closed, stopping active response module");
                        break;
                    }
                };

                match &event.kind {
                    EventKind::ActiveResponseRequest { action, parameters } => {
                        debug!(action, "received active response request");

                        let params: ActionParams = serde_json::from_value(parameters.clone())
                            .unwrap_or_else(|_| {
                                ActionParams {
                                    ip: parameters.get("ip").and_then(|v| v.as_str()).map(String::from),
                                    pid: parameters.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32),
                                    user: parameters.get("user").and_then(|v| v.as_str()).map(String::from),
                                    timeout: parameters.get("timeout").and_then(|v| v.as_u64()).unwrap_or(0),
                                    extra: std::collections::HashMap::new(),
                                }
                            });

                        let result = registry.dispatch(action, &params, timeout).await;

                        let result_event = Event::new(
                            "active_response",
                            Priority::Critical,
                            EventKind::ActiveResponseResult {
                                action: action.clone(),
                                success: result.success,
                                output: result.output.clone(),
                            },
                        );
                        if let Err(e) = bus.publish_to_server(result_event).await {
                            warn!(error = %e, "failed to publish AR result");
                        }

                        // Schedule undo if timeout > 0
                        if result.success && params.timeout > 0 {
                            schedule_undo(
                                action.clone(),
                                params,
                                timeout,
                                bus.clone(),
                                ar_config.actions.clone(),
                            );
                        }
                    }
                    EventKind::ServerCommand { command, payload }
                        if command == "execd" || command == "active-response" || payload.contains("#!-execd") =>
                    {
                        if let Some((action, params)) = parse_ar_command(payload) {
                            debug!(action, "parsed AR command from server");

                            let result = registry.dispatch(&action, &params, timeout).await;

                            let result_event = Event::new(
                                "active_response",
                                Priority::Critical,
                                EventKind::ActiveResponseResult {
                                    action: action.clone(),
                                    success: result.success,
                                    output: result.output.clone(),
                                },
                            );
                            if let Err(e) = bus.publish_to_server(result_event).await {
                                warn!(error = %e, "failed to publish AR result");
                            }

                            if result.success && params.timeout > 0 {
                                schedule_undo(
                                    action,
                                    params,
                                    timeout,
                                    bus.clone(),
                                    ar_config.actions.clone(),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("active response module stopped");
    Ok(())
}

/// Schedule an undo action after the specified timeout.
fn schedule_undo(
    action: String,
    params: ActionParams,
    exec_timeout: Duration,
    bus: EventBus,
    allowed_actions: Vec<String>,
) {
    let sleep_duration = Duration::from_secs(params.timeout);
    tokio::spawn(async move {
        tokio::time::sleep(sleep_duration).await;
        let registry = ActionRegistry::new(&allowed_actions);
        let undo_result = registry.dispatch_undo(&action, &params, exec_timeout).await;

        let undo_event = Event::new(
            "active_response",
            Priority::Normal,
            EventKind::ActiveResponseResult {
                action: format!("undo_{}", action),
                success: undo_result.success,
                output: undo_result.output,
            },
        );
        let _ = bus.publish_to_server(undo_event).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use wda_core::config::{ActiveResponseConfig, ModulesConfig};
    use wda_core::signal::ShutdownController;

    #[test]
    fn test_parse_ar_json_command() {
        let payload = r#"{"version":1,"command":"firewall-drop0","parameters":{"alert":{"data":{"srcip":"10.0.0.1"}},"timeout":300}}"#;
        let (action, params) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "block_ip");
        assert_eq!(params.ip.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn test_parse_ar_execd_prefix() {
        let payload = r#"#!-execd {"command":"firewall-drop0","parameters":{"ip":"192.168.1.100","timeout":60}}"#;
        let (action, params) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "block_ip");
        assert_eq!(params.ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(params.timeout, 60);
    }

    #[test]
    fn test_parse_ar_legacy_format() {
        let payload = "firewall-drop0 - - 10.99.99.99 600";
        let (action, params) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "block_ip");
        assert_eq!(params.ip.as_deref(), Some("10.99.99.99"));
        assert_eq!(params.timeout, 600);
    }

    #[test]
    fn test_parse_ar_legacy_disable_account() {
        let payload = "disable-account0 - jdoe - - 300";
        let (action, params) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "disable_account");
        assert_eq!(params.user.as_deref(), Some("jdoe"));
        assert_eq!(params.timeout, 300);
    }

    #[test]
    fn test_extract_action_name() {
        assert_eq!(extract_action_name("firewall-drop0"), "block_ip");
        assert_eq!(extract_action_name("firewall-drop1"), "block_ip");
        assert_eq!(extract_action_name("firewall-drop"), "block_ip");
        assert_eq!(extract_action_name("disable-account0"), "disable_account");
        assert_eq!(extract_action_name("custom-action0"), "custom_action");
    }

    #[tokio::test]
    async fn test_module_starts_and_stops() {
        let config = AgentConfig {
            modules: ModulesConfig {
                active_response: ActiveResponseConfig {
                    enabled: true,
                    timeout: 5,
                    actions: vec!["block_ip".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, _server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();

        let handle = ActiveResponseModule::start(&config, bus, signal);
        assert_eq!(handle.name, "active_response");

        tokio::time::sleep(Duration::from_millis(50)).await;

        controller.shutdown();
        let result = tokio::time::timeout(Duration::from_secs(5), handle.task).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_module_processes_ar_request() {
        let config = AgentConfig {
            modules: ModulesConfig {
                active_response: ActiveResponseConfig {
                    enabled: true,
                    timeout: 5,
                    actions: vec!["kill_process".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, mut server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();

        let _handle = ActiveResponseModule::start(&config, bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let ar_event = Event::new(
            "test",
            Priority::Critical,
            EventKind::ActiveResponseRequest {
                action: "kill_process".to_string(),
                parameters: serde_json::json!({"pid": 4000000}),
            },
        );
        bus.publish(ar_event).unwrap();

        let result_event = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
            .await
            .expect("timed out waiting for AR result")
            .expect("server_rx closed");

        match &result_event.kind {
            EventKind::ActiveResponseResult { action, .. } => {
                assert_eq!(action, "kill_process");
            }
            other => panic!("expected ActiveResponseResult, got: {:?}", other),
        }

        controller.shutdown();
    }

    #[tokio::test]
    async fn test_module_processes_server_command() {
        let config = AgentConfig {
            modules: ModulesConfig {
                active_response: ActiveResponseConfig {
                    enabled: true,
                    timeout: 5,
                    actions: vec!["block_ip".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, mut server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();

        let _handle = ActiveResponseModule::start(&config, bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let cmd_event = Event::new(
            "comms",
            Priority::Critical,
            EventKind::ServerCommand {
                command: "execd".to_string(),
                payload:
                    r#"{"command":"firewall-drop0","parameters":{"ip":"10.99.99.99","timeout":0}}"#
                        .to_string(),
            },
        );
        bus.publish(cmd_event).unwrap();

        let result_event = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
            .await
            .expect("timed out waiting for AR result")
            .expect("server_rx closed");

        match &result_event.kind {
            EventKind::ActiveResponseResult { action, .. } => {
                assert_eq!(action, "block_ip");
            }
            other => panic!("expected ActiveResponseResult, got: {:?}", other),
        }

        controller.shutdown();
    }
}
