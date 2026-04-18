//! Firewall drop action — blocks an IP via iptables on Linux.

use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, info};

use super::{ActionParams, ActionResult, ResponseAction};
use crate::executor;

/// Blocks an IP address by inserting an iptables DROP rule.
pub struct FirewallDropAction;

impl Default for FirewallDropAction {
    fn default() -> Self {
        Self
    }
}

impl FirewallDropAction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ResponseAction for FirewallDropAction {
    fn name(&self) -> &str {
        "block_ip"
    }

    async fn execute(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let ip = match &params.ip {
            Some(ip) => ip,
            None => return ActionResult::err("missing 'ip' parameter for block_ip action"),
        };

        // Validate IP format (basic check)
        if !is_valid_ip(ip) {
            return ActionResult::err(format!("invalid IP address: {}", ip));
        }

        info!(ip, "blocking IP via iptables");

        let result = executor::execute_command(
            "iptables",
            &["-I", "INPUT", "-s", ip, "-j", "DROP"],
            timeout,
            false, // iptables requires root, don't drop privileges
        )
        .await;

        if result.success {
            debug!(ip, "IP blocked successfully");
            ActionResult::ok(format!("blocked IP {}", ip))
        } else {
            ActionResult::err(format!(
                "failed to block IP {}: {}",
                ip,
                result.combined_output()
            ))
        }
    }

    async fn undo(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let ip = match &params.ip {
            Some(ip) => ip,
            None => return ActionResult::err("missing 'ip' parameter for unblock_ip action"),
        };

        if !is_valid_ip(ip) {
            return ActionResult::err(format!("invalid IP address: {}", ip));
        }

        info!(ip, "unblocking IP via iptables");

        let result = executor::execute_command(
            "iptables",
            &["-D", "INPUT", "-s", ip, "-j", "DROP"],
            timeout,
            false,
        )
        .await;

        if result.success {
            ActionResult::ok(format!("unblocked IP {}", ip))
        } else {
            ActionResult::err(format!(
                "failed to unblock IP {}: {}",
                ip,
                result.combined_output()
            ))
        }
    }
}

/// Basic IP address validation (IPv4 only for now).
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("10.0.0.1"));
        assert!(is_valid_ip("::1"));
        assert!(!is_valid_ip("not-an-ip"));
        assert!(!is_valid_ip(""));
        assert!(!is_valid_ip("256.1.1.1"));
    }

    #[tokio::test]
    async fn test_missing_ip_parameter() {
        let action = FirewallDropAction::new();
        let params = ActionParams {
            ip: None,
            pid: None,
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("missing"));
    }

    #[tokio::test]
    async fn test_invalid_ip() {
        let action = FirewallDropAction::new();
        let params = ActionParams {
            ip: Some("not-valid".to_string()),
            pid: None,
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("invalid IP"));
    }
}
