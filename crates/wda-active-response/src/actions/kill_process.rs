//! Kill process action — terminates a process by PID.

use std::time::Duration;

use async_trait::async_trait;
use tracing::info;

use super::{ActionParams, ActionResult, ResponseAction};
use crate::executor;

/// Terminates a process by PID using `kill -9`.
pub struct KillProcessAction;

impl Default for KillProcessAction {
    fn default() -> Self {
        Self
    }
}

impl KillProcessAction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ResponseAction for KillProcessAction {
    fn name(&self) -> &str {
        "kill_process"
    }

    async fn execute(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let pid = match params.pid {
            Some(pid) => pid,
            None => return ActionResult::err("missing 'pid' parameter for kill_process action"),
        };

        if pid == 0 || pid == 1 {
            return ActionResult::err(format!("refusing to kill PID {}", pid));
        }

        info!(pid, "killing process");

        let pid_str = pid.to_string();
        let result =
            executor::execute_command("kill", &["-9", &pid_str], timeout, false).await;

        if result.success {
            ActionResult::ok(format!("killed process {}", pid))
        } else {
            // kill returns non-zero if process doesn't exist, which is fine
            if result.stderr.contains("No such process") {
                ActionResult::ok(format!("process {} already terminated", pid))
            } else {
                ActionResult::err(format!(
                    "failed to kill process {}: {}",
                    pid,
                    result.combined_output()
                ))
            }
        }
    }

    async fn undo(&self, _params: &ActionParams, _timeout: Duration) -> ActionResult {
        // Cannot undo a kill
        ActionResult::err("cannot undo process termination")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_missing_pid() {
        let action = KillProcessAction::new();
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
    async fn test_refuse_pid_1() {
        let action = KillProcessAction::new();
        let params = ActionParams {
            ip: None,
            pid: Some(1),
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("refusing"));
    }

    #[tokio::test]
    async fn test_kill_nonexistent_pid() {
        let action = KillProcessAction::new();
        // Use a very high PID that almost certainly doesn't exist
        let params = ActionParams {
            ip: None,
            pid: Some(4_000_000),
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        // Should handle gracefully (either success because "already terminated" or error)
        // The exact behavior depends on the system
        assert!(!result.output.is_empty());
    }
}
