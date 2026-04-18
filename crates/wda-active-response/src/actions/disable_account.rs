//! Disable account action — locks a user account.
//!
//! - Linux: `passwd -l <user>` / `passwd -u <user>`
//! - macOS: `dscl . -create /Users/<user> UserShell /usr/bin/false`
//! - Windows: `net user <user> /active:no`

use std::time::Duration;

use async_trait::async_trait;
use tracing::info;

use super::{ActionParams, ActionResult, ResponseAction};
use crate::executor;

/// Disables a user account using platform-native tools.
pub struct DisableAccountAction;

impl Default for DisableAccountAction {
    fn default() -> Self {
        Self
    }
}

impl DisableAccountAction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ResponseAction for DisableAccountAction {
    fn name(&self) -> &str {
        "disable_account"
    }

    async fn execute(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let user = match &params.user {
            Some(user) => user,
            None => {
                return ActionResult::err("missing 'user' parameter for disable_account action")
            }
        };

        if user == "root" || user == "Administrator" {
            return ActionResult::err("refusing to disable root/Administrator account");
        }

        if !is_valid_username(user) {
            return ActionResult::err(format!("invalid username: {}", user));
        }

        info!(user, "disabling user account");

        platform_disable_account(user, timeout).await
    }

    async fn undo(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let user = match &params.user {
            Some(user) => user,
            None => return ActionResult::err("missing 'user' parameter for enable_account action"),
        };

        if user == "root" || user == "Administrator" {
            return ActionResult::err("refusing to re-enable root/Administrator account");
        }

        if !is_valid_username(user) {
            return ActionResult::err(format!("invalid username: {}", user));
        }

        info!(user, "re-enabling user account");

        platform_enable_account(user, timeout).await
    }
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn platform_disable_account(user: &str, timeout: Duration) -> ActionResult {
    let result = executor::execute_command("passwd", &["-l", user], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("disabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to disable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "linux")]
async fn platform_enable_account(user: &str, timeout: Duration) -> ActionResult {
    let result = executor::execute_command("passwd", &["-u", user], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("re-enabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to re-enable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

// ── macOS ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn platform_disable_account(user: &str, timeout: Duration) -> ActionResult {
    let user_path = format!("/Users/{}", user);
    let result = executor::execute_command(
        "dscl",
        &[".", "-create", &user_path, "UserShell", "/usr/bin/false"],
        timeout,
        false,
    )
    .await;
    if result.success {
        ActionResult::ok(format!("disabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to disable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "macos")]
async fn platform_enable_account(user: &str, timeout: Duration) -> ActionResult {
    let user_path = format!("/Users/{}", user);
    let result = executor::execute_command(
        "dscl",
        &[".", "-create", &user_path, "UserShell", "/bin/zsh"],
        timeout,
        false,
    )
    .await;
    if result.success {
        ActionResult::ok(format!("re-enabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to re-enable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn platform_disable_account(user: &str, timeout: Duration) -> ActionResult {
    let result =
        executor::execute_command("net", &["user", user, "/active:no"], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("disabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to disable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "windows")]
async fn platform_enable_account(user: &str, timeout: Duration) -> ActionResult {
    let result =
        executor::execute_command("net", &["user", user, "/active:yes"], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("re-enabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to re-enable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

// ── Fallback ─────────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn platform_disable_account(user: &str, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "disable_account not supported on this platform for user {}",
        user
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn platform_enable_account(user: &str, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "enable_account not supported on this platform for user {}",
        user
    ))
}

/// Basic username validation: alphanumeric, underscore, hyphen, dot.
fn is_valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && user
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_valid_username() {
        assert!(is_valid_username("testuser"));
        assert!(is_valid_username("test_user"));
        assert!(is_valid_username("test-user"));
        assert!(is_valid_username("user.name"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("user;rm -rf /"));
        assert!(!is_valid_username("user name"));
    }

    #[tokio::test]
    async fn test_missing_user() {
        let action = DisableAccountAction::new();
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
    async fn test_refuse_root() {
        let action = DisableAccountAction::new();
        let params = ActionParams {
            ip: None,
            pid: None,
            user: Some("root".to_string()),
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("refusing"));
    }

    #[tokio::test]
    async fn test_invalid_username() {
        let action = DisableAccountAction::new();
        let params = ActionParams {
            ip: None,
            pid: None,
            user: Some("user;rm -rf /".to_string()),
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("invalid username"));
    }
}
