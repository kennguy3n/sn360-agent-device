//! Agent enrollment with the Wazuh server.
//!
//! Implements the authd enrollment protocol on port 1515.
//! Supports both pre-shared key and password-based enrollment.

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::info;

/// Enrollment errors.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("enrollment connection failed: {0}")]
    ConnectionFailed(String),
    #[error("enrollment rejected by server: {0}")]
    Rejected(String),
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    #[error("key storage failed: {0}")]
    StorageFailed(String),
    #[error("timeout during enrollment")]
    Timeout,
}

/// Agent key information stored after enrollment.
#[derive(Debug, Clone)]
pub struct AgentKey {
    /// Assigned agent ID.
    pub id: String,
    /// Agent name.
    pub name: String,
    /// Server-assigned IP or "any".
    pub ip: String,
    /// Pre-shared key for encryption.
    pub key: String,
}

impl AgentKey {
    /// Encode the key in Wazuh client.keys format.
    pub fn to_keys_line(&self) -> String {
        format!("{} {} {} {}", self.id, self.name, self.ip, self.key)
    }

    /// Parse a key from Wazuh client.keys format.
    pub fn from_keys_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() == 4 {
            Some(Self {
                id: parts[0].to_string(),
                name: parts[1].to_string(),
                ip: parts[2].to_string(),
                key: parts[3].to_string(),
            })
        } else {
            None
        }
    }
}

/// Enrollment client for registering with a Wazuh server.
pub struct EnrollmentClient {
    /// Enrollment server address.
    server: String,
    /// Enrollment server port.
    port: u16,
    /// Agent name to register.
    agent_name: String,
    /// Optional enrollment password/key.
    password: Option<String>,
    /// Optional group assignment.
    groups: Option<Vec<String>>,
}

impl EnrollmentClient {
    /// Create a new enrollment client.
    pub fn new(server: &str, port: u16, agent_name: &str) -> Self {
        Self {
            server: server.to_string(),
            port,
            agent_name: agent_name.to_string(),
            password: None,
            groups: None,
        }
    }

    /// Set the enrollment password.
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Set group assignments.
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = Some(groups);
        self
    }

    /// Perform enrollment and return the assigned agent key.
    pub async fn enroll(&self) -> Result<AgentKey, EnrollmentError> {
        let addr = format!("{}:{}", self.server, self.port);
        info!(address = %addr, agent = %self.agent_name, "starting enrollment");

        // Connect to enrollment server
        let timeout = std::time::Duration::from_secs(30);
        let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| EnrollmentError::Timeout)?
            .map_err(|e| EnrollmentError::ConnectionFailed(e.to_string()))?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Build enrollment request
        // Format: OSSEC A:'agent_name'\n
        // With password: OSSEC PASS: password OSSEC A:'agent_name'\n
        let request = if let Some(ref password) = self.password {
            format!("OSSEC PASS: {} OSSEC A:'{}'\n", password, self.agent_name)
        } else {
            format!("OSSEC A:'{}'\n", self.agent_name)
        };

        // Send enrollment request
        writer
            .write_all(request.as_bytes())
            .await
            .map_err(|e| EnrollmentError::ConnectionFailed(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| EnrollmentError::ConnectionFailed(e.to_string()))?;

        // Read response
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .await
            .map_err(|e| EnrollmentError::InvalidResponse(e.to_string()))?;

        let response = response.trim();
        info!(response = %response, "enrollment response received");

        // Parse response
        // Success format: OSSEC K:'<id> <name> <ip> <key>'
        if let Some(key_data) = response.strip_prefix("OSSEC K:'") {
            let key_data = key_data.trim_end_matches('\'');
            let agent_key = AgentKey::from_keys_line(key_data).ok_or_else(|| {
                EnrollmentError::InvalidResponse("failed to parse agent key".to_string())
            })?;

            info!(
                agent_id = %agent_key.id,
                agent_name = %agent_key.name,
                "enrollment successful"
            );

            Ok(agent_key)
        } else if response.starts_with("ERROR") {
            Err(EnrollmentError::Rejected(response.to_string()))
        } else {
            Err(EnrollmentError::InvalidResponse(response.to_string()))
        }
    }
}

/// Path to the agent keys file.
pub fn keys_file_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/wazuh-desktop-agent/client.keys")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Program Files\WazuhDesktopAgent\client.keys")
    }
}

/// Load an existing agent key from disk.
pub fn load_agent_key() -> Option<AgentKey> {
    let path = keys_file_path();
    let contents = std::fs::read_to_string(&path).ok()?;
    let line = contents.lines().next()?;
    AgentKey::from_keys_line(line.trim())
}

/// Save an agent key to disk.
pub fn save_agent_key(key: &AgentKey) -> Result<(), EnrollmentError> {
    let path = keys_file_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| EnrollmentError::StorageFailed(e.to_string()))?;
    }

    std::fs::write(&path, key.to_keys_line())
        .map_err(|e| EnrollmentError::StorageFailed(e.to_string()))?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o640);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| EnrollmentError::StorageFailed(e.to_string()))?;
    }

    info!(path = %path.display(), "agent key saved");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_key_roundtrip() {
        let key = AgentKey {
            id: "001".to_string(),
            name: "test-agent".to_string(),
            ip: "any".to_string(),
            key: "abc123def456".to_string(),
        };

        let line = key.to_keys_line();
        assert_eq!(line, "001 test-agent any abc123def456");

        let parsed = AgentKey::from_keys_line(&line).unwrap();
        assert_eq!(parsed.id, "001");
        assert_eq!(parsed.name, "test-agent");
        assert_eq!(parsed.ip, "any");
        assert_eq!(parsed.key, "abc123def456");
    }

    #[test]
    fn test_agent_key_parse_invalid() {
        assert!(AgentKey::from_keys_line("too short").is_none());
        assert!(AgentKey::from_keys_line("only two parts").is_none());
    }
}
