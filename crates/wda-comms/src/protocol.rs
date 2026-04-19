//! Wazuh protocol message formatting.
//!
//! Implements the Wazuh wire protocol. Messages are encrypted with
//! Blowfish-CBC or AES-256-CBC. The agent ID is sent in the clear as a
//! routing prefix; only the message body is encrypted.
//!
//! On the wire (TCP): `4-byte-length | agent_id ":" encrypted_body`

use serde::{Deserialize, Serialize};

/// Wazuh protocol message types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Syscheck (FIM) event.
    Syscheck,
    /// Log collection event.
    Log,
    /// Rootcheck event.
    Rootcheck,
    /// SCA event.
    Sca,
    /// Syscollector (inventory) event.
    Syscollector,
    /// Agent keepalive.
    Keepalive,
    /// Active response result.
    ActiveResponse,
    /// Agent startup notification.
    Startup,
    /// Agent shutdown notification.
    Shutdown,
    /// Request from server.
    Request,
    /// Generic message.
    Generic,
}

impl MessageType {
    /// Get the Wazuh protocol string for this message type.
    pub fn as_protocol_str(&self) -> &'static str {
        match self {
            MessageType::Syscheck => "syscheck",
            MessageType::Log => "log",
            MessageType::Rootcheck => "rootcheck",
            MessageType::Sca => "sca",
            MessageType::Syscollector => "syscollector",
            MessageType::Keepalive => "keep_alive",
            MessageType::ActiveResponse => "active-response",
            MessageType::Startup => "agent_start",
            MessageType::Shutdown => "agent_stop",
            MessageType::Request => "request",
            MessageType::Generic => "message",
        }
    }

    /// Parse a protocol string into a message type.
    pub fn from_protocol_str(s: &str) -> Self {
        match s {
            "syscheck" => MessageType::Syscheck,
            "log" => MessageType::Log,
            "rootcheck" => MessageType::Rootcheck,
            "sca" => MessageType::Sca,
            "syscollector" => MessageType::Syscollector,
            "keep_alive" => MessageType::Keepalive,
            "active-response" => MessageType::ActiveResponse,
            "agent_start" => MessageType::Startup,
            "agent_stop" => MessageType::Shutdown,
            "request" => MessageType::Request,
            _ => MessageType::Generic,
        }
    }
}

/// A Wazuh protocol message ready for transmission.
#[derive(Debug, Clone)]
pub struct WazuhMessage {
    /// Agent ID (e.g., "001").
    pub agent_id: String,
    /// Message type.
    pub msg_type: MessageType,
    /// Message payload.
    pub payload: String,
    /// Whether to compress the payload.
    pub compress: bool,
}

impl WazuhMessage {
    /// Create a new message.
    pub fn new(
        agent_id: impl Into<String>,
        msg_type: MessageType,
        payload: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            msg_type,
            payload: payload.into(),
            compress: false,
        }
    }

    /// Enable compression for this message.
    pub fn with_compression(mut self) -> Self {
        self.compress = true;
        self
    }

    /// Encode the full wire-format message (legacy — includes agent_id).
    ///
    /// Format: `{agent_id}:{msg_type}:{payload}`
    ///
    /// Kept for backward compatibility with tests. Prefer `encode_body()`
    /// for the real protocol path.
    pub fn encode(&self) -> Vec<u8> {
        let wire = format!(
            "{}:{}:{}",
            self.agent_id,
            self.msg_type.as_protocol_str(),
            self.payload,
        );

        if self.compress {
            compress_payload(wire.as_bytes())
        } else {
            wire.into_bytes()
        }
    }

    /// Encode only the message body (the part that gets encrypted).
    ///
    /// The agent ID is NOT included — it is sent as a plaintext routing
    /// prefix by `ConnectionManager::send()`.
    pub fn encode_body(&self) -> Vec<u8> {
        let body = match self.msg_type {
            MessageType::Syscheck => format!("8:syscheck:{}", self.payload),
            MessageType::Log => format!("1:{}", self.payload),
            MessageType::Syscollector => format!("d:{}", self.payload),
            MessageType::Rootcheck => format!("9:{}", self.payload),
            // Control messages already carry the correct prefix.
            MessageType::Keepalive | MessageType::Startup | MessageType::Shutdown => {
                self.payload.clone()
            }
            _ => self.payload.clone(),
        };

        if self.compress {
            compress_payload(body.as_bytes())
        } else {
            body.into_bytes()
        }
    }

    /// Decode a message from the Wazuh wire format.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;
        let mut parts = text.splitn(3, ':');

        let agent_id = parts.next()?.to_string();
        let msg_type_str = parts.next()?;
        let payload = parts.next().unwrap_or("").to_string();

        Some(Self {
            agent_id,
            msg_type: MessageType::from_protocol_str(msg_type_str),
            payload,
            compress: false,
        })
    }

    /// Create a keepalive message.
    ///
    /// Wazuh's `run_notify()` in `notify.c` sends a multi-line control
    /// message.  The server's `save_controlmsg` looks for `\n` in the
    /// body; if none is found it logs "Invalid message from agent".
    ///
    /// Minimal format accepted by remoted:
    ///   `#!-<uname>\n<shared_file_hash>\n`
    pub fn keepalive(agent_id: &str) -> Self {
        let uname = basic_uname();
        // Wazuh agent sends: "<md5> merged.mg\n" for the shared files line.
        // We don't have a merged.mg, so send a placeholder hash.
        let body = format!("#!-{}\nx merged.mg\n", uname);
        Self::new(agent_id, MessageType::Keepalive, body)
    }

    /// Create an agent startup message.
    ///
    /// Wazuh's `agent_handshake_to_server` in `start_agent.c` sends:
    ///   `CONTROL_HEADER + HC_STARTUP + agent_info_json`
    /// where `HC_STARTUP` = `"agent startup "` (trailing space) and
    /// `agent_info_json` = `{"version":"..."}`.  The server parses
    /// the JSON to extract the version; if missing it responds with
    /// an error.
    pub fn startup(agent_id: &str) -> Self {
        // Match the Wazuh 4.x version string format.
        let body = "#!-agent startup {\"version\":\"v4.9.2\"}".to_string();
        Self::new(agent_id, MessageType::Startup, body)
    }
}

/// Compress data using zlib/deflate.
fn compress_payload(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).expect("compression failed");
    encoder.finish().expect("compression finalization failed")
}

/// Decompress zlib/deflate data.
pub fn decompress_payload(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    Some(result)
}

/// Return a minimal uname-style string for keepalive messages.
///
/// Wazuh's `run_notify()` calls `getuname()` which returns something
/// like `Linux myhost 5.15.0 #1 SMP x86_64 |Linux|x86_64`.  We
/// build a comparable string from the information available at
/// runtime.
fn basic_uname() -> String {
    #[cfg(target_os = "linux")]
    {
        let nodename = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let machine = std::env::consts::ARCH;
        format!(
            "Linux {} {} #1 SMP {} |Linux|{}",
            nodename, release, machine, machine
        )
    }
    #[cfg(target_os = "macos")]
    {
        let machine = std::env::consts::ARCH;
        let nodename = run_cmd("hostname", &[]);
        let release = run_cmd("uname", &["-r"]);
        let version = run_cmd("uname", &["-v"]);
        format!(
            "Darwin {} {} {} |Darwin|{}",
            nodename, release, version, machine
        )
    }
    #[cfg(target_os = "windows")]
    {
        let machine = std::env::consts::ARCH;
        let nodename = run_cmd("hostname", &[]);
        let ver_output = run_cmd("cmd", &["/C", "ver"]);
        let version = ver_output
            .split("Version ")
            .nth(1)
            .unwrap_or("10.0")
            .trim_end_matches(']')
            .trim();
        format!(
            "Microsoft Windows {} {} |Windows|{}",
            version, nodename, machine
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "Unknown |Unknown|unknown".to_string()
    }
}

/// Run a command synchronously and return trimmed stdout, or a fallback.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_cmd(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encode() {
        let msg = WazuhMessage::new("001", MessageType::Keepalive, "#!-agent keep_alive");
        let encoded = msg.encode();
        let expected = b"001:keep_alive:#!-agent keep_alive";
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_message_decode() {
        let data = b"001:syscheck:{\"path\":\"/etc/passwd\"}";
        let msg = WazuhMessage::decode(data).unwrap();
        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.payload, "{\"path\":\"/etc/passwd\"}");
    }

    #[test]
    fn test_compress_decompress() {
        let data = b"hello world hello world hello world";
        let compressed = compress_payload(data);
        let decompressed = decompress_payload(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_keepalive_message() {
        let msg = WazuhMessage::keepalive("002");
        assert_eq!(msg.agent_id, "002");
        assert_eq!(msg.msg_type, MessageType::Keepalive);
        // Body must start with "#!-" and contain a newline (required by
        // Wazuh remoted's save_controlmsg).
        assert!(msg.payload.starts_with("#!-"));
        assert!(msg.payload.contains('\n'));
        assert!(msg.payload.contains("merged.mg"));
    }

    #[test]
    fn test_startup_message() {
        let msg = WazuhMessage::startup("001");
        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.msg_type, MessageType::Startup);
        // Must contain the control header, HC_STARTUP ("agent startup "),
        // and a JSON version object.
        assert!(msg.payload.starts_with("#!-agent startup "));
        assert!(msg.payload.contains("version"));
    }

    #[test]
    fn test_message_type_roundtrip() {
        let types = vec![
            MessageType::Syscheck,
            MessageType::Log,
            MessageType::Rootcheck,
            MessageType::Sca,
            MessageType::Syscollector,
            MessageType::Keepalive,
            MessageType::ActiveResponse,
            MessageType::Startup,
            MessageType::Shutdown,
            MessageType::Request,
            MessageType::Generic,
        ];

        for mt in types {
            let s = mt.as_protocol_str();
            let parsed = MessageType::from_protocol_str(s);
            assert_eq!(mt, parsed);
        }
    }
}
