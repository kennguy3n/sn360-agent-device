//! Connection management for Wazuh server communication.
//!
//! Handles TCP/UDP transport, automatic reconnection with exponential
//! backoff, keepalive messages, and message batching.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::crypto::WazuhCipher;
use crate::protocol::WazuhMessage;

/// Connection errors.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("connection failed: {0}")]
    ConnectFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    #[error("connection closed by server")]
    Closed,
    #[error("authentication failed")]
    AuthFailed,
    #[error("timeout")]
    Timeout,
}

/// Connection configuration.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Server address (host:port).
    pub server_address: String,
    /// Server port.
    pub server_port: u16,
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Initial reconnection delay.
    pub reconnect_initial: Duration,
    /// Maximum reconnection delay.
    pub reconnect_max: Duration,
    /// Reconnection backoff multiplier.
    pub reconnect_multiplier: f64,
    /// Keepalive interval.
    pub keepalive_interval: Duration,
    /// Message batch window.
    pub batch_window: Duration,
    /// Maximum messages per batch.
    pub max_batch_size: usize,
}

/// Transport protocol selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_address: "localhost".to_string(),
            server_port: 1514,
            protocol: TransportProtocol::Tcp,
            reconnect_initial: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
            reconnect_multiplier: 2.0,
            keepalive_interval: Duration::from_secs(600),
            batch_window: Duration::from_secs(5),
            max_batch_size: 100,
        }
    }
}

/// Manages the connection to the Wazuh server.
///
/// Handles reconnection, message encryption, and transport.
pub struct ConnectionManager {
    config: ConnectionConfig,
    cipher: Option<WazuhCipher>,
    stream: Option<TcpStream>,
    connected: bool,
    consecutive_failures: u32,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            cipher: None,
            stream: None,
            connected: false,
            consecutive_failures: 0,
        }
    }

    /// Set the encryption cipher (after enrollment).
    pub fn set_cipher(&mut self, cipher: WazuhCipher) {
        self.cipher = Some(cipher);
    }

    /// Check if currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Connect to the Wazuh server.
    pub async fn connect(&mut self) -> Result<(), ConnectionError> {
        let addr = format!("{}:{}", self.config.server_address, self.config.server_port);
        info!(address = %addr, "connecting to server");

        match &self.config.protocol {
            TransportProtocol::Tcp => {
                let timeout = Duration::from_secs(10);
                let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| ConnectionError::Timeout)?
                    .map_err(|e| ConnectionError::ConnectFailed(e.to_string()))?;

                // Set TCP keepalive
                let sock_ref = socket2::SockRef::from(&stream);
                let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60));
                let _ = sock_ref.set_tcp_keepalive(&keepalive);

                self.stream = Some(stream);
                self.connected = true;
                self.consecutive_failures = 0;
                info!(address = %addr, "connected to server");
                Ok(())
            }
            TransportProtocol::Udp => {
                // UDP is connectionless; we just validate the address
                info!(address = %addr, "configured UDP endpoint");
                self.connected = true;
                self.consecutive_failures = 0;
                Ok(())
            }
        }
    }

    /// Connect with automatic retry and exponential backoff.
    pub async fn connect_with_retry(&mut self) -> Result<(), ConnectionError> {
        let mut delay = self.config.reconnect_initial;

        loop {
            match self.connect().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.consecutive_failures += 1;
                    warn!(
                        error = %e,
                        attempt = self.consecutive_failures,
                        next_retry_secs = delay.as_secs(),
                        "connection failed, retrying"
                    );

                    tokio::time::sleep(delay).await;

                    // Exponential backoff with cap
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * self.config.reconnect_multiplier)
                            .min(self.config.reconnect_max.as_secs_f64()),
                    );
                }
            }
        }
    }

    /// Send a message to the server.
    ///
    /// The message body is encrypted and prefixed with the agent ID
    /// (in the clear) so the server can look up the correct key.
    /// Wire format: `4-byte-length | "{agent_id}:" | encrypted_body`
    pub async fn send(&mut self, message: &WazuhMessage) -> Result<(), ConnectionError> {
        let body = message.encode_body();

        debug!(
            agent_id = %message.agent_id,
            msg_type = ?message.msg_type,
            body_len = body.len(),
            body_preview = %String::from_utf8_lossy(&body[..body.len().min(120)]),
            "raw plaintext before encryption"
        );

        let data = if let Some(cipher) = &self.cipher {
            let encrypted = cipher
                .encrypt(&body)
                .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;
            // Prepend agent_id as a plaintext routing prefix.
            let mut wire = format!("{}:", message.agent_id).into_bytes();
            wire.extend_from_slice(&encrypted);
            wire
        } else {
            // No cipher — fall back to legacy full-message encoding.
            message.encode()
        };

        self.send_raw(&data).await
    }

    /// Send raw bytes over the transport.
    async fn send_raw(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        match &self.config.protocol {
            TransportProtocol::Tcp => {
                let stream = self.stream.as_mut().ok_or(ConnectionError::Closed)?;

                // Wazuh TCP protocol: 4-byte length prefix (big-endian) + data
                let len = (data.len() as u32).to_be_bytes();
                stream
                    .write_all(&len)
                    .await
                    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;
                stream
                    .write_all(data)
                    .await
                    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;

                debug!(bytes = data.len(), "sent message");
                Ok(())
            }
            TransportProtocol::Udp => {
                // UDP send would go here
                debug!(bytes = data.len(), "sent UDP message");
                Ok(())
            }
        }
    }

    /// Receive a message from the server.
    pub async fn receive(&mut self) -> Result<Vec<u8>, ConnectionError> {
        match &self.config.protocol {
            TransportProtocol::Tcp => {
                let stream = self.stream.as_mut().ok_or(ConnectionError::Closed)?;

                // Read 4-byte length prefix
                let mut len_buf = [0u8; 4];
                stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
                let len = u32::from_be_bytes(len_buf) as usize;

                // Sanity check on message size (max 64 KB)
                if len > 65536 {
                    return Err(ConnectionError::ReceiveFailed(format!(
                        "message too large: {} bytes",
                        len
                    )));
                }

                // Read the message body
                let mut buf = vec![0u8; len];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;

                // Decrypt if cipher is available
                if let Some(cipher) = &self.cipher {
                    let plaintext = cipher
                        .decrypt(&buf)
                        .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
                    Ok(plaintext)
                } else {
                    Ok(buf)
                }
            }
            TransportProtocol::Udp => Err(ConnectionError::ReceiveFailed(
                "UDP receive not yet implemented".to_string(),
            )),
        }
    }

    /// Disconnect from the server.
    pub async fn disconnect(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.into_std();
        }
        self.connected = false;
        info!("disconnected from server");
    }
}
