//! Agent configuration loading and parsing.
//!
//! Supports YAML configuration files with backward-compatible XML reading.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;

/// Top-level agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    /// Server connection settings.
    #[serde(default)]
    pub server: ServerConfig,

    /// Enrollment settings.
    #[serde(default)]
    pub enrollment: EnrollmentConfig,

    /// Module-specific configuration.
    #[serde(default)]
    pub modules: ModulesConfig,

    /// Resource limit settings.
    #[serde(default)]
    pub resource_limits: ResourceLimits,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Server connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server address (hostname or IP).
    #[serde(default = "default_server_address")]
    pub address: String,

    /// Server port.
    #[serde(default = "default_server_port")]
    pub port: u16,

    /// Transport protocol (tcp or udp).
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_interval: u64,
}

/// Enrollment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentConfig {
    /// Enrollment server address (defaults to server address).
    pub server: Option<String>,

    /// Enrollment port.
    #[serde(default = "default_enrollment_port")]
    pub port: u16,

    /// Whether to auto-enroll on first start.
    #[serde(default = "default_true")]
    pub auto_enroll: bool,

    /// Pre-shared key for enrollment (optional).
    pub key: Option<String>,

    /// Agent name override.
    pub agent_name: Option<String>,

    /// Agent group assignment.
    pub groups: Option<Vec<String>>,
}

/// Module enable/disable configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModulesConfig {
    #[serde(default)]
    pub fim: FimConfig,
    #[serde(default)]
    pub logcollector: LogCollectorConfig,
    #[serde(default)]
    pub inventory: ModuleToggle,
    #[serde(default)]
    pub sca: ModuleToggle,
    #[serde(default)]
    pub active_response: ModuleToggle,
    #[serde(default)]
    pub rootcheck: ModuleToggle,
}

/// FIM-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    /// Whether the FIM module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directories to monitor.
    #[serde(default = "default_fim_directories")]
    pub directories: Vec<FimDirectory>,
    /// Baseline scan interval in seconds (default 12h).
    #[serde(default = "default_fim_scan_interval")]
    pub scan_interval: u64,
    /// Debounce window in milliseconds (default 100).
    #[serde(default = "default_fim_debounce_ms")]
    pub debounce_ms: u64,
}

/// A directory entry in FIM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimDirectory {
    /// Path to monitor.
    pub path: String,
    /// Whether to watch recursively.
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// Whether to enable real-time monitoring.
    #[serde(default = "default_true")]
    pub realtime: bool,
    /// Whether to compute SHA-256 hashes.
    #[serde(default = "default_true")]
    pub check_sha256: bool,
    /// Glob patterns to exclude.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Log collector configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogCollectorConfig {
    /// Whether the log collector module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Log sources to monitor.
    #[serde(default)]
    pub sources: Vec<LogSource>,
}

/// A log source entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// Source type: "file" or "journald".
    #[serde(default = "default_source_type")]
    pub source_type: String,
    /// Path to the log file (for file sources).
    #[serde(default)]
    pub path: Option<String>,
    /// Log format: "syslog", "json", or "plain".
    #[serde(default = "default_log_source_format")]
    pub format: String,
}

/// Simple module enable/disable toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleToggle {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Resource limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU usage percentage.
    #[serde(default = "default_max_cpu")]
    pub max_cpu_percent: u8,

    /// Maximum memory usage in MB.
    #[serde(default = "default_max_memory")]
    pub max_memory_mb: u32,

    /// Battery mode: "adaptive", "minimal", "normal".
    #[serde(default = "default_battery_mode")]
    pub battery_mode: String,

    /// Whether to detect user idle state.
    #[serde(default = "default_true")]
    pub idle_detection: bool,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log output format: "text" or "json".
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path (optional; defaults to stderr).
    pub file: Option<PathBuf>,
}

// --- Default value functions ---

fn default_server_address() -> String {
    "localhost".to_string()
}
fn default_server_port() -> u16 {
    1514
}
fn default_protocol() -> String {
    "tcp".to_string()
}
fn default_keepalive() -> u64 {
    600
}
fn default_enrollment_port() -> u16 {
    1515
}
fn default_true() -> bool {
    true
}
fn default_max_cpu() -> u8 {
    3
}
fn default_max_memory() -> u32 {
    50
}
fn default_battery_mode() -> String {
    "adaptive".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}
fn default_fim_scan_interval() -> u64 {
    43200 // 12 hours
}
fn default_fim_debounce_ms() -> u64 {
    100
}
fn default_source_type() -> String {
    "file".to_string()
}
fn default_log_source_format() -> String {
    "syslog".to_string()
}

// --- Trait implementations ---

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: default_server_address(),
            port: default_server_port(),
            protocol: default_protocol(),
            keepalive_interval: default_keepalive(),
        }
    }
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            server: None,
            port: default_enrollment_port(),
            auto_enroll: true,
            key: None,
            agent_name: None,
            groups: None,
        }
    }
}

impl Default for ModuleToggle {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directories: default_fim_directories(),
            scan_interval: default_fim_scan_interval(),
            debounce_ms: default_fim_debounce_ms(),
        }
    }
}

fn default_fim_directories() -> Vec<FimDirectory> {
    #[cfg(unix)]
    {
        vec![
            FimDirectory {
                path: "/etc".to_string(),
                recursive: true,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: "/usr/bin".to_string(),
                recursive: false,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: "/usr/sbin".to_string(),
                recursive: false,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: "/boot".to_string(),
                recursive: true,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
        ]
    }
    #[cfg(windows)]
    {
        vec![
            FimDirectory {
                path: r"C:\Windows\System32\drivers\etc".to_string(),
                recursive: true,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: r"C:\Windows\System32".to_string(),
                recursive: false,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
        ]
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_percent: default_max_cpu(),
            max_memory_mb: default_max_memory(),
            battery_mode: default_battery_mode(),
            idle_detection: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file: None,
        }
    }
}

impl AgentConfig {
    /// Load configuration from a YAML file.
    pub fn from_yaml_file(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: AgentConfig = serde_yaml::from_str(&contents)?;
        info!(path = %path.display(), "loaded configuration");
        Ok(config)
    }

    /// Load configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let config: AgentConfig = serde_yaml::from_str(yaml)?;
        Ok(config)
    }

    /// Try to load from the default config path for this platform.
    pub fn load_default() -> anyhow::Result<Self> {
        let path = Self::default_config_path();
        if path.exists() {
            Self::from_yaml_file(&path)
        } else {
            info!("no config file found, using defaults");
            Ok(Self::default())
        }
    }

    /// Get the default configuration file path for the current platform.
    pub fn default_config_path() -> PathBuf {
        #[cfg(unix)]
        {
            PathBuf::from("/etc/wazuh-desktop-agent/config.yaml")
        }
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\Program Files\WazuhDesktopAgent\config.yaml")
        }
    }

    /// Get the enrollment server address (falls back to main server).
    pub fn enrollment_address(&self) -> &str {
        self.enrollment
            .server
            .as_deref()
            .unwrap_or(&self.server.address)
    }
}
