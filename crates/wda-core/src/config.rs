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

    /// Override for the `client.keys` file location. When unset the
    /// platform default is used (`/etc/wazuh-desktop-agent/client.keys`
    /// on Unix, `C:\Program Files\WazuhDesktopAgent\client.keys` on Windows).
    pub keys_file: Option<PathBuf>,
}

/// Module enable/disable configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModulesConfig {
    #[serde(default)]
    pub fim: FimConfig,
    #[serde(default)]
    pub logcollector: LogCollectorConfig,
    #[serde(default)]
    pub inventory: InventoryConfig,
    #[serde(default)]
    pub sca: ScaConfig,
    #[serde(default)]
    pub active_response: ActiveResponseConfig,
    #[serde(default)]
    pub rootcheck: RootcheckConfig,
    #[serde(default)]
    pub local_detection: LocalDetectionConfig,
    #[serde(default)]
    pub enhanced_inventory: EnhancedInventoryConfig,
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
    /// Maximum SHA-256 hashes dispatched per second (default 100).
    ///
    /// Bounds CPU usage of the real-time FIM path under bursts. When
    /// the limit is reached the loop sleeps to the next second boundary
    /// before dispatching more hashes. Set to `0` to disable rate
    /// limiting.
    #[serde(default = "default_fim_max_hashes_per_sec")]
    pub max_hashes_per_sec: u32,
    /// Maximum number of events to accumulate before flushing to the
    /// event bus (default 50).
    #[serde(default = "default_fim_batch_size")]
    pub batch_size: usize,
    /// Maximum time to hold events before flushing (default 200 ms).
    #[serde(default = "default_fim_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
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
    /// Systemd unit filters (for journald sources).
    #[serde(default)]
    pub units: Vec<String>,
}

/// Inventory module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryConfig {
    /// Whether the inventory module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Collection interval in seconds (default 3600).
    #[serde(default = "default_inventory_interval")]
    pub interval: u64,
    /// Categories to collect: "os", "network", "packages", "hardware".
    #[serde(default = "default_inventory_collect")]
    pub collect: Vec<String>,
}

/// Simple module enable/disable toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleToggle {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Rootcheck (rootkit detection) module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootcheckConfig {
    /// Whether the rootcheck module is enabled.
    ///
    /// Rootcheck is off by default — it runs privileged filesystem
    /// sweeps and PID scans, so operators opt in explicitly.
    #[serde(default)]
    pub enabled: bool,
    /// Interval in seconds between rootcheck sweeps (default 1h).
    #[serde(default = "default_rootcheck_scan_interval")]
    pub scan_interval_secs: u64,
    /// Additional file paths that should be flagged as rootkit
    /// indicators if present. The built-in signature list is always
    /// checked first; these are appended to it.
    #[serde(default)]
    pub signature_paths: Vec<String>,
    /// System binary paths whose SHA-256 is tracked for drift.
    ///
    /// When empty the platform-specific defaults from
    /// [`default_rootcheck_binary_paths`] are used.
    #[serde(default)]
    pub binary_paths: Vec<String>,
    /// Path to the on-disk baseline file that stores the initial
    /// SHA-256 hashes of each tracked binary. The file is created on
    /// first run and subsequent runs compare current hashes against
    /// the stored baseline.
    #[serde(default = "default_rootcheck_baseline_path")]
    pub baseline_path: PathBuf,
    /// Whether to run the hidden-process check.
    ///
    /// Only meaningful on Linux; no-op on other platforms.
    #[serde(default = "default_true")]
    pub hidden_process_check: bool,
    /// Whether to run the binary-integrity check.
    #[serde(default = "default_true")]
    pub binary_integrity_check: bool,
    /// Upper bound for PIDs to probe with `kill(pid, 0)` during the
    /// hidden-process sweep. Keep this conservative to cap CPU cost.
    #[serde(default = "default_rootcheck_max_pid")]
    pub max_pid: u32,
}

/// Local Detection Engine (LDE) module configuration.
///
/// The LDE evaluates detection rules locally at the edge — IOC matching
/// via Aho-Corasick + bloom filters, behavioral rule state machines,
/// and YARA file scanning — without a server round-trip. See
/// [`PROPOSAL.md`](../../../PROPOSAL.md) § 5.x / Phase 4 tasks 4.1–4.6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDetectionConfig {
    /// Whether the LDE is enabled. Off by default — operators opt in.
    #[serde(default)]
    pub enabled: bool,
    /// Interval in seconds between rule-bundle pulls from the Tenant
    /// Rule Distribution Service (TRDS).
    #[serde(default = "default_lde_rule_pull_interval")]
    pub rule_pull_interval: u64,
    /// Maximum number of detections buffered in the offline queue
    /// when the server is unreachable. Bounded FIFO — oldest entries
    /// are evicted when the queue is full.
    #[serde(default = "default_lde_offline_queue_max")]
    pub offline_queue_max: usize,
    /// Upper bound on YARA scans per second. The scanner sleeps to
    /// the next second boundary when the budget is exhausted.
    #[serde(default = "default_lde_yara_scan_rate_limit")]
    pub yara_scan_rate_limit: u32,
    /// Files larger than this (MB) are skipped by the YARA scanner.
    #[serde(default = "default_lde_yara_max_file_size_mb")]
    pub yara_max_file_size_mb: u64,
    /// Target false-positive rate for the hash/IP bloom filters.
    #[serde(default = "default_lde_bloom_filter_fpr")]
    pub bloom_filter_fpr: f64,
    /// Maximum sliding-window size (seconds) for behavioral rules.
    #[serde(default = "default_lde_behavioral_max_window_sec")]
    pub behavioral_max_window_sec: u64,
    /// Maximum number of distinct entities (subjects) tracked by the
    /// behavioral engine. Bounds memory use.
    #[serde(default = "default_lde_behavioral_max_tracked_entities")]
    pub behavioral_max_tracked_entities: usize,
    /// Whether `block_ip` local responses are allowed.
    #[serde(default)]
    pub block_ip: bool,
    /// Whether `kill_process` local responses are allowed.
    #[serde(default)]
    pub kill_process: bool,
    /// Whether `quarantine` local responses (move file aside) are allowed.
    #[serde(default)]
    pub quarantine: bool,
    /// Path to the MessagePack rule bundle on disk.
    #[serde(default = "default_lde_rule_bundle_path")]
    pub rule_bundle_path: PathBuf,
    /// Path to the SQLite offline-queue database.
    #[serde(default = "default_lde_offline_queue_path")]
    pub offline_queue_path: PathBuf,
    /// Directory where quarantined files are moved.
    #[serde(default = "default_lde_quarantine_dir")]
    pub quarantine_dir: PathBuf,
    /// Interval in seconds between attempts to replay detections from
    /// the offline queue back to the server. Floored to 5 s.
    #[serde(default = "default_lde_offline_drain_interval")]
    pub offline_drain_interval: u64,
    /// Maximum number of detections drained per replay tick.
    #[serde(default = "default_lde_offline_drain_batch")]
    pub offline_drain_batch: usize,
}

/// Enhanced Inventory module configuration.
///
/// The enhanced inventory extends the base inventory with running
/// software monitoring (task 4.7), browser extension enumeration
/// (task 4.8), and CycloneDX SBOM generation (task 4.9). See
/// [`PROPOSAL.md`](../../../PROPOSAL.md) § 13.2 for design details.
///
/// The module is **off by default** — operators opt in explicitly
/// because running-software snapshots touch `/proc` on Linux and the
/// equivalent syscalls on macOS / Windows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnhancedInventoryConfig {
    /// Whether the enhanced inventory module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Running-software monitor settings.
    #[serde(default)]
    pub running_software: RunningSoftwareConfig,
}

/// Running-software monitor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningSoftwareConfig {
    /// Whether the running-software monitor is enabled when the
    /// enhanced inventory module itself is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Interval in seconds between process-list snapshots.
    #[serde(default = "default_running_software_interval")]
    pub interval: u64,
}

/// SCA (Security Configuration Assessment) module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaConfig {
    /// Whether the SCA module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directory containing YAML policy files to load at startup.
    #[serde(default = "default_sca_policy_dir")]
    pub policy_dir: PathBuf,
    /// Interval in seconds between policy re-evaluations (default 12h).
    #[serde(default = "default_sca_scan_interval")]
    pub scan_interval: u64,
}

/// Active response module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveResponseConfig {
    /// Whether the active response module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Command execution timeout in seconds.
    #[serde(default = "default_ar_timeout")]
    pub timeout: u64,
    /// Allowed response actions.
    #[serde(default = "default_ar_actions")]
    pub actions: Vec<String>,
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
fn default_fim_max_hashes_per_sec() -> u32 {
    100
}
fn default_fim_batch_size() -> usize {
    50
}
fn default_fim_batch_timeout_ms() -> u64 {
    200
}
fn default_source_type() -> String {
    "file".to_string()
}
fn default_log_source_format() -> String {
    "syslog".to_string()
}
fn default_inventory_interval() -> u64 {
    3600
}
fn default_inventory_collect() -> Vec<String> {
    vec![
        "os".to_string(),
        "network".to_string(),
        "packages".to_string(),
        "hardware".to_string(),
    ]
}
fn default_sca_policy_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/wazuh-desktop-agent/sca")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Program Files\WazuhDesktopAgent\sca")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_sca_scan_interval() -> u64 {
    43200 // 12 hours
}
fn default_rootcheck_scan_interval() -> u64 {
    3600 // 1 hour
}
fn default_rootcheck_max_pid() -> u32 {
    32768
}
fn default_rootcheck_baseline_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/wazuh-desktop-agent/rootcheck-baseline.json")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\WazuhDesktopAgent\rootcheck-baseline.json")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
/// Platform-default list of critical system binary paths monitored for
/// SHA-256 drift by the rootcheck module.
pub fn default_rootcheck_binary_paths() -> Vec<String> {
    #[cfg(unix)]
    {
        vec![
            "/bin/ls".to_string(),
            "/bin/ps".to_string(),
            "/bin/login".to_string(),
            "/usr/bin/ssh".to_string(),
            "/usr/bin/sudo".to_string(),
            "/usr/bin/passwd".to_string(),
            "/usr/bin/su".to_string(),
            "/usr/sbin/sshd".to_string(),
        ]
    }
    #[cfg(windows)]
    {
        vec![
            r"C:\Windows\System32\cmd.exe".to_string(),
            r"C:\Windows\System32\svchost.exe".to_string(),
            r"C:\Windows\System32\lsass.exe".to_string(),
            r"C:\Windows\explorer.exe".to_string(),
        ]
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}
fn default_ar_timeout() -> u64 {
    30
}
fn default_running_software_interval() -> u64 {
    60
}
fn default_lde_rule_pull_interval() -> u64 {
    300
}
fn default_lde_offline_queue_max() -> usize {
    10_000
}
fn default_lde_yara_scan_rate_limit() -> u32 {
    1
}
fn default_lde_yara_max_file_size_mb() -> u64 {
    50
}
fn default_lde_bloom_filter_fpr() -> f64 {
    0.01
}
fn default_lde_behavioral_max_window_sec() -> u64 {
    300
}
fn default_lde_behavioral_max_tracked_entities() -> usize {
    5_000
}
fn default_lde_rule_bundle_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/wazuh-desktop-agent/lde-rules.msgpack")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\WazuhDesktopAgent\lde-rules.msgpack")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_lde_offline_queue_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/wazuh-desktop-agent/lde-offline-queue.db")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\WazuhDesktopAgent\lde-offline-queue.db")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_lde_offline_drain_interval() -> u64 {
    30
}
fn default_lde_offline_drain_batch() -> usize {
    128
}
fn default_lde_quarantine_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/wazuh-desktop-agent/quarantine")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\WazuhDesktopAgent\quarantine")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_ar_actions() -> Vec<String> {
    vec![
        "block_ip".to_string(),
        "kill_process".to_string(),
        "disable_account".to_string(),
    ]
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
            keys_file: None,
        }
    }
}

impl Default for InventoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_inventory_interval(),
            collect: default_inventory_collect(),
        }
    }
}

impl Default for ModuleToggle {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for ScaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            policy_dir: default_sca_policy_dir(),
            scan_interval: default_sca_scan_interval(),
        }
    }
}

impl Default for RootcheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: default_rootcheck_scan_interval(),
            signature_paths: Vec::new(),
            binary_paths: Vec::new(),
            baseline_path: default_rootcheck_baseline_path(),
            hidden_process_check: true,
            binary_integrity_check: true,
            max_pid: default_rootcheck_max_pid(),
        }
    }
}

impl Default for LocalDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rule_pull_interval: default_lde_rule_pull_interval(),
            offline_queue_max: default_lde_offline_queue_max(),
            yara_scan_rate_limit: default_lde_yara_scan_rate_limit(),
            yara_max_file_size_mb: default_lde_yara_max_file_size_mb(),
            bloom_filter_fpr: default_lde_bloom_filter_fpr(),
            behavioral_max_window_sec: default_lde_behavioral_max_window_sec(),
            behavioral_max_tracked_entities: default_lde_behavioral_max_tracked_entities(),
            block_ip: false,
            kill_process: false,
            quarantine: false,
            rule_bundle_path: default_lde_rule_bundle_path(),
            offline_queue_path: default_lde_offline_queue_path(),
            quarantine_dir: default_lde_quarantine_dir(),
            offline_drain_interval: default_lde_offline_drain_interval(),
            offline_drain_batch: default_lde_offline_drain_batch(),
        }
    }
}

impl Default for RunningSoftwareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_running_software_interval(),
        }
    }
}

impl Default for ActiveResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: default_ar_timeout(),
            actions: default_ar_actions(),
        }
    }
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directories: default_fim_directories(),
            scan_interval: default_fim_scan_interval(),
            debounce_ms: default_fim_debounce_ms(),
            max_hashes_per_sec: default_fim_max_hashes_per_sec(),
            batch_size: default_fim_batch_size(),
            batch_timeout_ms: default_fim_batch_timeout_ms(),
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
