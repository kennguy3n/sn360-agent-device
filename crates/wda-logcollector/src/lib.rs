//! Log collection module for the Wazuh Desktop Agent.
//!
//! Collects logs from various sources (syslog, journald, Windows Event Log,
//! macOS Unified Log) using event-driven APIs and forwards them to the
//! event bus.
//!
//! Phase 2 implementation placeholder.

/// Log collector module placeholder.
pub struct LogCollectorModule;

impl LogCollectorModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LogCollectorModule {
    fn default() -> Self {
        Self::new()
    }
}
