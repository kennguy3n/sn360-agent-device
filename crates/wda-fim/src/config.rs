//! FIM module configuration re-exports and defaults.

pub use wda_core::config::{FimConfig, FimDirectory};

/// Default database path for FIM state.
pub fn default_db_path() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/var/lib/wazuh-desktop-agent/fim.db")
    }
    #[cfg(windows)]
    {
        std::path::PathBuf::from(r"C:\ProgramData\WazuhDesktopAgent\fim.db")
    }
}
