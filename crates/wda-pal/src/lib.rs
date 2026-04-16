//! Platform Abstraction Layer (PAL) for the Wazuh Desktop Agent.
//!
//! Provides cross-platform traits and implementations for filesystem watching,
//! system information, power status, and service management.

pub mod fs_watcher;
pub mod power;
pub mod sysinfo;
pub mod types;

pub use types::*;
