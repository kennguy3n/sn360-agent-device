//! Core agent runtime for the Wazuh Desktop Agent.
//!
//! Provides lifecycle management, configuration loading, signal handling,
//! and module orchestration.

pub mod agent;
pub mod config;
pub mod module;
pub mod signal;

pub use agent::Agent;
pub use config::AgentConfig;
pub use module::{AgentModule, ModuleHealth, ModuleStatus};
pub use signal::{ShutdownSignal, ShutdownTrigger};
