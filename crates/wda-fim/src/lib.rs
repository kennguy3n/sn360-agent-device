//! File Integrity Monitoring (FIM) module for the Wazuh Desktop Agent.
//!
//! Monitors filesystem changes using OS-native notification APIs
//! (inotify/FSEvents/ReadDirectoryChangesW) and reports changes
//! to the event bus for server delivery.
//!
//! Phase 2 implementation placeholder.

/// FIM module placeholder.
pub struct FimModule;

impl FimModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FimModule {
    fn default() -> Self {
        Self::new()
    }
}
