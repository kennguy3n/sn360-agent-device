//! System inventory collection module for the Wazuh Desktop Agent.
//!
//! Collects hardware, OS, package, network, and process information
//! using event-driven change detection where possible.
//!
//! Phase 2 implementation placeholder.

/// Inventory module placeholder.
pub struct InventoryModule;

impl InventoryModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for InventoryModule {
    fn default() -> Self {
        Self::new()
    }
}
