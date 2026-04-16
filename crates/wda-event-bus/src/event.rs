use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Priority level for event processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Priority {
    /// Critical events that must never be deferred (active response, keepalive).
    Critical = 0,
    /// Normal operational events (real-time FIM, log collection).
    Normal = 1,
    /// Low-priority background events (baseline scans, inventory).
    Low = 2,
}

/// The kind of event flowing through the bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    // --- FIM events ---
    /// A file was created.
    FileCreated { path: String },
    /// A file was modified.
    FileModified { path: String },
    /// A file was deleted.
    FileDeleted { path: String },
    /// A file's metadata (permissions, ownership) changed.
    FileMetadataChanged { path: String },

    // --- Log events ---
    /// A new log line was collected.
    LogCollected {
        source: String,
        message: String,
        format: String,
    },

    // --- Inventory events ---
    /// System inventory was updated.
    InventoryUpdate {
        category: String,
        data: serde_json::Value,
    },

    // --- SCA events ---
    /// SCA check result.
    ScaResult {
        policy_id: String,
        check_id: String,
        result: String,
    },

    // --- Active Response events ---
    /// Request to execute an active response action.
    ActiveResponseRequest {
        action: String,
        parameters: serde_json::Value,
    },
    /// Active response execution result.
    ActiveResponseResult {
        action: String,
        success: bool,
        output: String,
    },

    // --- Agent lifecycle events ---
    /// Agent keepalive to server.
    Keepalive,
    /// Agent is shutting down.
    Shutdown,
    /// Configuration was reloaded.
    ConfigReloaded,

    // --- Communication events ---
    /// Message to be sent to the server.
    ServerMessage { payload: String },
    /// Message received from the server.
    ServerCommand { command: String, payload: String },
}

/// An event that flows through the event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier.
    pub id: u64,
    /// When the event was created.
    pub timestamp: DateTime<Utc>,
    /// Source module that generated this event.
    pub source: String,
    /// Priority level.
    pub priority: Priority,
    /// The event payload.
    pub kind: EventKind,
}

impl Event {
    /// Create a new event with auto-generated ID and timestamp.
    pub fn new(source: impl Into<String>, priority: Priority, kind: EventKind) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        Self {
            id: COUNTER.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now(),
            source: source.into(),
            priority,
            kind,
        }
    }
}
