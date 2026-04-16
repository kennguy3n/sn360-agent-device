//! Cross-platform power and idle status detection.

use crate::types::PowerState;
use std::time::Duration;

/// Power and idle status provider.
///
/// Detects battery state and user idle time to enable adaptive scheduling.
pub struct PowerMonitor;

impl PowerMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Get the current power state (AC or battery).
    pub fn power_state(&self) -> PowerState {
        #[cfg(target_os = "linux")]
        {
            linux_power_state()
        }
        #[cfg(not(target_os = "linux"))]
        {
            PowerState::Unknown
        }
    }

    /// Get the battery charge percentage, if available.
    pub fn battery_percentage(&self) -> Option<u8> {
        #[cfg(target_os = "linux")]
        {
            linux_battery_percentage()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Check whether the user appears to be idle.
    pub fn is_user_idle(&self, idle_threshold: Duration) -> bool {
        self.user_idle_duration()
            .map(|d| d >= idle_threshold)
            .unwrap_or(false)
    }

    /// Get the user idle duration, if detectable.
    pub fn user_idle_duration(&self) -> Option<Duration> {
        // Idle detection requires platform-specific APIs.
        // Linux: XScreenSaver extension or /proc/interrupts heuristics
        // macOS: CGEventSourceSecondsSinceLastEventType
        // Windows: GetLastInputInfo
        // For now, return None (user is never considered idle).
        None
    }
}

impl Default for PowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn linux_power_state() -> PowerState {
    // Read /sys/class/power_supply/*/online or /sys/class/power_supply/*/status
    let ac_path = std::path::Path::new("/sys/class/power_supply/AC/online");
    if let Ok(contents) = std::fs::read_to_string(ac_path) {
        return match contents.trim() {
            "1" => PowerState::AC,
            "0" => PowerState::Battery,
            _ => PowerState::Unknown,
        };
    }

    // Try alternative paths
    if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply/") {
        for entry in entries.flatten() {
            let online_path = entry.path().join("online");
            if let Ok(contents) = std::fs::read_to_string(&online_path) {
                match contents.trim() {
                    "1" => return PowerState::AC,
                    "0" => return PowerState::Battery,
                    _ => continue,
                }
            }
        }
    }

    PowerState::Unknown
}

#[cfg(target_os = "linux")]
fn linux_battery_percentage() -> Option<u8> {
    if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply/") {
        for entry in entries.flatten() {
            let capacity_path = entry.path().join("capacity");
            if let Ok(contents) = std::fs::read_to_string(&capacity_path) {
                if let Ok(pct) = contents.trim().parse::<u8>() {
                    return Some(pct);
                }
            }
        }
    }
    None
}

/// Power profile that determines agent behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerProfile {
    /// AC power, user active: normal operation.
    Normal,
    /// AC power, user idle: run deferred scans.
    IdleAC,
    /// Battery, user active: minimal scans, larger batches.
    BatteryActive,
    /// Battery, user idle: reduced scans, extended intervals.
    BatteryIdle,
    /// Critical battery (<10%): essential only.
    CriticalBattery,
}

impl PowerProfile {
    /// Determine the current power profile from system state.
    pub fn detect(monitor: &PowerMonitor, idle_threshold: Duration) -> Self {
        let power = monitor.power_state();
        let is_idle = monitor.is_user_idle(idle_threshold);
        let battery_pct = monitor.battery_percentage();

        match (power, is_idle, battery_pct) {
            (PowerState::Battery, _, Some(pct)) if pct < 10 => PowerProfile::CriticalBattery,
            (PowerState::Battery, true, _) => PowerProfile::BatteryIdle,
            (PowerState::Battery, false, _) => PowerProfile::BatteryActive,
            (_, true, _) => PowerProfile::IdleAC,
            _ => PowerProfile::Normal,
        }
    }

    /// Get the FIM scan rate multiplier for this profile.
    pub fn fim_scan_rate(&self) -> f64 {
        match self {
            PowerProfile::Normal => 1.0,
            PowerProfile::IdleAC => 2.0,
            PowerProfile::BatteryActive => 0.5,
            PowerProfile::BatteryIdle => 0.25,
            PowerProfile::CriticalBattery => 0.0, // Paused
        }
    }

    /// Get the log batch interval for this profile.
    pub fn log_batch_interval(&self) -> Duration {
        match self {
            PowerProfile::Normal => Duration::from_secs(5),
            PowerProfile::IdleAC => Duration::from_secs(5),
            PowerProfile::BatteryActive => Duration::from_secs(10),
            PowerProfile::BatteryIdle => Duration::from_secs(20),
            PowerProfile::CriticalBattery => Duration::from_secs(60),
        }
    }

    /// Get the inventory collection interval for this profile.
    pub fn inventory_interval(&self) -> Duration {
        match self {
            PowerProfile::Normal => Duration::from_secs(3600),
            PowerProfile::IdleAC => Duration::from_secs(3600),
            PowerProfile::BatteryActive => Duration::from_secs(14400),
            PowerProfile::BatteryIdle => Duration::from_secs(28800),
            PowerProfile::CriticalBattery => Duration::from_secs(86400),
        }
    }

    /// Whether SCA scans should run in this profile.
    pub fn sca_enabled(&self) -> bool {
        !matches!(self, PowerProfile::CriticalBattery)
    }
}
