//! Hardware information collection for the inventory module.
//!
//! Parses `/proc/cpuinfo` and `/proc/meminfo` on Linux.

use serde_json::Value;
use tracing::{debug, warn};

use crate::syscollector_format::build_hwinfo;

/// Collect hardware information and return it as a syscollector `dbsync_hwinfo` payload.
pub fn collect_hardware_info() -> Value {
    let cpu = parse_cpuinfo();
    let mem = parse_meminfo();

    let data = serde_json::json!({
        "cpu_name": cpu.model_name,
        "cpu_cores": cpu.core_count,
        "cpu_mhz": cpu.mhz,
        "ram_total": mem.total_kb,
        "ram_free": mem.free_kb,
    });

    debug!(
        cpu = %cpu.model_name,
        cores = cpu.core_count,
        ram_mb = mem.total_kb / 1024,
        "collected hardware info"
    );
    build_hwinfo(data)
}

#[derive(Debug, Default)]
pub(crate) struct CpuInfo {
    model_name: String,
    core_count: u32,
    mhz: f64,
}

#[derive(Debug, Default)]
pub(crate) struct MemInfo {
    total_kb: u64,
    free_kb: u64,
}

/// Parse `/proc/cpuinfo` for CPU model and core count.
fn parse_cpuinfo() -> CpuInfo {
    let content = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to read /proc/cpuinfo");
            return CpuInfo::default();
        }
    };
    parse_cpuinfo_content(&content)
}

/// Parse cpuinfo content from a string (testable).
pub(crate) fn parse_cpuinfo_content(content: &str) -> CpuInfo {
    let mut info = CpuInfo::default();
    let mut processor_count: u32 = 0;

    for line in content.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "processor" => {
                    processor_count += 1;
                }
                "model name" if info.model_name.is_empty() => {
                    info.model_name = value.to_string();
                }
                "cpu MHz" if info.mhz == 0.0 => {
                    info.mhz = value.parse().unwrap_or(0.0);
                }
                _ => {}
            }
        }
    }

    info.core_count = processor_count;
    info
}

/// Parse `/proc/meminfo` for total and free RAM.
fn parse_meminfo() -> MemInfo {
    let content = match std::fs::read_to_string("/proc/meminfo") {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to read /proc/meminfo");
            return MemInfo::default();
        }
    };
    parse_meminfo_content(&content)
}

/// Parse meminfo content from a string (testable).
pub(crate) fn parse_meminfo_content(content: &str) -> MemInfo {
    let mut info = MemInfo::default();

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            info.total_kb = parse_kb_value(rest);
        } else if let Some(rest) = line.strip_prefix("MemFree:") {
            info.free_kb = parse_kb_value(rest);
        }
    }

    info
}

/// Parse a value like "  16384000 kB" into a u64 of kB.
fn parse_kb_value(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpuinfo_content() {
        let content = r#"processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz
cpu MHz		: 2592.000

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz
cpu MHz		: 2592.000
"#;
        let info = parse_cpuinfo_content(content);
        assert_eq!(info.core_count, 2);
        assert!(info.model_name.contains("i7-10750H"));
        assert!(info.mhz > 0.0);
    }

    #[test]
    fn test_parse_cpuinfo_empty() {
        let info = parse_cpuinfo_content("");
        assert_eq!(info.core_count, 0);
        assert_eq!(info.model_name, "");
    }

    #[test]
    fn test_parse_meminfo_content() {
        let content = r#"MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12000000 kB
Buffers:          500000 kB
"#;
        let info = parse_meminfo_content(content);
        assert_eq!(info.total_kb, 16384000);
        assert_eq!(info.free_kb, 8192000);
    }

    #[test]
    fn test_parse_meminfo_empty() {
        let info = parse_meminfo_content("");
        assert_eq!(info.total_kb, 0);
        assert_eq!(info.free_kb, 0);
    }

    #[test]
    fn test_parse_kb_value() {
        assert_eq!(parse_kb_value("  16384000 kB"), 16384000);
        assert_eq!(parse_kb_value("1024 kB"), 1024);
        assert_eq!(parse_kb_value(""), 0);
    }

    #[test]
    fn test_collect_hardware_info_returns_valid_json() {
        let info = collect_hardware_info();
        assert_eq!(info["type"], "dbsync_hwinfo");
        assert!(info["data"]["cpu_cores"].is_number());
        assert!(info["data"]["ram_total"].is_number());
    }
}
