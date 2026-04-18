//! Wazuh syscollector wire format helpers.
//!
//! Each inventory message is formatted as `d:syscollector:{json_payload}`
//! following the Wazuh dbsync schema.

use serde_json::Value;

/// Wrap a JSON payload into the Wazuh syscollector wire format.
///
/// Returns a string like `d:syscollector:{"type":"dbsync_osinfo",...}`.
pub fn wrap_syscollector(json_payload: &Value) -> String {
    format!("d:syscollector:{}", json_payload)
}

/// Build a dbsync osinfo payload.
pub fn build_osinfo(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_osinfo",
        "data": data,
    })
}

/// Build a dbsync packages payload.
pub fn build_packages(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_packages",
        "data": data,
    })
}

/// Build a dbsync network interface payload.
pub fn build_netiface(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_netiface",
        "data": data,
    })
}

/// Build a dbsync network address payload.
pub fn build_netaddr(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_netaddr",
        "data": data,
    })
}

/// Build a dbsync hardware info payload.
pub fn build_hwinfo(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_hwinfo",
        "data": data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_syscollector_format() {
        let payload = serde_json::json!({"type": "dbsync_osinfo", "data": {}});
        let wire = wrap_syscollector(&payload);
        assert!(wire.starts_with("d:syscollector:"));
        assert!(wire.contains("dbsync_osinfo"));
    }

    #[test]
    fn test_build_osinfo() {
        let data = serde_json::json!({"os_name": "Ubuntu"});
        let result = build_osinfo(data);
        assert_eq!(result["type"], "dbsync_osinfo");
        assert_eq!(result["data"]["os_name"], "Ubuntu");
    }

    #[test]
    fn test_build_packages() {
        let data = serde_json::json!({"name": "vim", "version": "8.2"});
        let result = build_packages(data);
        assert_eq!(result["type"], "dbsync_packages");
        assert_eq!(result["data"]["name"], "vim");
    }

    #[test]
    fn test_build_netiface() {
        let data = serde_json::json!({"name": "eth0"});
        let result = build_netiface(data);
        assert_eq!(result["type"], "dbsync_netiface");
    }

    #[test]
    fn test_build_netaddr() {
        let data = serde_json::json!({"address": "192.168.1.1"});
        let result = build_netaddr(data);
        assert_eq!(result["type"], "dbsync_netaddr");
    }

    #[test]
    fn test_build_hwinfo() {
        let data = serde_json::json!({"cpu_name": "Intel"});
        let result = build_hwinfo(data);
        assert_eq!(result["type"], "dbsync_hwinfo");
    }
}
