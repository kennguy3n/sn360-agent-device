//! Network interface collection for the inventory module.
//!
//! Enumerates network interfaces from `/sys/class/net/` on Linux.
//! Returns an empty list on non-Unix platforms.

use serde_json::Value;

/// Collect network interface information.
///
/// Returns a vector of syscollector payloads: one `dbsync_netiface` per
/// interface plus one `dbsync_netaddr` per address.
///
/// On non-Unix platforms this returns an empty vector.
#[cfg(not(unix))]
pub fn collect_network_info() -> Vec<Value> {
    tracing::warn!("network interface collection is not supported on this platform");
    Vec::new()
}

#[cfg(unix)]
pub fn collect_network_info() -> Vec<Value> {
    unix_impl::collect_network_info()
}

#[cfg(unix)]
mod unix_impl {
    use std::net::IpAddr;

    use serde_json::Value;
    use tracing::{debug, warn};

    use crate::syscollector_format::{build_netaddr, build_netiface};

    pub fn collect_network_info() -> Vec<Value> {
        let mut payloads = Vec::new();

        match nix::ifaddrs::getifaddrs() {
            Ok(ifaddrs) => {
                let entries: Vec<_> = ifaddrs.collect();
                let mut seen_ifaces: std::collections::HashSet<String> =
                    std::collections::HashSet::new();

                for ifaddr in &entries {
                    let name = ifaddr.interface_name.clone();

                    // Emit one netiface entry per unique interface name.
                    if seen_ifaces.insert(name.clone()) {
                        let mac = read_mac_address(&name).unwrap_or_default();
                        let state =
                            read_interface_state(&name).unwrap_or_else(|| "unknown".to_string());
                        let mtu = read_interface_mtu(&name).unwrap_or(0);

                        let iface_data = serde_json::json!({
                            "name": name,
                            "mac": mac,
                            "state": state,
                            "mtu": mtu,
                        });
                        payloads.push(build_netiface(iface_data));
                        debug!(interface = %name, mac = %mac, state = %state, "collected network interface");
                    }

                    // Emit netaddr entries for each address.
                    if let Some(addr) = ifaddr.address {
                        if let Some(sock_addr) = addr.as_sockaddr_in() {
                            let ip = IpAddr::V4(sock_addr.ip());
                            let netmask = ifaddr
                                .netmask
                                .and_then(|n| {
                                    n.as_sockaddr_in().map(|s| IpAddr::V4(s.ip()).to_string())
                                })
                                .unwrap_or_default();
                            let broadcast = ifaddr
                                .broadcast
                                .and_then(|b| {
                                    b.as_sockaddr_in().map(|s| IpAddr::V4(s.ip()).to_string())
                                })
                                .unwrap_or_default();

                            let addr_data = serde_json::json!({
                                "iface": name,
                                "proto": 0,
                                "address": ip.to_string(),
                                "netmask": netmask,
                                "broadcast": broadcast,
                            });
                            payloads.push(build_netaddr(addr_data));
                        } else if let Some(sock_addr) = addr.as_sockaddr_in6() {
                            let ip = IpAddr::V6(sock_addr.ip());
                            let netmask = ifaddr
                                .netmask
                                .and_then(|n| {
                                    n.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip()).to_string())
                                })
                                .unwrap_or_default();

                            let addr_data = serde_json::json!({
                                "iface": name,
                                "proto": 1,
                                "address": ip.to_string(),
                                "netmask": netmask,
                                "broadcast": "",
                            });
                            payloads.push(build_netaddr(addr_data));
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to enumerate network interfaces via getifaddrs");
            }
        }

        payloads
    }

    /// Read MAC address from `/sys/class/net/{iface}/address`.
    fn read_mac_address(iface: &str) -> Option<String> {
        let path = format!("/sys/class/net/{}/address", iface);
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Read interface operational state from `/sys/class/net/{iface}/operstate`.
    fn read_interface_state(iface: &str) -> Option<String> {
        let path = format!("/sys/class/net/{}/operstate", iface);
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Read interface MTU from `/sys/class/net/{iface}/mtu`.
    fn read_interface_mtu(iface: &str) -> Option<u64> {
        let path = format!("/sys/class/net/{}/mtu", iface);
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_collect_network_info_returns_results() {
            let payloads = collect_network_info();
            // Should find at least the loopback interface.
            assert!(
                !payloads.is_empty(),
                "expected at least one network payload"
            );

            let has_netiface = payloads.iter().any(|p| p["type"] == "dbsync_netiface");
            assert!(has_netiface, "expected at least one netiface entry");
        }

        #[test]
        fn test_read_mac_address_loopback() {
            let mac = read_mac_address("lo");
            assert!(mac.is_some(), "expected loopback MAC address");
            assert_eq!(mac.unwrap(), "00:00:00:00:00:00");
        }

        #[test]
        fn test_read_interface_state_loopback() {
            let state = read_interface_state("lo");
            assert!(state.is_some());
            assert_eq!(state.unwrap(), "unknown");
        }

        #[test]
        fn test_read_interface_mtu_loopback() {
            let mtu = read_interface_mtu("lo");
            assert!(mtu.is_some());
            assert!(mtu.unwrap() > 0);
        }

        #[test]
        fn test_read_mac_address_nonexistent() {
            let mac = read_mac_address("nonexistent_iface_xyz");
            assert!(mac.is_none());
        }
    }
}
