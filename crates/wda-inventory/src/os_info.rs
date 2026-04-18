//! OS information collection for the inventory module.
//!
//! Parses `/etc/os-release` and `uname` data on Linux.

use serde_json::Value;
use tracing::{debug, warn};

use crate::syscollector_format::build_osinfo;

/// Collect OS information and return it as a syscollector dbsync_osinfo payload.
pub fn collect_os_info() -> Value {
    let os_release = parse_os_release();

    let hostname = read_file_trimmed("/etc/hostname")
        .unwrap_or_else(gethostname_fallback);

    let kernel_release = read_file_trimmed("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|| "unknown".to_string());

    let kernel_name = read_file_trimmed("/proc/sys/kernel/ostype")
        .unwrap_or_else(|| "Linux".to_string());

    let architecture = std::env::consts::ARCH.to_string();

    let data = serde_json::json!({
        "hostname": hostname,
        "architecture": architecture,
        "os_name": os_release.name,
        "os_version": os_release.version,
        "os_codename": os_release.version_codename,
        "os_major": os_release.version_major(),
        "os_minor": os_release.version_minor(),
        "os_platform": os_release.id,
        "sysname": kernel_name,
        "release": kernel_release,
    });

    debug!(os_name = %os_release.name, version = %os_release.version, "collected OS info");
    build_osinfo(data)
}

/// Parsed fields from `/etc/os-release`.
#[derive(Debug, Default)]
pub(crate) struct OsRelease {
    name: String,
    version: String,
    id: String,
    version_codename: String,
}

impl OsRelease {
    fn version_major(&self) -> String {
        self.version
            .split('.')
            .next()
            .unwrap_or("")
            .to_string()
    }

    fn version_minor(&self) -> String {
        self.version
            .split('.')
            .nth(1)
            .unwrap_or("")
            .to_string()
    }
}

/// Parse `/etc/os-release` into an `OsRelease` struct.
pub(crate) fn parse_os_release() -> OsRelease {
    let content = match std::fs::read_to_string("/etc/os-release") {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to read /etc/os-release");
            return OsRelease::default();
        }
    };
    parse_os_release_content(&content)
}

/// Parse os-release content from a string (testable without filesystem).
pub(crate) fn parse_os_release_content(content: &str) -> OsRelease {
    let mut release = OsRelease::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_matches('"');
            match key {
                "NAME" => release.name = value.to_string(),
                "VERSION_ID" => release.version = value.to_string(),
                "ID" => release.id = value.to_string(),
                "VERSION_CODENAME" => release.version_codename = value.to_string(),
                _ => {}
            }
        }
    }

    release
}

fn read_file_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn gethostname_fallback() -> String {
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release_ubuntu() {
        let content = r#"
NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
VERSION_CODENAME=jammy
HOME_URL="https://www.ubuntu.com/"
"#;
        let release = parse_os_release_content(content);
        assert_eq!(release.name, "Ubuntu");
        assert_eq!(release.version, "22.04");
        assert_eq!(release.id, "ubuntu");
        assert_eq!(release.version_codename, "jammy");
        assert_eq!(release.version_major(), "22");
        assert_eq!(release.version_minor(), "04");
    }

    #[test]
    fn test_parse_os_release_fedora() {
        let content = r#"
NAME="Fedora Linux"
VERSION_ID="39"
ID=fedora
VERSION_CODENAME=""
"#;
        let release = parse_os_release_content(content);
        assert_eq!(release.name, "Fedora Linux");
        assert_eq!(release.version, "39");
        assert_eq!(release.id, "fedora");
        assert_eq!(release.version_major(), "39");
        assert_eq!(release.version_minor(), "");
    }

    #[test]
    fn test_parse_os_release_empty() {
        let release = parse_os_release_content("");
        assert_eq!(release.name, "");
        assert_eq!(release.version, "");
    }

    #[test]
    fn test_parse_os_release_comments_and_blanks() {
        let content = "# comment\n\nNAME=\"Test OS\"\n";
        let release = parse_os_release_content(content);
        assert_eq!(release.name, "Test OS");
    }

    #[test]
    fn test_collect_os_info_returns_valid_json() {
        let info = collect_os_info();
        assert_eq!(info["type"], "dbsync_osinfo");
        assert!(info["data"]["architecture"].is_string());
        assert!(info["data"]["hostname"].is_string());
    }
}
