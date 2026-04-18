//! Installed package collection for the inventory module.
//!
//! Uses `dpkg-query` (Debian/Ubuntu) and `rpm` (RHEL/Fedora) to enumerate
//! installed packages via async process execution.

use serde_json::Value;
use tracing::{debug, warn};

use crate::syscollector_format::build_packages;

/// Collect installed packages asynchronously.
///
/// Tries dpkg first, then rpm. Returns a vector of `dbsync_packages` payloads.
pub async fn collect_packages() -> Vec<Value> {
    let mut payloads = Vec::new();

    // Try dpkg-query (Debian/Ubuntu).
    match collect_dpkg_packages().await {
        Ok(pkgs) if !pkgs.is_empty() => {
            debug!(count = pkgs.len(), "collected packages via dpkg-query");
            payloads.extend(pkgs);
        }
        Ok(_) => {
            debug!("dpkg-query returned no packages, trying rpm");
        }
        Err(e) => {
            debug!(error = %e, "dpkg-query not available or failed, trying rpm");
        }
    }

    // Try rpm if dpkg found nothing.
    if payloads.is_empty() {
        match collect_rpm_packages().await {
            Ok(pkgs) if !pkgs.is_empty() => {
                debug!(count = pkgs.len(), "collected packages via rpm");
                payloads.extend(pkgs);
            }
            Ok(_) => {
                warn!("rpm returned no packages");
            }
            Err(e) => {
                debug!(error = %e, "rpm not available or failed");
            }
        }
    }

    payloads
}

/// Collect packages using `dpkg-query`.
async fn collect_dpkg_packages() -> anyhow::Result<Vec<Value>> {
    let output = tokio::process::Command::new("dpkg-query")
        .args([
            "-W",
            "-f",
            "${Package}\t${Version}\t${Architecture}\t${Maintainer}\n",
        ])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("dpkg-query exited with status {}", output.status);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_dpkg_output(&stdout))
}

/// Parse dpkg-query tab-delimited output into package payloads.
pub(crate) fn parse_dpkg_output(output: &str) -> Vec<Value> {
    let mut payloads = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.splitn(4, '\t').collect();
        if fields.len() < 2 {
            continue;
        }

        let name = fields[0];
        let version = fields.get(1).copied().unwrap_or("");
        let architecture = fields.get(2).copied().unwrap_or("");
        let vendor = fields.get(3).copied().unwrap_or("");

        let data = serde_json::json!({
            "name": name,
            "version": version,
            "architecture": architecture,
            "vendor": vendor,
            "format": "deb",
        });
        payloads.push(build_packages(data));
    }

    payloads
}

/// Collect packages using `rpm`.
async fn collect_rpm_packages() -> anyhow::Result<Vec<Value>> {
    let output = tokio::process::Command::new("rpm")
        .args([
            "-qa",
            "--queryformat",
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n",
        ])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("rpm exited with status {}", output.status);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_rpm_output(&stdout))
}

/// Parse rpm tab-delimited output into package payloads.
pub(crate) fn parse_rpm_output(output: &str) -> Vec<Value> {
    let mut payloads = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.splitn(4, '\t').collect();
        if fields.len() < 2 {
            continue;
        }

        let name = fields[0];
        let version = fields.get(1).copied().unwrap_or("");
        let architecture = fields.get(2).copied().unwrap_or("");
        let vendor = fields.get(3).copied().unwrap_or("");

        let data = serde_json::json!({
            "name": name,
            "version": version,
            "architecture": architecture,
            "vendor": vendor,
            "format": "rpm",
        });
        payloads.push(build_packages(data));
    }

    payloads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dpkg_output() {
        let output = "vim\t2:8.2.3995-1ubuntu2.13\tamd64\tUbuntu Developers\n\
                       curl\t7.81.0-1ubuntu1.14\tamd64\tUbuntu Developers\n";
        let pkgs = parse_dpkg_output(output);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0]["data"]["name"], "vim");
        assert_eq!(pkgs[0]["data"]["format"], "deb");
        assert_eq!(pkgs[1]["data"]["name"], "curl");
        assert_eq!(pkgs[1]["data"]["architecture"], "amd64");
    }

    #[test]
    fn test_parse_dpkg_output_empty() {
        let pkgs = parse_dpkg_output("");
        assert!(pkgs.is_empty());
    }

    #[test]
    fn test_parse_dpkg_output_partial_fields() {
        let output = "minimal-pkg\t1.0\n";
        let pkgs = parse_dpkg_output(output);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0]["data"]["name"], "minimal-pkg");
        assert_eq!(pkgs[0]["data"]["version"], "1.0");
    }

    #[test]
    fn test_parse_rpm_output() {
        let output = "bash\t5.2.15-3.fc39\tx86_64\tFedora Project\n\
                       vim-minimal\t9.0.2081-1.fc39\tx86_64\tFedora Project\n";
        let pkgs = parse_rpm_output(output);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0]["data"]["name"], "bash");
        assert_eq!(pkgs[0]["data"]["format"], "rpm");
        assert_eq!(pkgs[1]["data"]["name"], "vim-minimal");
    }

    #[test]
    fn test_parse_rpm_output_empty() {
        let pkgs = parse_rpm_output("");
        assert!(pkgs.is_empty());
    }

    #[tokio::test]
    async fn test_collect_packages_runs_without_panic() {
        // This may return empty on systems without dpkg/rpm, but should not panic.
        let pkgs = collect_packages().await;
        // On this Ubuntu-based CI machine, dpkg should be available.
        // We just verify no panic; actual count may vary.
        let _ = pkgs;
    }
}
