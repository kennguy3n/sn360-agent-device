//! Cross-platform running-software (process) enumeration.
//!
//! Emits a uniform [`ProcessEntry`] shape per process regardless of the
//! host:
//!
//! | Field         | Description                                               |
//! |---------------|-----------------------------------------------------------|
//! | `pid`         | Process identifier                                        |
//! | `name`        | Short command / image name                                |
//! | `path`        | Absolute path to the executable image, when resolvable    |
//! | `started_at`  | RFC 3339 start time of the process, when available        |
//! | `publisher`   | Vendor / signer, when the platform exposes one cheaply    |
//!
//! Enumeration is implemented per platform and never panics on
//! per-process errors — a transient failure (short-lived process,
//! permission-denied) is silently skipped so the snapshot still
//! succeeds for every visible process.

use serde::{Deserialize, Serialize};

/// A single running-process entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEntry {
    /// Process identifier.
    pub pid: u32,
    /// Short command / image name.
    pub name: String,
    /// Absolute path to the executable image, when resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// RFC 3339 timestamp of when the process was started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Vendor / signer for the executable, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
}

/// Enumerate every visible running process on the host.
///
/// Blocking filesystem / syscall work — call from
/// [`tokio::task::spawn_blocking`].
pub fn enumerate_processes() -> Vec<ProcessEntry> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::enumerate()
    }
    #[cfg(target_os = "macos")]
    {
        macos_impl::enumerate()
    }
    #[cfg(target_os = "windows")]
    {
        windows_impl::enumerate()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

// ── Linux /proc-based implementation ─────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::ProcessEntry;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub(super) fn enumerate() -> Vec<ProcessEntry> {
        let entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if let Some(p) = read_process(pid) {
                out.push(p);
            }
        }
        out
    }

    fn read_process(pid: u32) -> Option<ProcessEntry> {
        let base = PathBuf::from(format!("/proc/{}", pid));
        let stat = fs::read_to_string(base.join("stat")).ok()?;
        let (name, start_ticks) = parse_stat(&stat)?;

        let path = fs::read_link(base.join("exe"))
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()));

        let cmdline_name = fs::read(base.join("cmdline"))
            .ok()
            .and_then(|bytes| first_cmdline_arg(&bytes));

        // Prefer the image basename from `exe` when available; fall back
        // to the first argv entry; fall back finally to /proc/[pid]/stat.
        let resolved_name = path
            .as_deref()
            .and_then(|p| Path::new(p).file_name().and_then(|s| s.to_str()))
            .map(|s| s.to_string())
            .or_else(|| cmdline_name.clone())
            .unwrap_or(name);

        let started_at = start_time_rfc3339(start_ticks);

        Some(ProcessEntry {
            pid,
            name: resolved_name,
            path,
            started_at,
            publisher: None,
        })
    }

    /// Parse `/proc/[pid]/stat`.
    ///
    /// Returns `(comm, start_time_ticks)`.  `comm` is extracted from the
    /// `(name)` parenthesised span (which may contain whitespace or
    /// close-parens) and `start_time_ticks` is field 22 (1-indexed) as
    /// documented in `proc(5)`.
    fn parse_stat(contents: &str) -> Option<(String, u64)> {
        let open = contents.find('(')?;
        let close = contents.rfind(')')?;
        if close <= open {
            return None;
        }
        let comm = contents[open + 1..close].to_string();
        let tail = contents.get(close + 1..)?.trim_start();
        // After `)`, fields start at index 3 (state is field 3).  We
        // want field 22 — i.e. 19 additional whitespace-separated
        // tokens past `state`.
        let fields: Vec<&str> = tail.split_whitespace().collect();
        if fields.len() < 20 {
            return None;
        }
        let start_ticks: u64 = fields[19].parse().ok()?;
        Some((comm, start_ticks))
    }

    /// Read `/proc/[pid]/cmdline` — a null-byte-delimited blob — and
    /// return the basename of the first argv entry when present.
    fn first_cmdline_arg(bytes: &[u8]) -> Option<String> {
        let first = bytes.split(|b| *b == 0).next()?;
        if first.is_empty() {
            return None;
        }
        let s = std::str::from_utf8(first).ok()?;
        Path::new(s)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    }

    fn start_time_rfc3339(start_ticks: u64) -> Option<String> {
        let boot = boot_time_unix()?;
        let hz = clock_ticks_per_sec();
        if hz == 0 {
            return None;
        }
        let seconds_since_boot = start_ticks / hz;
        let unix_secs = boot.checked_add(seconds_since_boot)?;
        let ts = UNIX_EPOCH.checked_add(Duration::from_secs(unix_secs))?;
        let dt: chrono::DateTime<chrono::Utc> = ts.into();
        Some(dt.to_rfc3339())
    }

    fn boot_time_unix() -> Option<u64> {
        static CACHE: OnceLock<Option<u64>> = OnceLock::new();
        *CACHE.get_or_init(|| {
            let stat = fs::read_to_string("/proc/stat").ok()?;
            for line in stat.lines() {
                if let Some(rest) = line.strip_prefix("btime ") {
                    return rest.trim().parse::<u64>().ok();
                }
            }
            // Fallback: derive boot time from the current time minus
            // the uptime reported by /proc/uptime.
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            let uptime = fs::read_to_string("/proc/uptime").ok()?;
            let first = uptime.split_whitespace().next()?;
            let up_secs: f64 = first.parse().ok()?;
            now.checked_sub(up_secs as u64)
        })
    }

    fn clock_ticks_per_sec() -> u64 {
        static CACHE: OnceLock<u64> = OnceLock::new();
        *CACHE.get_or_init(|| {
            // `_SC_CLK_TCK` — conventionally 100 on Linux, but check.
            match nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK) {
                Ok(Some(v)) if v > 0 => v as u64,
                _ => 100,
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_parse_stat_handles_parens_and_whitespace() {
            // Synthetic `/proc/[pid]/stat`: the 22nd field (start_time)
            // is the 19th whitespace-separated token after `)`.
            let mut fields: Vec<String> = Vec::new();
            fields.push("S".to_string()); // state
            for i in 0..18 {
                fields.push(i.to_string());
            }
            fields.push("4242".to_string()); // start_time
            fields.push("0".to_string()); // extra
            let tail = fields.join(" ");
            let line = format!("123 (weird (name) with spaces) {}", tail);
            let (comm, start) = parse_stat(&line).expect("parse_stat should succeed");
            assert_eq!(comm, "weird (name) with spaces");
            assert_eq!(start, 4242);
        }

        #[test]
        fn test_parse_stat_rejects_short_input() {
            assert!(parse_stat("1 (x) S").is_none());
        }

        #[test]
        fn test_first_cmdline_arg_handles_absolute_path() {
            let buf = b"/usr/bin/zsh\0-l\0";
            assert_eq!(first_cmdline_arg(buf).as_deref(), Some("zsh"));
        }

        #[test]
        fn test_first_cmdline_arg_empty_yields_none() {
            assert!(first_cmdline_arg(b"").is_none());
            assert!(first_cmdline_arg(b"\0").is_none());
        }

        #[test]
        fn test_clock_ticks_positive() {
            assert!(clock_ticks_per_sec() > 0);
        }
    }
}

// ── macOS `ps` shell-out implementation ──────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::ProcessEntry;
    use std::process::Command;

    pub(super) fn enumerate() -> Vec<ProcessEntry> {
        // `ps -A -o pid=,comm=,lstart=` prints one line per process.
        // `lstart` is a human-readable 5-field date ("Mon Apr 20
        // 06:30:00 2026") — we keep it as-is in `started_at`.
        let output = match Command::new("/bin/ps")
            .args(["-A", "-o", "pid=,comm=,lstart="])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut out = Vec::new();
        for line in text.lines() {
            if let Some(entry) = parse_line(line) {
                out.push(entry);
            }
        }
        out
    }

    fn parse_line(line: &str) -> Option<ProcessEntry> {
        let line = line.trim_start();
        let mut it = line.splitn(2, char::is_whitespace);
        let pid: u32 = it.next()?.parse().ok()?;
        let rest = it.next()?.trim_start();
        // `comm` on macOS `ps` is the absolute path to the executable,
        // optionally truncated.  It never contains whitespace unless
        // the binary path itself does — which is extremely rare — so
        // split on the first whitespace for the remainder.
        let mut it = rest.splitn(2, char::is_whitespace);
        let comm = it.next()?.to_string();
        let lstart = it.next().map(|s| s.trim().to_string());

        let path_opt = if comm.starts_with('/') {
            Some(comm.clone())
        } else {
            None
        };
        let name = std::path::Path::new(&comm)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&comm)
            .to_string();

        Some(ProcessEntry {
            pid,
            name,
            path: path_opt,
            started_at: lstart.filter(|s| !s.is_empty()),
            publisher: None,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_parse_line_absolute_path_with_lstart() {
            let line = "  123 /bin/zsh Mon Apr 20 06:30:00 2026";
            let p = parse_line(line).unwrap();
            assert_eq!(p.pid, 123);
            assert_eq!(p.name, "zsh");
            assert_eq!(p.path.as_deref(), Some("/bin/zsh"));
            assert_eq!(p.started_at.as_deref(), Some("Mon Apr 20 06:30:00 2026"));
        }

        #[test]
        fn test_parse_line_name_only() {
            let p = parse_line("9 launchd").unwrap();
            assert_eq!(p.pid, 9);
            assert_eq!(p.name, "launchd");
            assert!(p.path.is_none());
        }

        #[test]
        fn test_parse_line_rejects_garbage() {
            assert!(parse_line("").is_none());
            assert!(parse_line("not-a-pid foo").is_none());
        }
    }
}

// ── Windows ToolHelp32 implementation ────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::ProcessEntry;
    use std::path::Path;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    pub(super) fn enumerate() -> Vec<ProcessEntry> {
        // SAFETY: CreateToolhelp32Snapshot returns an error on failure;
        // we close the handle with `CloseHandle` in every exit path.
        let snap: HANDLE = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // SAFETY: `snap` is valid, `entry.dwSize` is correctly set.
        if unsafe { Process32FirstW(snap, &mut entry) }.is_ok() {
            loop {
                let name = wide_to_string(&entry.szExeFile);
                if !name.is_empty() {
                    out.push(ProcessEntry {
                        pid: entry.th32ProcessID,
                        name: Path::new(&name)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&name)
                            .to_string(),
                        path: None,
                        started_at: None,
                        publisher: None,
                    });
                }

                // SAFETY: `snap` is still valid; `entry.dwSize` is
                // unchanged across calls.
                if unsafe { Process32NextW(snap, &mut entry) }.is_err() {
                    break;
                }
            }
        }

        // SAFETY: `snap` was created above and hasn't been closed.
        let _ = unsafe { CloseHandle(snap) };

        out
    }

    fn wide_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_wide_to_string_strips_null_terminator() {
            let mut buf = [0u16; 8];
            for (i, c) in "abc".encode_utf16().enumerate() {
                buf[i] = c;
            }
            assert_eq!(wide_to_string(&buf), "abc");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_running_processes_returns_results() {
        let processes = enumerate_processes();
        assert!(
            !processes.is_empty(),
            "enumerate_processes must return at least the test process"
        );
    }

    #[test]
    fn test_enumerate_includes_current_pid() {
        let me = std::process::id();
        let processes = enumerate_processes();
        assert!(
            processes.iter().any(|p| p.pid == me),
            "enumerate_processes must include the current PID {}",
            me
        );
    }

    #[test]
    fn test_process_entry_has_required_fields() {
        // PID 0 is a real kernel-level entry on Windows ("[System Process]")
        // and also appears as the swapper task on some Unix snapshots, so the
        // invariant we care about is only that the name is populated.
        let processes = enumerate_processes();
        for p in &processes {
            assert!(!p.name.is_empty(), "name must be non-empty: {:?}", p);
        }
    }

    #[test]
    fn test_process_entry_serializes_to_json_object() {
        let entry = ProcessEntry {
            pid: 123,
            name: "wda-agent".to_string(),
            path: Some("/usr/bin/wda-agent".to_string()),
            started_at: Some("2026-04-20T06:30:00+00:00".to_string()),
            publisher: None,
        };
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(value["pid"], 123);
        assert_eq!(value["name"], "wda-agent");
        assert_eq!(value["path"], "/usr/bin/wda-agent");
        assert!(value.get("publisher").is_none(), "None fields are skipped");
    }
}
