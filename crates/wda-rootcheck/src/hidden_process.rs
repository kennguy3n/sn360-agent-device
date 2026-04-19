//! Hidden-process detection.
//!
//! On Linux, enumerates visible PIDs via `/proc` and compares them
//! against a `kill(pid, 0)` probe for the range `1..=max_pid`. Any
//! PID that responds to the signal-zero probe but is not present in
//! `/proc` is reported as potentially hidden by a kernel-level
//! rootkit.
//!
//! On macOS / Windows / other platforms the function is a no-op and
//! always returns an empty list.

/// A PID that passed the "exists according to kill(pid, 0)" probe
/// but did not appear in the `/proc` enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenPid {
    pub pid: u32,
}

/// Scan for hidden processes.
///
/// `max_pid` bounds the upper end of the PID range probed with
/// `kill(pid, 0)`. On Linux this must be at least
/// `/proc/sys/kernel/pid_max`; values beyond that just waste cycles.
pub fn scan(max_pid: u32) -> Vec<HiddenPid> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::scan(max_pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = max_pid;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::HiddenPid;
    use std::collections::HashSet;

    /// Enumerate PIDs visible via `/proc` directory listing.
    fn enumerate_proc_pids() -> HashSet<u32> {
        let mut pids = HashSet::new();

        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return pids,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Ok(pid) = name.parse::<u32>() {
                pids.insert(pid);
            }
        }

        pids
    }

    /// Returns `true` only when `kill(pid, 0)` succeeds, i.e. the
    /// process exists **and** the caller has permission to signal it.
    ///
    /// `EPERM` is deliberately treated as "not present" — on
    /// unprivileged runs it otherwise produces a flood of false
    /// positives for processes the caller happens to not own. The
    /// stronger `Ok` signal means that when the check does fire
    /// ("exists according to kill, absent from /proc") it is a real
    /// rootkit indicator and not permission noise.
    ///
    /// PIDs that don't fit in `i32` are skipped: a negative value
    /// passed to `kill(2)` addresses a process group, which would
    /// change the probe's meaning entirely.
    fn pid_exists(pid: u32) -> bool {
        use nix::sys::signal::kill;
        use nix::unistd::Pid;

        let Ok(raw_pid) = i32::try_from(pid) else {
            return false;
        };
        matches!(kill(Pid::from_raw(raw_pid), None), Ok(()))
    }

    pub fn scan(max_pid: u32) -> Vec<HiddenPid> {
        let visible = enumerate_proc_pids();
        let mut hidden = Vec::new();

        for pid in 1..=max_pid {
            if !visible.contains(&pid) && pid_exists(pid) {
                hidden.push(HiddenPid { pid });
            }
        }

        hidden
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_runs_to_completion_on_clean_system() {
        // The scan must always return a concrete (possibly empty)
        // list without panicking, even in environments where `/proc`
        // visibility is restricted (CI containers, PID namespaces).
        // We don't assert emptiness: on shared hosts, PID namespace
        // boundaries can legitimately make some PIDs answer to
        // `kill(0)` while not appearing in this process's `/proc`
        // view, and that's outside the module's control.
        let _ = scan(4096);
    }

    #[test]
    fn test_own_pid_is_visible_and_not_reported_hidden() {
        // The test process itself must be present in `/proc` and
        // therefore never appear in the hidden list.
        let my_pid = std::process::id();
        let hidden = scan(my_pid.saturating_add(1));
        assert!(
            !hidden.iter().any(|h| h.pid == my_pid),
            "own PID unexpectedly reported as hidden: {:?}",
            hidden
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_noop_on_non_linux() {
        assert!(scan(100_000).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_scan_handles_max_pid_zero() {
        // Range `1..=0` is empty — must return no hits and not panic.
        let hidden = scan(0);
        assert!(hidden.is_empty());
    }
}
