//! Local Detection Engine (LDE) for the Wazuh Desktop Agent.
//!
//! Evaluates detection rules locally at the edge — IOC matching via
//! Aho-Corasick + bloom filters, behavioural rule state machines, and
//! YARA file scanning — without a server round-trip.  All findings are
//! republished on the shared event bus as
//! [`EventKind::LocalDetectionAlert`](wda_event_bus::EventKind::LocalDetectionAlert)
//! and, when the server is unreachable, spooled to the on-disk offline
//! queue.
//!
//! The module follows the same lifecycle pattern as
//! `wda_rootcheck::RootcheckModule`: an `AtomicU8` status, a
//! [`ModuleHandle`] returned from `start()`, and a `tokio::select!`
//! loop driven by a [`ShutdownSignal`].

pub mod behavioral;
pub mod ioc_matcher;
pub mod offline_queue;
pub mod response;
pub mod rule_store;
pub mod yara_scanner;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use wda_core::config::{AgentConfig, LocalDetectionConfig};
use wda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use wda_core::signal::ShutdownSignal;
use wda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};

use crate::behavioral::{BehavioralEngine, BehavioralEvent, BehavioralMatch};
use crate::ioc_matcher::{IocMatch, IocMatcher};
use crate::offline_queue::OfflineQueue;
use crate::response::LocalResponder;
use crate::rule_store::{IocList, RuleBundle};
use crate::yara_scanner::{YaraMatch, YaraScanner};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Local Detection Engine module handle.
pub struct LocalDetectionModule {
    status: Arc<AtomicU8>,
}

impl LocalDetectionModule {
    /// Spawn the LDE run loop and return a [`ModuleHandle`].
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let lde_config = config.modules.local_detection.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(lde_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "local detection module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("local_detection", task)
    }
}

impl Default for LocalDetectionModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl AgentModule for LocalDetectionModule {
    fn name(&self) -> &'static str {
        "local_detection"
    }

    fn status(&self) -> ModuleStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleStatus::Running,
            STATUS_STOPPED => ModuleStatus::Stopped,
            STATUS_FAILED => ModuleStatus::Failed,
            _ => ModuleStatus::Initialized,
        }
    }

    fn health(&self) -> ModuleHealth {
        match self.status.load(Ordering::Relaxed) {
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

/// The detection pipeline the run loop drives on every incoming event.
struct DetectionPipeline {
    iocs: IocMatcher,
    behavioral: Mutex<BehavioralEngine>,
    yara: YaraScanner,
    responder: LocalResponder,
    offline: OfflineQueue,
    bundle_version: u64,
}

impl DetectionPipeline {
    fn new(config: &LocalDetectionConfig, bundle: RuleBundle) -> anyhow::Result<Self> {
        let iocs = IocMatcher::build(&bundle.iocs, config.bloom_filter_fpr)?;
        let behavioral = Mutex::new(BehavioralEngine::new(
            bundle.behavioral.clone(),
            config.behavioral_max_tracked_entities,
            config.behavioral_max_window_sec,
        ));
        let yara = YaraScanner::new(
            &bundle.yara_paths,
            config.yara_scan_rate_limit,
            config.yara_max_file_size_mb,
        )
        .unwrap_or_else(|e| {
            warn!(error = %e, "falling back to empty YARA scanner");
            YaraScanner::empty(config.yara_scan_rate_limit, config.yara_max_file_size_mb)
        });
        let responder = LocalResponder::new(config.clone());
        let offline = OfflineQueue::open(&config.offline_queue_path, config.offline_queue_max)
            .unwrap_or_else(|e| {
                warn!(
                    path = %config.offline_queue_path.display(),
                    error = %e,
                    "falling back to in-memory offline queue"
                );
                OfflineQueue::in_memory(config.offline_queue_max)
                    .expect("in-memory sqlite creation")
            });
        Ok(Self {
            iocs,
            behavioral,
            yara,
            responder,
            offline,
            bundle_version: bundle.version,
        })
    }
}

/// Build the initial rule bundle from `config.rule_bundle_path`.  A
/// missing or unreadable bundle is *not* fatal — we degrade gracefully
/// to an empty bundle so the run loop can still serve as a pass-through
/// (and future TRDS pulls can populate rules).
fn load_initial_bundle(path: &std::path::Path) -> RuleBundle {
    match RuleBundle::load(path) {
        Ok(b) => {
            info!(
                path = %path.display(),
                version = b.version,
                strings = b.iocs.strings.len(),
                hashes = b.iocs.hashes.len(),
                ips = b.iocs.ips.len(),
                behavioral = b.behavioral.len(),
                yara = b.yara_paths.len(),
                "loaded LDE rule bundle"
            );
            b
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "LDE rule bundle unavailable; starting with empty ruleset"
            );
            RuleBundle::default()
        }
    }
}

async fn publish_alert(bus: &EventBus, alert: &LocalAlert, offline: &OfflineQueue) {
    let kind = EventKind::LocalDetectionAlert {
        rule_id: alert.rule_id.clone(),
        rule_type: alert.rule_type.to_string(),
        severity: alert.severity.clone(),
        description: alert.description.clone(),
        matched_value: alert.matched_value.clone(),
    };
    let event = Event::new("local_detection", Priority::Normal, kind.clone());
    match bus.publish_to_server(event).await {
        Ok(()) => {}
        Err(e) => {
            warn!(error = %e, "server-bound publish failed; spooling to offline queue");
            if let Ok(payload) = serde_json::to_string(&kind) {
                if let Err(qe) = offline.enqueue(&payload) {
                    warn!(error = %qe, "offline queue enqueue failed");
                }
            }
        }
    }
}

/// A uniform alert shape shared by IOC, behavioural and YARA matches.
#[derive(Debug, Clone)]
struct LocalAlert {
    rule_id: String,
    rule_type: &'static str,
    severity: String,
    description: String,
    matched_value: String,
}

impl From<IocMatch> for LocalAlert {
    fn from(m: IocMatch) -> Self {
        Self {
            rule_id: m.rule_id,
            rule_type: m.rule_type,
            severity: m.severity,
            description: m.description,
            matched_value: m.matched_value,
        }
    }
}

impl From<BehavioralMatch> for LocalAlert {
    fn from(m: BehavioralMatch) -> Self {
        Self {
            rule_id: m.rule_id,
            rule_type: "behavioral",
            severity: m.severity,
            description: m.description,
            matched_value: m.entity,
        }
    }
}

impl LocalAlert {
    fn from_yara(path: &std::path::Path, m: YaraMatch, severity: &str) -> Self {
        Self {
            rule_id: m.rule_id.clone(),
            rule_type: "yara",
            severity: severity.to_string(),
            description: format!("YARA rule {} matched file", m.rule_id),
            matched_value: path.to_string_lossy().into_owned(),
        }
    }
}

/// Handle a single inbound event by running it through every rule
/// backend and firing alerts for each hit.
async fn handle_event(pipeline: &DetectionPipeline, bus: &EventBus, event: &Event) {
    // Extract the interesting fields from the event kind.
    let (source_tag, entity, primary_text, fim_path, sha256, ips): (
        &str,
        String,
        String,
        Option<PathBuf>,
        Option<String>,
        Vec<String>,
    ) = match &event.kind {
        EventKind::FileCreated {
            path,
            syscheck_payload,
        }
        | EventKind::FileModified {
            path,
            syscheck_payload,
        } => (
            "fim",
            path.clone(),
            path.clone(),
            Some(PathBuf::from(path)),
            extract_sha256_from_syscheck(syscheck_payload.as_deref()),
            Vec::new(),
        ),
        EventKind::FileDeleted {
            path,
            syscheck_payload,
        }
        | EventKind::FileMetadataChanged {
            path,
            syscheck_payload,
        } => (
            "fim",
            path.clone(),
            path.clone(),
            None,
            extract_sha256_from_syscheck(syscheck_payload.as_deref()),
            Vec::new(),
        ),
        EventKind::LogCollected {
            source, message, ..
        } => (
            "logcollector",
            source.clone(),
            message.clone(),
            None,
            None,
            extract_ipv4s(message),
        ),
        // The LDE only observes FIM and logcollector streams; other
        // event kinds pass through untouched.
        _ => return,
    };

    // --- IOC matching (string, hash, IP backends) ---
    let mut ioc_hits = pipeline
        .iocs
        .matches(&[&primary_text], sha256.as_deref(), None);
    // Probe every IP found in the log message against the IP bloom.
    for ip in &ips {
        if let Some(m) = pipeline.iocs.match_ip(ip) {
            ioc_hits.push(m);
        }
    }
    for hit in ioc_hits {
        let alert: LocalAlert = hit.into();
        maybe_respond(pipeline, &alert, fim_path.as_deref()).await;
        publish_alert(bus, &alert, &pipeline.offline).await;
    }

    // --- Behavioural rules ---
    let behavioral_hits = {
        let mut engine = pipeline.behavioral.lock().await;
        engine.evaluate(&BehavioralEvent {
            source: source_tag,
            entity: &entity,
            text: &primary_text,
        })
    };
    for hit in behavioral_hits {
        let alert: LocalAlert = hit.into();
        maybe_respond(pipeline, &alert, fim_path.as_deref()).await;
        publish_alert(bus, &alert, &pipeline.offline).await;
    }

    // --- YARA on FIM-created/modified files ---
    if let Some(path) = fim_path {
        if pipeline.yara.has_rules() {
            match pipeline.yara.scan_file(&path).await {
                Ok(hits) => {
                    for m in hits {
                        let alert = LocalAlert::from_yara(&path, m, rule_store::SEV_HIGH);
                        maybe_respond(pipeline, &alert, Some(&path)).await;
                        publish_alert(bus, &alert, &pipeline.offline).await;
                    }
                }
                Err(e) => warn!(path = %path.display(), error = %e, "YARA scan failed"),
            }
        }
    }
}

/// Dispatch local responses for a finalised alert, when enabled by
/// configuration.
async fn maybe_respond(
    pipeline: &DetectionPipeline,
    alert: &LocalAlert,
    fim_path: Option<&std::path::Path>,
) {
    // IP-matched IOCs may warrant a block.
    if alert.rule_type == "ip" {
        let outcome = pipeline.responder.block_ip(&alert.matched_value).await;
        debug!(rule = %alert.rule_id, outcome = ?outcome, "block_ip response");
    }
    // YARA matches on a file path may warrant quarantine.
    if alert.rule_type == "yara" {
        if let Some(path) = fim_path {
            let outcome = pipeline.responder.quarantine(path).await;
            debug!(rule = %alert.rule_id, path = %path.display(), outcome = ?outcome, "quarantine response");
        }
    }
}

/// Main LDE run loop.
async fn run(
    config: LocalDetectionConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        rule_bundle = %config.rule_bundle_path.display(),
        offline_queue = %config.offline_queue_path.display(),
        block_ip = config.block_ip,
        kill_process = config.kill_process,
        quarantine = config.quarantine,
        "local detection module starting"
    );

    let bundle = load_initial_bundle(&config.rule_bundle_path);
    let pipeline = DetectionPipeline::new(&config, bundle)?;
    info!(
        rules = pipeline.iocs.rule_count(),
        yara_loaded = pipeline.yara.has_rules(),
        version = pipeline.bundle_version,
        "local detection engine ready"
    );

    let mut rx: EventReceiver = bus.subscribe();
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    let mut rule_pull_timer =
        tokio::time::interval(Duration::from_secs(config.rule_pull_interval.max(30)));
    // Consume the immediate first tick — bundle was just loaded.
    rule_pull_timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("local detection module received shutdown signal");
                break;
            }

            event = rx.recv() => {
                let event = match event {
                    Some(ev) => ev,
                    None => {
                        warn!("event bus closed, stopping local detection module");
                        break;
                    }
                };
                handle_event(&pipeline, &bus, &event).await;
            }

            _ = rule_pull_timer.tick() => {
                // Placeholder for TRDS pull.  The real pull will reach
                // out to the Tenant Rule Distribution Service; for now
                // we simply log — operators can hot-swap by writing a
                // new bundle and restarting the module.
                debug!("LDE rule pull timer fired (hot-reload not yet implemented)");
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("local detection module stopped");
    Ok(())
}

/// Helper for building empty IOC lists — used by tooling that wants a
/// minimal pipeline.
pub fn empty_ioc_list() -> IocList {
    IocList::default()
}

/// Extract the SHA-256 digest from a Wazuh-syscheck JSON payload.
///
/// The syscheck daemon emits events like
/// `{"type":"event","data":{"path":"...","hash_sha256":"...", ...}}`.
/// We accept a handful of common field names (`hash_sha256`, `sha256`,
/// `sha256sum`) and return the lower-cased 64-character hex string when
/// found.  Anything else yields `None`, letting the caller skip the
/// hash backend cleanly.
fn extract_sha256_from_syscheck(payload: Option<&str>) -> Option<String> {
    let raw = payload?;
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let keys = ["hash_sha256", "sha256", "sha256sum", "sha256_after"];
    fn find<'a>(v: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
        for k in keys {
            if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
                return Some(s);
            }
        }
        None
    }
    let found = find(&v, &keys)
        .or_else(|| v.get("data").and_then(|d| find(d, &keys)))
        .or_else(|| {
            v.get("data")
                .and_then(|d| d.get("attributes"))
                .and_then(|a| find(a, &keys))
        })?;
    let lower = found.to_ascii_lowercase();
    if lower.len() == 64 && lower.bytes().all(|c| c.is_ascii_hexdigit()) {
        Some(lower)
    } else {
        None
    }
}

/// Scan free-form text for dotted-quad IPv4 literals.
///
/// Deliberately avoids a regex dependency — syslog lines rarely contain
/// more than a handful of candidates and a linear scan is more than
/// fast enough.  IPv6 extraction is intentionally out of scope until we
/// have a concrete detection use case for it.
fn extract_ipv4s(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut octets = 0usize;
            let mut digits = 0usize;
            let mut valid = true;
            while i < bytes.len() && octets < 4 {
                if bytes[i].is_ascii_digit() {
                    digits += 1;
                    if digits > 3 {
                        valid = false;
                        break;
                    }
                    i += 1;
                } else if bytes[i] == b'.' && digits > 0 && octets < 3 {
                    octets += 1;
                    digits = 0;
                    i += 1;
                } else {
                    break;
                }
            }
            if valid && octets == 3 && digits > 0 {
                // Reject candidates that are actually a prefix of a longer
                // dotted sequence (e.g. "1.2.3.4.5") — those aren't IPv4.
                let followed_by_dot_digit =
                    i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit();
                let candidate = &text[start..i];
                if !followed_by_dot_digit && candidate.split('.').all(|o| o.parse::<u8>().is_ok()) {
                    out.push(candidate.to_string());
                    continue;
                }
            }
            // Advance past the partial run to avoid re-scanning the
            // same prefix on the next iteration.
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_store::{
        BehavioralRule, BehavioralRuleKind, HashIoc, IpIoc, StringIoc, SEV_HIGH, SEV_MEDIUM,
    };
    use wda_core::config::{AgentConfig, ModulesConfig};
    use wda_core::signal::ShutdownController;
    use wda_event_bus::EventBus;

    fn test_config(tmp: &tempfile::TempDir) -> LocalDetectionConfig {
        LocalDetectionConfig {
            enabled: true,
            rule_pull_interval: 3600,
            offline_queue_max: 100,
            yara_scan_rate_limit: 10,
            yara_max_file_size_mb: 10,
            bloom_filter_fpr: 0.01,
            behavioral_max_window_sec: 60,
            behavioral_max_tracked_entities: 100,
            block_ip: false,
            kill_process: false,
            quarantine: false,
            rule_bundle_path: tmp.path().join("bundle.msgpack"),
            offline_queue_path: tmp.path().join("queue.db"),
            quarantine_dir: tmp.path().join("quarantine"),
        }
    }

    fn bundle_with_string_ioc(value: &str) -> RuleBundle {
        let mut b = RuleBundle {
            version: 1,
            ..Default::default()
        };
        b.iocs.strings.push(StringIoc {
            id: "test-ioc".into(),
            value: value.into(),
            kind: "path".into(),
            severity: SEV_HIGH.into(),
            description: "unit test IOC".into(),
        });
        b
    }

    #[tokio::test]
    async fn test_module_lifecycle_starts_and_stops() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let agent_config = AgentConfig {
            modules: ModulesConfig {
                local_detection: cfg,
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, _server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let handle = LocalDetectionModule::start(&agent_config, bus, signal);
        assert_eq!(handle.name, "local_detection");

        tokio::time::sleep(Duration::from_millis(50)).await;
        controller.shutdown();

        tokio::time::timeout(Duration::from_secs(2), handle.task)
            .await
            .expect("LDE task did not stop within 2s")
            .expect("join error")
            .expect("LDE run returned Err");
    }

    #[tokio::test]
    async fn test_string_ioc_match_publishes_alert() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let bundle = bundle_with_string_ioc("/tmp/suspicious.exe");
        bundle.save(&cfg.rule_bundle_path).unwrap();

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();
        let fim_event = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/tmp/suspicious.exe".into(),
                syscheck_payload: None,
            },
        );
        handle_event(&pipeline, &bus, &fim_event).await;

        let ev = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected an LDE alert")
            .expect("server_rx closed");
        match ev.kind {
            EventKind::LocalDetectionAlert {
                rule_id, rule_type, ..
            } => {
                assert_eq!(rule_id, "test-ioc");
                assert_eq!(rule_type, "string");
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_log_event_does_not_trigger_yara_scan() {
        // Regression — YARA must only scan FIM file-created/modified
        // events, not logcollector payloads that happen to look like
        // paths.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let bundle = RuleBundle::default();
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();
        let log_event = Event::new(
            "logcollector",
            Priority::Normal,
            EventKind::LogCollected {
                source: "sshd".into(),
                message: "login".into(),
                format: "syslog".into(),
            },
        );
        handle_event(&pipeline, &bus, &log_event).await;
        let maybe = tokio::time::timeout(Duration::from_millis(100), server_rx.recv()).await;
        assert!(maybe.is_err(), "no alerts expected on benign log");
    }

    #[tokio::test]
    async fn test_behavioral_threshold_produces_alert() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle::default();
        bundle.behavioral.push(BehavioralRule {
            id: "brute-ssh".into(),
            severity: SEV_MEDIUM.into(),
            description: "ssh brute".into(),
            event_source: "logcollector".into(),
            kind: BehavioralRuleKind::Threshold {
                contains: "auth failure".into(),
                min_count: 2,
                window_secs: 60,
            },
        });

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();

        for _ in 0..2 {
            let ev = Event::new(
                "logcollector",
                Priority::Normal,
                EventKind::LogCollected {
                    source: "sshd".into(),
                    message: "sshd: auth failure for root".into(),
                    format: "syslog".into(),
                },
            );
            handle_event(&pipeline, &bus, &ev).await;
        }

        let ev = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected behavioural alert")
            .expect("server_rx closed");
        match ev.kind {
            EventKind::LocalDetectionAlert { rule_type, .. } => {
                assert_eq!(rule_type, "behavioral");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_pipeline_with_empty_bundle_builds() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let pipeline = DetectionPipeline::new(&cfg, RuleBundle::default()).unwrap();
        assert_eq!(pipeline.iocs.rule_count(), 0);
        assert!(!pipeline.yara.has_rules());
        assert_eq!(pipeline.bundle_version, 0);
    }

    #[test]
    fn test_load_initial_bundle_missing_is_empty() {
        let b = load_initial_bundle(std::path::Path::new("/nonexistent"));
        assert_eq!(b.version, 0);
        assert!(b.iocs.strings.is_empty());
    }

    #[test]
    fn test_local_alert_from_yara_uses_file_path() {
        let alert = LocalAlert::from_yara(
            std::path::Path::new("/tmp/x.bin"),
            YaraMatch {
                rule_id: "R".into(),
                tags: vec![],
            },
            SEV_HIGH,
        );
        assert_eq!(alert.matched_value, "/tmp/x.bin");
        assert_eq!(alert.rule_type, "yara");
        assert_eq!(alert.severity, SEV_HIGH);
    }

    #[test]
    fn test_extract_sha256_from_syscheck_top_level() {
        let payload = serde_json::json!({ "sha256": "A".repeat(64) }).to_string();
        let got = extract_sha256_from_syscheck(Some(&payload)).unwrap();
        assert_eq!(got.len(), 64);
        assert!(got.chars().all(|c| c == 'a'));
    }

    #[test]
    fn test_extract_sha256_from_syscheck_nested() {
        let payload = serde_json::json!({
            "type": "event",
            "data": { "path": "/etc/passwd", "hash_sha256": "b".repeat(64) }
        })
        .to_string();
        let got = extract_sha256_from_syscheck(Some(&payload)).unwrap();
        assert_eq!(got, "b".repeat(64));
    }

    #[test]
    fn test_extract_sha256_rejects_wrong_length_or_garbage() {
        assert!(extract_sha256_from_syscheck(None).is_none());
        assert!(extract_sha256_from_syscheck(Some("not json")).is_none());
        let short = serde_json::json!({ "sha256": "abc" }).to_string();
        assert!(extract_sha256_from_syscheck(Some(&short)).is_none());
        let non_hex = serde_json::json!({ "sha256": "z".repeat(64) }).to_string();
        assert!(extract_sha256_from_syscheck(Some(&non_hex)).is_none());
    }

    #[test]
    fn test_extract_ipv4s_finds_all_dotted_quads() {
        let msg = "sshd: failed login from 203.0.113.9 port 22 (also seen via proxy 198.51.100.4)";
        let found = extract_ipv4s(msg);
        assert_eq!(found, vec!["203.0.113.9", "198.51.100.4"]);
    }

    #[test]
    fn test_extract_ipv4s_rejects_invalid_octets_and_malformed() {
        // 256 is out of range, 1.2.3 is too short, 1.2.3.4.5 has a trailing group.
        let msg = "bad 256.0.0.1 short 1.2.3 ok 10.0.0.1 trailing 1.2.3.4.5";
        let found = extract_ipv4s(msg);
        assert_eq!(found, vec!["10.0.0.1"]);
    }

    #[tokio::test]
    async fn test_hash_ioc_match_via_syscheck_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle {
            version: 1,
            ..Default::default()
        };
        let bad_hash = "c".repeat(64);
        bundle.iocs.hashes.push(HashIoc {
            id: "bad-file".into(),
            sha256: bad_hash.clone(),
            severity: SEV_HIGH.into(),
            description: "known-bad".into(),
        });

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();

        let payload = serde_json::json!({
            "type": "event",
            "data": { "path": "/tmp/clean-path", "sha256": bad_hash }
        })
        .to_string();
        let ev = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/tmp/clean-path".into(),
                syscheck_payload: Some(payload),
            },
        );
        handle_event(&pipeline, &bus, &ev).await;

        let alert = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected hash IOC alert")
            .expect("server_rx closed");
        match alert.kind {
            EventKind::LocalDetectionAlert {
                rule_type, rule_id, ..
            } => {
                assert_eq!(rule_type, "hash");
                assert_eq!(rule_id, "bad-file");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_ip_ioc_match_via_log_message() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle {
            version: 1,
            ..Default::default()
        };
        bundle.iocs.ips.push(IpIoc {
            id: "c2".into(),
            ip: "203.0.113.9".into(),
            severity: SEV_MEDIUM.into(),
            description: "known C2".into(),
        });

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();

        let ev = Event::new(
            "logcollector",
            Priority::Normal,
            EventKind::LogCollected {
                source: "sshd".into(),
                message: "Accepted publickey for root from 203.0.113.9 port 22".into(),
                format: "syslog".into(),
            },
        );
        handle_event(&pipeline, &bus, &ev).await;

        let alert = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected IP IOC alert")
            .expect("server_rx closed");
        match alert.kind {
            EventKind::LocalDetectionAlert {
                rule_type, rule_id, ..
            } => {
                assert_eq!(rule_type, "ip");
                assert_eq!(rule_id, "c2");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_hash_and_ip_ioc_build_ok() {
        // Ensure hash/IP bloom construction exercises the whole code path.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle::default();
        bundle.iocs.hashes.push(HashIoc {
            id: "h".into(),
            sha256: "a".repeat(64),
            severity: SEV_HIGH.into(),
            description: "".into(),
        });
        bundle.iocs.ips.push(IpIoc {
            id: "i".into(),
            ip: "203.0.113.9".into(),
            severity: SEV_MEDIUM.into(),
            description: "".into(),
        });
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();
        assert_eq!(pipeline.iocs.rule_count(), 2);
    }
}
