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
    let (source_tag, entity, primary_text, fim_path): (&str, String, String, Option<PathBuf>) =
        match &event.kind {
            EventKind::FileCreated { path, .. } | EventKind::FileModified { path, .. } => {
                ("fim", path.clone(), path.clone(), Some(PathBuf::from(path)))
            }
            EventKind::FileDeleted { path, .. } | EventKind::FileMetadataChanged { path, .. } => {
                ("fim", path.clone(), path.clone(), None)
            }
            EventKind::LogCollected {
                source, message, ..
            } => ("logcollector", source.clone(), message.clone(), None),
            // The LDE only observes FIM and logcollector streams; other
            // event kinds pass through untouched.
            _ => return,
        };

    // --- IOC matching ---
    let ioc_hits = pipeline.iocs.matches(&[&primary_text], None, None);
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
        let mut b = RuleBundle::default();
        b.version = 1;
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
        let mut agent_config = AgentConfig::default();
        agent_config.modules = ModulesConfig {
            local_detection: cfg,
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
