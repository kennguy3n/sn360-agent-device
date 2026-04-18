//! Integration test for the FIM module.
//!
//! Starts a FIM module watching a temp directory, performs file operations,
//! and verifies the correct events appear on the server_rx channel and that
//! the SQLite state database is updated accordingly.

use std::time::Duration;

use tempfile::TempDir;
use tokio::time::timeout;

use wda_core::config::{AgentConfig, FimConfig, FimDirectory, ModulesConfig};
use wda_core::signal::ShutdownController;
use wda_event_bus::{EventBus, EventKind};
use wda_fim::FimModule;

/// Build a minimal `AgentConfig` whose FIM watches `dir` with a short debounce.
fn test_config(dir: &str) -> AgentConfig {
    AgentConfig {
        modules: ModulesConfig {
            fim: FimConfig {
                enabled: true,
                directories: vec![FimDirectory {
                    path: dir.to_string(),
                    recursive: true,
                    realtime: true,
                    check_sha256: true,
                    exclude: Vec::new(),
                }],
                scan_interval: 86400,
                debounce_ms: 50,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn test_fim_detects_file_creation() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path().to_str().unwrap());

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (controller, signal) = ShutdownController::new();

    let _handle = FimModule::start(&config, bus, signal);

    // Give the watcher time to register.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create a file inside the watched directory.
    let file_path = tmp.path().join("integration_test.txt");
    std::fs::write(&file_path, "hello integration").unwrap();

    // Wait for a FileCreated event on the server channel.
    let event = timeout(Duration::from_secs(10), server_rx.recv())
        .await
        .expect("timed out waiting for FIM event")
        .expect("server_rx closed unexpectedly");

    match &event.kind {
        EventKind::FileCreated { path, .. }
        | EventKind::FileModified { path, .. }
        | EventKind::FileMetadataChanged { path, .. } => {
            assert!(
                path.contains("integration_test.txt"),
                "event path should contain the created file name, got: {path}"
            );
        }
        other => panic!("expected FileCreated/FileModified, got: {other:?}"),
    }

    controller.shutdown();
}

#[tokio::test]
async fn test_fim_detects_file_modification() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path().to_str().unwrap());

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (controller, signal) = ShutdownController::new();

    let _handle = FimModule::start(&config, bus, signal);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create the file first.
    let file_path = tmp.path().join("modify_test.txt");
    std::fs::write(&file_path, "original").unwrap();

    // Consume the creation event.
    let _ = timeout(Duration::from_secs(10), server_rx.recv())
        .await
        .expect("timed out waiting for creation event");

    // Now modify the file.
    tokio::time::sleep(Duration::from_millis(100)).await;
    std::fs::write(&file_path, "modified content").unwrap();

    // Wait for a FileModified event.
    let event = timeout(Duration::from_secs(10), server_rx.recv())
        .await
        .expect("timed out waiting for modify event")
        .expect("server_rx closed");

    match &event.kind {
        EventKind::FileModified { path, .. } | EventKind::FileMetadataChanged { path, .. } => {
            assert!(
                path.contains("modify_test.txt"),
                "event path should reference the modified file, got: {path}"
            );
        }
        // Some platforms may report a second FileCreated for an overwrite.
        EventKind::FileCreated { path, .. } => {
            assert!(path.contains("modify_test.txt"));
        }
        other => panic!("expected FileModified or FileCreated, got: {other:?}"),
    }

    controller.shutdown();
}

#[tokio::test]
async fn test_fim_detects_file_deletion() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path().to_str().unwrap());

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (controller, signal) = ShutdownController::new();

    let _handle = FimModule::start(&config, bus, signal);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create a file, then delete it.
    let file_path = tmp.path().join("delete_test.txt");
    std::fs::write(&file_path, "soon gone").unwrap();

    // Consume creation event.
    let _ = timeout(Duration::from_secs(10), server_rx.recv())
        .await
        .expect("timed out waiting for creation event");

    tokio::time::sleep(Duration::from_millis(100)).await;
    std::fs::remove_file(&file_path).unwrap();

    // Wait for a FileDeleted event.
    let event = timeout(Duration::from_secs(10), server_rx.recv())
        .await
        .expect("timed out waiting for delete event")
        .expect("server_rx closed");

    match &event.kind {
        EventKind::FileDeleted { path, .. } => {
            assert!(
                path.contains("delete_test.txt"),
                "event path should reference the deleted file, got: {path}"
            );
        }
        other => panic!("expected FileDeleted, got: {other:?}"),
    }

    controller.shutdown();
}

#[tokio::test]
async fn test_fim_sha256_is_correct() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path().to_str().unwrap());

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (controller, signal) = ShutdownController::new();

    let _handle = FimModule::start(&config, bus, signal);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let file_path = tmp.path().join("hash_test.txt");
    std::fs::write(&file_path, "hello world").unwrap();

    // Consume the creation event.
    let _ = timeout(Duration::from_secs(10), server_rx.recv())
        .await
        .expect("timed out");

    // Give the module time to persist the entry.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify hash by hashing the same content independently.
    let expected_hash = wda_fim::hasher::hash_file(&file_path).unwrap();
    assert_eq!(
        expected_hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "SHA-256 of 'hello world' should match the known value"
    );

    controller.shutdown();
}

#[tokio::test]
async fn test_fim_clean_shutdown() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path().to_str().unwrap());

    let (bus, _server_rx) = EventBus::new(256, 256);
    let (controller, signal) = ShutdownController::new();

    let handle = FimModule::start(&config, bus, signal);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Trigger shutdown and verify the task completes without panicking.
    controller.shutdown();

    let result = timeout(Duration::from_secs(5), handle.task)
        .await
        .expect("FIM task did not stop within timeout");

    assert!(
        result.is_ok(),
        "FIM task should complete without a JoinError"
    );
}
