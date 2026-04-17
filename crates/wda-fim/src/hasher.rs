//! File hashing using SHA-256.
//!
//! Designed to be called via `tokio::task::spawn_blocking` since it
//! performs blocking file I/O.

use std::path::Path;

use sha2::{Digest, Sha256};

/// Read a file and return its hex-encoded SHA-256 hash.
///
/// This function performs blocking I/O and should be called from
/// a blocking context (e.g., `tokio::task::spawn_blocking`).
pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_known_content() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        let hash = hash_file(f.path()).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hash_empty_file() {
        let f = NamedTempFile::new().unwrap();
        let hash = hash_file(f.path()).unwrap();
        // SHA-256 of empty input
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_nonexistent_file() {
        let result = hash_file(Path::new("/nonexistent/file/path"));
        assert!(result.is_err());
    }
}
