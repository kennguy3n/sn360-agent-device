//! SQLite-backed FIM state store.
//!
//! Tracks file metadata (hash, size, permissions, ownership, timestamps)
//! to detect changes between observations.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

/// A single FIM state entry representing a monitored file's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FimEntry {
    pub path: String,
    pub sha256: Option<String>,
    pub size: i64,
    pub permissions: i64,
    pub uid: i64,
    pub gid: i64,
    pub mtime: i64,
    pub inode: i64,
    pub last_scan: String,
}

/// SQLite-backed state database for FIM.
pub struct StateDb {
    conn: Connection,
}

impl StateDb {
    /// Open (or create) the FIM state database at the given path.
    ///
    /// Uses WAL journal mode for concurrent read/write performance.
    /// Pass `":memory:"` for an in-memory database (useful for tests).
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        // Ensure parent directory exists for on-disk databases.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS fim_state (
                path        TEXT PRIMARY KEY,
                sha256      TEXT,
                size        INTEGER NOT NULL DEFAULT 0,
                permissions INTEGER NOT NULL DEFAULT 0,
                uid         INTEGER NOT NULL DEFAULT 0,
                gid         INTEGER NOT NULL DEFAULT 0,
                mtime       INTEGER NOT NULL DEFAULT 0,
                inode       INTEGER NOT NULL DEFAULT 0,
                last_scan   TEXT NOT NULL DEFAULT ''
            );",
        )?;

        Ok(Self { conn })
    }

    /// Open an in-memory database (convenience for tests).
    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::open(Path::new(":memory:"))
    }

    /// Look up a single entry by path.
    pub fn get_entry(&self, path: &str) -> anyhow::Result<Option<FimEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, size, permissions, uid, gid, mtime, inode, last_scan
             FROM fim_state WHERE path = ?1",
        )?;

        let entry = stmt
            .query_row(params![path], |row| {
                Ok(FimEntry {
                    path: row.get(0)?,
                    sha256: row.get(1)?,
                    size: row.get(2)?,
                    permissions: row.get(3)?,
                    uid: row.get(4)?,
                    gid: row.get(5)?,
                    mtime: row.get(6)?,
                    inode: row.get(7)?,
                    last_scan: row.get(8)?,
                })
            })
            .optional()?;

        Ok(entry)
    }

    /// Insert or update an entry.
    pub fn upsert_entry(&self, entry: &FimEntry) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO fim_state (path, sha256, size, permissions, uid, gid, mtime, inode, last_scan)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(path) DO UPDATE SET
                sha256 = excluded.sha256,
                size = excluded.size,
                permissions = excluded.permissions,
                uid = excluded.uid,
                gid = excluded.gid,
                mtime = excluded.mtime,
                inode = excluded.inode,
                last_scan = excluded.last_scan",
            params![
                entry.path,
                entry.sha256,
                entry.size,
                entry.permissions,
                entry.uid,
                entry.gid,
                entry.mtime,
                entry.inode,
                entry.last_scan,
            ],
        )?;
        Ok(())
    }

    /// Delete an entry by path.
    pub fn delete_entry(&self, path: &str) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM fim_state WHERE path = ?1", params![path])?;
        Ok(())
    }

    /// Retrieve all stored entries.
    pub fn get_all_entries(&self) -> anyhow::Result<Vec<FimEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, size, permissions, uid, gid, mtime, inode, last_scan
             FROM fim_state ORDER BY path",
        )?;

        let entries = stmt
            .query_map([], |row| {
                Ok(FimEntry {
                    path: row.get(0)?,
                    sha256: row.get(1)?,
                    size: row.get(2)?,
                    permissions: row.get(3)?,
                    uid: row.get(4)?,
                    gid: row.get(5)?,
                    mtime: row.get(6)?,
                    inode: row.get(7)?,
                    last_scan: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Return the path where the database is stored (if on-disk).
    pub fn path(&self) -> Option<PathBuf> {
        self.conn.path().map(|p| PathBuf::from(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(path: &str) -> FimEntry {
        FimEntry {
            path: path.to_string(),
            sha256: Some("abcdef1234567890".to_string()),
            size: 1024,
            permissions: 0o644,
            uid: 1000,
            gid: 1000,
            mtime: 1700000000,
            inode: 12345,
            last_scan: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_open_in_memory() {
        let db = StateDb::open_in_memory();
        assert!(db.is_ok());
    }

    #[test]
    fn test_insert_and_get() {
        let db = StateDb::open_in_memory().unwrap();
        let entry = sample_entry("/etc/passwd");

        db.upsert_entry(&entry).unwrap();
        let fetched = db.get_entry("/etc/passwd").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap(), entry);
    }

    #[test]
    fn test_get_nonexistent() {
        let db = StateDb::open_in_memory().unwrap();
        let fetched = db.get_entry("/no/such/file").unwrap();
        assert!(fetched.is_none());
    }

    #[test]
    fn test_upsert_updates_existing() {
        let db = StateDb::open_in_memory().unwrap();
        let mut entry = sample_entry("/etc/passwd");
        db.upsert_entry(&entry).unwrap();

        entry.sha256 = Some("new_hash_value".to_string());
        entry.size = 2048;
        db.upsert_entry(&entry).unwrap();

        let fetched = db.get_entry("/etc/passwd").unwrap().unwrap();
        assert_eq!(fetched.sha256.as_deref(), Some("new_hash_value"));
        assert_eq!(fetched.size, 2048);
    }

    #[test]
    fn test_delete() {
        let db = StateDb::open_in_memory().unwrap();
        let entry = sample_entry("/etc/passwd");
        db.upsert_entry(&entry).unwrap();

        db.delete_entry("/etc/passwd").unwrap();
        let fetched = db.get_entry("/etc/passwd").unwrap();
        assert!(fetched.is_none());
    }

    #[test]
    fn test_get_all_entries() {
        let db = StateDb::open_in_memory().unwrap();
        db.upsert_entry(&sample_entry("/a")).unwrap();
        db.upsert_entry(&sample_entry("/b")).unwrap();
        db.upsert_entry(&sample_entry("/c")).unwrap();

        let all = db.get_all_entries().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].path, "/a");
        assert_eq!(all[1].path, "/b");
        assert_eq!(all[2].path, "/c");
    }

    #[test]
    fn test_entry_with_null_sha256() {
        let db = StateDb::open_in_memory().unwrap();
        let entry = FimEntry {
            path: "/tmp/nosha".to_string(),
            sha256: None,
            size: 0,
            permissions: 0,
            uid: 0,
            gid: 0,
            mtime: 0,
            inode: 0,
            last_scan: String::new(),
        };
        db.upsert_entry(&entry).unwrap();
        let fetched = db.get_entry("/tmp/nosha").unwrap().unwrap();
        assert_eq!(fetched.sha256, None);
    }
}
