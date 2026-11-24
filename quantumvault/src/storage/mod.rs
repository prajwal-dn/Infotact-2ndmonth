//! Atomic metadata persistence primitives for QuantumVault.
//!
//! This module provides an atomic file-replacement helper. It does not
//! implement encrypted storage, key serialization, or rollback protection.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const MAX_TEMP_ATTEMPTS: usize = 32;

/// Checks that a metadata filename is a single normal path component.
fn validate_filename(filename: &str) -> io::Result<()> {
    let path = Path::new(filename);
    let mut components = path.components();

    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) if name == filename && !filename.is_empty() => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "metadata filename must be a single normal path component",
        )),
    }
}

/// Creates a new temporary file with restrictive permissions.
fn create_temp_file(directory: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);

        let name = format!(".quantumvault-{}-{}.tmp", std::process::id(), counter);

        let path = directory.join(name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        options.mode(0o600);

        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique metadata temporary file",
    ))
}

/// Atomically replaces a metadata file.
///
/// The temporary file is created in the target directory so that rename
/// remains on the same filesystem. The file is synced before rename, and
/// the parent directory is synced after rename.
///
/// The caller must ensure the directory is trusted and appropriately
/// permissioned. This function does not provide rollback protection.
pub fn atomic_write(directory: &Path, filename: &str, contents: &[u8]) -> io::Result<()> {
    validate_filename(filename)?;

    if !directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "metadata directory does not exist",
        ));
    }

    let (temp_path, mut temp_file) = create_temp_file(directory)?;

    let write_result = (|| {
        temp_file.write_all(contents)?;
        temp_file.sync_all()?;
        drop(temp_file);

        let destination = directory.join(filename);
        fs::rename(&temp_path, &destination)?;

        // Persist the directory entry update where supported.
        File::open(directory)?.sync_all()?;

        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    write_result
}

#[cfg(test)]
mod tests {
    use super::atomic_write;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_directory() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quantumvault-storage-test-{}-{}",
            std::process::id(),
            counter
        ));

        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn atomic_write_creates_metadata_file() {
        let directory = test_directory();

        atomic_write(&directory, "vault.meta", b"test metadata").unwrap();

        let contents = fs::read(directory.join("vault.meta")).unwrap();
        assert_eq!(contents, b"test metadata");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_write_replaces_existing_file() {
        let directory = test_directory();

        atomic_write(&directory, "vault.meta", b"old value").unwrap();
        atomic_write(&directory, "vault.meta", b"new value").unwrap();

        let contents = fs::read(directory.join("vault.meta")).unwrap();
        assert_eq!(contents, b"new value");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_write_rejects_path_traversal() {
        let directory = test_directory();

        let result = atomic_write(&directory, "../outside.meta", b"data");

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_creates_file_with_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = test_directory();

        atomic_write(&directory, "vault.meta", b"secret metadata").unwrap();

        let metadata = fs::metadata(directory.join("vault.meta")).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);

        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn atomic_write_rejects_trailing_separator() {
        let directory = test_directory();

        let result = atomic_write(&directory, "vault.meta/", b"data");

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_write_rejects_missing_directory() {
        let directory = test_directory();
        let missing = directory.join("missing");

        let result = atomic_write(&missing, "vault.meta", b"data");

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);

        fs::remove_dir_all(directory).unwrap();
    }
}
