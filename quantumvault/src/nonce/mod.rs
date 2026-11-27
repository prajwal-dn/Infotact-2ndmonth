//! Persistent AES-256-GCM nonce allocation and crash-safe state management.
//!
//! Each AES-GCM encryption key/domain maintains an independent persisted
//! counter state file (`.qvnc`). Nonces are 96 bits constructed as:
//! `nonce_prefix (4 bytes) || counter (8 bytes big-endian)`.
//!
//! Reservations are persisted atomically via `storage::atomic_write` before
//! any nonce is returned for encryption. If a crash or I/O error occurs
//! during or after persistence, the allocator fails closed and reloading from
//! disk advances from the last durably persisted counter (wasting at most the
//! in-flight reservation rather than risking nonce reuse).
//!
//! # Limitations
//!
//! Local durable counter persistence does NOT protect against full
//! backing-store rollback (e.g., restoring an older filesystem snapshot).
//! Rollback detection requires a trusted external anchor.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::key_manager::AES_GCM_NONCE_LEN;
use crate::storage;

pub const NONCE_STATE_MAGIC: &[u8; 4] = b"QVNC";
pub const NONCE_STATE_VERSION: u16 = 1;
pub const NONCE_PREFIX_LEN: usize = 4;
pub const NONCE_COUNTER_LEN: usize = 8;
pub const NONCE_CHECKSUM_LEN: usize = 32;
pub const NONCE_STATE_BODY_SIZE: usize = 51;
pub const NONCE_STATE_RECORD_SIZE: usize = NONCE_STATE_BODY_SIZE + NONCE_CHECKSUM_LEN; // 83 bytes

/// Independent nonce allocation domains to prevent cross-purpose collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NonceDomain {
    /// Nonces used with the HKDF-derived DEK-wrapping key.
    DekWrapping = 1,
    /// Nonces used with a per-file Data Encryption Key (DEK) for file chunks.
    FileChunk = 2,
}

impl NonceDomain {
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(value: u8) -> Result<Self, NonceError> {
        match value {
            1 => Ok(Self::DekWrapping),
            2 => Ok(Self::FileChunk),
            _ => Err(NonceError::InvalidDomain),
        }
    }
}

/// A 96-bit AES-GCM nonce and its corresponding monotonic counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatedNonce {
    pub prefix: [u8; NONCE_PREFIX_LEN],
    pub counter: u64,
    pub bytes: [u8; AES_GCM_NONCE_LEN],
}

impl AllocatedNonce {
    /// Constructs a 96-bit nonce from a 32-bit prefix and 64-bit counter.
    pub fn from_parts(prefix: [u8; NONCE_PREFIX_LEN], counter: u64) -> Self {
        let mut bytes = [0_u8; AES_GCM_NONCE_LEN];
        bytes[..NONCE_PREFIX_LEN].copy_from_slice(&prefix);
        bytes[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
        Self {
            prefix,
            counter,
            bytes,
        }
    }
}

/// A contiguous range of durably reserved AES-GCM nonces `[start_counter, start_counter + count)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatedNonceRange {
    pub prefix: [u8; NONCE_PREFIX_LEN],
    pub start_counter: u64,
    pub count: u64,
}

impl AllocatedNonceRange {
    /// Returns the 96-bit nonce at `offset` within this reserved range.
    pub fn nonce_at(&self, offset: u64) -> Result<AllocatedNonce, NonceError> {
        if offset >= self.count {
            return Err(NonceError::InvalidAllocationCount);
        }
        let counter = self
            .start_counter
            .checked_add(offset)
            .ok_or(NonceError::CounterOverflow)?;
        Ok(AllocatedNonce::from_parts(self.prefix, counter))
    }
}

/// Persisted nonce counter metadata for a single key identity and domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceState {
    pub version: u16,
    pub domain: NonceDomain,
    pub vault_id: [u8; 16],
    pub key_id: [u8; 16],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub next_counter: u64,
}

impl NonceState {
    /// Computes the SHA-256 integrity checksum over the 51-byte metadata body.
    fn compute_checksum(body: &[u8]) -> [u8; NONCE_CHECKSUM_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let digest = hasher.finalize();
        let mut out = [0_u8; NONCE_CHECKSUM_LEN];
        out.copy_from_slice(&digest);
        out
    }

    /// Serializes the nonce state into a fixed 83-byte versioned binary record.
    ///
    /// Layout:
    /// - `[0..4]`   Magic: `b"QVNC"`
    /// - `[4..6]`   Version: `u16` (big-endian)
    /// - `[6..7]`   Domain: `u8` (`1 = DekWrapping`, `2 = FileChunk`)
    /// - `[7..23]`  Vault ID: 16 bytes
    /// - `[23..39]` Key ID: 16 bytes
    /// - `[39..43]` Nonce prefix: 4 bytes
    /// - `[43..51]` Next counter: `u64` (big-endian)
    /// - `[51..83]` SHA-256 checksum over `[0..51]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_STATE_RECORD_SIZE);
        bytes.extend_from_slice(NONCE_STATE_MAGIC);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.push(self.domain.to_byte());
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.key_id);
        bytes.extend_from_slice(&self.nonce_prefix);
        bytes.extend_from_slice(&self.next_counter.to_be_bytes());

        let checksum = Self::compute_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    /// Deserializes and strictly validates a persisted nonce state record.
    /// Never panics on malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NonceError> {
        if bytes.len() < NONCE_STATE_RECORD_SIZE {
            return Err(NonceError::TruncatedMetadata);
        }
        if bytes.len() > NONCE_STATE_RECORD_SIZE {
            return Err(NonceError::CorruptedMetadata);
        }

        if &bytes[0..4] != NONCE_STATE_MAGIC {
            return Err(NonceError::InvalidMagic);
        }

        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != NONCE_STATE_VERSION {
            return Err(NonceError::UnsupportedVersion);
        }

        let domain = NonceDomain::from_byte(bytes[6])?;

        let expected_checksum = Self::compute_checksum(&bytes[0..NONCE_STATE_BODY_SIZE]);
        if bytes[NONCE_STATE_BODY_SIZE..NONCE_STATE_RECORD_SIZE] != expected_checksum {
            return Err(NonceError::CorruptedMetadata);
        }

        let mut vault_id = [0_u8; 16];
        vault_id.copy_from_slice(&bytes[7..23]);

        let mut key_id = [0_u8; 16];
        key_id.copy_from_slice(&bytes[23..39]);

        let mut nonce_prefix = [0_u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&bytes[39..43]);

        let mut counter_bytes = [0_u8; NONCE_COUNTER_LEN];
        counter_bytes.copy_from_slice(&bytes[43..51]);
        let next_counter = u64::from_be_bytes(counter_bytes);

        Ok(Self {
            version,
            domain,
            vault_id,
            key_id,
            nonce_prefix,
            next_counter,
        })
    }
}

/// Checks that a nonce metadata filename is a single normal path component.
fn validate_filename(filename: &str) -> Result<(), NonceError> {
    let path = Path::new(filename);
    let mut components = path.components();

    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) if name == filename && !filename.is_empty() => Ok(()),
        _ => Err(NonceError::InvalidFilename),
    }
}

/// RAII guard for an exclusive cross-process file lock on `<filename>.lock`.
pub struct FileLockGuard {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    _marker: (),
}

#[cfg(unix)]
impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // SAFETY: `self.file` is an open file descriptor owned by this guard.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn acquire_file_lock(directory: &Path, filename: &str) -> io::Result<FileLockGuard> {
    if !directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "nonce metadata directory does not exist",
        ));
    }
    let lock_path = directory.join(format!("{}.lock", filename));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;

    loop {
        // SAFETY: `file.as_raw_fd()` is a valid open file descriptor.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc == 0 {
            return Ok(FileLockGuard { file });
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// Non-Unix fallback: no OS-level file lock is acquired.
/// Multiprocess and multi-instance concurrency safety is NOT provided on non-Unix targets.
#[cfg(not(unix))]
fn acquire_file_lock(_directory: &Path, _filename: &str) -> io::Result<FileLockGuard> {
    Ok(FileLockGuard { _marker: () })
}

/// Storage abstraction for atomic nonce metadata persistence and locking.
///
/// The default production implementation delegates to `storage::atomic_write`
/// and OS-level `flock(LOCK_EX)` advisory file locking.
/// Abstracted as a trait to support deterministic failure injection in tests
/// without altering production persistence semantics.
pub trait NoncePersistence: Send + Sync {
    fn acquire_lock(&self, directory: &Path, filename: &str) -> io::Result<FileLockGuard>;
    fn write_atomic(&self, directory: &Path, filename: &str, contents: &[u8]) -> io::Result<()>;
    fn read_file(&self, directory: &Path, filename: &str) -> io::Result<Vec<u8>>;
    fn exists(&self, directory: &Path, filename: &str) -> bool;
}

/// Production persistence backend backed by `crate::storage::atomic_write`
/// and `flock(LOCK_EX)` cross-process locking.
#[derive(Debug, Default, Clone, Copy)]
pub struct AtomicFilePersistence;

impl NoncePersistence for AtomicFilePersistence {
    fn acquire_lock(&self, directory: &Path, filename: &str) -> io::Result<FileLockGuard> {
        acquire_file_lock(directory, filename)
    }

    fn write_atomic(&self, directory: &Path, filename: &str, contents: &[u8]) -> io::Result<()> {
        storage::atomic_write(directory, filename, contents)
    }

    fn read_file(&self, directory: &Path, filename: &str) -> io::Result<Vec<u8>> {
        fs::read(directory.join(filename))
    }

    fn exists(&self, directory: &Path, filename: &str) -> bool {
        directory.join(filename).exists()
    }
}

struct AllocatorInner {
    state: NonceState,
    tainted: bool,
}

/// Thread-safe, crash-safe persistent AES-256-GCM nonce allocator.
///
/// Every allocation persists the incremented `next_counter` durably before
/// returning the reserved nonce. If persistence fails, the allocator transitions
/// to a tainted fail-closed state and refuses further allocations until
/// reopened from verified disk state.
pub struct NonceAllocator<P: NoncePersistence = AtomicFilePersistence> {
    directory: PathBuf,
    filename: String,
    persistence: P,
    inner: Mutex<AllocatorInner>,
}

impl NonceAllocator<AtomicFilePersistence> {
    /// Initializes a brand-new nonce state file on disk for the given vault,
    /// key identity, and domain using an OS-generated random 32-bit prefix.
    ///
    /// Fails closed with `NonceError::AlreadyExists` if the target file already
    /// exists, preventing accidental counter reset.
    pub fn init_new(
        directory: &Path,
        filename: &str,
        vault_id: [u8; 16],
        key_id: [u8; 16],
        domain: NonceDomain,
    ) -> Result<Self, NonceError> {
        let mut prefix = [0_u8; NONCE_PREFIX_LEN];
        getrandom::fill(&mut prefix).map_err(NonceError::Random)?;
        Self::init_with_backend(
            directory,
            filename,
            vault_id,
            key_id,
            domain,
            prefix,
            AtomicFilePersistence,
        )
    }

    /// Opens an existing nonce state file from disk and verifies its version,
    /// integrity checksum, domain, vault ID, and key ID.
    ///
    /// Fails closed if the file is missing, truncated, corrupted, or mismatched.
    pub fn open(
        directory: &Path,
        filename: &str,
        expected_vault_id: &[u8; 16],
        expected_key_id: &[u8; 16],
        expected_domain: NonceDomain,
    ) -> Result<Self, NonceError> {
        Self::open_with_backend(
            directory,
            filename,
            expected_vault_id,
            expected_key_id,
            expected_domain,
            AtomicFilePersistence,
        )
    }
}

impl<P: NoncePersistence> NonceAllocator<P> {
    /// Initializes a new nonce state file using an explicit prefix and storage backend.
    pub fn init_with_backend(
        directory: &Path,
        filename: &str,
        vault_id: [u8; 16],
        key_id: [u8; 16],
        domain: NonceDomain,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        persistence: P,
    ) -> Result<Self, NonceError> {
        validate_filename(filename)?;

        let _file_lock = persistence
            .acquire_lock(directory, filename)
            .map_err(NonceError::Io)?;

        if persistence.exists(directory, filename) {
            return Err(NonceError::AlreadyExists);
        }

        let state = NonceState {
            version: NONCE_STATE_VERSION,
            domain,
            vault_id,
            key_id,
            nonce_prefix,
            next_counter: 0,
        };

        let serialized = state.to_bytes();
        persistence
            .write_atomic(directory, filename, &serialized)
            .map_err(NonceError::Io)?;

        Ok(Self {
            directory: directory.to_path_buf(),
            filename: filename.to_string(),
            persistence,
            inner: Mutex::new(AllocatorInner {
                state,
                tainted: false,
            }),
        })
    }

    /// Opens an existing nonce state file using a custom storage backend.
    pub fn open_with_backend(
        directory: &Path,
        filename: &str,
        expected_vault_id: &[u8; 16],
        expected_key_id: &[u8; 16],
        expected_domain: NonceDomain,
        persistence: P,
    ) -> Result<Self, NonceError> {
        validate_filename(filename)?;

        let _file_lock = persistence
            .acquire_lock(directory, filename)
            .map_err(NonceError::Io)?;

        let bytes = persistence
            .read_file(directory, filename)
            .map_err(NonceError::from)?;
        let state = NonceState::from_bytes(&bytes)?;

        if &state.vault_id != expected_vault_id {
            return Err(NonceError::VaultIdMismatch);
        }
        if &state.key_id != expected_key_id {
            return Err(NonceError::KeyIdMismatch);
        }
        if state.domain != expected_domain {
            return Err(NonceError::DomainMismatch);
        }

        Ok(Self {
            directory: directory.to_path_buf(),
            filename: filename.to_string(),
            persistence,
            inner: Mutex::new(AllocatorInner {
                state,
                tainted: false,
            }),
        })
    }

    /// Durably reserves and returns a single unique 96-bit AES-GCM nonce.
    ///
    /// Persistence completes before the nonce is returned. Concurrent callers
    /// (both across threads and across OS processes) are serialized by the
    /// internal mutex and `flock(LOCK_EX)` file lock so no two callers can
    /// receive the same counter value.
    pub fn allocate_nonce(&self) -> Result<AllocatedNonce, NonceError> {
        let range = self.allocate_range(1)?;
        range.nonce_at(0)
    }

    /// Durably reserves and returns a contiguous range of `count` unique nonces.
    pub fn allocate_range(&self, count: u64) -> Result<AllocatedNonceRange, NonceError> {
        if count == 0 {
            return Err(NonceError::InvalidAllocationCount);
        }

        let mut guard = self.inner.lock().map_err(|_| NonceError::LockPoisoned)?;

        if guard.tainted {
            return Err(NonceError::UntrustedState);
        }

        // Acquire cross-process exclusive lock and re-read latest durable state
        // so independent allocator instances or separate processes cannot use
        // a stale cached counter.
        let _file_lock = self
            .persistence
            .acquire_lock(&self.directory, &self.filename)
            .map_err(NonceError::Io)?;

        let disk_bytes = self
            .persistence
            .read_file(&self.directory, &self.filename)
            .map_err(NonceError::from)?;
        let disk_state = NonceState::from_bytes(&disk_bytes)?;

        if disk_state.vault_id != guard.state.vault_id {
            guard.tainted = true;
            return Err(NonceError::VaultIdMismatch);
        }
        if disk_state.key_id != guard.state.key_id {
            guard.tainted = true;
            return Err(NonceError::KeyIdMismatch);
        }
        if disk_state.domain != guard.state.domain {
            guard.tainted = true;
            return Err(NonceError::DomainMismatch);
        }
        if disk_state.nonce_prefix != guard.state.nonce_prefix {
            guard.tainted = true;
            return Err(NonceError::CorruptedMetadata);
        }
        if disk_state.next_counter < guard.state.next_counter {
            guard.tainted = true;
            return Err(NonceError::RollbackDetected);
        }

        let start_counter = disk_state.next_counter;
        let new_next_counter = start_counter
            .checked_add(count)
            .ok_or(NonceError::CounterOverflow)?;

        let mut candidate = disk_state;
        candidate.next_counter = new_next_counter;
        let serialized = candidate.to_bytes();

        if let Err(err) =
            self.persistence
                .write_atomic(&self.directory, &self.filename, &serialized)
        {
            // Persistence failed (potentially after rename but before directory sync).
            // Fail closed so in-memory state cannot diverge from disk and risk reuse.
            guard.tainted = true;
            return Err(NonceError::Io(err));
        }

        let prefix = candidate.nonce_prefix;
        guard.state = candidate;

        Ok(AllocatedNonceRange {
            prefix,
            start_counter,
            count,
        })
    }

    /// Returns the next counter value that will be allocated (for inspection/diagnostics).
    pub fn next_counter(&self) -> Result<u64, NonceError> {
        let mut guard = self.inner.lock().map_err(|_| NonceError::LockPoisoned)?;
        if guard.tainted {
            return Err(NonceError::UntrustedState);
        }
        let _file_lock = self
            .persistence
            .acquire_lock(&self.directory, &self.filename)
            .map_err(NonceError::Io)?;
        let disk_bytes = self
            .persistence
            .read_file(&self.directory, &self.filename)
            .map_err(NonceError::from)?;
        let disk_state = NonceState::from_bytes(&disk_bytes)?;
        if disk_state.next_counter < guard.state.next_counter {
            guard.tainted = true;
            return Err(NonceError::RollbackDetected);
        }
        guard.state.next_counter = disk_state.next_counter;
        Ok(guard.state.next_counter)
    }

    /// Returns the 32-bit nonce prefix bound to this allocator.
    pub fn nonce_prefix(&self) -> Result<[u8; NONCE_PREFIX_LEN], NonceError> {
        let guard = self.inner.lock().map_err(|_| NonceError::LockPoisoned)?;
        if guard.tainted {
            return Err(NonceError::UntrustedState);
        }
        Ok(guard.state.nonce_prefix)
    }
}

/// Errors returned by persistent nonce allocation and metadata validation.
#[derive(Debug)]
pub enum NonceError {
    InvalidFilename,
    AlreadyExists,
    MissingMetadata,
    TruncatedMetadata,
    CorruptedMetadata,
    InvalidMagic,
    UnsupportedVersion,
    InvalidDomain,
    VaultIdMismatch,
    KeyIdMismatch,
    DomainMismatch,
    CounterOverflow,
    InvalidAllocationCount,
    RollbackDetected,
    UntrustedState,
    LockPoisoned,
    Random(getrandom::Error),
    Io(io::Error),
}

impl From<io::Error> for NonceError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::NotFound {
            Self::MissingMetadata
        } else {
            Self::Io(error)
        }
    }
}

impl fmt::Display for NonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFilename => write!(f, "invalid nonce metadata filename"),
            Self::AlreadyExists => {
                write!(
                    f,
                    "nonce metadata already exists; refusing to reset counter"
                )
            }
            Self::MissingMetadata => write!(f, "nonce metadata file not found"),
            Self::TruncatedMetadata => write!(f, "nonce metadata record is truncated"),
            Self::CorruptedMetadata => write!(f, "nonce metadata failed integrity validation"),
            Self::InvalidMagic => write!(f, "invalid magic bytes in nonce metadata"),
            Self::UnsupportedVersion => write!(f, "unsupported nonce metadata format version"),
            Self::InvalidDomain => write!(f, "unknown nonce domain in metadata"),
            Self::VaultIdMismatch => write!(f, "nonce metadata vault identifier mismatch"),
            Self::KeyIdMismatch => write!(f, "nonce metadata key identifier mismatch"),
            Self::DomainMismatch => write!(f, "nonce metadata domain mismatch"),
            Self::CounterOverflow => write!(f, "nonce counter exhausted (64-bit overflow)"),
            Self::InvalidAllocationCount => write!(f, "invalid nonce allocation count"),
            Self::RollbackDetected => write!(
                f,
                "nonce counter on disk regressed below last observed monotonic value"
            ),
            Self::UntrustedState => {
                write!(f, "nonce allocator is in a tainted fail-closed state")
            }
            Self::LockPoisoned => write!(f, "nonce allocator mutex poisoned"),
            Self::Random(e) => write!(f, "secure random generation failed: {}", e),
            Self::Io(e) => write!(f, "I/O error during nonce persistence: {}", e),
        }
    }
}

impl Error for NonceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread;

    fn test_temp_dir(prefix: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_vault_id() -> [u8; 16] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    fn sample_key_id(tag: u8) -> [u8; 16] {
        [tag; 16]
    }

    /// Fault-injecting persistence wrapper for deterministic crash and I/O failure tests.
    #[derive(Clone)]
    struct FaultInjectingPersistence {
        /// 0 = normal, 1 = fail BEFORE write, 2 = write to disk THEN fail (simulated crash).
        mode: Arc<AtomicUsize>,
    }

    impl FaultInjectingPersistence {
        fn new(mode: usize) -> Self {
            Self {
                mode: Arc::new(AtomicUsize::new(mode)),
            }
        }

        fn set_mode(&self, mode: usize) {
            self.mode.store(mode, Ordering::SeqCst);
        }
    }

    impl NoncePersistence for FaultInjectingPersistence {
        fn acquire_lock(&self, directory: &Path, filename: &str) -> io::Result<FileLockGuard> {
            acquire_file_lock(directory, filename)
        }

        fn write_atomic(
            &self,
            directory: &Path,
            filename: &str,
            contents: &[u8],
        ) -> io::Result<()> {
            match self.mode.load(Ordering::SeqCst) {
                1 => Err(io::Error::other("injected pre-write I/O failure")),
                2 => {
                    // Simulate durable commit reaching disk right before process crash.
                    storage::atomic_write(directory, filename, contents)?;
                    Err(io::Error::other("injected post-persist crash"))
                }
                _ => storage::atomic_write(directory, filename, contents),
            }
        }

        fn read_file(&self, directory: &Path, filename: &str) -> io::Result<Vec<u8>> {
            fs::read(directory.join(filename))
        }

        fn exists(&self, directory: &Path, filename: &str) -> bool {
            directory.join(filename).exists()
        }
    }

    #[test]
    fn first_nonce_allocation_starts_at_zero_and_persists() {
        let dir = test_temp_dir("qv-nonce-first");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xAA);

        let allocator =
            NonceAllocator::init_new(&dir, "file.qvnc", vault_id, key_id, NonceDomain::FileChunk)
                .unwrap();

        assert_eq!(allocator.next_counter().unwrap(), 0);
        let nonce = allocator.allocate_nonce().unwrap();
        assert_eq!(nonce.counter, 0);
        assert_eq!(&nonce.bytes[..4], &nonce.prefix);
        assert_eq!(&nonce.bytes[4..12], &0_u64.to_be_bytes());
        assert_eq!(allocator.next_counter().unwrap(), 1);

        let persisted = NonceState::from_bytes(&fs::read(dir.join("file.qvnc")).unwrap()).unwrap();
        assert_eq!(persisted.next_counter, 1);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sequential_allocation_and_uniqueness_across_many_calls() {
        let dir = test_temp_dir("qv-nonce-seq");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x11);

        let allocator =
            NonceAllocator::init_new(&dir, "seq.qvnc", vault_id, key_id, NonceDomain::DekWrapping)
                .unwrap();

        let mut seen = HashSet::new();
        for expected in 0..25_u64 {
            let n = allocator.allocate_nonce().unwrap();
            assert_eq!(n.counter, expected);
            assert!(seen.insert(n.bytes), "duplicate nonce generated");
        }
        assert_eq!(seen.len(), 25);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persistence_across_allocator_recreation_and_restart() {
        let dir = test_temp_dir("qv-nonce-restart");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x22);

        let prefix = {
            let alloc = NonceAllocator::init_new(
                &dir,
                "restart.qvnc",
                vault_id,
                key_id,
                NonceDomain::FileChunk,
            )
            .unwrap();
            assert_eq!(alloc.allocate_nonce().unwrap().counter, 0);
            assert_eq!(alloc.allocate_nonce().unwrap().counter, 1);
            let range = alloc.allocate_range(3).unwrap();
            assert_eq!(range.start_counter, 2);
            assert_eq!(range.nonce_at(2).unwrap().counter, 4);
            alloc.nonce_prefix().unwrap()
        };

        // Reopen after simulated restart.
        let reopened = NonceAllocator::open(
            &dir,
            "restart.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::FileChunk,
        )
        .unwrap();

        assert_eq!(reopened.nonce_prefix().unwrap(), prefix);
        assert_eq!(reopened.next_counter().unwrap(), 5);
        let next = reopened.allocate_nonce().unwrap();
        assert_eq!(next.counter, 5);
        assert_eq!(next.prefix, prefix);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn independent_key_identities_and_domains_are_isolated() {
        let dir = test_temp_dir("qv-nonce-indep");
        let vault_id = sample_vault_id();
        let dek_wrap_key = sample_key_id(0x01);
        let file_a_key = sample_key_id(0x02);
        let file_b_key = sample_key_id(0x03);

        let wrap_alloc = NonceAllocator::init_new(
            &dir,
            "dek_wrap.qvnc",
            vault_id,
            dek_wrap_key,
            NonceDomain::DekWrapping,
        )
        .unwrap();
        let file_a_alloc = NonceAllocator::init_new(
            &dir,
            "file_a.qvnc",
            vault_id,
            file_a_key,
            NonceDomain::FileChunk,
        )
        .unwrap();
        let file_b_alloc = NonceAllocator::init_new(
            &dir,
            "file_b.qvnc",
            vault_id,
            file_b_key,
            NonceDomain::FileChunk,
        )
        .unwrap();

        assert_eq!(wrap_alloc.allocate_nonce().unwrap().counter, 0);
        assert_eq!(wrap_alloc.allocate_nonce().unwrap().counter, 1);
        assert_eq!(file_a_alloc.allocate_nonce().unwrap().counter, 0);
        assert_eq!(file_b_alloc.allocate_nonce().unwrap().counter, 0);

        // Domain mismatch on open must fail closed.
        let err = NonceAllocator::open(
            &dir,
            "dek_wrap.qvnc",
            &vault_id,
            &dek_wrap_key,
            NonceDomain::FileChunk,
        );
        assert!(matches!(err, Err(NonceError::DomainMismatch)));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupted_metadata_fails_closed() {
        let dir = test_temp_dir("qv-nonce-corrupt");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x33);

        let alloc = NonceAllocator::init_new(
            &dir,
            "corrupt.qvnc",
            vault_id,
            key_id,
            NonceDomain::FileChunk,
        )
        .unwrap();
        alloc.allocate_nonce().unwrap();
        drop(alloc);

        // Flip a bit in the persisted counter field (offset 50) without updating checksum.
        let path = dir.join("corrupt.qvnc");
        let mut raw = fs::read(&path).unwrap();
        raw[50] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        let err = NonceAllocator::open(
            &dir,
            "corrupt.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::FileChunk,
        );
        assert!(matches!(err, Err(NonceError::CorruptedMetadata)));

        // Also test oversized metadata.
        raw.push(0xFF);
        assert!(matches!(
            NonceState::from_bytes(&raw),
            Err(NonceError::CorruptedMetadata)
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn truncated_metadata_fails_closed() {
        let dir = test_temp_dir("qv-nonce-trunc");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x44);

        NonceAllocator::init_new(&dir, "trunc.qvnc", vault_id, key_id, NonceDomain::FileChunk)
            .unwrap();

        let path = dir.join("trunc.qvnc");
        let raw = fs::read(&path).unwrap();
        fs::write(&path, &raw[..40]).unwrap();

        let err = NonceAllocator::open(
            &dir,
            "trunc.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::FileChunk,
        );
        assert!(matches!(err, Err(NonceError::TruncatedMetadata)));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_version_magic_and_domain_rejected() {
        let state = NonceState {
            version: NONCE_STATE_VERSION,
            domain: NonceDomain::FileChunk,
            vault_id: sample_vault_id(),
            key_id: sample_key_id(0x55),
            nonce_prefix: [1, 2, 3, 4],
            next_counter: 42,
        };
        let valid = state.to_bytes();

        // Invalid magic
        let mut bad_magic = valid.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            NonceState::from_bytes(&bad_magic),
            Err(NonceError::InvalidMagic)
        ));

        // Unsupported version
        let mut bad_ver = valid.clone();
        bad_ver[4..6].copy_from_slice(&99_u16.to_be_bytes());
        assert!(matches!(
            NonceState::from_bytes(&bad_ver),
            Err(NonceError::UnsupportedVersion)
        ));

        // Invalid domain
        let mut bad_dom = valid;
        bad_dom[6] = 0x7F;
        assert!(matches!(
            NonceState::from_bytes(&bad_dom),
            Err(NonceError::InvalidDomain)
        ));
    }

    #[test]
    fn invalid_vault_and_key_identity_rejected() {
        let dir = test_temp_dir("qv-nonce-id");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x66);

        NonceAllocator::init_new(&dir, "id.qvnc", vault_id, key_id, NonceDomain::FileChunk)
            .unwrap();

        let wrong_vault = [0xFF_u8; 16];
        let wrong_key = [0xEE_u8; 16];

        assert!(matches!(
            NonceAllocator::open(
                &dir,
                "id.qvnc",
                &wrong_vault,
                &key_id,
                NonceDomain::FileChunk
            ),
            Err(NonceError::VaultIdMismatch)
        ));
        assert!(matches!(
            NonceAllocator::open(
                &dir,
                "id.qvnc",
                &vault_id,
                &wrong_key,
                NonceDomain::FileChunk
            ),
            Err(NonceError::KeyIdMismatch)
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_and_duplicate_init_fail_closed() {
        let dir = test_temp_dir("qv-nonce-missing");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x77);

        // Missing metadata must never silently initialize to 0.
        assert!(matches!(
            NonceAllocator::open(
                &dir,
                "missing.qvnc",
                &vault_id,
                &key_id,
                NonceDomain::FileChunk
            ),
            Err(NonceError::MissingMetadata)
        ));

        // Re-initializing an existing state file must fail closed.
        NonceAllocator::init_new(
            &dir,
            "exists.qvnc",
            vault_id,
            key_id,
            NonceDomain::FileChunk,
        )
        .unwrap();
        assert!(matches!(
            NonceAllocator::init_new(
                &dir,
                "exists.qvnc",
                vault_id,
                key_id,
                NonceDomain::FileChunk
            ),
            Err(NonceError::AlreadyExists)
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn counter_overflow_is_rejected_without_wrapping() {
        let dir = test_temp_dir("qv-nonce-overflow");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x88);

        let near_max = NonceState {
            version: NONCE_STATE_VERSION,
            domain: NonceDomain::FileChunk,
            vault_id,
            key_id,
            nonce_prefix: [9, 8, 7, 6],
            next_counter: u64::MAX - 1,
        };
        storage::atomic_write(&dir, "overflow.qvnc", &near_max.to_bytes()).unwrap();

        let alloc = NonceAllocator::open(
            &dir,
            "overflow.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::FileChunk,
        )
        .unwrap();

        // Range of 3 would overflow u64.
        assert!(matches!(
            alloc.allocate_range(3),
            Err(NonceError::CounterOverflow)
        ));

        // Single allocation at u64::MAX - 1 succeeds (next_counter becomes u64::MAX).
        assert_eq!(alloc.allocate_nonce().unwrap().counter, u64::MAX - 1);
        assert_eq!(alloc.next_counter().unwrap(), u64::MAX);

        // Next allocation would overflow u64 -> must fail closed.
        assert!(matches!(
            alloc.allocate_nonce(),
            Err(NonceError::CounterOverflow)
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_write_failure_transitions_to_fail_closed_state() {
        let dir = test_temp_dir("qv-nonce-iofail");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0x99);
        let backend = FaultInjectingPersistence::new(0);

        let alloc = NonceAllocator::init_with_backend(
            &dir,
            "iofail.qvnc",
            vault_id,
            key_id,
            NonceDomain::DekWrapping,
            [1, 2, 3, 4],
            backend.clone(),
        )
        .unwrap();

        assert_eq!(alloc.allocate_nonce().unwrap().counter, 0);

        // Inject pre-write I/O failure.
        backend.set_mode(1);
        assert!(matches!(alloc.allocate_nonce(), Err(NonceError::Io(_))));

        // Even if underlying I/O recovers, this instance stays tainted until reopened.
        backend.set_mode(0);
        assert!(matches!(
            alloc.allocate_nonce(),
            Err(NonceError::UntrustedState)
        ));

        // Reopening from disk recovers safely at counter 1.
        let reopened = NonceAllocator::open(
            &dir,
            "iofail.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::DekWrapping,
        )
        .unwrap();
        assert_eq!(reopened.allocate_nonce().unwrap().counter, 1);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn crash_after_durable_persist_wastes_nonce_never_reuses() {
        let dir = test_temp_dir("qv-nonce-crash");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xAB);
        let backend = FaultInjectingPersistence::new(0);

        let alloc = NonceAllocator::init_with_backend(
            &dir,
            "crash.qvnc",
            vault_id,
            key_id,
            NonceDomain::FileChunk,
            [0xDE, 0xAD, 0xBE, 0xEF],
            backend.clone(),
        )
        .unwrap();

        assert_eq!(alloc.allocate_nonce().unwrap().counter, 0);

        // Inject crash AFTER durable atomic_write succeeds on disk.
        backend.set_mode(2);
        assert!(matches!(alloc.allocate_nonce(), Err(NonceError::Io(_))));
        assert!(matches!(
            alloc.allocate_nonce(),
            Err(NonceError::UntrustedState)
        ));

        // After restart, counter 1 was durably reserved before the crash and is wasted.
        // Next allocation MUST be counter 2, never 1.
        let reopened = NonceAllocator::open(
            &dir,
            "crash.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::FileChunk,
        )
        .unwrap();
        assert_eq!(reopened.next_counter().unwrap(), 2);
        assert_eq!(reopened.allocate_nonce().unwrap().counter, 2);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_allocations_produce_unique_non_overlapping_nonces() {
        let dir = test_temp_dir("qv-nonce-conc");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xCD);

        let alloc = Arc::new(
            NonceAllocator::init_new(&dir, "conc.qvnc", vault_id, key_id, NonceDomain::FileChunk)
                .unwrap(),
        );

        let threads = 6;
        let per_thread = 10;
        let mut handles = Vec::with_capacity(threads);

        for _ in 0..threads {
            let a = Arc::clone(&alloc);
            handles.push(thread::spawn(move || {
                let mut local = Vec::with_capacity(per_thread);
                for _ in 0..per_thread {
                    local.push(a.allocate_nonce().unwrap());
                }
                local
            }));
        }

        let mut all_counters = HashSet::new();
        let mut all_nonces = HashSet::new();
        for h in handles {
            for item in h.join().unwrap() {
                assert!(all_counters.insert(item.counter));
                assert!(all_nonces.insert(item.bytes));
            }
        }

        let total = (threads * per_thread) as u64;
        assert_eq!(all_counters.len() as u64, total);
        assert_eq!(all_nonces.len() as u64, total);
        assert_eq!(alloc.next_counter().unwrap(), total);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn aes_gcm_integration_with_allocated_nonces() {
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };

        let dir = test_temp_dir("qv-nonce-aes");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xEF);
        let dek = [0x42_u8; 32];

        let alloc =
            NonceAllocator::init_new(&dir, "aes.qvnc", vault_id, key_id, NonceDomain::FileChunk)
                .unwrap();

        let n1 = alloc.allocate_nonce().unwrap();
        let n2 = alloc.allocate_nonce().unwrap();
        assert_ne!(n1.bytes, n2.bytes);

        let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
        let ct1 = cipher
            .encrypt(Nonce::from_slice(&n1.bytes), b"chunk zero".as_ref())
            .unwrap();
        let ct2 = cipher
            .encrypt(Nonce::from_slice(&n2.bytes), b"chunk one".as_ref())
            .unwrap();

        assert_eq!(
            cipher
                .decrypt(Nonce::from_slice(&n1.bytes), ct1.as_ref())
                .unwrap(),
            b"chunk zero"
        );
        assert_eq!(
            cipher
                .decrypt(Nonce::from_slice(&n2.bytes), ct2.as_ref())
                .unwrap(),
            b"chunk one"
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn multiple_allocator_instances_in_same_process_never_reuse_nonces() {
        let dir = test_temp_dir("qv-nonce-multi-inst");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xE1);

        let alloc_a = Arc::new(
            NonceAllocator::init_new(
                &dir,
                "shared.qvnc",
                vault_id,
                key_id,
                NonceDomain::FileChunk,
            )
            .unwrap(),
        );
        let alloc_b = Arc::new(
            NonceAllocator::open(
                &dir,
                "shared.qvnc",
                &vault_id,
                &key_id,
                NonceDomain::FileChunk,
            )
            .unwrap(),
        );

        // Interleaved sequential allocations across two independent instances.
        assert_eq!(alloc_a.allocate_nonce().unwrap().counter, 0);
        assert_eq!(alloc_b.allocate_nonce().unwrap().counter, 1);
        assert_eq!(alloc_a.allocate_nonce().unwrap().counter, 2);
        assert_eq!(alloc_b.allocate_nonce().unwrap().counter, 3);

        // Concurrent allocations from both independent instances.
        let mut handles = Vec::new();
        for inst in [Arc::clone(&alloc_a), Arc::clone(&alloc_b)] {
            for _ in 0..3 {
                let i = Arc::clone(&inst);
                handles.push(thread::spawn(move || {
                    let mut out = Vec::new();
                    for _ in 0..10 {
                        out.push(i.allocate_nonce().unwrap());
                    }
                    out
                }));
            }
        }

        let mut counters = HashSet::new();
        let mut nonces = HashSet::new();
        for h in handles {
            for item in h.join().unwrap() {
                assert!(counters.insert(item.counter));
                assert!(nonces.insert(item.bytes));
            }
        }
        assert_eq!(counters.len(), 60);
        assert_eq!(alloc_a.next_counter().unwrap(), 64);
        assert_eq!(alloc_b.next_counter().unwrap(), 64);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_rollback_detected_fails_closed() {
        let dir = test_temp_dir("qv-nonce-rollback");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xE2);

        let alloc =
            NonceAllocator::init_new(&dir, "rb.qvnc", vault_id, key_id, NonceDomain::DekWrapping)
                .unwrap();
        assert_eq!(alloc.allocate_nonce().unwrap().counter, 0);
        let snapshot_at_1 = fs::read(dir.join("rb.qvnc")).unwrap();
        assert_eq!(alloc.allocate_nonce().unwrap().counter, 1);

        // Externally roll back disk state to an older valid snapshot (next_counter = 1).
        storage::atomic_write(&dir, "rb.qvnc", &snapshot_at_1).unwrap();

        assert!(matches!(
            alloc.allocate_nonce(),
            Err(NonceError::RollbackDetected)
        ));
        assert!(matches!(
            alloc.allocate_nonce(),
            Err(NonceError::UntrustedState)
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn path_traversal_filename_rejected() {
        let dir = test_temp_dir("qv-nonce-path");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xE3);

        assert!(matches!(
            NonceAllocator::init_new(
                &dir,
                "../evil.qvnc",
                vault_id,
                key_id,
                NonceDomain::FileChunk
            ),
            Err(NonceError::InvalidFilename)
        ));
        assert!(matches!(
            NonceAllocator::open(
                &dir,
                "sub/evil.qvnc",
                &vault_id,
                &key_id,
                NonceDomain::FileChunk
            ),
            Err(NonceError::InvalidFilename)
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cross_process_worker() {
        let Ok(dir_str) = std::env::var("QV_CROSS_PROC_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir_str);
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xF0);

        let alloc = NonceAllocator::open(
            &dir,
            "xproc.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::FileChunk,
        )
        .unwrap();

        for _ in 0..10 {
            let n = alloc.allocate_nonce().unwrap();
            let hex_nonce: String = n.bytes.iter().map(|b| format!("{:02x}", b)).collect();
            println!("NONCE:{}:{}", n.counter, hex_nonce);
        }
    }

    #[test]
    fn cross_process_concurrent_allocations_never_reuse_nonces() {
        use std::process::Command;

        let dir = test_temp_dir("qv-nonce-xproc");
        let vault_id = sample_vault_id();
        let key_id = sample_key_id(0xF0);

        let _init =
            NonceAllocator::init_new(&dir, "xproc.qvnc", vault_id, key_id, NonceDomain::FileChunk)
                .unwrap();

        let exe = std::env::current_exe().unwrap();
        let num_procs = 4;
        let mut children = Vec::with_capacity(num_procs);

        for _ in 0..num_procs {
            let child = Command::new(&exe)
                .arg("--exact")
                .arg("nonce::tests::cross_process_worker")
                .arg("--nocapture")
                .env("QV_CROSS_PROC_DIR", &dir)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            children.push(child);
        }

        let mut counters = HashSet::new();
        let mut nonces = HashSet::new();

        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "child process failed: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            for line in stdout.lines() {
                if let Some(rest) = line.strip_prefix("NONCE:") {
                    let mut parts = rest.split(':');
                    let counter: u64 = parts.next().unwrap().parse().unwrap();
                    let nonce_hex = parts.next().unwrap().to_string();
                    assert!(
                        counters.insert(counter),
                        "duplicate counter across processes: {}",
                        counter
                    );
                    assert!(
                        nonces.insert(nonce_hex.clone()),
                        "duplicate nonce across processes: {}",
                        nonce_hex
                    );
                }
            }
        }

        assert_eq!(counters.len(), 40);
        assert_eq!(nonces.len(), 40);

        let reopened = NonceAllocator::open(
            &dir,
            "xproc.qvnc",
            &vault_id,
            &key_id,
            NonceDomain::FileChunk,
        )
        .unwrap();
        assert_eq!(reopened.next_counter().unwrap(), 40);

        fs::remove_dir_all(dir).unwrap();
    }
}
