# QuantumVault Key Management Design

**Status:** Design proposal with partial foundational implementation
**Version:** 1.0

## 1. Purpose

This document defines the proposed key hierarchy, key lifecycle,
protection, persistence and recovery model for QuantumVault.

The design separates post-quantum key establishment, key derivation,
per-file encryption and digital signatures.

## 2. Key Hierarchy

The proposed hierarchy is:

1. User password is processed using Argon2id with a unique random salt.
2. Argon2id derives a password-based protection key.
3. The protection key protects the ML-KEM-768 private key.
4. ML-KEM-768 decapsulation uses the persisted encapsulation ciphertext
   and protected private key to recover the shared secret.
5. HKDF-SHA-256 derives domain-separated vault key material.
6. A dedicated DEK-wrapping key protects individual file DEKs.
7. Each file receives a unique 256-bit DEK.
8. AES-256-GCM uses the DEK to encrypt and authenticate file chunks.

ML-KEM establishes shared secret material. It does not encrypt files.

## 3. Key Separation

The implementation must maintain separate keys for separate purposes:

- ML-KEM-768 keypair: post-quantum key establishment.
- ML-DSA-65 keypair: digital signatures.
- Password-derived protection key: protection of stored private material.
- Vault key material: derived using HKDF-SHA-256.
- DEK-wrapping key: protects per-file DEKs.
- File DEK: encrypts chunks belonging to one file.

HKDF context labels must be distinct and documented.
Keys must never be reused across cryptographic purposes.

## 4. Key Generation

- ML-KEM and ML-DSA keypairs must be generated independently.
- Each file must receive a cryptographically random 256-bit DEK.
- Password salts and required nonces must be generated using a
  cryptographically secure random number generator.
- Key and nonce generation failures must stop the operation.
- The current foundation uses the OS-backed `getrandom` interface
  for random byte generation and salt creation.

## 5. Key Protection and Persistence

The storage design must preserve enough information for recovery:

- Vault identifier and format version.
- Argon2id salt and parameter metadata.
- Protected ML-KEM private-key material.
- ML-KEM public key and encapsulation ciphertext.
- Protected ML-DSA identity key material, when signing is enabled.
- Wrapped per-file DEKs.
- Required manifest and file metadata.

Private keys, shared secrets, passwords and plaintext DEKs must
never be written to logs or stored unprotected.

## 6. Per-File DEK Wrapping

Each file receives a unique DEK.

A dedicated wrapping key derived through HKDF-SHA-256 protects
the DEK using AES-256-GCM.

The wrapped record must authenticate:

- Vault ID.
- File ID.
- Format version.
- Wrapping purpose identifier.

The wrapping nonce must be unique for each encryption under the
same wrapping key. Its allocation and persistence must be designed
independently from file-chunk nonce allocation.

## 7. Key Lifecycle

The future implementation must define:

- Vault initialization.
- Key generation.
- Password-based unlock.
- Key loading and validation.
- File DEK creation and wrapping.
- Vault lock and memory cleanup.
- Password change and key re-protection.
- Recovery and remount behavior.
- Key rotation and secure retirement.

No lifecycle operation should expose secret key material unnecessarily.

## 8. Memory Safety

- Use zeroization for sensitive buffers wherever practical.
- Avoid unnecessary secret copies.
- Clear temporary secrets after use.
- Do not log passwords, private keys, shared secrets or plaintext DEKs.
- Handle allocation and cryptographic failures without exposing secrets.

The current implementation includes a `SecretBytes` wrapper backed by
the Rust `zeroize` crate. Its buffer is zeroized when the wrapper is
dropped. This is a foundational safeguard and does not guarantee that
all copies of secret material throughout the process are erased.

## 9. Recovery and Rollback

ML-KEM encapsulation ciphertext and protected private-key material
must be persisted for restart and remount.

Nonce reservation state must be durable before encryption uses
reserved counter values.

If key material or nonce state is missing, corrupted or untrusted,
the implementation must fail closed.

Durable local counters alone cannot detect restoration of an entire
old backing-store snapshot. A trusted external rollback anchor or
equivalent mechanism is required for that protection.

## 10. Implementation Sequence

1. Finalize key hierarchy and cryptographic interfaces.
2. Define versioned key metadata structures.
3. Integrate password-based protection with persisted key metadata.
4. Implement ML-KEM key persistence and recovery.
5. Integrate HKDF derivation with the actual vault key hierarchy.
6. Implement per-file DEK generation and wrapping.
7. Implement ML-DSA identity-key protection separately.
8. Add negative, recovery and tampering tests.

Encrypted filesystem writes must remain disabled until the
file format, nonce allocation, persistence and crash recovery
requirements are implemented and tested.

## 11. Current Status and Limitations

### 11.1 Implemented Key-Management Features (Day 11 & Day 12)

- **Password Key Derivation:** Argon2id version 0x13 with 64 MiB memory cost, 3 iterations, and parallelism 1.
- **OS-Backed Randomness:** Secure random byte and salt generation via `getrandom`.
- **Secret Memory Safety:** `SecretBytes` wrapper with `zeroize` on drop and redacted `Debug` implementation.
- **Purpose-Separated Subkey Derivation:** HKDF-SHA-256 derivation with distinct domain labels for:
  - `KeyPurpose::VaultMaster`
  - `KeyPurpose::DekWrapping`
  - `KeyPurpose::KemPrivateKeyProtection`
  - `KeyPurpose::DsaPrivateKeyProtection`
- **Protected Key Record Format (`.qvpk`):**
  - Binary serialization and deserialization via `ProtectedKeyRecord::to_bytes()` and `ProtectedKeyRecord::from_bytes()`.
  - Strict 55-byte header including magic bytes `b"QVPK"`, format version 1 (`u16`), 16-byte vault ID, 1-byte key kind (`1 = ML-KEM`, `2 = ML-DSA`), 16-byte Argon2 salt, 12-byte AES-GCM nonce, and 4-byte big-endian ciphertext length.
  - Authenticated Associated Data (AAD) binding format version, vault ID, and key kind label (`b"QuantumVault/protected-key/" || version || vault_id || aad_label`).
- **Authenticated Encryption:** AES-256-GCM encryption with 96-bit random nonces and 128-bit authentication tags.
- **Persistent Key Storage & Recovery:**
  - Atomic persistence using `storage::atomic_write()` with restrictive `0600` permissions on Unix platforms.
  - Safe APIs: `save_protected_key_record`, `save_mlkem_private_key`, `save_mldsa_private_key`, `load_protected_key_record`, `recover_private_key`, `load_and_recover_mlkem_private_key`, and `load_and_recover_mldsa_private_key`.
  - Key-type and vault ID validation on save, load, and unprotect operations.
  - Strict input validation rejecting truncated headers, truncated ciphertext, inconsistent ciphertext lengths, invalid magic bytes, unsupported versions, and oversized records (> 1 MiB).
- **Comprehensive Test Suite:** 35 unit tests in `key_manager` including round-trip serialization, disk persistence, correct and incorrect password recovery, ciphertext tampering, vault ID mismatch, magic corruption, key type corruption, version validation, truncation, oversized payload rejection, and atomic replacement verification.

### 11.2 Encryption and Recovery Flow

1. **Protection Flow:**
   - Plaintext private key material and password are provided.
   - A fresh 16-byte random salt is generated via OS RNG.
   - Argon2id derives a 32-byte password key.
   - HKDF-SHA-256 derives a dedicated 32-byte AES-256-GCM key bound to the specific key purpose (`KemPrivateKeyProtection` vs `DsaPrivateKeyProtection`).
   - A fresh 96-bit random nonce is generated via OS RNG.
   - AES-256-GCM encrypts the private key with AAD binding the vault ID, version, and key type.
   - The serialized record is written to disk via atomic temporary file replacement with restrictive permissions (`0600`).
   - Plaintext temporary keys and buffers are zeroized upon leaving scope.

2. **Recovery Flow:**
   - The `.qvpk` file is read from the designated directory.
   - Binary header, magic, version, key type, and ciphertext lengths are strictly validated.
   - Expected vault ID is verified against the record.
   - Argon2id re-derives the password key from the supplied password and persisted salt.
   - HKDF-SHA-256 re-derives the purpose-separated AES key.
   - AES-256-GCM authenticates and decrypts the ciphertext using the reconstructed AAD and nonce.
   - The recovered plaintext is returned inside a `SecretBytes` wrapper that zeroizes upon drop.

### 11.3 Cryptographic Nonce Policy & Probabilistic Uniqueness

Protected key records generate a 96-bit (12-byte) cryptographically secure random nonce for each encryption operation.

**Assumptions and Limitations:**
- A 96-bit random nonce provides probabilistic collision resistance, not an absolute deterministic uniqueness guarantee.
- Under the birthday bound, the collision probability remains negligible for infrequent key-protection operations (e.g., initial vault setup, password change, key rotation). For $N \ll 2^{48}$ protected key encryptions under the same key, collision risk is infinitesimally small.
- Because each call also generates a fresh 16-byte Argon2 salt, the derived AES-256 key is itself unique per encryption even if the password remains identical.
- This random nonce policy is acceptable for infrequent private key protection, but **must not** be used for continuous high-throughput file-chunk encryption, which requires a persistent monotonically increasing counter.

### 11.4 Persistent AES-GCM Nonce Management (Day 13)

- **Module:** `src/nonce/mod.rs` (`NonceAllocator`, `NonceState`, `NonceDomain`, `AllocatedNonce`, `AllocatedNonceRange`).
- **96-bit Nonce Construction:** `nonce_prefix (4 bytes, OS-random on init) || counter (8 bytes big-endian)`, matching the encrypted file format specification.
- **Domain Separation:** `NonceDomain::DekWrapping` and `NonceDomain::FileChunk` enforce independent counter namespaces and state files (`.qvnc`), preventing cross-purpose nonce collisions.
- **Write-Ahead Durable Reservation:** `allocate_nonce()` and `allocate_range(count)` serialize the incremented `next_counter` and persist it atomically via `storage::atomic_write()` (with file and directory `sync_all()`) *before* returning any nonce to the caller.
- **Concurrency Safety (Multi-Thread & Cross-Process on Unix):** Allocations are serialized behind an internal `std::sync::Mutex` and, on Unix, an OS-level exclusive advisory file lock (`flock(LOCK_EX)` on `<filename>.lock` with `0600` permissions). Under the lock, the allocator re-reads and validates the latest `.qvnc` state from disk before incrementing `next_counter`, preventing stale cached counters across independent instances or separate processes. On non-Unix targets, no OS-level file lock is implemented and multiprocess/multi-instance safety is not guaranteed.
- **Fail-Closed & Crash Semantics:**
  - `NonceAllocator::init_new()` acquires the exclusive file lock and refuses to overwrite an existing `.qvnc` file (`AlreadyExists`).
  - `NonceAllocator::open()` fails closed on missing, truncated, corrupted, version-mismatched, domain-mismatched, vault-ID-mismatched, or key-ID-mismatched metadata—never silently resetting a counter to zero.
  - Runtime rollback detection: if the on-disk `next_counter` regresses below the last counter observed by a live allocator, the allocator fails closed (`RollbackDetected`). This does not detect full-store snapshot rollback across restarts.
  - If `atomic_write` fails, the live allocator marks itself tainted (`UntrustedState`) so in-memory state cannot diverge from disk.
  - A crash after durable persistence wastes the in-flight reserved counter(s) on restart rather than risking nonce reuse.
- **Rollback Limitation:** Local durable counter persistence does **not** protect against full backing-store rollback (e.g., restoring an older filesystem snapshot). Rollback protection requires a trusted external anchor.

### 11.5 Remaining Limitations (Not Yet Implemented)

- Persistent vault master-key hierarchy integration and lifecycle (unlock/lock of entire vault).
- Per-file DEK generation, wrapping, and persistence (using `NonceDomain::DekWrapping`).
- AES-256-GCM chunk-level file encryption and persistent filesystem storage (using `NonceDomain::FileChunk`).
- Rollback protection against external backing-store restoration (requires a trusted external anchor).
- Writable FUSE filesystem encryption (remains disabled until DEK wrapping, chunk encryption, and remount recovery are integrated and tested).
