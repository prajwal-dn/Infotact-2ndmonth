# Day 13 — Persistent AES-GCM Nonce Management

## Objective
Design, implement, and verify a crash-safe, concurrency-safe, persistent AES-256-GCM nonce allocation subsystem (`src/nonce/mod.rs`) that prevents nonce reuse across restarts, supports domain separation between DEK wrapping and file-chunk encryption, and fails closed on untrusted or corrupted metadata.

## Architecture & Implementation
- **Module:** `src/nonce/mod.rs` (exported via `pub mod nonce;` in `src/lib.rs`).
- **96-bit Nonce Construction:** `AllocatedNonce` builds 12-byte AES-GCM nonces as `nonce_prefix (4 bytes, OS-random via getrandom) || counter (8 bytes big-endian)`.
- **Domain Separation:** `NonceDomain` separates `DekWrapping` (`1`) and `FileChunk` (`2`) allocation states so independent keys and cryptographic purposes never share counter state.
- **Persistent Metadata Format (`.qvnc`):** Fixed 83-byte versioned binary record (`NonceState`):
  - Magic bytes: `b"QVNC"` (4 bytes)
  - Format version: `1` (`u16` big-endian)
  - Domain: `u8` (`1 = DekWrapping`, `2 = FileChunk`)
  - Vault ID: 16 bytes
  - Key ID: 16 bytes
  - Nonce prefix: 4 bytes
  - Next counter: `u64` big-endian
  - SHA-256 checksum: 32 bytes over the preceding 51 bytes
- **Write-Ahead Atomic Persistence:**
  - `NonceAllocator::init_new()` creates a new state file via `storage::atomic_write()` and fails closed (`AlreadyExists`) if the file already exists.
  - `NonceAllocator::open()` loads and validates magic, version, domain, SHA-256 checksum, `vault_id`, and `key_id`, failing closed on any mismatch or missing file.
  - `allocate_nonce()` and `allocate_range(count)` persist the incremented `next_counter` durably *before* returning any reserved nonce(s).
- **Concurrency & Crash Recovery:**
  - Allocations are serialized under `std::sync::Mutex<AllocatorInner>` and, on Unix, an OS-level `flock(LOCK_EX)` exclusive lock on `<filename>.lock` (`0600`), re-reading and validating the latest on-disk `.qvnc` state under the lock so independent allocator instances and separate OS processes cannot reuse counters. (On non-Unix targets, no OS-level file lock is implemented and multiprocess/multi-instance safety is not guaranteed.)
  - Runtime rollback detection fails closed (`RollbackDetected`) if on-disk `next_counter` regresses below a live allocator's last observed value (this does not detect full-store snapshot rollback across restarts).
  - If `atomic_write` fails (including after rename but before directory sync), the live allocator transitions to a tainted fail-closed state (`UntrustedState`).
  - Reopening from disk after a crash after durable persistence skips/wastes the in-flight reservation rather than risking nonce reuse.
  - 64-bit `checked_add` prevents integer overflow (`CounterOverflow`).
- **Testability:** `NoncePersistence` trait abstracts disk persistence and locking (`AtomicFilePersistence` in production) to enable deterministic pre-write and post-persist crash injection in unit tests.

## Test Coverage
Added 19 unit tests in `src/nonce/mod.rs` (including multi-instance and 4-process concurrent allocation tests) covering:
1. First nonce allocation starting at counter 0 and immediate persistence.
2. Sequential allocation and uniqueness across 25 allocations.
3. Persistence across allocator drop/reopen (restart simulation).
4. Independent key identities and domain separation (`DekWrapping` vs `FileChunk`, domain mismatch rejection).
5. Corrupted metadata (bit-flip in counter caught by SHA-256 checksum, oversized record rejection).
6. Truncated metadata rejection.
7. Invalid magic bytes, unsupported version, and unknown domain byte rejection.
8. Vault ID and key ID mismatch rejection.
9. Missing metadata fail-closed behavior and duplicate `init_new` rejection (`AlreadyExists`).
10. 64-bit counter overflow protection (`CounterOverflow` on single and range allocations).
11. Atomic-write failure transitioning live allocator to `UntrustedState`, followed by safe disk recovery.
12. Deterministic crash-after-durable-persist simulation proving the in-flight nonce is wasted and never reused.
13. Multi-threaded concurrent allocation (6 threads × 10 allocations = 60 unique non-overlapping nonces).
14. End-to-end AES-256-GCM encryption/decryption round trip using allocated nonces.
15. Multi-instance concurrency in the same process (interleaved + 6 threads × 10 allocations across 2 independent instances = 60 unique nonces).
16. Cross-process concurrency across 4 OS child processes (`cross_process_concurrent_allocations_never_reuse_nonces` + `cross_process_worker`, 40 unique nonces).
17. Runtime rollback detection (`RollbackDetected` -> `UntrustedState`).
18. Path traversal filename rejection (`InvalidFilename`).

## Security Limitations & Remaining Work
- **Full-Store Rollback:** Local durable counter persistence does not detect restoration of an entire older backing-store snapshot across restarts. A trusted external rollback anchor is required for full rollback protection.
- **Non-Unix Locking:** Cross-process and multi-instance file locking relies on Unix `flock(LOCK_EX)`; non-Unix targets have no equivalent OS-level lock.
- **Unkeyed Checksum:** The SHA-256 checksum detects accidental corruption/bit-flips and truncation, not malicious tampering by an attacker with direct write access to the backing store.
- **Not Yet Integrated:** Per-file DEK wrapping, chunked file encryption, and writable encrypted FUSE operations remain disabled until the remaining File Format and Key Manager integration milestones are completed.
