# QuantumVault Build Plan

**Status:** Proposed implementation roadmap
**Version:** 0.1

## Phase 1: Foundation

Objectives:
- Confirm Rust, Cargo, GCC, CMake and FUSE environment.
- Maintain a clean Cargo project structure.
- Finalize architecture, API contract and file format.
- Define the liboqs integration boundary.
- Record exact dependency versions.

Exit criteria:
- Project builds successfully.
- Documentation is internally consistent.
- Build instructions are reproducible.

## Phase 2: Read/Write FUSE Filesystem

Objectives:
- Generalize the existing static read-only filesystem.
- Implement create, open, read, write, readdir and unlink.
- Handle file offsets and partial writes correctly.
- Implement metadata handling.

Tests:
- Empty files.
- Binary files.
- Repeated writes.
- Offset-based reads.
- Directory listing.
- File deletion.

Security gate:
- Keep writable encrypted-vault operations disabled until
  encryption and nonce persistence are ready.

## Phase 3: Post-Quantum Cryptography

Objectives:
- Build and pin a verified liboqs version.
- Implement a narrow C wrapper and Rust FFI.
- Verify ML-KEM-768 key generation, encapsulation and decapsulation.
- Verify ML-DSA-65 key generation, signing and verification.

Tests:
- Matching ML-KEM shared secrets.
- Invalid decapsulation inputs.
- Valid ML-DSA signatures.
- Modified-message verification failure.

Exit criteria:
- Exact algorithm identifiers and library version verified.
- No silent algorithm substitution.

## Phase 4: Key Derivation and AEAD

Objectives:
- Implement Argon2id password-based protection.
- Implement HKDF-SHA-256.
- Implement AES-256-GCM encryption and decryption.
- Define per-file DEK wrapping and recovery.

Tests:
- Encryption/decryption round trip.
- Wrong-key failure.
- Modified ciphertext rejection.
- Modified AAD rejection.
- Invalid authentication tag rejection.

## Phase 5: Encrypted Storage Format

Objectives:
- Implement versioned file header and chunk records.
- Implement deterministic AAD encoding.
- Implement per-file nonce prefix and counter allocation.
- Persist counter reservations before encryption.
- Handle concurrent writers safely.
- Implement crash recovery and fail-closed behavior.

Tests:
- Chunk boundary cases.
- Truncated and malformed records.
- Counter persistence across restart.
- Crash after counter reservation.
- No overlapping counter allocations.

## Phase 6: Key Manager and Vault Persistence

Objectives:
- Initialize and unlock vaults.
- Persist ML-KEM encapsulation ciphertext.
- Protect and recover private-key material.
- Persist wrapped per-file DEKs.
- Protect ML-DSA identity keys separately.
- Add permission checks and sensitive-buffer zeroization.

Tests:
- Restart and remount recovery.
- Wrong password.
- Missing or malformed metadata.
- Key recovery failure.
- No secret leakage in logs.

## Phase 7: FUSE Encryption Integration

Objectives:
- Encrypt data before backing-store persistence.
- Decrypt data before returning reads.
- Verify ciphertext at rest.
- Preserve file semantics and metadata.
- Support safe remount persistence.

Tests:
- Plaintext round trip through FUSE.
- Ciphertext inspection in backing storage.
- Large and binary files.
- Repeated writes and partial reads.
- Remount recovery.
- Corruption and authentication failure.

## Phase 8: CLI and Digital Signatures

Objectives:
- Implement init, mount, unmount and identity commands.
- Sign selected manifest or identity objects using ML-DSA-65.
- Verify signatures before trusting signed metadata.

Tests:
- CLI argument validation.
- Signature verification.
- Modified manifest rejection.
- Permission and error handling.

## Phase 9: Hardening and Demonstration

Objectives:
- Run regression tests.
- Verify clean-environment setup.
- Document limitations and known issues.
- Prepare user guide and test report.
- Prepare a repeatable demonstration.

Security limitations:
- Full backing-store rollback protection is not implemented
  unless a trusted external anchor is added.
- The prototype is not production-audited or certified.

## Development Rules

- Preserve existing functionality.
- Do not merge unfinished work into main.
- Keep implementation and documentation status accurate.
- Never commit passwords, private keys or secret material.
- Do not enable encrypted writes before all required security gates pass.
