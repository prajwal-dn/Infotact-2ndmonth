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

The project has implemented foundational key-management and
metadata-persistence primitives. These do not yet constitute a
complete or integrated vault key-management system.

Implemented foundations:

- Argon2id password-key derivation using Argon2id version 0x13,
  with 64 MiB memory cost, 3 iterations and parallelism 1.
- Random 16-byte password salt generation using OS-backed randomness.
- OS-backed random byte generation through `getrandom`.
- `SecretBytes` wrapper with zeroization on drop.
- HKDF-SHA-256 subkey derivation with distinct labels for
  `VaultMaster` and `DekWrapping` purposes.
- Atomic metadata file replacement using a temporary file,
  file synchronization, rename and parent-directory synchronization.
- Restrictive 0600 permissions for newly created metadata files.
- Unit tests for derivation, randomness, zeroization-related
  behaviour and metadata-write validation.

Still not implemented:

- Persisted Argon2 parameters and password-based unlock workflow.
- Protection, serialization and persistence of ML-KEM private keys.
- Integration of ML-KEM shared-secret recovery into the key hierarchy.
- Production vault master-key initialization and lifecycle.
- Per-file DEK generation, wrapping and persistent storage.
- AES-256-GCM encryption and decryption.
- Durable nonce allocation for encrypted file writes.
- Persistent encrypted file records, crash recovery and rollback protection.
- ML-DSA identity-key protection and persistence.

The HKDF primitives are currently foundational APIs. Their presence
does not mean the complete proposed key hierarchy is integrated.
Atomic metadata writes do not provide encrypted storage or rollback
protection. A directory synchronization error after rename may also
mean that the destination was already replaced.

The ML-KEM-768 and ML-DSA-65 C/Rust integrations remain self-tests,
not production key-management APIs.

QuantumVault is an educational internship prototype and has
not undergone an independent security audit.
