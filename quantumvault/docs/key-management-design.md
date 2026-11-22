# QuantumVault Key Management Design

**Status:** Design proposal — not implemented
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
3. Implement password-based protection using Argon2id.
4. Implement ML-KEM key persistence and recovery.
5. Implement HKDF domain-separated derivation.
6. Implement per-file DEK generation and wrapping.
7. Implement ML-DSA identity-key protection separately.
8. Add negative, recovery and tampering tests.

Encrypted filesystem writes must remain disabled until the
file format, nonce allocation, persistence and crash recovery
requirements are implemented and tested.

## 11. Current Status and Limitations

This document describes a proposed design, not completed
key-management functionality.

The current project has ML-KEM-768 and ML-DSA-65 C/Rust
self-test integrations. These are validation bridges, not
production key-management APIs.

Persistent key storage, password protection, HKDF integration,
DEK wrapping and recovery remain future implementation tasks.

QuantumVault is an educational internship prototype and has
not undergone an independent security audit.
