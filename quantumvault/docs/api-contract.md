# QuantumVault API Contract

**Status:** Draft — proposed interfaces, not yet implemented
**Version:** 0.1

## 1. Purpose

This document defines the planned responsibilities and interfaces
between QuantumVault modules.

The interfaces may change during implementation, but security
invariants must be preserved.

## 2. Module Responsibilities

### 2.1 Filesystem (`src/filesystem/`)

Responsible for:
- FUSE mount operations.
- File and directory metadata.
- Read and write request handling.
- Passing plaintext data to the crypto layer for encryption
  before persistent storage.
- Decrypting stored data before returning it to the caller.

Planned operations:
- lookup
- getattr
- readdir
- create
- open
- read
- write
- unlink
- release

Writes must remain disabled until the encrypted storage format
and nonce allocation policy are implemented and tested.

### 2.2 Crypto (`src/crypto/`)

Responsible for cryptographic primitives.

Planned interfaces:

- ML-KEM-768:
  - generate_keypair()
  - encapsulate()
  - decapsulate()

- ML-DSA-65:
  - generate_keypair()
  - sign()
  - verify()

- Key derivation:
  - derive_key_hkdf()

- Authenticated encryption:
  - encrypt_aes_256_gcm()
  - decrypt_aes_256_gcm()

These are conceptual operation names. Exact Rust signatures and
error types will be finalized during implementation.

### 2.3 Key Manager (`src/key_manager/`)

Responsible for:
- Vault initialization and unlocking.
- Password-based key protection using Argon2id.
- ML-KEM private-key protection.
- Persisting and recovering KEM encapsulation ciphertext.
- Deriving the vault master key through the documented hierarchy.
- Wrapping and unwrapping per-file data encryption keys.
- Protecting ML-DSA identity keys separately.

Secret material must never be logged or written to source control.

### 2.4 Storage (`src/storage/`)

Responsible for:
- Reading and writing encrypted file records.
- Persisting vault metadata.
- Persisting wrapped per-file keys.
- Handling versioned encrypted file records.
- Rejecting malformed or unsupported records.

Storage must never persist plaintext file contents.

### 2.5 CLI (`src/cli/`)

Planned commands:
- init
- mount
- unmount
- identity

The CLI must not print passwords, private keys, shared secrets,
or plaintext data encryption keys.

## 3. Cryptographic Data Flow

1. A password is processed using Argon2id.
2. The resulting protection key protects the ML-KEM private key.
3. ML-KEM decapsulation recovers the shared secret using
   persisted encapsulation ciphertext.
4. HKDF-SHA-256 derives vault key material.
5. Per-file DEKs are generated and wrapped under the vault key.
6. AES-256-GCM encrypts and authenticates file chunks.
7. ML-DSA-65 signs selected metadata or manifest objects.

ML-KEM is key establishment, not file encryption.
ML-DSA signatures do not replace AEAD authentication.

## 4. Security Invariants

- ML-KEM and ML-DSA keypairs must remain separate.
- AES-GCM nonces must never repeat with the same key.
- Nonce allocation must survive crashes and remounts without reuse.
- Vault ID, file ID, format version, and chunk index must be
  authenticated as associated data.
- Authentication failure must not return unauthenticated plaintext.
- Private keys, passwords, shared secrets, and plaintext DEKs
  must not appear in logs.
- Sensitive buffers should be zeroized where practical.

## 5. Error Handling

Planned errors include:
- InvalidInput
- UnsupportedAlgorithm
- KeyGenerationFailed
- EncapsulationFailed
- DecapsulationFailed
- SignatureVerificationFailed
- AuthenticationFailed
- InvalidRecord
- UnsupportedFormatVersion
- StorageError
- PermissionDenied

Exact error types and mappings will be defined during implementation.

## 6. Implementation Status

This document describes the intended architecture.
It does not claim that the listed operations are implemented.

Current implementation:
- Read-only FUSE prototype.
- Static hello.txt file.
- No cryptographic integration.
- No encrypted storage.
- No key persistence.
