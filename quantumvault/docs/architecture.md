# QuantumVault Architecture

## 1. Project Goal

QuantumVault is a Linux virtual filesystem prototype that
aims to provide transparent file encryption using
post-quantum cryptographic key establishment.

## 2. Technology Stack

- Rust: Core filesystem and application logic.
- FUSE: Userspace filesystem interface.
- liboqs: Post-quantum cryptographic operations through
  a narrow C/Rust FFI boundary.
- ML-KEM-768: Post-quantum key establishment.
- ML-DSA-65: Post-quantum digital signatures.
- Argon2id: Password-based key protection.
- HKDF-SHA-256: Key derivation.
- AES-256-GCM: Authenticated file encryption.

## 3. Module Architecture

- filesystem: FUSE operations and transparent file access.
- crypto: Cryptographic primitives and liboqs integration.
- key_manager: Vault keys, key derivation and key lifecycle.
- storage: Encrypted file records and metadata persistence.
- cli: Vault initialization and mount management.

## 4. Cryptographic Key Hierarchy

1. A user password is processed using Argon2id.
2. The derived protection key protects the ML-KEM private key.
3. ML-KEM decapsulation recovers the shared secret using
   persisted encapsulation ciphertext.
4. HKDF-SHA-256 derives vault key material.
5. The vault key protects per-file Data Encryption Keys (DEKs).
6. Each file uses its own DEK for AES-256-GCM encryption.

ML-DSA identity keys are separate from ML-KEM keys and
must be protected independently.

## 5. File Encryption

- Files are divided into independently authenticated chunks.
- AES-256-GCM encrypts and authenticates each chunk.
- Each file has a unique DEK.
- Nonces use a per-file prefix and monotonically increasing counter.
- Counter values must be durably reserved before encryption.
- Vault ID, file ID, format version, chunk index and plaintext
  length are authenticated as associated data (AAD).

The same nonce must never be reused with the same DEK.

## 6. Persistence and Recovery

The storage layer must persist:
- Vault metadata and identity.
- ML-KEM encapsulation ciphertext.
- Protected ML-KEM private-key material.
- Wrapped per-file DEKs.
- File metadata and encrypted chunks.
- Nonce counter reservation state.

Counter state must survive restarts and remounts.
If counter state cannot be trusted, encrypted writes must fail closed.

Full backing-store rollback detection requires a trusted external
anchor or equivalent mechanism. This protection is not currently
implemented and must not be claimed.

## 7. Digital Signatures

ML-DSA-65 is intended for signing selected manifest or identity
objects.

Signatures do not replace AES-GCM authenticated encryption.

ML-KEM and ML-DSA keypairs must remain separate.

## 8. Security Boundaries

- Passwords, private keys, shared secrets and plaintext DEKs
  must never be logged.
- Sensitive buffers should be zeroized where practical.
- Authentication failures must not return unauthenticated plaintext.
- Malformed or unsupported encrypted records must be rejected.
- Writable filesystem operations must remain disabled until
  encryption, nonce allocation, persistence and recovery are
  implemented and tested.

## 9. Current Implementation Status

Implemented:
- Rust Cargo project.
- Basic read-only FUSE filesystem.
- Static hello.txt file.
- Initial architecture and format documentation.

Not yet implemented:
- Writable FUSE operations.
- liboqs integration.
- ML-KEM-768 and ML-DSA-65 operations.
- Argon2id and HKDF integration.
- AES-256-GCM encryption.
- Persistent key management.
- Encrypted storage and crash recovery.

## 10. Project Scope

QuantumVault is an educational internship prototype.
It has not been independently audited or certified for
production use.
