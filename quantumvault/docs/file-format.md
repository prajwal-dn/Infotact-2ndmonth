# QuantumVault Encrypted File Format

**Status:** Draft — proposed format, not implemented
**Format Version:** 1
**Encryption:** AES-256-GCM
**Nonce Size:** 96 bits
**Authentication Tag:** 128 bits

## 1. Purpose

This document defines the proposed on-disk representation of
encrypted QuantumVault file data.

The format supports independently authenticated chunks,
persistent key metadata, and recovery after crashes.

## 2. Cryptographic Design

Each file receives a unique 256-bit Data Encryption Key (DEK).

File contents are divided into chunks. Each chunk is encrypted
independently using AES-256-GCM.

ML-KEM-768 establishes shared secret material used in the
vault key hierarchy. It does not encrypt file contents.

HKDF-SHA-256 derives vault key material. The vault key protects
per-file DEKs.

ML-DSA-65 may sign selected manifest or identity objects.
It does not replace AES-GCM authentication.

## 3. Nonce Construction

AES-GCM uses a 96-bit nonce:

- 32-bit random per-file nonce prefix.
- 64-bit monotonically increasing counter.

Nonce = file_nonce_prefix || counter

The same nonce must never be used more than once with the
same DEK.

Each file must have its own DEK. A new file must receive a
new DEK and a new nonce prefix.

## 4. Counter Allocation and Crash Recovery

The counter must be persistent and monotonically increasing.

Before encrypting data:

1. Reserve the next counter value or a range of counter values.
2. Persist the reservation durably.
3. Confirm the persistence operation succeeded.
4. Only then use the reserved counter values for encryption.

A crash may waste reserved counter values. Wasted values
must never be reused.

Counter state must survive process restarts and remounts.

If counter state is missing, corrupted, rolled back, or cannot
be trusted, encryption must fail closed. The implementation
must not reset the counter to zero.

Concurrent writers must not receive overlapping counter values.

The final implementation must define durable reservation,
atomicity, synchronization, and recovery behavior.

## 5. Associated Authenticated Data (AAD)

Every encrypted chunk must authenticate the following metadata:

- Vault ID
- File ID
- Format version
- Chunk index
- Plaintext length

AAD must use a deterministic, unambiguous binary encoding.

Changing any authenticated field must cause authentication
verification to fail.

## 6. Proposed File Header

The proposed logical header contains:

| Field | Size | Description |
|---|---:|---|
| Magic | 4 bytes | QVLT |
| Format version | 2 bytes | Version 1 |
| Vault ID | 16 bytes | Vault identifier |
| File ID | 16 bytes | File identifier |
| Nonce prefix | 4 bytes | Per-file random prefix |
| Wrapped DEK length | 4 bytes | Length of wrapped DEK |
| Wrapped DEK | Variable | DEK protected by vault key |

All integer fields must use a documented byte order.
The implementation must define and test that encoding before
the format is considered stable.

## 7. Proposed Chunk Record

Each chunk record contains:

| Field | Size | Description |
|---|---:|---|
| Chunk index | 8 bytes | Chunk sequence number |
| Nonce counter | 8 bytes | Counter used for nonce |
| Plaintext length | 4 bytes | Original chunk length |
| Ciphertext | Variable | Encrypted chunk bytes |
| GCM tag | 16 bytes | Authentication tag |

The nonce is reconstructed using the file nonce prefix and
the stored counter.

The exact chunk size, record framing, maximum lengths, and
byte order must be finalized during implementation.

## 8. Authentication and Decryption

For every chunk:

1. Validate the record structure and lengths.
2. Reconstruct the nonce.
3. Reconstruct AAD from trusted file and vault metadata.
4. Verify and decrypt using AES-256-GCM.
5. Return plaintext only after authentication succeeds.

Authentication failure must never return unauthenticated
plaintext.

Malformed, truncated, or unsupported records must be rejected.

## 9. Persistence Requirements

The implementation must persist enough information to recover:

- Vault identity and format version.
- File identity.
- Wrapped per-file DEK.
- Per-file nonce prefix.
- Durable nonce counter reservation state.
- Required manifest and integrity metadata.

The ML-KEM encapsulation ciphertext and protected private-key
material must also be persisted through the key manager.

## 10. Security Requirements

- Never reuse an AES-GCM nonce with the same DEK.
- Never reset a counter after remount or restart.
- Never reuse a DEK for a different file.
- Authenticate all security-relevant chunk metadata.
- Reject authentication failures and malformed records.
- Never store plaintext file contents in the backing store.
- Never log passwords, private keys, shared secrets, or DEKs.

## 11. Implementation Gate

Writable FUSE operations must remain disabled until:

- The binary encoding is finalized.
- DEK wrapping and recovery work.
- Nonce allocation is durable and concurrency-safe.
- Crash recovery is implemented and tested.
- AES-GCM round-trip and tampering tests pass.
- Remount persistence tests pass.

This is an educational internship prototype and has not
been independently audited or certified for production use.

## 12. Rollback Protection Limitation

Durable counter persistence alone does not prevent rollback
of the complete backing store to an older snapshot.

If an attacker restores an older snapshot, previously
persisted counter state may also be restored.

A trusted external rollback anchor or equivalent
rollback-detection mechanism is required to detect this
condition reliably.

Until such a mechanism is implemented, the prototype must
document this limitation and must not claim protection
against full backing-store rollback.

If rollback is detected, or counter state cannot be trusted,
encrypted writes must fail closed.

## 13. Per-File DEK Wrapping

Each file has a unique 256-bit DEK.

The vault key hierarchy must derive a dedicated DEK-wrapping
key using HKDF-SHA-256 with a distinct, documented context
label. The wrapping key must be cryptographically separated
from other key purposes.

The DEK must be protected using AES-256-GCM.

The persisted wrapped-DEK record must contain:
- Wrapping format version.
- Wrapping nonce (96 bits).
- Wrapped DEK ciphertext.
- Authentication tag (128 bits).

The wrapping AAD must bind at least:
- Vault ID.
- File ID.
- Format version.
- Wrapping purpose identifier.

The wrapping nonce must never repeat with the same
DEK-wrapping key.

The implementation must define nonce generation, persistence,
and recovery for DEK wrapping before the format is finalized.

A wrapped DEK must be authenticated successfully before
it can be used for file encryption or decryption.
