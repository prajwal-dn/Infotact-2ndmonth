# Review: Key Management Design (Day 10)
Reviewer: Aman Gaikwad

## 1. Key Hierarchy Security
- The hierarchy (Argon2id -> KEM -> HKDF -> DEK Wrapping Key -> Per-file DEKs) looks logically sound.
- **Recommendation:** Ensure that the DEK wrapping key is never used for actual file data encryption, only for wrapping/unwrapping per-file DEKs.

## 2. Key Separation
- ML-KEM (for key exchange) and ML-DSA (for signatures) must use entirely separate keypairs. The design reflects this.
- **Recommendation:** Ensure the vault master key and the ML-KEM private key are stored as distinct entities with distinct protection (even if both are ultimately protected by the Argon2id password).

## 3. Missing Recovery & Edge Cases
- What happens if the process crashes *while* writing a new wrapped DEK?
- **Suggestion:** Implement an atomic write mechanism (e.g., write to a `.tmp` file and rename) for metadata and wrapped keys to prevent partial/corrupted key records.
- What if the user forgets the password? (Answer: Data is permanently lost, we must document this clearly).

## 4. Nonce Requirements
- **File Encryption:** 96-bit nonce. Must have a durable counter that never resets. 
- **DEK Wrapping:** Needs its own separate nonce space. A nonce used for wrapping a DEK cannot be used for encrypting file data with that DEK.
- **Suggestion:** Add a requirement to persist the nonce counter state to disk *before* actual encryption takes place, to survive sudden power loss.

## 5. Proposed Negative Tests (Next Phase)
- **Malformed Key Material:** Try to load a truncated/corrupted vault key file. Ensure it fails gracefully and doesn't panic.
- **Corrupted Metadata:** Tamper with the vault metadata (e.g., change the Argon2id salt). Ensure it fails authentication.
- **Invalid Cryptographic Inputs:** Call the Rust FFI with empty/zero-length buffers or null pointers (where safe to do so via Rust) to ensure the C shim handles it.

## Conclusion
The design is solid and follows cryptographic best practices. We are ready to implement the key-management foundations once these edge cases are acknowledged.
