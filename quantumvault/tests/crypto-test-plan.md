# QuantumVault Crypto Test Plan (Aman)

**Status:** Planning & Scaffolding Phase
**liboqs Version Verified:** 0.16.0
**Algorithm Identifiers:** `OQS_KEM_alg_ml_kem_768`, `OQS_SIG_alg_ml_dsa_65`

## 1. ML-KEM-768 Test Plan (Planned)
These tests will run once the Rust FFI bindings are exposed by Prajwal.

- [ ] **Key Generation:** Generate a valid KEM keypair. Verify public and private keys are generated and correctly sized.
- [ ] **Encapsulation/Decapsulation:** Encapsulate using the public key to get a ciphertext and shared secret (SS1). Decapsulate using the private key and ciphertext to get shared secret (SS2). Verify `SS1 == SS2`.
- [ ] **Invalid Ciphertext Handling:** Attempt decapsulation with a randomly modified ciphertext. Ensure it fails gracefully or returns a different shared secret, without panicking.
- [ ] **Wrong Key Handling:** Attempt decapsulation with a different private key. Ensure the derived shared secret does not match.

## 2. ML-DSA-65 Test Plan (Planned)
These tests will run once the Rust FFI bindings are exposed by Prajwal.

- [ ] **Key Generation:** Generate a valid DSA keypair (signing key and verification key).
- [ ] **Valid Signature:** Sign a known message with the private key. Verify the signature with the public key. It must pass.
- [ ] **Modified Message Rejection:** Modify a single byte of the original message. Verify the signature against the modified message. It must fail.
- [ ] **Modified Signature Rejection:** Modify a single byte of the signature. Verify against the original message. It must fail.
- [ ] **Wrong Public Key Rejection:** Verify the signature against a different public key. It must fail.

## 3. AES-256-GCM Test Plan (Planned)
These tests will run once the AEAD module is integrated.

- [ ] **Valid Round-Trip:** Encrypt plaintext, then decrypt ciphertext. Verify plaintext matches original.
- [ ] **Tampered Ciphertext Rejection:** Flip a bit in the ciphertext. Attempt decryption. It must fail authentication.
- [ ] **Tampered AAD Rejection:** Modify the Associated Data (AAD). Attempt decryption. It must fail authentication.
- [ ] **Wrong Key Rejection:** Attempt decryption with an incorrect key. It must fail authentication.
- [ ] **Boundary Sizes:** Test encryption/decryption with 0 bytes (empty), 1 byte, and a large buffer (e.g., 64KB).

## Prerequisites for Execution
- Rust FFI bindings must be compiled and linked against liboqs 0.16.0.
- Test commands will likely use `cargo test --test crypto_tests` (or similar).
- Shared secrets and private keys must NEVER be printed in test outputs.

## Notes
- Currently, these are just plans. No Rust FFI code exists yet to execute them.
- Will update status to `[x]` as soon as implementations are ready and tests are actually run.
## Day 6 Update (Prajwal's Progress)
- Prajwal has successfully verified the C API for ML-KEM-768 (Commit: 961a9a0).
- Keypair gen, Encapsulation, Decapsulation, and matching 32-byte secrets are verified in C.
- **Status:** Waiting for the Rust FFI wrapper to be implemented so Aman can write and execute the independent Rust tests against these functions.
## Day 8 Update (Prajwal's Progress)
- Prajwal has successfully verified the C API for ML-DSA-65 (Commit: 4921b46).
- Keygen, Sign, Verify, and Modified message rejection are verified in C.
- **Status:** Waiting for the Rust FFI wrapper to be implemented. 
- **Rust Test Harness:** Created `tests/mldsa_ffi_test.rs` (marked as `#[ignore]` until FFI is ready).
## Day 9 Update (Prajwal's Progress)
- Rust FFI for ML-DSA-65 is now implemented (Commit: 47ea0ab).
- `mldsa65_self_test()` successfully validated from Rust.
- Keygen, Sign, Verify, and Modified message rejection work across the FFI.
- **Status:** KEM and DSA basic FFI bridges are complete. Waiting for final storage/key-management API.
