# Day 9 — Rust ML-DSA-65 FFI Integration

## Objective
Extend the existing liboqs C shim and Rust FFI bridge with an ML-DSA-65 self-test.

## Implementation
- Added qv_mldsa65_self_test() to src/crypto/oqs_shim.c.
- Used the official OQS_SIG_alg_ml_dsa_65 identifier.
- Allocated public key, secret key and signature buffers using runtime OQS_SIG lengths.
- Implemented key generation, signing and signature verification.
- Verified that an altered message is rejected.
- Cleansed the secret key before freeing memory.
- Added mldsa65_self_test() to src/crypto/mod.rs.
- Preserved the existing ML-KEM-768 FFI functionality.

## Test Results
- ML-KEM-768 Rust FFI test: PASS
- ML-DSA-65 Rust FFI test: PASS
- Existing filesystem tests: PASS
- Total unit tests: 29 passed, 0 failed, 0 ignored.

## Quality Checks
- cargo fmt --check: PASS
- cargo clippy --all-targets -- -D warnings: PASS
- git diff --check: PASS

## Limitations
These functions are cryptographic self-tests, not production signing or key-management APIs.

Not yet implemented:
- Production-safe Rust key types.
- Persistent key storage and recovery.
- Vault identity and manifest signing.
- Production key lifecycle management.
- Full filesystem cryptographic integration.

The project remains an internship prototype and has not undergone a formal security audit.
