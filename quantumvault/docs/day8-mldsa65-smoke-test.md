# Day 8 — ML-DSA-65 C Smoke Test

## Objective
Verify ML-DSA-65 using installed liboqs 0.16.0.

## Implementation
- Added tests/c/mldsa65_smoke.c.
- Used OQS_SIG_alg_ml_dsa_65.
- Allocated buffers using runtime OQS_SIG lengths.
- Tested key generation, signing and verification.
- Tested rejection of a modified message.
- Cleansed the secret key before freeing memory.

## Test Results
- PASS: ML-DSA-65 key generation.
- PASS: ML-DSA-65 signing and verification.
- PASS: altered message rejected.
- Signature length: 3309 bytes.

## Status
C-level ML-DSA-65 smoke test passed.

## Pending
- Rust ML-DSA FFI integration.
- Persistent key storage.
- Manifest and identity signing.
- Filesystem integration tests.

This is a prototype validation, not a production security audit.
