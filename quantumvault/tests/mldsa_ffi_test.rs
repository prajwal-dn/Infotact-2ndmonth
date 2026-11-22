// Independent test for Prajwal's Day 9 ML-DSA-65 FFI bridge
// Verifies that the Rust-C FFI bridge works for ML-DSA-65 signatures.

#[test]
fn test_mldsa65_ffi_bridge() {
    // Call the smoke-test function provided by Prajwal's FFI.
    let result = quantumvault::crypto::mldsa65_self_test();
    
    // The function should return Ok(()) if keygen, sign, and verify succeed,
    // and modified message is rejected.
    assert!(result.is_ok(), "ML-DSA FFI self-test failed: {:?}", result.err());
    
    println!("✅ ML-DSA-65 FFI bridge validated successfully from Rust.");
}
