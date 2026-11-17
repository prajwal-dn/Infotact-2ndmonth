#[test]
fn test_mlkem768_ffi_bridge() {
    let result = quantumvault::crypto::mlkem768_self_test();
    assert!(result.is_ok(), "ML-KEM FFI self-test failed: {:?}", result.err());
    println!("✅ ML-KEM-768 FFI bridge validated successfully from Rust.");
}
