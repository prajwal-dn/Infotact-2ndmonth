//! Initial liboqs FFI smoke-test bridges.
//! These are validation functions, not production key-management APIs.

unsafe extern "C" {
    fn qv_mlkem768_self_test() -> i32;
    fn qv_mldsa65_self_test() -> i32;
}

/// Runs an ML-KEM-768 key generation, encapsulation and decapsulation test.
pub fn mlkem768_self_test() -> Result<(), &'static str> {
    let result = unsafe { qv_mlkem768_self_test() };

    match result {
        0 => Ok(()),
        1 => Err("ML-KEM-768 unavailable"),
        2 => Err("ML-KEM memory allocation failed"),
        3 => Err("ML-KEM key generation failed"),
        4 => Err("ML-KEM encapsulation failed"),
        5 => Err("ML-KEM decapsulation failed"),
        6 => Err("ML-KEM shared secrets did not match"),
        _ => Err("unknown ML-KEM FFI error"),
    }
}

/// Runs ML-DSA-65 key generation, signing and verification tests.
///
/// Secret key material remains inside the C shim and is cleansed before
/// memory is released. This is a self-test, not a production signing API.
pub fn mldsa65_self_test() -> Result<(), &'static str> {
    let result = unsafe { qv_mldsa65_self_test() };

    match result {
        0 => Ok(()),
        10 => Err("ML-DSA-65 unavailable"),
        11 => Err("ML-DSA memory allocation failed"),
        12 => Err("ML-DSA key generation failed"),
        13 => Err("ML-DSA signing failed"),
        14 => Err("ML-DSA valid signature verification failed"),
        15 => Err("ML-DSA accepted an altered message"),
        16 => Err("ML-DSA signature length exceeded buffer"),
        _ => Err("unknown ML-DSA FFI error"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn mlkem768_roundtrip_through_ffi() {
        crate::crypto::mlkem768_self_test().unwrap();
    }

    #[test]
    fn mldsa65_sign_verify_through_ffi() {
        crate::crypto::mldsa65_self_test().unwrap();
    }
}
