//! Initial liboqs FFI smoke-test bridge.
//! This is not yet the production vault key-management API.

unsafe extern "C" {
    fn qv_mlkem768_self_test() -> i32;
}

/// Runs an ML-KEM-768 key-generation, encapsulation and decapsulation test.
pub fn mlkem768_self_test() -> Result<(), &'static str> {
    // The C shim owns all buffers and does not expose secret material.
    let result = unsafe { qv_mlkem768_self_test() };

    match result {
        0 => Ok(()),
        1 => Err("ML-KEM-768 unavailable"),
        2 => Err("memory allocation failed"),
        3 => Err("ML-KEM key generation failed"),
        4 => Err("ML-KEM encapsulation failed"),
        5 => Err("ML-KEM decapsulation failed"),
        6 => Err("shared secrets did not match"),
        _ => Err("unknown liboqs FFI error"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn mlkem768_roundtrip_through_ffi() {
        crate::crypto::mlkem768_self_test().unwrap();
    }
}
