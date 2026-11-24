//! QuantumVault key-management primitives.
//!
//! Implements secret-memory handling, OS-backed randomness, Argon2id
//! password derivation, and purpose-separated HKDF-SHA-256 derivation.
//!
//! Persistent key storage and production encryption are not implemented.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub const ARGON2_SALT_LEN: usize = 16;
pub const DERIVED_KEY_LEN: usize = 32;

const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

/// Holds sensitive bytes and clears its owned buffer when dropped.
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Purpose labels prevent accidental reuse of the same derived key
/// for different cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    VaultMaster,
    DekWrapping,
}

impl KeyPurpose {
    fn info(self) -> &'static [u8] {
        match self {
            Self::VaultMaster => b"QuantumVault/v1/vault-master",
            Self::DekWrapping => b"QuantumVault/v1/dek-wrapping",
        }
    }
}

/// Errors returned by key derivation operations.
#[derive(Debug)]
pub enum KeyDerivationError {
    InvalidSaltLength,
    EmptyInputKeyMaterial,
    Argon2(argon2::Error),
    HkdfExpand,
}

impl From<argon2::Error> for KeyDerivationError {
    fn from(error: argon2::Error) -> Self {
        Self::Argon2(error)
    }
}

/// Generates a random 16-byte salt using the operating system RNG.
pub fn generate_salt() -> Result<[u8; ARGON2_SALT_LEN], getrandom::Error> {
    let mut salt = [0_u8; ARGON2_SALT_LEN];
    getrandom::fill(&mut salt)?;
    Ok(salt)
}

/// Fills a buffer using the operating system's cryptographically secure RNG.
pub fn fill_random(output: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(output)
}

/// Generates random secret bytes. The returned buffer is zeroized on drop.
pub fn random_bytes(length: usize) -> Result<SecretBytes, getrandom::Error> {
    let mut bytes = vec![0_u8; length];

    if let Err(error) = fill_random(&mut bytes) {
        bytes.zeroize();
        return Err(error);
    }

    Ok(SecretBytes::new(bytes))
}

/// Derives a 32-byte key from a password using Argon2id.
///
/// The salt and Argon2 parameters must be stored with vault metadata.
/// This function does not itself encrypt or authenticate stored key material.
pub fn derive_password_key(
    password: &[u8],
    salt: &[u8],
) -> Result<SecretBytes, KeyDerivationError> {
    if salt.len() != ARGON2_SALT_LEN {
        return Err(KeyDerivationError::InvalidSaltLength);
    }

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived_key = vec![0_u8; DERIVED_KEY_LEN];

    if let Err(error) = argon2.hash_password_into(password, salt, &mut derived_key) {
        derived_key.zeroize();
        return Err(KeyDerivationError::Argon2(error));
    }

    Ok(SecretBytes::new(derived_key))
}

/// Derives a purpose-specific 32-byte key using HKDF-SHA-256.
///
/// `input_key_material` should be secret key material, such as the
/// output of Argon2id or another securely established secret.
///
/// `salt` is public HKDF salt material. It may be empty, but callers
/// should persist it when using a non-empty salt.
///
/// The fixed purpose label provides domain separation.
pub fn derive_subkey(
    input_key_material: &[u8],
    salt: &[u8],
    purpose: KeyPurpose,
) -> Result<SecretBytes, KeyDerivationError> {
    if input_key_material.is_empty() {
        return Err(KeyDerivationError::EmptyInputKeyMaterial);
    }

    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut output = vec![0_u8; DERIVED_KEY_LEN];

    if hkdf.expand(purpose.info(), &mut output).is_err() {
        output.zeroize();
        return Err(KeyDerivationError::HkdfExpand);
    }

    Ok(SecretBytes::new(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_preserve_contents_while_alive() {
        let secret = SecretBytes::new(vec![0x11, 0x22, 0x33]);

        assert_eq!(secret.expose(), &[0x11, 0x22, 0x33]);
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
    }

    #[test]
    fn empty_secret_is_supported() {
        let secret = SecretBytes::new(Vec::new());

        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn random_bytes_returns_requested_length() {
        let secret = random_bytes(32).unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn random_bytes_supports_empty_buffer() {
        let secret = random_bytes(0).unwrap();
        assert!(secret.is_empty());
    }

    #[test]
    fn fill_random_populates_buffer() {
        let mut bytes = [0_u8; 32];
        fill_random(&mut bytes).unwrap();
        assert!(bytes.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn generated_salt_has_expected_length() {
        let salt = generate_salt().unwrap();
        assert_eq!(salt.len(), ARGON2_SALT_LEN);
    }

    #[test]
    fn argon2id_derives_32_byte_key() {
        let salt = [0x42_u8; ARGON2_SALT_LEN];
        let key = derive_password_key(b"test-password", &salt).unwrap();

        assert_eq!(key.len(), DERIVED_KEY_LEN);
    }

    #[test]
    fn same_password_and_salt_produce_same_key() {
        let salt = [0x42_u8; ARGON2_SALT_LEN];

        let first = derive_password_key(b"test-password", &salt).unwrap();
        let second = derive_password_key(b"test-password", &salt).unwrap();

        assert_eq!(first.expose(), second.expose());
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = [0x42_u8; ARGON2_SALT_LEN];

        let first = derive_password_key(b"password-one", &salt).unwrap();
        let second = derive_password_key(b"password-two", &salt).unwrap();

        assert_ne!(first.expose(), second.expose());
    }

    #[test]
    fn invalid_salt_length_is_rejected() {
        let result = derive_password_key(b"test-password", &[0x42; 8]);

        assert!(matches!(result, Err(KeyDerivationError::InvalidSaltLength)));
    }

    #[test]
    fn hkdf_derives_32_byte_key() {
        let key = derive_subkey(&[0x42; 32], &[0x11; 32], KeyPurpose::VaultMaster).unwrap();

        assert_eq!(key.len(), DERIVED_KEY_LEN);
    }

    #[test]
    fn hkdf_is_deterministic_for_same_inputs() {
        let first = derive_subkey(b"test-input", b"test-salt", KeyPurpose::VaultMaster).unwrap();

        let second = derive_subkey(b"test-input", b"test-salt", KeyPurpose::VaultMaster).unwrap();

        assert_eq!(first.expose(), second.expose());
    }

    #[test]
    fn hkdf_separates_key_purposes() {
        let master = derive_subkey(b"test-input", b"test-salt", KeyPurpose::VaultMaster).unwrap();

        let wrapping = derive_subkey(b"test-input", b"test-salt", KeyPurpose::DekWrapping).unwrap();

        assert_ne!(master.expose(), wrapping.expose());
    }

    #[test]
    fn hkdf_rejects_empty_input_key_material() {
        let result = derive_subkey(b"", b"test-salt", KeyPurpose::VaultMaster);

        assert!(matches!(
            result,
            Err(KeyDerivationError::EmptyInputKeyMaterial)
        ));
    }
}
