//! QuantumVault key-management primitives.
//!
//! Implements secret-memory handling, OS-backed randomness, Argon2id
//! password derivation, and purpose-separated HKDF-SHA-256 derivation.
//! Protected private-key encryption, serialization, persistence, and recovery
//! primitives are implemented; production filesystem encryption and durable
//! nonce allocation remain pending.

use std::error::Error;
use std::fmt;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub const ARGON2_SALT_LEN: usize = 16;
pub const DERIVED_KEY_LEN: usize = 32;
pub const PROTECTED_KEY_VERSION: u16 = 1;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const PROTECTED_KEY_MAGIC: &[u8; 4] = b"QVPK";
pub const PROTECTED_KEY_HEADER_SIZE: usize = 55;
pub const MIN_CIPHERTEXT_LEN: usize = 16;
pub const MAX_PROTECTED_KEY_SIZE: usize = 1024 * 1024;

pub const MLKEM_PRIVATE_KEY_FILENAME: &str = "mlkem_private_key.qvpk";
pub const MLDSA_PRIVATE_KEY_FILENAME: &str = "mldsa_private_key.qvpk";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtectedKeyKind {
    MlKemPrivateKey = 1,
    MlDsaPrivateKey = 2,
}

impl ProtectedKeyKind {
    pub fn purpose(self) -> KeyPurpose {
        match self {
            Self::MlKemPrivateKey => KeyPurpose::KemPrivateKeyProtection,
            Self::MlDsaPrivateKey => KeyPurpose::DsaPrivateKeyProtection,
        }
    }

    pub fn aad_label(self) -> &'static [u8] {
        match self {
            Self::MlKemPrivateKey => b"ml-kem-768-private-key",
            Self::MlDsaPrivateKey => b"ml-dsa-65-private-key",
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(value: u8) -> Result<Self, ProtectedKeyError> {
        match value {
            1 => Ok(Self::MlKemPrivateKey),
            2 => Ok(Self::MlDsaPrivateKey),
            _ => Err(ProtectedKeyError::UnknownKeyType),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedKeyRecord {
    pub version: u16,
    pub vault_id: [u8; 16],
    pub kind: ProtectedKeyKind,
    pub salt: [u8; ARGON2_SALT_LEN],
    pub nonce: [u8; AES_GCM_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl ProtectedKeyRecord {
    /// Serializes the protected key record into a versioned binary format.
    ///
    /// Binary format layout:
    /// - [0..4]   Magic bytes: `b"QVPK"`
    /// - [4..6]   Format version: u16 (big-endian)
    /// - [6..22]  Vault ID: 16 bytes
    /// - [22]     Key type: 1 byte (1 = ML-KEM, 2 = ML-DSA)
    /// - [23..39] Argon2 salt: 16 bytes
    /// - [39..51] AES-GCM nonce: 12 bytes
    /// - [51..55] Ciphertext length: u32 (big-endian)
    /// - [55..]   Ciphertext including 16-byte authentication tag
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PROTECTED_KEY_HEADER_SIZE + self.ciphertext.len());
        bytes.extend_from_slice(PROTECTED_KEY_MAGIC);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.vault_id);
        bytes.push(self.kind.to_byte());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        let ct_len = self.ciphertext.len() as u32;
        bytes.extend_from_slice(&ct_len.to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Alias for `to_bytes`.
    pub fn serialize(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Deserializes and validates a protected key record from raw bytes.
    ///
    /// Validates magic bytes, format version, key type, header length,
    /// maximum record size, and ciphertext length consistency.
    /// Never panics on malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtectedKeyError> {
        if bytes.len() > MAX_PROTECTED_KEY_SIZE {
            return Err(ProtectedKeyError::OversizedRecord);
        }

        if bytes.len() < PROTECTED_KEY_HEADER_SIZE {
            return Err(ProtectedKeyError::TruncatedHeader);
        }

        if &bytes[0..4] != PROTECTED_KEY_MAGIC {
            return Err(ProtectedKeyError::InvalidMagic);
        }

        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != PROTECTED_KEY_VERSION {
            return Err(ProtectedKeyError::UnsupportedVersion);
        }

        let mut vault_id = [0_u8; 16];
        vault_id.copy_from_slice(&bytes[6..22]);

        let kind = ProtectedKeyKind::from_byte(bytes[22])?;

        let mut salt = [0_u8; ARGON2_SALT_LEN];
        salt.copy_from_slice(&bytes[23..39]);

        let mut nonce = [0_u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&bytes[39..51]);

        let ciphertext_len =
            u32::from_be_bytes([bytes[51], bytes[52], bytes[53], bytes[54]]) as usize;

        if ciphertext_len < MIN_CIPHERTEXT_LEN {
            return Err(ProtectedKeyError::InvalidCiphertextLength);
        }

        let remaining_len = bytes.len() - PROTECTED_KEY_HEADER_SIZE;
        if remaining_len < ciphertext_len {
            return Err(ProtectedKeyError::TruncatedCiphertext);
        }
        if remaining_len > ciphertext_len {
            return Err(ProtectedKeyError::InvalidCiphertextLength);
        }

        let ciphertext = bytes[PROTECTED_KEY_HEADER_SIZE..].to_vec();

        Ok(ProtectedKeyRecord {
            version,
            vault_id,
            kind,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Alias for `from_bytes`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtectedKeyError> {
        Self::from_bytes(bytes)
    }
}

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

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.bytes.len())
    }
}

/// Purpose labels prevent accidental reuse of the same derived key
/// for different cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    VaultMaster,
    DekWrapping,
    KemPrivateKeyProtection,
    DsaPrivateKeyProtection,
}

impl KeyPurpose {
    fn info(self) -> &'static [u8] {
        match self {
            Self::VaultMaster => b"QuantumVault/v1/vault-master",
            Self::DekWrapping => b"QuantumVault/v1/dek-wrapping",
            Self::KemPrivateKeyProtection => b"QuantumVault/v1/kem-private-key-protection",
            Self::DsaPrivateKeyProtection => b"QuantumVault/v1/dsa-private-key-protection",
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

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSaltLength => write!(f, "invalid salt length for Argon2"),
            Self::EmptyInputKeyMaterial => write!(f, "empty input key material for HKDF"),
            Self::Argon2(e) => write!(f, "Argon2 derivation error: {}", e),
            Self::HkdfExpand => write!(f, "HKDF expand error"),
        }
    }
}

impl Error for KeyDerivationError {}

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

/// Builds authenticated metadata for a protected private-key record.
fn protected_key_aad(version: u16, vault_id: &[u8; 16], kind: ProtectedKeyKind) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"QuantumVault/protected-key/");
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(kind.aad_label());
    aad
}

/// Encrypts private-key material using Argon2id, HKDF and AES-256-GCM.
pub fn protect_private_key(
    password: &[u8],
    vault_id: [u8; 16],
    kind: ProtectedKeyKind,
    private_key: &[u8],
) -> Result<ProtectedKeyRecord, ProtectedKeyError> {
    if password.is_empty() || private_key.is_empty() {
        return Err(ProtectedKeyError::EmptyInput);
    }

    let salt = generate_salt().map_err(ProtectedKeyError::Random)?;
    let nonce_bytes = random_bytes(AES_GCM_NONCE_LEN).map_err(ProtectedKeyError::Random)?;

    let password_key = derive_password_key(password, &salt)?;
    let encryption_key = derive_subkey(password_key.expose(), &salt, kind.purpose())?;

    let cipher = Aes256Gcm::new_from_slice(encryption_key.expose())
        .map_err(|_| ProtectedKeyError::InvalidKey)?;

    let aad = protected_key_aad(PROTECTED_KEY_VERSION, &vault_id, kind);
    let nonce = Nonce::from_slice(nonce_bytes.expose());

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: private_key,
                aad: &aad,
            },
        )
        .map_err(|_| ProtectedKeyError::Encryption)?;

    let mut nonce = [0_u8; AES_GCM_NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes.expose());

    Ok(ProtectedKeyRecord {
        version: PROTECTED_KEY_VERSION,
        vault_id,
        kind,
        salt,
        nonce,
        ciphertext,
    })
}

/// Authenticates and decrypts a protected private-key record.
pub fn unprotect_private_key(
    password: &[u8],
    expected_vault_id: &[u8; 16],
    record: &ProtectedKeyRecord,
) -> Result<SecretBytes, ProtectedKeyError> {
    if password.is_empty() {
        return Err(ProtectedKeyError::EmptyInput);
    }

    if record.version != PROTECTED_KEY_VERSION {
        return Err(ProtectedKeyError::UnsupportedVersion);
    }

    if &record.vault_id != expected_vault_id {
        return Err(ProtectedKeyError::VaultIdMismatch);
    }

    if record.ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(ProtectedKeyError::InvalidCiphertext);
    }

    let password_key = derive_password_key(password, &record.salt)?;
    let encryption_key = derive_subkey(password_key.expose(), &record.salt, record.kind.purpose())?;

    let cipher = Aes256Gcm::new_from_slice(encryption_key.expose())
        .map_err(|_| ProtectedKeyError::InvalidKey)?;

    let aad = protected_key_aad(record.version, &record.vault_id, record.kind);
    let nonce = Nonce::from_slice(&record.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &record.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ProtectedKeyError::Authentication)?;

    Ok(SecretBytes::new(plaintext))
}

/// Authenticates and decrypts an ML-KEM private-key record specifically.
pub fn unprotect_mlkem_private_key(
    password: &[u8],
    expected_vault_id: &[u8; 16],
    record: &ProtectedKeyRecord,
) -> Result<SecretBytes, ProtectedKeyError> {
    if record.kind != ProtectedKeyKind::MlKemPrivateKey {
        return Err(ProtectedKeyError::WrongKeyType);
    }
    unprotect_private_key(password, expected_vault_id, record)
}

/// Authenticates and decrypts an ML-DSA private-key record specifically.
pub fn unprotect_mldsa_private_key(
    password: &[u8],
    expected_vault_id: &[u8; 16],
    record: &ProtectedKeyRecord,
) -> Result<SecretBytes, ProtectedKeyError> {
    if record.kind != ProtectedKeyKind::MlDsaPrivateKey {
        return Err(ProtectedKeyError::WrongKeyType);
    }
    unprotect_private_key(password, expected_vault_id, record)
}

// ---------------------------------------------------------------------------
// Persistent Key Storage APIs
// ---------------------------------------------------------------------------

/// Persists a protected key record to the specified directory and filename
/// using atomic file replacement and restrictive file permissions.
pub fn save_protected_key_record(
    directory: &Path,
    filename: &str,
    record: &ProtectedKeyRecord,
) -> Result<(), ProtectedKeyError> {
    let bytes = record.to_bytes();
    crate::storage::atomic_write(directory, filename, &bytes).map_err(ProtectedKeyError::from)
}

/// Protects an ML-KEM private key and saves it to disk under `filename`.
pub fn save_mlkem_private_key_as(
    directory: &Path,
    filename: &str,
    password: &[u8],
    vault_id: [u8; 16],
    private_key: &[u8],
) -> Result<ProtectedKeyRecord, ProtectedKeyError> {
    let record = protect_private_key(
        password,
        vault_id,
        ProtectedKeyKind::MlKemPrivateKey,
        private_key,
    )?;
    save_protected_key_record(directory, filename, &record)?;
    Ok(record)
}

/// Protects an ML-KEM private key and saves it to disk under `MLKEM_PRIVATE_KEY_FILENAME`.
pub fn save_mlkem_private_key(
    directory: &Path,
    password: &[u8],
    vault_id: [u8; 16],
    private_key: &[u8],
) -> Result<ProtectedKeyRecord, ProtectedKeyError> {
    save_mlkem_private_key_as(
        directory,
        MLKEM_PRIVATE_KEY_FILENAME,
        password,
        vault_id,
        private_key,
    )
}

/// Saves an existing ML-KEM protected key record to disk under `MLKEM_PRIVATE_KEY_FILENAME`.
pub fn save_mlkem_private_key_record(
    directory: &Path,
    record: &ProtectedKeyRecord,
) -> Result<(), ProtectedKeyError> {
    if record.kind != ProtectedKeyKind::MlKemPrivateKey {
        return Err(ProtectedKeyError::WrongKeyType);
    }
    save_protected_key_record(directory, MLKEM_PRIVATE_KEY_FILENAME, record)
}

/// Protects an ML-DSA private key and saves it to disk under `filename`.
pub fn save_mldsa_private_key_as(
    directory: &Path,
    filename: &str,
    password: &[u8],
    vault_id: [u8; 16],
    private_key: &[u8],
) -> Result<ProtectedKeyRecord, ProtectedKeyError> {
    let record = protect_private_key(
        password,
        vault_id,
        ProtectedKeyKind::MlDsaPrivateKey,
        private_key,
    )?;
    save_protected_key_record(directory, filename, &record)?;
    Ok(record)
}

/// Protects an ML-DSA private key and saves it to disk under `MLDSA_PRIVATE_KEY_FILENAME`.
pub fn save_mldsa_private_key(
    directory: &Path,
    password: &[u8],
    vault_id: [u8; 16],
    private_key: &[u8],
) -> Result<ProtectedKeyRecord, ProtectedKeyError> {
    save_mldsa_private_key_as(
        directory,
        MLDSA_PRIVATE_KEY_FILENAME,
        password,
        vault_id,
        private_key,
    )
}

/// Saves an existing ML-DSA protected key record to disk under `MLDSA_PRIVATE_KEY_FILENAME`.
pub fn save_mldsa_private_key_record(
    directory: &Path,
    record: &ProtectedKeyRecord,
) -> Result<(), ProtectedKeyError> {
    if record.kind != ProtectedKeyKind::MlDsaPrivateKey {
        return Err(ProtectedKeyError::WrongKeyType);
    }
    save_protected_key_record(directory, MLDSA_PRIVATE_KEY_FILENAME, record)
}

/// Loads and validates a protected key record from disk.
pub fn load_protected_key_record(
    directory: &Path,
    filename: &str,
) -> Result<ProtectedKeyRecord, ProtectedKeyError> {
    let path = directory.join(filename);
    let bytes = std::fs::read(&path).map_err(ProtectedKeyError::from)?;
    ProtectedKeyRecord::from_bytes(&bytes)
}

/// Loads a protected key record from disk, validates it, and recovers the private key
/// using the supplied password and expected vault ID.
pub fn recover_private_key(
    directory: &Path,
    filename: &str,
    password: &[u8],
    expected_vault_id: &[u8; 16],
) -> Result<SecretBytes, ProtectedKeyError> {
    let record = load_protected_key_record(directory, filename)?;
    unprotect_private_key(password, expected_vault_id, &record)
}

/// Loads and recovers an ML-KEM private key from `MLKEM_PRIVATE_KEY_FILENAME`.
pub fn load_and_recover_mlkem_private_key(
    directory: &Path,
    password: &[u8],
    expected_vault_id: &[u8; 16],
) -> Result<SecretBytes, ProtectedKeyError> {
    let record = load_protected_key_record(directory, MLKEM_PRIVATE_KEY_FILENAME)?;
    if record.kind != ProtectedKeyKind::MlKemPrivateKey {
        return Err(ProtectedKeyError::WrongKeyType);
    }
    unprotect_private_key(password, expected_vault_id, &record)
}

/// Loads and recovers an ML-DSA private key from `MLDSA_PRIVATE_KEY_FILENAME`.
pub fn load_and_recover_mldsa_private_key(
    directory: &Path,
    password: &[u8],
    expected_vault_id: &[u8; 16],
) -> Result<SecretBytes, ProtectedKeyError> {
    let record = load_protected_key_record(directory, MLDSA_PRIVATE_KEY_FILENAME)?;
    if record.kind != ProtectedKeyKind::MlDsaPrivateKey {
        return Err(ProtectedKeyError::WrongKeyType);
    }
    unprotect_private_key(password, expected_vault_id, &record)
}

/// Errors returned by protected private-key operations.
#[derive(Debug)]
pub enum ProtectedKeyError {
    EmptyInput,
    Random(getrandom::Error),
    Derivation(KeyDerivationError),
    InvalidKey,
    Encryption,
    Authentication,
    UnsupportedVersion,
    VaultIdMismatch,
    InvalidCiphertext,
    InvalidMagic,
    UnknownKeyType,
    InvalidRecord,
    TruncatedHeader,
    TruncatedCiphertext,
    InvalidCiphertextLength,
    OversizedRecord,
    MissingRecord,
    WrongKeyType,
    Io(std::io::Error),
}

impl From<KeyDerivationError> for ProtectedKeyError {
    fn from(error: KeyDerivationError) -> Self {
        Self::Derivation(error)
    }
}

impl From<std::io::Error> for ProtectedKeyError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            Self::MissingRecord
        } else {
            Self::Io(error)
        }
    }
}

impl fmt::Display for ProtectedKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty password or private key input"),
            Self::Random(e) => write!(f, "secure random number generation failed: {}", e),
            Self::Derivation(e) => write!(f, "key derivation error: {}", e),
            Self::InvalidKey => write!(f, "invalid key length for cipher"),
            Self::Encryption => write!(f, "encryption failed"),
            Self::Authentication => {
                write!(f, "authentication failed (wrong password or modified data)")
            }
            Self::UnsupportedVersion => write!(f, "unsupported record format version"),
            Self::VaultIdMismatch => write!(f, "vault identifier mismatch"),
            Self::InvalidCiphertext => write!(f, "invalid ciphertext length or content"),
            Self::InvalidMagic => write!(f, "invalid magic bytes in protected key record"),
            Self::UnknownKeyType => write!(f, "unknown or unsupported key type"),
            Self::InvalidRecord => write!(f, "invalid protected key record"),
            Self::TruncatedHeader => write!(f, "protected key record header is truncated"),
            Self::TruncatedCiphertext => write!(f, "protected key ciphertext is truncated"),
            Self::InvalidCiphertextLength => write!(f, "invalid or inconsistent ciphertext length"),
            Self::OversizedRecord => write!(f, "protected key record exceeds maximum allowed size"),
            Self::MissingRecord => write!(f, "protected key record file not found"),
            Self::WrongKeyType => {
                write!(f, "protected key record is not of the expected key type")
            }
            Self::Io(e) => write!(f, "I/O error during key persistence: {}", e),
        }
    }
}

impl Error for ProtectedKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Derivation(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_temp_directory(prefix: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), count));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn secret_bytes_preserve_contents_while_alive() {
        let secret = SecretBytes::new(vec![0x11, 0x22, 0x33]);

        assert_eq!(secret.expose(), &[0x11, 0x22, 0x33]);
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
    }

    #[test]
    fn secret_bytes_debug_redacts_content() {
        let secret = SecretBytes::new(vec![0xAA, 0xBB, 0xCC]);
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("REDACTED"));
        assert!(debug_str.contains("3 bytes"));
        assert!(!debug_str.contains("AA"));
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

    #[test]
    fn protected_key_round_trip_succeeds() {
        let vault_id = [0x11; 16];
        let private_key = b"test-ml-kem-private-key";

        let record = protect_private_key(
            b"correct-password",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            private_key,
        )
        .unwrap();

        let recovered = unprotect_private_key(b"correct-password", &vault_id, &record).unwrap();

        assert_eq!(recovered.expose(), private_key);
    }

    #[test]
    fn protected_key_rejects_wrong_password() {
        let vault_id = [0x11; 16];

        let record = protect_private_key(
            b"correct-password",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"private-key",
        )
        .unwrap();

        let result = unprotect_private_key(b"wrong-password", &vault_id, &record);

        assert!(matches!(result, Err(ProtectedKeyError::Authentication)));
    }

    #[test]
    fn protected_key_rejects_modified_ciphertext() {
        let vault_id = [0x11; 16];

        let mut record = protect_private_key(
            b"correct-password",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"private-key",
        )
        .unwrap();

        record.ciphertext[0] ^= 0x01;

        let result = unprotect_private_key(b"correct-password", &vault_id, &record);

        assert!(matches!(result, Err(ProtectedKeyError::Authentication)));
    }

    #[test]
    fn protected_key_rejects_wrong_vault_id() {
        let vault_id = [0x11; 16];
        let wrong_vault_id = [0x22; 16];

        let record = protect_private_key(
            b"correct-password",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"private-key",
        )
        .unwrap();

        let result = unprotect_private_key(b"correct-password", &wrong_vault_id, &record);

        assert!(matches!(result, Err(ProtectedKeyError::VaultIdMismatch)));
    }

    #[test]
    fn protected_key_rejects_unsupported_version() {
        let vault_id = [0x11; 16];

        let mut record = protect_private_key(
            b"correct-password",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"private-key",
        )
        .unwrap();

        record.version = 99;

        let result = unprotect_private_key(b"correct-password", &vault_id, &record);

        assert!(matches!(result, Err(ProtectedKeyError::UnsupportedVersion)));
    }

    #[test]
    fn protected_key_purposes_are_separate() {
        let salt = [0x42; ARGON2_SALT_LEN];
        let password_key = derive_password_key(b"test-password", &salt).unwrap();

        let kem_key = derive_subkey(
            password_key.expose(),
            &salt,
            KeyPurpose::KemPrivateKeyProtection,
        )
        .unwrap();

        let dsa_key = derive_subkey(
            password_key.expose(),
            &salt,
            KeyPurpose::DsaPrivateKeyProtection,
        )
        .unwrap();

        assert_ne!(kem_key.expose(), dsa_key.expose());
    }

    // -----------------------------------------------------------------------
    // Day 12 Required Recovery & Persistence Tests (1-15)
    // -----------------------------------------------------------------------

    #[test]
    fn test_01_serialization_round_trip() {
        let vault_id = [0x33; 16];
        let record = protect_private_key(
            b"strong-password-123",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"test-mlkem768-secret-key-material",
        )
        .unwrap();

        let serialized = record.to_bytes();
        assert_eq!(&serialized[0..4], PROTECTED_KEY_MAGIC);

        let deserialized = ProtectedKeyRecord::from_bytes(&serialized).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_02_save_and_load_round_trip() {
        let dir = test_temp_directory("save-load-roundtrip");
        let vault_id = [0x44; 16];
        let record = protect_private_key(
            b"passphrase-xyz",
            vault_id,
            ProtectedKeyKind::MlDsaPrivateKey,
            b"test-mldsa65-secret-key-material",
        )
        .unwrap();

        save_protected_key_record(&dir, "custom_key.qvpk", &record).unwrap();
        let loaded = load_protected_key_record(&dir, "custom_key.qvpk").unwrap();

        assert_eq!(record, loaded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_03_correct_password_recovery_after_loading_from_disk() {
        let dir = test_temp_directory("disk-recovery");
        let vault_id = [0x55; 16];
        let original_key = b"quantum-ml-kem-768-raw-private-key-bytes";

        save_mlkem_private_key(&dir, b"correct-vault-password", vault_id, original_key).unwrap();

        let recovered =
            load_and_recover_mlkem_private_key(&dir, b"correct-vault-password", &vault_id).unwrap();

        assert_eq!(recovered.expose(), original_key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_04_wrong_password_rejected() {
        let dir = test_temp_directory("wrong-pw-recovery");
        let vault_id = [0x55; 16];
        let original_key = b"quantum-ml-kem-768-raw-private-key-bytes";

        save_mlkem_private_key(&dir, b"correct-vault-password", vault_id, original_key).unwrap();

        let result =
            load_and_recover_mlkem_private_key(&dir, b"incorrect-vault-password", &vault_id);

        assert!(matches!(result, Err(ProtectedKeyError::Authentication)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_05_modified_ciphertext_rejection() {
        let dir = test_temp_directory("modified-ct");
        let vault_id = [0x55; 16];
        let original_key = b"quantum-ml-kem-768-raw-private-key-bytes";

        save_mlkem_private_key(&dir, b"correct-vault-password", vault_id, original_key).unwrap();

        // Tamper with the saved file by modifying the ciphertext section
        let file_path = dir.join(MLKEM_PRIVATE_KEY_FILENAME);
        let mut bytes = std::fs::read(&file_path).unwrap();
        let last_idx = bytes.len() - 1;
        bytes[last_idx] ^= 0xFF;
        std::fs::write(&file_path, &bytes).unwrap();

        let result = load_and_recover_mlkem_private_key(&dir, b"correct-vault-password", &vault_id);

        assert!(matches!(result, Err(ProtectedKeyError::Authentication)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_06_wrong_vault_id_rejection() {
        let dir = test_temp_directory("wrong-vault-id");
        let vault_id = [0x66; 16];
        let wrong_vault_id = [0x77; 16];
        let original_key = b"quantum-secret-key-material";

        save_mlkem_private_key(&dir, b"correct-password", vault_id, original_key).unwrap();

        let result = load_and_recover_mlkem_private_key(&dir, b"correct-password", &wrong_vault_id);

        assert!(matches!(result, Err(ProtectedKeyError::VaultIdMismatch)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_07_invalid_magic_bytes() {
        let vault_id = [0x88; 16];
        let record = protect_private_key(
            b"test-pass",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"test-key",
        )
        .unwrap();

        let mut bytes = record.to_bytes();
        bytes[0..4].copy_from_slice(b"BADM");

        let result = ProtectedKeyRecord::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtectedKeyError::InvalidMagic)));
    }

    #[test]
    fn test_08_invalid_key_type() {
        let vault_id = [0x88; 16];
        let record = protect_private_key(
            b"test-pass",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"test-key",
        )
        .unwrap();

        let mut bytes = record.to_bytes();
        bytes[22] = 99; // unknown key type

        let result = ProtectedKeyRecord::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtectedKeyError::UnknownKeyType)));
    }

    #[test]
    fn test_09_unsupported_version() {
        let vault_id = [0x88; 16];
        let record = protect_private_key(
            b"test-pass",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"test-key",
        )
        .unwrap();

        let mut bytes = record.to_bytes();
        bytes[4..6].copy_from_slice(&2_u16.to_be_bytes()); // unsupported version 2

        let result = ProtectedKeyRecord::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtectedKeyError::UnsupportedVersion)));
    }

    #[test]
    fn test_10_truncated_header() {
        let vault_id = [0x88; 16];
        let record = protect_private_key(
            b"test-pass",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"test-key",
        )
        .unwrap();

        let bytes = record.to_bytes();
        // Truncate to less than PROTECTED_KEY_HEADER_SIZE (55 bytes)
        let truncated = &bytes[0..30];

        let result = ProtectedKeyRecord::from_bytes(truncated);
        assert!(matches!(result, Err(ProtectedKeyError::TruncatedHeader)));
    }

    #[test]
    fn test_11_truncated_ciphertext() {
        let vault_id = [0x88; 16];
        let record = protect_private_key(
            b"test-pass",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"test-key",
        )
        .unwrap();

        let bytes = record.to_bytes();
        // Truncate last 4 bytes of ciphertext
        let truncated = &bytes[0..bytes.len() - 4];

        let result = ProtectedKeyRecord::from_bytes(truncated);
        assert!(matches!(
            result,
            Err(ProtectedKeyError::TruncatedCiphertext)
        ));
    }

    #[test]
    fn test_12_incorrect_ciphertext_length() {
        let vault_id = [0x88; 16];
        let record = protect_private_key(
            b"test-pass",
            vault_id,
            ProtectedKeyKind::MlKemPrivateKey,
            b"test-key",
        )
        .unwrap();

        // Sub-case A: ciphertext_len declared is below MIN_CIPHERTEXT_LEN (16)
        let mut bytes_too_small = record.to_bytes();
        bytes_too_small[51..55].copy_from_slice(&5_u32.to_be_bytes());
        let result_small = ProtectedKeyRecord::from_bytes(&bytes_too_small);
        assert!(matches!(
            result_small,
            Err(ProtectedKeyError::InvalidCiphertextLength)
        ));

        // Sub-case B: extra trailing bytes after declared ciphertext length
        let mut bytes_extra = record.to_bytes();
        bytes_extra.extend_from_slice(b"extra-unexpected-bytes");
        let result_extra = ProtectedKeyRecord::from_bytes(&bytes_extra);
        assert!(matches!(
            result_extra,
            Err(ProtectedKeyError::InvalidCiphertextLength)
        ));
    }

    #[test]
    fn test_13_oversized_record() {
        let oversized = vec![0_u8; MAX_PROTECTED_KEY_SIZE + 1];
        let result = ProtectedKeyRecord::from_bytes(&oversized);
        assert!(matches!(result, Err(ProtectedKeyError::OversizedRecord)));
    }

    #[test]
    fn test_14_missing_record() {
        let dir = test_temp_directory("missing-record");
        let result = load_protected_key_record(&dir, "nonexistent-record.qvpk");
        assert!(matches!(result, Err(ProtectedKeyError::MissingRecord)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_15_atomic_replacement_behavior() {
        let dir = test_temp_directory("atomic-replacement");
        let vault_id = [0x99; 16];

        // Save initial record
        save_mlkem_private_key_as(
            &dir,
            "key.qvpk",
            b"initial-password",
            vault_id,
            b"initial-key-data",
        )
        .unwrap();

        let rec1 = recover_private_key(&dir, "key.qvpk", b"initial-password", &vault_id).unwrap();
        assert_eq!(rec1.expose(), b"initial-key-data");

        // Save replacement record to the same filename atomically
        save_mlkem_private_key_as(
            &dir,
            "key.qvpk",
            b"updated-password",
            vault_id,
            b"updated-key-data",
        )
        .unwrap();

        let rec2 = recover_private_key(&dir, "key.qvpk", b"updated-password", &vault_id).unwrap();
        assert_eq!(rec2.expose(), b"updated-key-data");

        // Old password must fail on updated file
        let old_pw_result = recover_private_key(&dir, "key.qvpk", b"initial-password", &vault_id);
        assert!(matches!(
            old_pw_result,
            Err(ProtectedKeyError::Authentication)
        ));

        // Ensure no leftover temporary files in directory
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".quantumvault-")
            })
            .collect();
        assert!(
            entries.is_empty(),
            "Found leftover temporary files: {:?}",
            entries
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
