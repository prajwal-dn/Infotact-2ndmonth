# QuantumVault Architecture

## Project Goal
QuantumVault is a Linux virtual filesystem prototype
that provides transparent file encryption using
post-quantum cryptographic key establishment.

## Components

- filesystem: Rust FUSE filesystem operations.
- crypto: Cryptographic interfaces and C/liboqs integration.
- key_manager: Key lifecycle and key derivation.
- storage: Encrypted file and metadata storage.
- cli: Vault initialization and mount management.

## Cryptographic Design

- ML-KEM-768: Post-quantum key establishment.
- ML-DSA-65: Post-quantum digital signatures.
- HKDF-SHA-256: Key derivation.
- AES-256-GCM: Authenticated file encryption.

## Security Notes

ML-KEM does not directly encrypt file contents.
AES-256-GCM protects file data.
ML-DSA signatures do not replace authenticated encryption.

This project is an educational internship prototype,
not a production-audited filesystem.
