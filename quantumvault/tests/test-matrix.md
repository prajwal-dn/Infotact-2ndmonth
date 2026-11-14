# QuantumVault Test Matrix (Aman)

**Status:** FUSE layer tested. Crypto APIs pending implementation.

## 1. ML-KEM-768 Tests (Planned)
- [ ] Encapsulation/Decapsulation produces matching shared secrets
- [ ] Invalid ciphertext fails gracefully
- [ ] Wrong key decapsulation fails

## 2. ML-DSA-65 Tests (Planned)
- [ ] Valid signature verifies successfully
- [ ] Modified message fails verification
- [ ] Modified signature fails verification
- [ ] Wrong public key fails verification

## 3. AES-256-GCM Tests (Planned)
- [ ] Round-trip encryption/decryption works
- [ ] Wrong key fails authentication
- [ ] Modified ciphertext fails authentication (tamper)
- [ ] Modified AAD fails authentication (tamper)
- [ ] Invalid tag is rejected
- [ ] Boundary sizes (0 bytes, 1 byte, 64KB, etc.)

## 4. Filesystem Integration Tests (Completed & Planned)
- [x] Mount & Setup
- [x] Create, Read, Update, Delete (CRUD) files
- [x] Append (O_APPEND)
- [x] Truncate (O_TRUNC)
- [x] Permissions (chmod)
- [x] Unmount & Cleanup
- [ ] Empty files (0 bytes)
- [ ] Binary files
- [ ] Offset-based reads (read from middle of file)
- [ ] Repeated writes to same file
- [ ] Directory listing (ls)
- [ ] Large files (>10MB)
- [ ] Unmount/Remount persistence (data survives) - *Pending storage integration*
- [ ] Nonce/AAD persistence and crash recovery - *Pending crypto integration*

## 5. Key Manager Tests (Planned)
- [ ] Vault initialization
- [ ] Unlock with correct password
- [ ] Fail unlock with wrong password
- [ ] Key file permissions check
- [ ] Malformed key record rejection
- [ ] Restart/remount recovery

## Notes
- FUSE tests passed on commit 71e2e6a.
- Writes are currently in-memory and plaintext.
- No crypto integration exists yet.
