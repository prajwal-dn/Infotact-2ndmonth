# QuantumVault Test Matrix (Aman)

**Status:** Planning phase. Tests will be implemented against actual code once APIs are implemented.

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

## 4. Filesystem Integration Tests (Planned)
- [ ] Create, Read, Update, Delete (CRUD) files
- [ ] Empty files (0 bytes)
- [ ] Binary files
- [ ] Offset-based reads (read from middle of file)
- [ ] Repeated writes to same file
- [ ] Directory listing (ls)
- [ ] Large files (>10MB)
- [ ] Unmount/Remount persistence (data survives)
- [ ] Nonce/AAD persistence and crash recovery (verify counters don't reset)

## 5. Key Manager Tests (Planned)
- [ ] Vault initialization
- [ ] Unlock with correct password
- [ ] Fail unlock with wrong password
- [ ] Key file permissions check
- [ ] Malformed key record rejection
- [ ] Restart/remount recovery

## Notes
- Writes are currently disabled per API contract.
- No crypto integration exists yet (static hello.txt only).
