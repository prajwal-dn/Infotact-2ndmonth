#include <oqs/oqs.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int qv_mlkem768_self_test(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) return 1;

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);

    int result = 2;
    if (!pk || !sk || !ct || !ss1 || !ss2) goto cleanup;

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        result = 3; goto cleanup;
    }
    if (OQS_KEM_encaps(kem, ct, ss1, pk) != OQS_SUCCESS) {
        result = 4; goto cleanup;
    }
    if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) {
        result = 5; goto cleanup;
    }

    result = memcmp(ss1, ss2, kem->length_shared_secret) == 0 ? 0 : 6;

cleanup:
    if (sk) OQS_MEM_cleanse(sk, kem->length_secret_key);
    if (ss1) OQS_MEM_cleanse(ss1, kem->length_shared_secret);
    if (ss2) OQS_MEM_cleanse(ss2, kem->length_shared_secret);
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    OQS_KEM_free(kem);
    return result;
}

/* ML-DSA-65 C-level self-test for the Rust FFI bridge. */
int qv_mldsa65_self_test(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) return 10;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    int result = 11;
    if (!pk || !sk || !signature) goto cleanup;

    static const uint8_t message[] = "QuantumVault ML-DSA-65 Rust FFI test";
    static const uint8_t altered[] = "QuantumVault ML-DSA-65 altered test";
    size_t signature_len = 0;

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        result = 12;
        goto cleanup;
    }

    if (OQS_SIG_sign(sig, signature, &signature_len,
                     message, sizeof(message) - 1, sk) != OQS_SUCCESS) {
        result = 13;
        goto cleanup;
    }

    if (signature_len > sig->length_signature) {
        result = 16;
        goto cleanup;
    }

    if (OQS_SIG_verify(sig, message, sizeof(message) - 1,
                       signature, signature_len, pk) != OQS_SUCCESS) {
        result = 14;
        goto cleanup;
    }

    if (OQS_SIG_verify(sig, altered, sizeof(altered) - 1,
                       signature, signature_len, pk) == OQS_SUCCESS) {
        result = 15;
        goto cleanup;
    }

    result = 0;

cleanup:
    if (sk) OQS_MEM_cleanse(sk, sig->length_secret_key);
    free(pk);
    free(sk);
    free(signature);
    OQS_SIG_free(sig);
    return result;
}
