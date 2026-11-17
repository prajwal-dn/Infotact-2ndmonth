#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "FAIL: ML-DSA-65 unavailable\n");
        return 1;
    }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    if (!pk || !sk || !signature) {
        fprintf(stderr, "FAIL: allocation failed\n");
        free(pk); free(sk); free(signature);
        OQS_SIG_free(sig);
        return 1;
    }

    const uint8_t message[] = "QuantumVault ML-DSA-65 smoke test";
    size_t signature_len = 0;
    int result = 1;

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: key generation\n");
        goto cleanup;
    }

    if (OQS_SIG_sign(sig, signature, &signature_len,
                     message, sizeof(message) - 1, sk) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: signing\n");
        goto cleanup;
    }

    if (signature_len > sig->length_signature ||
        OQS_SIG_verify(sig, message, sizeof(message) - 1,
                       signature, signature_len, pk) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: signature verification\n");
        goto cleanup;
    }

    uint8_t altered[] = "QuantumVault ML-DSA-65 altered test";
    if (OQS_SIG_verify(sig, altered, sizeof(altered) - 1,
                       signature, signature_len, pk) == OQS_SUCCESS) {
        fprintf(stderr, "FAIL: altered message was accepted\n");
        goto cleanup;
    }

    printf("PASS: ML-DSA-65 key generation\n");
    printf("PASS: ML-DSA-65 signing and verification\n");
    printf("PASS: altered message rejected\n");
    printf("Signature length: %zu bytes\n", signature_len);
    result = 0;

cleanup:
    OQS_MEM_cleanse(sk, sig->length_secret_key);
    free(pk);
    free(sk);
    free(signature);
    OQS_SIG_free(sig);
    return result;
}
