#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "FAIL: ML-KEM-768 unavailable\n");
        return 1;
    }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss1 || !ss2) {
        fprintf(stderr, "FAIL: allocation\n");
        free(pk); free(sk); free(ct); free(ss1); free(ss2);
        OQS_KEM_free(kem);
        return 1;
    }

    int result = 1;

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: keypair\n");
        goto cleanup;
    }
    if (OQS_KEM_encaps(kem, ct, ss1, pk) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: encapsulation\n");
        goto cleanup;
    }
    if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: decapsulation\n");
        goto cleanup;
    }
    if (memcmp(ss1, ss2, kem->length_shared_secret) != 0) {
        fprintf(stderr, "FAIL: shared secrets differ\n");
        goto cleanup;
    }

    printf("PASS: ML-KEM-768 keypair, encapsulation, decapsulation\n");
    printf("PASS: shared secrets match (%zu bytes)\n", kem->length_shared_secret);
    result = 0;

cleanup:
    OQS_MEM_cleanse(sk, kem->length_secret_key);
    OQS_MEM_cleanse(ss1, kem->length_shared_secret);
    OQS_MEM_cleanse(ss2, kem->length_shared_secret);
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    OQS_KEM_free(kem);
    return result;
}
