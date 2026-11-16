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
