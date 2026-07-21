#include <tinytest.h>

#include "mesh_mgmt_crypto.h"

#include <string.h>

static const uint8_t RFC8032_PRIVATE_KEY[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t RFC8032_PUBLIC_KEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

static const uint8_t RFC8032_SIGNATURE[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
};

static const uint8_t BLAKE2B_256_EMPTY[32] = {
    0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2,
    0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda, 0xa1,
    0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87,
    0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8,
};

static void test_crypto_matches_rfc8032_empty_message_vector(void) {
    uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE] = {0};
    uint8_t signature[MESH_MGMT_ED25519_SIGNATURE_SIZE] = {0};

    check_int_eq(mesh_mgmt_ed25519_public_from_private(
                     RFC8032_PRIVATE_KEY, public_key),
                 MESH_MGMT_CRYPTO_OK);
    check_mem_eq(public_key, RFC8032_PUBLIC_KEY, sizeof(public_key));
    check_int_eq(mesh_mgmt_ed25519_sign(RFC8032_PRIVATE_KEY, NULL, 0,
                                        signature),
                 MESH_MGMT_CRYPTO_OK);
    check_mem_eq(signature, RFC8032_SIGNATURE, sizeof(signature));
    check_int_eq(mesh_mgmt_ed25519_verify(RFC8032_PUBLIC_KEY, NULL, 0,
                                          RFC8032_SIGNATURE),
                 MESH_MGMT_CRYPTO_OK);
}

static void test_crypto_rejects_modified_signature(void) {
    uint8_t signature[MESH_MGMT_ED25519_SIGNATURE_SIZE];

    memcpy(signature, RFC8032_SIGNATURE, sizeof(signature));
    signature[0] ^= 0x01u;
    check_int_eq(mesh_mgmt_ed25519_verify(RFC8032_PUBLIC_KEY, NULL, 0,
                                          signature),
                 MESH_MGMT_CRYPTO_AUTH_FAILED);
}

static void test_crypto_matches_blake2b_256_empty_vector(void) {
    uint8_t digest[MESH_MGMT_BLAKE2B_256_SIZE] = {0};

    check_int_eq(mesh_mgmt_blake2b_256(NULL, 0, digest),
                 MESH_MGMT_CRYPTO_OK);
    check_mem_eq(digest, BLAKE2B_256_EMPTY, sizeof(digest));
    check_int_eq(mesh_mgmt_crypto_equal_32(digest, BLAKE2B_256_EMPTY), 1);
    digest[0] ^= 0x01u;
    check_int_eq(mesh_mgmt_crypto_equal_32(digest, BLAKE2B_256_EMPTY), 0);
    check_int_eq(mesh_mgmt_crypto_equal_32(NULL, BLAKE2B_256_EMPTY), 0);
    digest[0] ^= 0x01u;
    check_int_eq(mesh_mgmt_crypto_equal_16(digest, BLAKE2B_256_EMPTY), 1);
    digest[0] ^= 0x01u;
    check_int_eq(mesh_mgmt_crypto_equal_16(digest, BLAKE2B_256_EMPTY), 0);
    check_int_eq(mesh_mgmt_crypto_equal_16(NULL, BLAKE2B_256_EMPTY), 0);
}

static void test_crypto_rejects_invalid_arguments(void) {
    uint8_t output[MESH_MGMT_ED25519_SIGNATURE_SIZE] = {0};

    memset(output, 0xa5, sizeof(output));
    check_int_eq(mesh_mgmt_ed25519_public_from_private(NULL, output),
                 MESH_MGMT_CRYPTO_INVALID_ARG);
    check_mem_eq(output, (uint8_t[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE]){0},
                 MESH_MGMT_ED25519_PUBLIC_KEY_SIZE);
    memset(output, 0xa5, sizeof(output));
    check_int_eq(mesh_mgmt_ed25519_sign(RFC8032_PRIVATE_KEY, NULL, 1, output),
                 MESH_MGMT_CRYPTO_INVALID_ARG);
    check_mem_eq(output, (uint8_t[MESH_MGMT_ED25519_SIGNATURE_SIZE]){0},
                 MESH_MGMT_ED25519_SIGNATURE_SIZE);
    check_int_eq(mesh_mgmt_ed25519_verify(RFC8032_PUBLIC_KEY, NULL, 1,
                                          RFC8032_SIGNATURE),
                 MESH_MGMT_CRYPTO_INVALID_ARG);
    memset(output, 0xa5, sizeof(output));
    check_int_eq(mesh_mgmt_blake2b_256(NULL, 1, output),
                 MESH_MGMT_CRYPTO_INVALID_ARG);
    check_mem_eq(output, (uint8_t[MESH_MGMT_BLAKE2B_256_SIZE]){0},
                 MESH_MGMT_BLAKE2B_256_SIZE);
}

spec("mesh management crypto") {
    describe("standard primitives") {
        it("matches the RFC 8032 Ed25519 empty-message vector") {
            test_crypto_matches_rfc8032_empty_message_vector();
        }
        it("rejects a modified Ed25519 signature") {
            test_crypto_rejects_modified_signature();
        }
        it("matches the BLAKE2b-256 empty-message vector") {
            test_crypto_matches_blake2b_256_empty_vector();
        }
        it("rejects invalid pointers before entering crypto providers") {
            test_crypto_rejects_invalid_arguments();
        }
    }
}
