#ifndef TURBO_P2P_MESH_MGMT_CRYPTO_H
#define TURBO_P2P_MESH_MGMT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_ED25519_PRIVATE_KEY_SIZE 32u
#define MESH_MGMT_ED25519_PUBLIC_KEY_SIZE 32u
#define MESH_MGMT_ED25519_SIGNATURE_SIZE 64u
#define MESH_MGMT_BLAKE2B_256_SIZE 32u

typedef enum {
  MESH_MGMT_CRYPTO_OK = 0,
  MESH_MGMT_CRYPTO_INVALID_ARG = -1,
  MESH_MGMT_CRYPTO_FAILURE = -2,
  MESH_MGMT_CRYPTO_AUTH_FAILED = -3,
} mesh_mgmt_crypto_result_t;

mesh_mgmt_crypto_result_t
mesh_mgmt_ed25519_public_from_private(const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
                                      uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE]);

mesh_mgmt_crypto_result_t
mesh_mgmt_ed25519_sign(const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
                       const uint8_t *message, size_t message_len,
                       uint8_t signature[MESH_MGMT_ED25519_SIGNATURE_SIZE]);

mesh_mgmt_crypto_result_t
mesh_mgmt_ed25519_verify(const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
                         const uint8_t *message, size_t message_len,
                         const uint8_t signature[MESH_MGMT_ED25519_SIGNATURE_SIZE]);

mesh_mgmt_crypto_result_t mesh_mgmt_blake2b_256(const uint8_t *message, size_t message_len,
                                                uint8_t digest[MESH_MGMT_BLAKE2B_256_SIZE]);

/** Return 1 when both 32-byte values are equal, otherwise 0. */
int mesh_mgmt_crypto_equal_32(const uint8_t lhs[MESH_MGMT_BLAKE2B_256_SIZE],
                              const uint8_t rhs[MESH_MGMT_BLAKE2B_256_SIZE]);

/** Return 1 when both 16-byte values are equal, otherwise 0. */
int mesh_mgmt_crypto_equal_16(const uint8_t lhs[16], const uint8_t rhs[16]);

/** Prevent the compiler from eliding sensitive-memory clearing. */
void mesh_mgmt_crypto_wipe(void *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif
