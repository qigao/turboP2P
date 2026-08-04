#include "mesh_mgmt_crypto.h"

#include <turbo_crypto.h>
#include <openssl/evp.h>

#include <string.h>

/* Ed25519 signatures must stay on the OpenSSL EVP provider: TurboNet::Crypto
 * currently exposes Monocypher's BLAKE2b-based EdDSA, which is not RFC 8032
 * (SHA-512) compatible and would change the wire format of every signed
 * envelope and peer record.  The remaining primitives (BLAKE2b-256,
 * constant-time compare, secure wipe) come from TurboNet::Crypto. */

mesh_mgmt_crypto_result_t
mesh_mgmt_ed25519_public_from_private(const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
                                      uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE]) {
  EVP_PKEY *key = NULL;
  size_t public_key_len = MESH_MGMT_ED25519_PUBLIC_KEY_SIZE;
  mesh_mgmt_crypto_result_t result = MESH_MGMT_CRYPTO_FAILURE;

  if (!public_key) {
    return MESH_MGMT_CRYPTO_INVALID_ARG;
  }
  memset(public_key, 0, MESH_MGMT_ED25519_PUBLIC_KEY_SIZE);
  if (!private_key) {
    return MESH_MGMT_CRYPTO_INVALID_ARG;
  }
  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key,
                                     MESH_MGMT_ED25519_PRIVATE_KEY_SIZE);
  if (!key) {
    goto cleanup;
  }
  if (EVP_PKEY_get_raw_public_key(key, public_key, &public_key_len) != 1 ||
      public_key_len != MESH_MGMT_ED25519_PUBLIC_KEY_SIZE) {
    memset(public_key, 0, MESH_MGMT_ED25519_PUBLIC_KEY_SIZE);
    goto cleanup;
  }
  result = MESH_MGMT_CRYPTO_OK;

cleanup:
  EVP_PKEY_free(key);
  return result;
}

mesh_mgmt_crypto_result_t
mesh_mgmt_ed25519_sign(const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE],
                       const uint8_t *message, size_t message_len,
                       uint8_t signature[MESH_MGMT_ED25519_SIGNATURE_SIZE]) {
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  size_t signature_len = MESH_MGMT_ED25519_SIGNATURE_SIZE;
  mesh_mgmt_crypto_result_t result = MESH_MGMT_CRYPTO_FAILURE;

  if (!signature) {
    return MESH_MGMT_CRYPTO_INVALID_ARG;
  }
  memset(signature, 0, MESH_MGMT_ED25519_SIGNATURE_SIZE);
  if (!private_key || (!message && message_len != 0u)) {
    return MESH_MGMT_CRYPTO_INVALID_ARG;
  }
  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key,
                                     MESH_MGMT_ED25519_PRIVATE_KEY_SIZE);
  context = EVP_MD_CTX_new();
  if (!key || !context) {
    goto cleanup;
  }
  if (EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1 ||
      EVP_DigestSign(context, signature, &signature_len, message, message_len) != 1 ||
      signature_len != MESH_MGMT_ED25519_SIGNATURE_SIZE) {
    memset(signature, 0, MESH_MGMT_ED25519_SIGNATURE_SIZE);
    goto cleanup;
  }
  result = MESH_MGMT_CRYPTO_OK;

cleanup:
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

mesh_mgmt_crypto_result_t
mesh_mgmt_ed25519_verify(const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
                         const uint8_t *message, size_t message_len,
                         const uint8_t signature[MESH_MGMT_ED25519_SIGNATURE_SIZE]) {
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  mesh_mgmt_crypto_result_t result = MESH_MGMT_CRYPTO_FAILURE;
  int verify_result = 0;

  if (!public_key || (!message && message_len != 0u) || !signature) {
    return MESH_MGMT_CRYPTO_INVALID_ARG;
  }
  key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key,
                                    MESH_MGMT_ED25519_PUBLIC_KEY_SIZE);
  context = EVP_MD_CTX_new();
  if (!key || !context || EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) != 1) {
    goto cleanup;
  }
  verify_result = EVP_DigestVerify(context, signature, MESH_MGMT_ED25519_SIGNATURE_SIZE,
                                   message, message_len);
  if (verify_result == 1) {
    result = MESH_MGMT_CRYPTO_OK;
  } else if (verify_result == 0) {
    result = MESH_MGMT_CRYPTO_AUTH_FAILED;
  }

cleanup:
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

mesh_mgmt_crypto_result_t mesh_mgmt_blake2b_256(const uint8_t *message, size_t message_len,
                                                uint8_t digest[MESH_MGMT_BLAKE2B_256_SIZE]) {
  if (!digest) {
    return MESH_MGMT_CRYPTO_INVALID_ARG;
  }
  memset(digest, 0, MESH_MGMT_BLAKE2B_256_SIZE);
  if (!message && message_len != 0u) {
    return MESH_MGMT_CRYPTO_INVALID_ARG;
  }
  if (turbo_crypto_blake2b(digest, MESH_MGMT_BLAKE2B_256_SIZE, message, message_len) !=
      TURBO_CRYPTO_OK) {
    return MESH_MGMT_CRYPTO_FAILURE;
  }
  return MESH_MGMT_CRYPTO_OK;
}

int mesh_mgmt_crypto_equal_32(const uint8_t lhs[MESH_MGMT_BLAKE2B_256_SIZE],
                              const uint8_t rhs[MESH_MGMT_BLAKE2B_256_SIZE]) {
  if (!lhs || !rhs) {
    return 0;
  }
  return turbo_crypto_verify(lhs, rhs, MESH_MGMT_BLAKE2B_256_SIZE) == TURBO_CRYPTO_OK ? 1 : 0;
}

int mesh_mgmt_crypto_equal_16(const uint8_t lhs[16], const uint8_t rhs[16]) {
  if (!lhs || !rhs) {
    return 0;
  }
  return turbo_crypto_verify(lhs, rhs, 16u) == TURBO_CRYPTO_OK ? 1 : 0;
}

void mesh_mgmt_crypto_wipe(void *data, size_t length) {
  turbo_crypto_wipe(data, length);
}
