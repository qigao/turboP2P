/**
 * P2P cryptographic boundary for stable X25519 identity and the pinned
 * Noise-C XX/ChaChaPoly/BLAKE2s state machine.
 */

#include "p2p_crypto.h"
#include "../internal.h"
#include <salts/crypto.h>
#include <salts/random.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <limits.h>
#include <string.h>

static const uint8_t P2P_NOISE_PROLOGUE[] =
    "TurboP2P secure wire v2\0Noise_XX_25519_ChaChaPoly_BLAKE2s";

/* =============================================================================
 * Random Number Generation
 * ============================================================================= */

int p2p_crypto_random(uint8_t *buf, size_t len) {
    if (!buf && len > 0) {
        return P2P_ERR_INVALID_ARG;
    }
    if (salts_platform_secure_random(buf, len) != 0) {
        if (buf && len > 0) {
            OPENSSL_cleanse(buf, len);
        }
        return P2P_ERR_CRYPTO;
    }
    return P2P_OK;
}

int p2p_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t output[32]) {
    unsigned int output_len = 0;
    if ((!key && key_len != 0) || (!data && data_len != 0) || !output ||
        key_len > INT_MAX) {
        return P2P_ERR_INVALID_ARG;
    }
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, output,
              &output_len) ||
        output_len != 32U) {
        OPENSSL_cleanse(output, 32);
        return P2P_ERR_CRYPTO;
    }
    return P2P_OK;
}

int p2p_crypto_verify(const uint8_t *expected, const uint8_t *actual,
                      size_t len) {
    if ((!expected || !actual) && len != 0) {
        return 0;
    }
    if (len == 0) {
        return 1;
    }
    return CRYPTO_memcmp(expected, actual, len) == 0;
}

static int p2p_crypto_x25519_public_key(
    uint8_t public_key[P2P_KEY_SIZE],
    const uint8_t secret_key[P2P_KEY_SIZE]) {
    EVP_PKEY *key = NULL;
    size_t public_size = P2P_KEY_SIZE;
    int result = P2P_ERR_CRYPTO;
    if (!public_key || !secret_key) return P2P_ERR_INVALID_ARG;
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret_key,
                                       P2P_KEY_SIZE);
    if (key &&
        EVP_PKEY_get_raw_public_key(key, public_key, &public_size) == 1 &&
        public_size == P2P_KEY_SIZE) {
        result = P2P_OK;
    } else {
        OPENSSL_cleanse(public_key, P2P_KEY_SIZE);
    }
    EVP_PKEY_free(key);
    return result;
}

/* =============================================================================
 * Identity Management
 * ============================================================================= */

int p2p_crypto_generate_identity(p2p_identity_t *identity) {
    p2p_identity_t generated = {0};
    int ret = P2P_OK;

    if (!identity) return P2P_ERR_INVALID_ARG;

    ret = p2p_crypto_random(generated.secret_key, P2P_KEY_SIZE);
    if (ret != P2P_OK) {
        OPENSSL_cleanse(&generated, sizeof(generated));
        return ret;
    }

    if (p2p_crypto_x25519_public_key(generated.public_key,
                                      generated.secret_key) != P2P_OK) {
        OPENSSL_cleanse(&generated, sizeof(generated));
        return P2P_ERR_CRYPTO;
    }
    p2p_crypto_wipe(identity, sizeof(*identity));
    memcpy(identity, &generated, sizeof(*identity));
    OPENSSL_cleanse(&generated, sizeof(generated));

    return P2P_OK;
}

int p2p_crypto_identity_from_secret(p2p_identity_t *identity,
                                    const uint8_t secret_key[P2P_KEY_SIZE]) {
    p2p_identity_t loaded = {0};

    if (!identity || !secret_key) return P2P_ERR_INVALID_ARG;

    memcpy(loaded.secret_key, secret_key, P2P_KEY_SIZE);
    if (p2p_crypto_x25519_public_key(loaded.public_key,
                                      loaded.secret_key) != P2P_OK) {
        p2p_crypto_wipe(&loaded, sizeof(loaded));
        return P2P_ERR_CRYPTO;
    }
    p2p_crypto_wipe(identity, sizeof(*identity));
    memcpy(identity, &loaded, sizeof(*identity));
    p2p_crypto_wipe(&loaded, sizeof(loaded));
    return P2P_OK;
}

int p2p_crypto_identity_from_provider(
    p2p_identity_t *identity,
    const p2p_private_key_provider_v3_t *provider,
    const uint8_t public_key[P2P_KEY_SIZE]) {
    p2p_identity_t loaded = {0};

    if (!identity || !provider || !public_key ||
        provider->struct_size != sizeof(*provider) ||
        !provider->get_public_key || !provider->calculate_x25519) {
        return P2P_ERR_INVALID_ARG;
    }
    memcpy(loaded.public_key, public_key, sizeof(loaded.public_key));
    loaded.private_key_provider = *provider;
    loaded.uses_private_key_provider = 1;
    p2p_crypto_wipe(identity, sizeof(*identity));
    memcpy(identity, &loaded, sizeof(*identity));
    p2p_crypto_wipe(&loaded, sizeof(loaded));
    return P2P_OK;
}

int p2p_crypto_identity_from_blocking_provider(
    p2p_identity_t *identity,
    const p2p_blocking_private_key_provider_v4_t *provider,
    const uint8_t public_key[P2P_KEY_SIZE]) {
    p2p_identity_t loaded = {0};

    if (!identity || !provider || !public_key ||
        provider->struct_size != sizeof(*provider) ||
        !provider->get_public_key || !provider->calculate_x25519) {
        return P2P_ERR_INVALID_ARG;
    }
    memcpy(loaded.public_key, public_key, sizeof(loaded.public_key));
    loaded.blocking_private_key_provider = *provider;
    loaded.uses_blocking_private_key_provider = 1;
    p2p_crypto_wipe(identity, sizeof(*identity));
    memcpy(identity, &loaded, sizeof(*identity));
    p2p_crypto_wipe(&loaded, sizeof(loaded));
    return P2P_OK;
}

/* =============================================================================
 * Memory Wiping
 * ============================================================================= */

void p2p_crypto_wipe(void *data, size_t len) {
    if (data && len > 0) OPENSSL_cleanse(data, len);
}

/* =============================================================================
 * Session Management
 * ============================================================================= */

int p2p_crypto_session_is_ready(const p2p_crypto_session_t *sess) {
    return sess && sess->ready;
}

void p2p_crypto_session_destroy(p2p_crypto_session_t *sess) {
    p2p_noise_backend_session_destroy(sess);
}

int p2p_crypto_encrypt(p2p_crypto_session_t *sess,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len) {
    size_t capacity;

    if (pt_len > SIZE_MAX - P2P_NOISE_TAG_SIZE) {
        return P2P_ERR_INVALID_ARG;
    }
    capacity = pt_len + P2P_NOISE_TAG_SIZE;
    return p2p_noise_backend_encrypt(sess, pt, pt_len, ct, capacity, ct_len);
}

int p2p_crypto_decrypt(p2p_crypto_session_t *sess,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t pt_capacity, size_t *pt_len) {
    return p2p_noise_backend_decrypt(sess, ct, ct_len, pt, pt_capacity,
                                     pt_len);
}

int p2p_noise_init_initiator(p2p_noise_handshake_t *hs,
                             const p2p_identity_t *identity,
                             const uint8_t *remote_public) {
    (void)remote_public;
    return p2p_noise_init_v2(hs, identity, 1, P2P_NOISE_PROLOGUE,
                             sizeof(P2P_NOISE_PROLOGUE) - 1);
}

int p2p_noise_init_responder(p2p_noise_handshake_t *hs,
                             const p2p_identity_t *identity) {
    return p2p_noise_init_v2(hs, identity, 0, P2P_NOISE_PROLOGUE,
                             sizeof(P2P_NOISE_PROLOGUE) - 1);
}

int p2p_noise_init_v2(p2p_noise_handshake_t *hs,
                      const p2p_identity_t *identity,
                      int is_initiator,
                      const uint8_t *prologue,
                      size_t prologue_len) {
    if (!identity) {
        return P2P_ERR_INVALID_ARG;
    }
    if (identity->uses_private_key_provider) {
        return p2p_noise_backend_init_with_provider(
            hs, is_initiator, identity->public_key,
            &identity->private_key_provider, prologue, prologue_len);
    }
    if (identity->uses_blocking_private_key_provider) {
        return p2p_noise_backend_init_with_blocking_provider(
            hs, is_initiator, identity->public_key,
            &identity->blocking_private_key_provider, prologue,
            prologue_len);
    }
    return p2p_noise_backend_init(hs, is_initiator, identity->secret_key,
                                  prologue, prologue_len);
}

int p2p_noise_write_message(p2p_noise_handshake_t *hs,
                            uint8_t *out, size_t *out_len, size_t max_len) {
    return p2p_noise_write_message_with_payload(hs, NULL, 0, out, out_len,
                                                max_len);
}

int p2p_noise_write_message_with_payload(p2p_noise_handshake_t *hs,
                                         const uint8_t *payload,
                                         size_t payload_len,
                                         uint8_t *out, size_t *out_len,
                                         size_t max_len) {
    return p2p_noise_backend_write(hs, payload, payload_len, out, max_len,
                                   out_len);
}

int p2p_noise_write_message_with_payload_blocking(
    p2p_noise_handshake_t *hs,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t monotonic_deadline_ms,
    const p2p_private_key_cancel_v4_t *cancel,
    uint8_t *out,
    size_t *out_len,
    size_t max_len) {
    return p2p_noise_backend_write_blocking(
        hs, payload, payload_len, monotonic_deadline_ms, cancel, out,
        max_len, out_len);
}

int p2p_noise_read_message(p2p_noise_handshake_t *hs,
                           const uint8_t *data, size_t len) {
    uint8_t empty_payload[1];
    size_t payload_len = 0;

    return p2p_noise_read_message_with_payload(
        hs, data, len, empty_payload, sizeof(empty_payload), &payload_len);
}

int p2p_noise_read_message_with_payload(p2p_noise_handshake_t *hs,
                                        const uint8_t *data, size_t len,
                                        uint8_t *payload,
                                        size_t payload_capacity,
                                        size_t *payload_len) {
    return p2p_noise_backend_read(hs, data, len, payload, payload_capacity,
                                  payload_len);
}

int p2p_noise_is_complete(const p2p_noise_handshake_t *hs) {
    return p2p_noise_backend_is_ready_to_split(hs);
}

int p2p_noise_split(const p2p_noise_handshake_t *hs,
                    p2p_crypto_session_t *sess) {
    return p2p_noise_backend_split((p2p_noise_handshake_t *)hs, sess);
}

void p2p_noise_handshake_destroy(p2p_noise_handshake_t *hs) {
    p2p_noise_backend_handshake_destroy(hs);
}

/* =============================================================================
 * SHA-256
 * ============================================================================= */

void p2p_crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    if (!hash) return;
    if ((!data && len != 0) ||
        salts_crypto_sha256(data, len, hash) != SALTS_CRYPTO_OK) {
        OPENSSL_cleanse(hash, 32);
    }
}
