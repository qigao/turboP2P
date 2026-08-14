/**
 * P2P Crypto Module
 * Noise XX identity handshake and transport encryption.
 */
#ifndef P2P_CRYPTO_H
#define P2P_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "../../include/p2p.h"

/**
 * Identity (Permanent Keypair)
 */
typedef struct {
    uint8_t public_key[P2P_KEY_SIZE];
    uint8_t secret_key[P2P_KEY_SIZE];
    p2p_private_key_provider_v3_t private_key_provider;
    p2p_blocking_private_key_provider_v4_t blocking_private_key_provider;
    int uses_private_key_provider;
    int uses_blocking_private_key_provider;
} p2p_identity_t;

#include "../security/p2p_noise_backend.h"

typedef p2p_noise_backend_session_t p2p_crypto_session_t;

/**
 * Handshake State
 */
typedef p2p_noise_backend_handshake_t p2p_noise_handshake_t;

int p2p_noise_init_v2(p2p_noise_handshake_t *hs,
                      const p2p_identity_t *identity,
                      int is_initiator,
                      const uint8_t *prologue,
                      size_t prologue_len);

/**
 * Generate a new identity (keypair)
 */
int p2p_crypto_generate_identity(p2p_identity_t *identity);

/**
 * Load an identity from a caller-provided 32-byte secret key.
 */
int p2p_crypto_identity_from_secret(p2p_identity_t *identity,
                                    const uint8_t secret_key[P2P_KEY_SIZE]);

/** Install an already validated opaque provider and public key. */
int p2p_crypto_identity_from_provider(
    p2p_identity_t *identity,
    const p2p_private_key_provider_v3_t *provider,
    const uint8_t public_key[P2P_KEY_SIZE]);

/** Install an already validated blocking opaque provider and public key. */
int p2p_crypto_identity_from_blocking_provider(
    p2p_identity_t *identity,
    const p2p_blocking_private_key_provider_v4_t *provider,
    const uint8_t public_key[P2P_KEY_SIZE]);

/**
 * Securely wipe memory
 */
void p2p_crypto_wipe(void *data, size_t len);

/**
 * Check if crypto session is ready for encryption
 */
int p2p_crypto_session_is_ready(const p2p_crypto_session_t *sess);

/**
 * Destroy and wipe crypto session
 */
void p2p_crypto_session_destroy(p2p_crypto_session_t *sess);

/**
 * Encrypt data with session
 * @param sess Active session
 * @param pt Plaintext
 * @param pt_len Plaintext length
 * @param ct Ciphertext output (must be pt_len + P2P_NOISE_TAG_SIZE bytes)
 * @param ct_len Output ciphertext length
 * @return P2P_OK on success, P2P_ERR_CRYPTO when the counter is exhausted
 */
int p2p_crypto_encrypt(p2p_crypto_session_t *sess,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len);

/**
 * Decrypt data with session
 * @param sess Active session
 * @param ct Ciphertext and authentication tag
 * @param ct_len Ciphertext length
 * @param pt Plaintext output scratch buffer
 * @param pt_capacity Output capacity; must be at least ct_len because the
 * Noise backend authenticates in place before shortening the buffer
 * @param pt_len Output plaintext length
 * The session accepts only the next expected counter because its transport is
 * reliable and ordered. Duplicate and out-of-order frames are rejected.
 * @return P2P_OK on success, P2P_ERR_CRYPTO on authentication, replay,
 *         ordering, or counter-exhaustion failure
 */
int p2p_crypto_decrypt(p2p_crypto_session_t *sess,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t pt_capacity, size_t *pt_len);

/**
 * Initialize a Noise XX handshake as initiator
 */
int p2p_noise_init_initiator(p2p_noise_handshake_t *hs,
                             const p2p_identity_t *identity,
                             const uint8_t *remote_public);

/**
 * Initialize a Noise XX handshake as responder
 */
int p2p_noise_init_responder(p2p_noise_handshake_t *hs,
                             const p2p_identity_t *identity);

/**
 * Write next handshake message
 * @param hs Handshake state
 * @param out Output buffer
 * @param out_len Output length
 * @param max_len Maximum output size
 * @return P2P_OK on success
 */
int p2p_noise_write_message(p2p_noise_handshake_t *hs,
                            uint8_t *out, size_t *out_len, size_t max_len);

int p2p_noise_write_message_with_payload(p2p_noise_handshake_t *hs,
                                         const uint8_t *payload,
                                         size_t payload_len,
                                         uint8_t *out, size_t *out_len,
                                         size_t max_len);

int p2p_noise_write_message_with_payload_blocking(
    p2p_noise_handshake_t *hs,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t monotonic_deadline_ms,
    const p2p_private_key_cancel_v4_t *cancel,
    uint8_t *out,
    size_t *out_len,
    size_t max_len);

/**
 * Read handshake message from peer
 * @param hs Handshake state
 * @param data Input data
 * @param len Input length
 * @return P2P_OK on success
 */
int p2p_noise_read_message(p2p_noise_handshake_t *hs,
                           const uint8_t *data, size_t len);

int p2p_noise_read_message_with_payload(p2p_noise_handshake_t *hs,
                                        const uint8_t *data, size_t len,
                                        uint8_t *payload,
                                        size_t payload_capacity,
                                        size_t *payload_len);

/**
 * Check if handshake is complete
 */
int p2p_noise_is_complete(const p2p_noise_handshake_t *hs);

/**
 * Split handshake into session keys
 * @param hs Completed handshake
 * @param sess Output session
 * @return P2P_OK on success
 */
int p2p_noise_split(const p2p_noise_handshake_t *hs, p2p_crypto_session_t *sess);

void p2p_noise_handshake_destroy(p2p_noise_handshake_t *hs);

/**
 * Generate bytes with the operating-system CSPRNG.
 * On failure, a non-empty output buffer is securely wiped.
 * @return P2P_OK on success, P2P_ERR_INVALID_ARG for an invalid buffer,
 *         or P2P_ERR_CRYPTO when the CSPRNG fails
 */
int p2p_crypto_random(uint8_t *buf, size_t len);

/** Compute RFC 2104 HMAC-SHA256 through the project crypto boundary. */
int p2p_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t output[32]);

/** Constant-time equality for authenticated byte strings. */
int p2p_crypto_verify(const uint8_t *expected, const uint8_t *actual,
                      size_t len);

/**
 * SHA-256 hash
 */
void p2p_crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

#endif /* P2P_CRYPTO_H */
