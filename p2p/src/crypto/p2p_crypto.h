/**
 * P2P Crypto Module
 * Simple encryption using X25519 key exchange + ChaCha20-Poly1305
 */
#ifndef P2P_CRYPTO_H
#define P2P_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "../../include/p2p_types.h"

/**
 * Identity (Permanent Keypair)
 */
typedef struct {
    uint8_t public_key[P2P_KEY_SIZE];
    uint8_t secret_key[P2P_KEY_SIZE];
} p2p_identity_t;

/**
 * Active Crypto Session
 */
typedef struct {
    uint8_t tx_key[P2P_KEY_SIZE];
    uint8_t rx_key[P2P_KEY_SIZE];
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    int ready;
} p2p_crypto_session_t;

/**
 * Handshake State
 */
typedef struct {
    int is_initiator;
    int step;
    uint8_t ephemeral_public[P2P_KEY_SIZE];
    uint8_t ephemeral_secret[P2P_KEY_SIZE];
    uint8_t remote_public[P2P_KEY_SIZE];
    uint8_t shared_secret[P2P_KEY_SIZE];
} p2p_noise_handshake_t;

/**
 * Generate a new identity (keypair)
 */
int p2p_crypto_generate_identity(p2p_identity_t *identity);

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
 * @param ct Ciphertext output (must be pt_len + 24 bytes for nonce + tag)
 * @param ct_len Output ciphertext length
 * @return P2P_OK on success
 */
int p2p_crypto_encrypt(p2p_crypto_session_t *sess,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len);

/**
 * Decrypt data with session
 * @param sess Active session
 * @param ct Ciphertext (nonce + ciphertext + tag)
 * @param ct_len Ciphertext length
 * @param pt Plaintext output
 * @param pt_len Output plaintext length
 * @return P2P_OK on success
 */
int p2p_crypto_decrypt(p2p_crypto_session_t *sess,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t *pt_len);

/**
 * Initialize Noise-like handshake as initiator
 */
int p2p_noise_init_initiator(p2p_noise_handshake_t *hs,
                             const p2p_identity_t *identity,
                             const uint8_t *remote_public);

/**
 * Initialize Noise-like handshake as responder
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

/**
 * Read handshake message from peer
 * @param hs Handshake state
 * @param data Input data
 * @param len Input length
 * @return P2P_OK on success
 */
int p2p_noise_read_message(p2p_noise_handshake_t *hs,
                           const uint8_t *data, size_t len);

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

/**
 * Generate random bytes
 */
void p2p_crypto_random(uint8_t *buf, size_t len);

/**
 * SHA-256 hash
 */
void p2p_crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

#endif /* P2P_CRYPTO_H */
