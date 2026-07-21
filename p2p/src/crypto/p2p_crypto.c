/**
 * P2P Crypto Implementation
 * Using Monocypher for X25519 + XChaCha20-Poly1305
 */

#include "p2p_crypto.h"
#include "../internal.h"
#include <monocypher.h>
#include <platform.h>
#include <limits.h>
#include <string.h>

enum {
    P2P_NONCE_COUNTER_SIZE = 8,
    P2P_AEAD_NONCE_SIZE = 24,
    P2P_AEAD_FRAME_OVERHEAD = P2P_NONCE_COUNTER_SIZE + P2P_TAG_SIZE,
};

static void p2p_crypto_build_nonce(uint64_t counter,
                                   uint8_t nonce[P2P_AEAD_NONCE_SIZE]) {
    memset(nonce, 0, P2P_AEAD_NONCE_SIZE);
    for (int i = 0; i < P2P_NONCE_COUNTER_SIZE; i++) {
        nonce[i] = (uint8_t)((counter >> (i * CHAR_BIT)) & UINT8_MAX);
    }
}

/* =============================================================================
 * Random Number Generation
 * ============================================================================= */

int p2p_crypto_random(uint8_t *buf, size_t len) {
    if (!buf && len > 0) {
        return P2P_ERR_INVALID_ARG;
    }

    if (turbo_secure_random(buf, len) != 0) {
        if (buf && len > 0) {
            crypto_wipe(buf, len);
        }
        return P2P_ERR_CRYPTO;
    }

    return P2P_OK;
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
        crypto_wipe(&generated, sizeof(generated));
        return ret;
    }

    crypto_x25519_public_key(generated.public_key, generated.secret_key);
    memcpy(identity, &generated, sizeof(*identity));
    crypto_wipe(&generated, sizeof(generated));

    return P2P_OK;
}

int p2p_crypto_identity_from_secret(p2p_identity_t *identity,
                                    const uint8_t secret_key[P2P_KEY_SIZE]) {
    if (!identity || !secret_key) return P2P_ERR_INVALID_ARG;

    memcpy(identity->secret_key, secret_key, P2P_KEY_SIZE);
    crypto_x25519_public_key(identity->public_key, identity->secret_key);
    return P2P_OK;
}

/* =============================================================================
 * Memory Wiping
 * ============================================================================= */

void p2p_crypto_wipe(void *data, size_t len) {
    crypto_wipe(data, len);
}

/* =============================================================================
 * Session Management
 * ============================================================================= */

int p2p_crypto_session_is_ready(const p2p_crypto_session_t *sess) {
    return sess && sess->ready;
}

void p2p_crypto_session_destroy(p2p_crypto_session_t *sess) {
    if (sess) {
        crypto_wipe(sess, sizeof(*sess));
    }
}

/* =============================================================================
 * Encryption / Decryption
 *
 * Format: [8 bytes: nonce counter][16 bytes: tag][ciphertext]
 * ============================================================================= */

int p2p_crypto_encrypt(p2p_crypto_session_t *sess,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len) {
    if (!sess || !sess->ready || !pt || !ct || !ct_len) {
        return P2P_ERR_INVALID_ARG;
    }

    if (pt_len > SIZE_MAX - P2P_AEAD_FRAME_OVERHEAD) {
        return P2P_ERR_INVALID_ARG;
    }

    if (sess->tx_nonce == UINT64_MAX) {
        return P2P_ERR_CRYPTO;
    }

    uint8_t nonce[P2P_AEAD_NONCE_SIZE];
    p2p_crypto_build_nonce(sess->tx_nonce, nonce);

    /* Output format: [8 bytes nonce counter][16 bytes tag][ciphertext] */
    uint8_t *out_nonce = ct;
    uint8_t *out_tag = ct + P2P_NONCE_COUNTER_SIZE;
    uint8_t *out_ct = ct + P2P_AEAD_FRAME_OVERHEAD;

    /* Write nonce counter */
    memcpy(out_nonce, nonce, P2P_NONCE_COUNTER_SIZE);

    /* Encrypt with XChaCha20-Poly1305 */
    crypto_aead_lock(out_ct,            /* ciphertext */
                     out_tag,           /* tag */
                     sess->tx_key,      /* key */
                     nonce,             /* nonce */
                     NULL, 0,           /* no additional data */
                     pt, pt_len);       /* plaintext */

    sess->tx_nonce++;
    *ct_len = P2P_AEAD_FRAME_OVERHEAD + pt_len;
    return P2P_OK;
}

int p2p_crypto_decrypt(p2p_crypto_session_t *sess,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t *pt_len) {
    if (!sess || !sess->ready || !ct || !pt || !pt_len) {
        return P2P_ERR_INVALID_ARG;
    }

    if (ct_len < P2P_AEAD_FRAME_OVERHEAD) {
        return P2P_ERR_INVALID_ARG;
    }

    if (sess->rx_nonce == UINT64_MAX) {
        return P2P_ERR_CRYPTO;
    }

    size_t data_len = ct_len - P2P_AEAD_FRAME_OVERHEAD;

    /* Parse input */
    const uint8_t *in_nonce = ct;
    const uint8_t *in_tag = ct + P2P_NONCE_COUNTER_SIZE;
    const uint8_t *in_ct = ct + P2P_AEAD_FRAME_OVERHEAD;

    /* turbo_stream is ordered: reject duplicates and gaps before decryption. */
    uint8_t nonce[P2P_AEAD_NONCE_SIZE];
    p2p_crypto_build_nonce(sess->rx_nonce, nonce);
    if (memcmp(in_nonce, nonce, P2P_NONCE_COUNTER_SIZE) != 0) {
        return P2P_ERR_CRYPTO;
    }

    /* Verify and decrypt */
    int ret = crypto_aead_unlock(pt,             /* plaintext */
                                 in_tag,         /* tag */
                                 sess->rx_key,   /* key */
                                 nonce,          /* nonce */
                                 NULL, 0,        /* no additional data */
                                 in_ct, data_len); /* ciphertext */

    if (ret != 0) {
        return P2P_ERR_CRYPTO;
    }

    sess->rx_nonce++;

    *pt_len = data_len;
    return P2P_OK;
}

/* =============================================================================
 * Simplified Noise-like Handshake
 *
 * Not a full Noise Protocol, but similar structure:
 * 1. Initiator -> Responder: ephemeral public key
 * 2. Responder -> Initiator: ephemeral public key
 * 3. Both derive shared secret from ECDH
 * ============================================================================= */

int p2p_noise_init_initiator(p2p_noise_handshake_t *hs,
                             const p2p_identity_t *identity,
                             const uint8_t *remote_public) {
    int ret = P2P_OK;

    if (!hs || !identity) return P2P_ERR_INVALID_ARG;

    memset(hs, 0, sizeof(*hs));
    hs->is_initiator = 1;
    hs->step = 0;

    ret = p2p_crypto_random(hs->ephemeral_secret, P2P_KEY_SIZE);
    if (ret != P2P_OK) {
        return ret;
    }
    crypto_x25519_public_key(hs->ephemeral_public, hs->ephemeral_secret);
    memcpy(hs->local_static_public, identity->public_key, P2P_KEY_SIZE);
    memcpy(hs->local_static_secret, identity->secret_key, P2P_KEY_SIZE);

    /* Store remote public if known (for pre-authentication) */
    if (remote_public) {
        memcpy(hs->remote_public, remote_public, P2P_KEY_SIZE);
    }

    return P2P_OK;
}

int p2p_noise_init_responder(p2p_noise_handshake_t *hs,
                             const p2p_identity_t *identity) {
    int ret = P2P_OK;

    if (!hs || !identity) return P2P_ERR_INVALID_ARG;

    memset(hs, 0, sizeof(*hs));
    hs->is_initiator = 0;
    hs->step = 0;

    ret = p2p_crypto_random(hs->ephemeral_secret, P2P_KEY_SIZE);
    if (ret != P2P_OK) {
        return ret;
    }
    crypto_x25519_public_key(hs->ephemeral_public, hs->ephemeral_secret);
    memcpy(hs->local_static_public, identity->public_key, P2P_KEY_SIZE);
    memcpy(hs->local_static_secret, identity->secret_key, P2P_KEY_SIZE);

    return P2P_OK;
}

int p2p_noise_write_message(p2p_noise_handshake_t *hs,
                            uint8_t *out, size_t *out_len, size_t max_len) {
    if (!hs || !out || !out_len) return P2P_ERR_INVALID_ARG;

    if (max_len < P2P_KEY_SIZE) return P2P_ERR_INVALID_ARG;

    /* New peers append their static public key. Old peers accept the first
     * 32 bytes and ignore the extension, so this stays wire-compatible. */
    memcpy(out, hs->ephemeral_public, P2P_KEY_SIZE);
    *out_len = P2P_KEY_SIZE;
    if (max_len >= P2P_KEY_SIZE * 2) {
        memcpy(out + P2P_KEY_SIZE, hs->local_static_public, P2P_KEY_SIZE);
        *out_len = P2P_KEY_SIZE * 2;
    }

    if (hs->is_initiator) {
        if (hs->step < 1) {
            hs->step = 1; /* Sent first message */
        }
    } else {
        if (hs->step < 2) {
            hs->step = 2; /* Sent response */
        }
    }

    return P2P_OK;
}

int p2p_noise_read_message(p2p_noise_handshake_t *hs,
                           const uint8_t *data, size_t len) {
    if (!hs || !data) return P2P_ERR_INVALID_ARG;

    if (len < P2P_KEY_SIZE) return P2P_ERR_INVALID_ARG;

    /* Store remote ephemeral public key */
    memcpy(hs->remote_public, data, P2P_KEY_SIZE);

    /* Perform ECDH to derive shared secret */
    crypto_x25519(hs->shared_secret, hs->ephemeral_secret, hs->remote_public);
    if (len >= P2P_KEY_SIZE * 2) {
        memcpy(hs->remote_static_public, data + P2P_KEY_SIZE, P2P_KEY_SIZE);
        crypto_x25519(hs->static_shared_secret,
                      hs->local_static_secret,
                      hs->remote_static_public);
        hs->has_remote_static_public = 1;
    }

    if (hs->is_initiator) {
        hs->step = 3; /* Received response, handshake complete */
    } else {
        hs->step = 2; /* Received first message, ready to respond */
    }

    return P2P_OK;
}

int p2p_noise_is_complete(const p2p_noise_handshake_t *hs) {
    if (!hs) return 0;

    /* Initiator: complete after step 3 (sent first, received response) */
    /* Responder: complete after step 2 (received first, sent response) */
    if (hs->is_initiator) {
        return hs->step >= 3;
    } else {
        return hs->step >= 2;
    }
}

int p2p_noise_split(const p2p_noise_handshake_t *hs, p2p_crypto_session_t *sess) {
    if (!hs || !sess) return P2P_ERR_INVALID_ARG;

    if (!p2p_noise_is_complete(hs)) {
        return P2P_ERR_INVALID_STATE;
    }

    memset(sess, 0, sizeof(*sess));

    /* Derive keys using BLAKE2b
     * TX key = BLAKE2b(shared_secret || "tx" || role)
     * RX key = BLAKE2b(shared_secret || "rx" || role)
     */
    uint8_t tx_input[64], rx_input[64];

    if (hs->has_remote_static_public) {
        uint8_t identity_input[P2P_KEY_SIZE * 2];
        memcpy(identity_input, hs->shared_secret, P2P_KEY_SIZE);
        memcpy(identity_input + P2P_KEY_SIZE, hs->static_shared_secret, P2P_KEY_SIZE);
        crypto_blake2b(tx_input, 32, identity_input, sizeof(identity_input));
        memcpy(rx_input, tx_input, 32);
        p2p_crypto_wipe(identity_input, sizeof(identity_input));
    } else {
        memcpy(tx_input, hs->shared_secret, 32);
        memcpy(rx_input, hs->shared_secret, 32);
    }

    if (hs->is_initiator) {
        /* Initiator: tx=init->resp, rx=resp->init */
        memcpy(tx_input + 32, "initiator_to_responder__", 24);
        memcpy(rx_input + 32, "responder_to_initiator__", 24);
    } else {
        /* Responder: tx=resp->init, rx=init->resp */
        memcpy(tx_input + 32, "responder_to_initiator__", 24);
        memcpy(rx_input + 32, "initiator_to_responder__", 24);
    }

    crypto_blake2b(sess->tx_key, 32, tx_input, 56);
    crypto_blake2b(sess->rx_key, 32, rx_input, 56);

    sess->tx_nonce = 0;
    sess->rx_nonce = 0;
    sess->ready = 1;

    return P2P_OK;
}

/* =============================================================================
 * SHA-256 (using BLAKE2b as substitute, or implement simple SHA-256)
 *
 * For file hashing we use BLAKE2b which is faster and at least as secure.
 * If strict SHA-256 is needed, a dedicated implementation would be added.
 * ============================================================================= */

void p2p_crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    /* Use BLAKE2b-256 as a secure hash replacement */
    crypto_blake2b(hash, 32, data, len);
}
