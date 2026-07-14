/**
 * P2P Crypto Implementation
 * Using Monocypher for X25519 + XChaCha20-Poly1305
 */

#include "p2p_crypto.h"
#include "../internal.h"
#include <monocypher.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* =============================================================================
 * Random Number Generation
 * ============================================================================= */

void p2p_crypto_random(uint8_t *buf, size_t len) {
#ifdef _WIN32
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, len);
        close(fd);
    }
#endif
}

/* =============================================================================
 * Identity Management
 * ============================================================================= */

int p2p_crypto_generate_identity(p2p_identity_t *identity) {
    if (!identity) return P2P_ERR_INVALID_ARG;

    /* Generate random secret key */
    p2p_crypto_random(identity->secret_key, P2P_KEY_SIZE);

    /* Derive public key */
    crypto_x25519_public_key(identity->public_key, identity->secret_key);

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

    /* Build nonce from counter */
    uint8_t nonce[24];
    memset(nonce, 0, 24);
    uint64_t counter = sess->tx_nonce++;
    for (int i = 0; i < 8; i++) {
        nonce[i] = (uint8_t)((counter >> (i * 8)) & 0xFF);
    }

    /* Output format: [8 bytes nonce counter][16 bytes tag][ciphertext] */
    uint8_t *out_nonce = ct;
    uint8_t *out_tag = ct + 8;
    uint8_t *out_ct = ct + 8 + 16;

    /* Write nonce counter */
    memcpy(out_nonce, nonce, 8);

    /* Encrypt with XChaCha20-Poly1305 */
    crypto_aead_lock(out_ct,            /* ciphertext */
                     out_tag,           /* tag */
                     sess->tx_key,      /* key */
                     nonce,             /* nonce */
                     NULL, 0,           /* no additional data */
                     pt, pt_len);       /* plaintext */

    *ct_len = 8 + 16 + pt_len;
    return P2P_OK;
}

int p2p_crypto_decrypt(p2p_crypto_session_t *sess,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t *pt_len) {
    if (!sess || !sess->ready || !ct || !pt || !pt_len) {
        return P2P_ERR_INVALID_ARG;
    }

    /* Minimum: 8 (nonce) + 16 (tag) */
    if (ct_len < 24) {
        return P2P_ERR_INVALID_ARG;
    }

    size_t data_len = ct_len - 8 - 16;

    /* Parse input */
    const uint8_t *in_nonce = ct;
    const uint8_t *in_tag = ct + 8;
    const uint8_t *in_ct = ct + 8 + 16;

    /* Build full nonce */
    uint8_t nonce[24];
    memset(nonce, 0, 24);
    memcpy(nonce, in_nonce, 8);

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

    /* Update expected nonce (could add replay protection here) */
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
    if (!hs || !identity) return P2P_ERR_INVALID_ARG;

    memset(hs, 0, sizeof(*hs));
    hs->is_initiator = 1;
    hs->step = 0;

    /* Generate ephemeral keypair */
    p2p_crypto_random(hs->ephemeral_secret, P2P_KEY_SIZE);
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
    if (!hs || !identity) return P2P_ERR_INVALID_ARG;

    memset(hs, 0, sizeof(*hs));
    hs->is_initiator = 0;
    hs->step = 0;

    /* Generate ephemeral keypair */
    p2p_crypto_random(hs->ephemeral_secret, P2P_KEY_SIZE);
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
