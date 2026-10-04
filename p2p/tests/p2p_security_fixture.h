#ifndef P2P_SECURITY_FIXTURE_H
#define P2P_SECURITY_FIXTURE_H

#include "crypto/p2p_crypto.h"
#include <monocypher.h>
#include <string.h>

static int p2p_test_x25519(uint8_t shared[32], const uint8_t secret[32],
                           const uint8_t remote[32]) {
    const uint8_t zero[32] = {0};
    crypto_x25519(shared, secret, remote);
    return crypto_verify32(shared, zero) == 0 ? P2P_ERR_CRYPTO : P2P_OK;
}

enum {
    P2P_TEST_AEAD_FRAME_OVERHEAD = P2P_NOISE_TAG_SIZE,
};

static int p2p_test_crypto_sessions(p2p_crypto_session_t *initiator_session,
                                    p2p_crypto_session_t *responder_session) {
    p2p_identity_t initiator_identity;
    p2p_identity_t responder_identity;
    p2p_noise_handshake_t initiator;
    p2p_noise_handshake_t responder;
    uint8_t message[P2P_SECURITY_HANDSHAKE_FRAME_MAX];
    size_t message_len = 0;
    int result = P2P_ERR_CRYPTO;

    memset(&initiator_identity, 0, sizeof(initiator_identity));
    memset(&responder_identity, 0, sizeof(responder_identity));
    memset(&initiator, 0, sizeof(initiator));
    memset(&responder, 0, sizeof(responder));
    memset(initiator_session, 0, sizeof(*initiator_session));
    memset(responder_session, 0, sizeof(*responder_session));
    if (p2p_crypto_generate_identity(&initiator_identity) != P2P_OK ||
        p2p_crypto_generate_identity(&responder_identity) != P2P_OK ||
        p2p_noise_init_initiator(&initiator, &initiator_identity, NULL) != P2P_OK ||
        p2p_noise_init_responder(&responder, &responder_identity) != P2P_OK ||
        p2p_noise_write_message(&initiator, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&responder, message, message_len) != P2P_OK ||
        p2p_noise_write_message(&responder, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&initiator, message, message_len) != P2P_OK ||
        p2p_noise_write_message(&initiator, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&responder, message, message_len) != P2P_OK ||
        p2p_noise_split(&initiator, initiator_session) != P2P_OK ||
        p2p_noise_split(&responder, responder_session) != P2P_OK) {
        goto cleanup;
    }
    result = P2P_OK;

cleanup:
    p2p_noise_handshake_destroy(&initiator);
    p2p_noise_handshake_destroy(&responder);
    p2p_crypto_wipe(&initiator_identity, sizeof(initiator_identity));
    p2p_crypto_wipe(&responder_identity, sizeof(responder_identity));
    p2p_crypto_wipe(message, sizeof(message));
    if (result != P2P_OK) {
        p2p_crypto_session_destroy(initiator_session);
        p2p_crypto_session_destroy(responder_session);
    }
    return result;
}

#endif
