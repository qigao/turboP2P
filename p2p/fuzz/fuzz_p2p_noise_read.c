#include "crypto/p2p_crypto.h"

#include <noise/protocol.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    FUZZ_NOISE_STAGE_COUNT = 3,
    FUZZ_NOISE_INPUT_MAX = P2P_SECURITY_HANDSHAKE_FRAME_MAX + 1,
};

static int fuzz_set_ephemeral(p2p_noise_handshake_t *handshake,
                              const uint8_t private_key[P2P_KEY_SIZE]) {
    NoiseDHState *dh;

    if (!handshake || !handshake->state) {
        return 0;
    }
    dh = noise_handshakestate_get_fixed_ephemeral_dh(
        (NoiseHandshakeState *)handshake->state);
    return dh && noise_dhstate_set_keypair_private(
                     dh, private_key, P2P_KEY_SIZE) == NOISE_ERROR_NONE;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t initiator_static[P2P_KEY_SIZE] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    };
    static const uint8_t responder_static[P2P_KEY_SIZE] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    };
    static const uint8_t initiator_ephemeral[P2P_KEY_SIZE] = {
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    };
    static const uint8_t responder_ephemeral[P2P_KEY_SIZE] = {
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
        0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
    };
    static const uint8_t prologue[] = "TurboP2P fuzz Noise XX";
    p2p_identity_t initiator_identity = {0};
    p2p_identity_t responder_identity = {0};
    p2p_noise_handshake_t initiator = {0};
    p2p_noise_handshake_t responder = {0};
    uint8_t message[P2P_SECURITY_HANDSHAKE_FRAME_MAX] = {0};
    uint8_t payload[P2P_SECURITY_CREDENTIAL_MAX] = {0};
    size_t message_len = 0;
    size_t payload_len = 0;
    const uint8_t empty = 0;
    const uint8_t *fuzz_message;
    size_t fuzz_size;
    uint8_t stage;

    if ((!data && size != 0) || size > FUZZ_NOISE_INPUT_MAX) {
        return 0;
    }
    stage = size > 0 ? (uint8_t)(data[0] % FUZZ_NOISE_STAGE_COUNT) : 0;
    fuzz_message = size > 1 ? data + 1 : &empty;
    fuzz_size = size > 1 ? size - 1 : 0;

    if (p2p_crypto_identity_from_secret(&initiator_identity,
                                        initiator_static) != P2P_OK ||
        p2p_crypto_identity_from_secret(&responder_identity,
                                        responder_static) != P2P_OK ||
        p2p_noise_init_v2(&initiator, &initiator_identity, 1, prologue,
                          sizeof(prologue) - 1) != P2P_OK ||
        p2p_noise_init_v2(&responder, &responder_identity, 0, prologue,
                          sizeof(prologue) - 1) != P2P_OK ||
        !fuzz_set_ephemeral(&initiator, initiator_ephemeral) ||
        !fuzz_set_ephemeral(&responder, responder_ephemeral)) {
        goto cleanup;
    }

    if (stage == 0) {
        (void)p2p_noise_read_message_with_payload(
            &responder, fuzz_message, fuzz_size, payload, sizeof(payload),
            &payload_len);
        goto cleanup;
    }
    if (p2p_noise_write_message(&initiator, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&responder, message, message_len) != P2P_OK) {
        goto cleanup;
    }
    if (stage == 1) {
        (void)p2p_noise_read_message_with_payload(
            &initiator, fuzz_message, fuzz_size, payload, sizeof(payload),
            &payload_len);
        goto cleanup;
    }
    if (p2p_noise_write_message(&responder, message, &message_len,
                                sizeof(message)) != P2P_OK ||
        p2p_noise_read_message(&initiator, message, message_len) != P2P_OK) {
        goto cleanup;
    }
    (void)p2p_noise_read_message_with_payload(
        &responder, fuzz_message, fuzz_size, payload, sizeof(payload),
        &payload_len);

cleanup:
    p2p_noise_handshake_destroy(&responder);
    p2p_noise_handshake_destroy(&initiator);
    p2p_crypto_wipe(&responder_identity, sizeof(responder_identity));
    p2p_crypto_wipe(&initiator_identity, sizeof(initiator_identity));
    p2p_crypto_wipe(message, sizeof(message));
    p2p_crypto_wipe(payload, sizeof(payload));
    return 0;
}
