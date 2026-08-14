#include "p2p_noise_backend.h"
#include "p2p_noise_c_platform.h"

#include "../crypto/p2p_crypto.h"
#include "../../include/p2p.h"

#include <noise/protocol.h>

#include <string.h>

static const char P2P_NOISE_PROTOCOL_NAME[] =
    "Noise_XX_25519_ChaChaPoly_BLAKE2s";

static int map_noise_error(int error) {
    switch (error) {
        case NOISE_ERROR_NONE:
            return P2P_OK;
        case NOISE_ERROR_NO_MEMORY:
            return P2P_ERR_NO_MEM;
        case NOISE_ERROR_INVALID_PARAM:
        case NOISE_ERROR_INVALID_LENGTH:
            return P2P_ERR_INVALID_ARG;
        case NOISE_ERROR_INVALID_STATE:
            return P2P_ERR_INVALID_STATE;
        case NOISE_ERROR_MAC_FAILURE:
        case NOISE_ERROR_INVALID_NONCE:
        case NOISE_ERROR_INVALID_PRIVATE_KEY:
        case NOISE_ERROR_INVALID_PUBLIC_KEY:
            return P2P_ERR_CRYPTO;
        default:
            return P2P_ERR_PROTOCOL;
    }
}

static int normalize_provider_error(int error) {
    switch (error) {
        case P2P_ERR_CRYPTO:
        case P2P_ERR_IO:
        case P2P_ERR_TIMEOUT:
        case P2P_ERR_RESOURCE_EXHAUSTED:
            return error;
        default:
            return P2P_ERR_CRYPTO;
    }
}

static int map_handshake_error(NoiseHandshakeState *state, int error) {
    NoiseDHState *local_dh;
    int provider_error;

    if (state) {
        local_dh = noise_handshakestate_get_local_keypair_dh(state);
        provider_error = p2p_noise_curve25519_take_provider_error(local_dh);
        if (provider_error != 0) {
            return normalize_provider_error(provider_error);
        }
    }
    return map_noise_error(error);
}

static int blocking_provider_calculate(
    void *context,
    const uint8_t remote_public_key[P2P_KEY_SIZE],
    uint8_t shared_key_out[P2P_KEY_SIZE]) {
    p2p_noise_backend_handshake_t *handshake =
        (p2p_noise_backend_handshake_t *)context;

    if (!handshake || !handshake->uses_blocking_provider ||
        !handshake->blocking_provider.calculate_x25519 ||
        handshake->blocking_deadline_ms == 0 ||
        !handshake->blocking_cancel) {
        return P2P_ERR_CRYPTO;
    }
    return handshake->blocking_provider.calculate_x25519(
        handshake->blocking_provider.context, remote_public_key,
        handshake->blocking_deadline_ms, handshake->blocking_cancel,
        shared_key_out);
}

static int p2p_noise_backend_init_internal(
    p2p_noise_backend_handshake_t *handshake, int is_initiator,
    const uint8_t *local_private_key, const uint8_t *local_public_key,
    const p2p_private_key_provider_v3_t *provider, const uint8_t *prologue,
    size_t prologue_len) {
    NoiseHandshakeState *state = NULL;
    NoiseDHState *local_dh;
    int error;

    if (!handshake || (!prologue && prologue_len != 0) ||
        ((local_private_key != NULL) == (provider != NULL)) ||
        (provider &&
         (!local_public_key ||
          provider->struct_size != sizeof(*provider) ||
          !provider->get_public_key || !provider->calculate_x25519))) {
        return P2P_ERR_INVALID_ARG;
    }
    memset(handshake, 0, sizeof(*handshake));
    error = noise_handshakestate_new_by_name(
        &state, P2P_NOISE_PROTOCOL_NAME,
        is_initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);
    if (error != NOISE_ERROR_NONE) {
        return map_noise_error(error);
    }
    error = noise_handshakestate_set_prologue(state, prologue, prologue_len);
    if (error != NOISE_ERROR_NONE) {
        noise_handshakestate_free(state);
        return map_noise_error(error);
    }
    local_dh = noise_handshakestate_get_local_keypair_dh(state);
    if (!local_dh) {
        noise_handshakestate_free(state);
        return P2P_ERR_CRYPTO;
    }
    if (provider) {
        error = p2p_noise_curve25519_set_provider(
            local_dh, local_public_key, provider->calculate_x25519,
            provider->context);
    } else {
        error = noise_dhstate_set_keypair_private(local_dh, local_private_key,
                                                   P2P_KEY_SIZE);
    }
    if (error != NOISE_ERROR_NONE) {
        noise_handshakestate_free(state);
        return map_noise_error(error);
    }
    error = noise_handshakestate_start(state);
    if (error != NOISE_ERROR_NONE) {
        noise_handshakestate_free(state);
        return map_noise_error(error);
    }
    handshake->state = state;
    handshake->is_initiator = is_initiator != 0;
    return P2P_OK;
}

int p2p_noise_backend_init_with_blocking_provider(
    p2p_noise_backend_handshake_t *handshake, int is_initiator,
    const uint8_t local_public_key[P2P_KEY_SIZE],
    const p2p_blocking_private_key_provider_v4_t *provider,
    const uint8_t *prologue, size_t prologue_len) {
    p2p_private_key_provider_v3_t adapter = {0};
    int ret;

    if (!handshake || !local_public_key || !provider ||
        provider->struct_size != sizeof(*provider) ||
        !provider->get_public_key || !provider->calculate_x25519) {
        return P2P_ERR_INVALID_ARG;
    }
    adapter.struct_size = sizeof(adapter);
    adapter.get_public_key = provider->get_public_key;
    adapter.calculate_x25519 = blocking_provider_calculate;
    adapter.context = handshake;
    ret = p2p_noise_backend_init_internal(
        handshake, is_initiator, NULL, local_public_key, &adapter,
        prologue, prologue_len);
    if (ret != P2P_OK) {
        return ret;
    }
    handshake->blocking_provider = *provider;
    handshake->uses_blocking_provider = 1;
    return P2P_OK;
}

int p2p_noise_backend_init(p2p_noise_backend_handshake_t *handshake,
                           int is_initiator,
                           const uint8_t local_private_key[P2P_KEY_SIZE],
                           const uint8_t *prologue,
                           size_t prologue_len) {
    return p2p_noise_backend_init_internal(
        handshake, is_initiator, local_private_key, NULL, NULL, prologue,
        prologue_len);
}

int p2p_noise_backend_init_with_provider(
    p2p_noise_backend_handshake_t *handshake, int is_initiator,
    const uint8_t local_public_key[P2P_KEY_SIZE],
    const p2p_private_key_provider_v3_t *provider, const uint8_t *prologue,
    size_t prologue_len) {
    return p2p_noise_backend_init_internal(
        handshake, is_initiator, NULL, local_public_key, provider, prologue,
        prologue_len);
}

int p2p_noise_backend_write(p2p_noise_backend_handshake_t *handshake,
                            const uint8_t *payload,
                            size_t payload_len,
                            uint8_t *output,
                            size_t output_capacity,
                            size_t *out_len) {
    NoiseBuffer message_buffer;
    NoiseBuffer payload_buffer;
    NoiseHandshakeState *state;
    int error;

    if (!handshake || !handshake->state || !output || !out_len ||
        (!payload && payload_len != 0)) {
        return P2P_ERR_INVALID_ARG;
    }
    *out_len = 0;
    state = (NoiseHandshakeState *)handshake->state;
    if (noise_handshakestate_get_action(state) != NOISE_ACTION_WRITE_MESSAGE) {
        return P2P_ERR_INVALID_STATE;
    }
    noise_buffer_set_output(message_buffer, output, output_capacity);
    noise_buffer_set_input(payload_buffer, (uint8_t *)payload, payload_len);
    error = noise_handshakestate_write_message(
        state, &message_buffer, payload_len ? &payload_buffer : NULL);
    if (error != NOISE_ERROR_NONE) {
        return map_handshake_error(state, error);
    }
    *out_len = message_buffer.size;
    return P2P_OK;
}

int p2p_noise_backend_write_blocking(
    p2p_noise_backend_handshake_t *handshake,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t monotonic_deadline_ms,
    const p2p_private_key_cancel_v4_t *cancel,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len) {
    int ret;

    if (!handshake || !handshake->uses_blocking_provider ||
        monotonic_deadline_ms == 0 || !cancel ||
        cancel->struct_size != sizeof(*cancel) || !cancel->is_cancelled) {
        return P2P_ERR_INVALID_ARG;
    }
    handshake->blocking_deadline_ms = monotonic_deadline_ms;
    handshake->blocking_cancel = cancel;
    ret = p2p_noise_backend_write(handshake, payload, payload_len, output,
                                  output_capacity, out_len);
    handshake->blocking_cancel = NULL;
    handshake->blocking_deadline_ms = 0;
    return ret;
}

int p2p_noise_backend_read(p2p_noise_backend_handshake_t *handshake,
                           const uint8_t *message,
                           size_t message_len,
                           uint8_t *payload,
                           size_t payload_capacity,
                           size_t *out_payload_len) {
    NoiseBuffer message_buffer;
    NoiseBuffer payload_buffer;
    NoiseHandshakeState *state;
    int error;

    if (!handshake || !handshake->state || !message || !payload ||
        !out_payload_len) {
        return P2P_ERR_INVALID_ARG;
    }
    *out_payload_len = 0;
    state = (NoiseHandshakeState *)handshake->state;
    if (noise_handshakestate_get_action(state) != NOISE_ACTION_READ_MESSAGE) {
        return P2P_ERR_INVALID_STATE;
    }
    noise_buffer_set_input(message_buffer, (uint8_t *)message, message_len);
    noise_buffer_set_output(payload_buffer, payload, payload_capacity);
    error = noise_handshakestate_read_message(state, &message_buffer,
                                              &payload_buffer);
    if (error != NOISE_ERROR_NONE) {
        return map_handshake_error(state, error);
    }
    *out_payload_len = payload_buffer.size;
    return P2P_OK;
}

int p2p_noise_backend_is_ready_to_split(
    const p2p_noise_backend_handshake_t *handshake) {
    return handshake && handshake->state && !handshake->split &&
           noise_handshakestate_get_action(
               (const NoiseHandshakeState *)handshake->state) ==
               NOISE_ACTION_SPLIT;
}

int p2p_noise_backend_split(p2p_noise_backend_handshake_t *handshake,
                            p2p_noise_backend_session_t *session) {
    NoiseHandshakeState *state;
    NoiseDHState *remote_dh;
    NoiseCipherState *send_cipher = NULL;
    NoiseCipherState *receive_cipher = NULL;
    int error;

    if (!handshake || !session || !p2p_noise_backend_is_ready_to_split(handshake)) {
        return P2P_ERR_INVALID_STATE;
    }
    memset(session, 0, sizeof(*session));
    state = (NoiseHandshakeState *)handshake->state;
    remote_dh = noise_handshakestate_get_remote_public_key_dh(state);
    if (!remote_dh ||
        noise_dhstate_get_public_key(remote_dh,
                                     handshake->remote_static_public,
                                     sizeof(handshake->remote_static_public)) !=
            NOISE_ERROR_NONE ||
        noise_handshakestate_get_handshake_hash(
            state, handshake->handshake_hash,
            sizeof(handshake->handshake_hash)) != NOISE_ERROR_NONE) {
        return P2P_ERR_CRYPTO;
    }
    error = noise_handshakestate_split(state, &send_cipher, &receive_cipher);
    if (error != NOISE_ERROR_NONE) {
        return map_noise_error(error);
    }
    session->send_cipher = send_cipher;
    session->receive_cipher = receive_cipher;
    session->ready = 1;
    handshake->split = 1;
    return P2P_OK;
}

void p2p_noise_backend_handshake_destroy(
    p2p_noise_backend_handshake_t *handshake) {
    if (!handshake) {
        return;
    }
    if (handshake->state) {
        noise_handshakestate_free((NoiseHandshakeState *)handshake->state);
    }
    p2p_crypto_wipe(handshake, sizeof(*handshake));
}

void p2p_noise_backend_session_destroy(p2p_noise_backend_session_t *session) {
    if (!session) {
        return;
    }
    if (session->send_cipher) {
        noise_cipherstate_free((NoiseCipherState *)session->send_cipher);
    }
    if (session->receive_cipher) {
        noise_cipherstate_free((NoiseCipherState *)session->receive_cipher);
    }
    p2p_crypto_wipe(session, sizeof(*session));
}

int p2p_noise_backend_encrypt(p2p_noise_backend_session_t *session,
                              const uint8_t *plaintext,
                              size_t plaintext_len,
                              uint8_t *ciphertext,
                              size_t ciphertext_capacity,
                              size_t *out_ciphertext_len) {
    NoiseBuffer buffer;
    int error;

    if (!session || !session->ready || !session->send_cipher || !plaintext ||
        !ciphertext || !out_ciphertext_len ||
        plaintext_len > P2P_NOISE_MAX_PLAINTEXT_SIZE ||
        ciphertext_capacity < plaintext_len + P2P_NOISE_TAG_SIZE) {
        return P2P_ERR_INVALID_ARG;
    }
    if (session->sent_frames >= P2P_NOISE_SESSION_FRAME_LIMIT) {
        return P2P_ERR_KEY_EXHAUSTED;
    }
    memcpy(ciphertext, plaintext, plaintext_len);
    noise_buffer_set_inout(buffer, ciphertext, plaintext_len,
                           ciphertext_capacity);
    error = noise_cipherstate_encrypt((NoiseCipherState *)session->send_cipher,
                                      &buffer);
    if (error != NOISE_ERROR_NONE) {
        return map_noise_error(error);
    }
    session->sent_frames++;
    *out_ciphertext_len = buffer.size;
    return P2P_OK;
}

int p2p_noise_backend_decrypt(p2p_noise_backend_session_t *session,
                              const uint8_t *ciphertext,
                              size_t ciphertext_len,
                              uint8_t *plaintext,
                              size_t plaintext_capacity,
                              size_t *out_plaintext_len) {
    NoiseBuffer buffer;
    int error;

    if (!session || !session->ready || !session->receive_cipher ||
        !ciphertext || !plaintext || !out_plaintext_len ||
        ciphertext_len < P2P_NOISE_TAG_SIZE ||
        ciphertext_len > P2P_NOISE_MAX_FRAME_SIZE ||
        plaintext_capacity < ciphertext_len) {
        return P2P_ERR_INVALID_ARG;
    }
    if (session->received_frames >= P2P_NOISE_SESSION_FRAME_LIMIT) {
        return P2P_ERR_KEY_EXHAUSTED;
    }
    memcpy(plaintext, ciphertext, ciphertext_len);
    noise_buffer_set_inout(buffer, plaintext, ciphertext_len,
                           plaintext_capacity);
    error = noise_cipherstate_decrypt(
        (NoiseCipherState *)session->receive_cipher, &buffer);
    if (error != NOISE_ERROR_NONE) {
        p2p_crypto_wipe(plaintext, ciphertext_len);
        return map_noise_error(error);
    }
    session->received_frames++;
    *out_plaintext_len = buffer.size;
    return P2P_OK;
}

int p2p_noise_backend_blake2s(
    const uint8_t *data, size_t data_len,
    uint8_t output[P2P_NOISE_HANDSHAKE_HASH_SIZE]) {
    NoiseHashState *state = NULL;
    int error;

    if ((!data && data_len != 0) || !output) {
        return P2P_ERR_INVALID_ARG;
    }
    error = noise_hashstate_new_by_name(&state, "BLAKE2s");
    if (error == NOISE_ERROR_NONE) {
        error = noise_hashstate_hash_one(state, data, data_len, output,
                                         P2P_NOISE_HANDSHAKE_HASH_SIZE);
    }
    if (state) {
        noise_hashstate_free(state);
    }
    return map_noise_error(error);
}
