#ifndef TURBO_P2P_NOISE_BACKEND_H
#define TURBO_P2P_NOISE_BACKEND_H

#include "../../include/p2p.h"

#include <stddef.h>
#include <stdint.h>

enum {
    P2P_NOISE_HANDSHAKE_HASH_SIZE = 32,
    P2P_NOISE_TAG_SIZE = 16,
    P2P_NOISE_MAX_FRAME_SIZE = 65535,
    P2P_NOISE_MAX_PLAINTEXT_SIZE =
        P2P_NOISE_MAX_FRAME_SIZE - P2P_NOISE_TAG_SIZE,
    P2P_NOISE_SESSION_FRAME_LIMIT = 1 << 20,
};

typedef struct {
    void *state;
    int is_initiator;
    int split;
    p2p_blocking_private_key_provider_v4_t blocking_provider;
    uint64_t blocking_deadline_ms;
    const p2p_private_key_cancel_v4_t *blocking_cancel;
    int uses_blocking_provider;
    uint8_t remote_static_public[P2P_KEY_SIZE];
    uint8_t handshake_hash[P2P_NOISE_HANDSHAKE_HASH_SIZE];
} p2p_noise_backend_handshake_t;

typedef struct {
    void *send_cipher;
    void *receive_cipher;
    uint64_t sent_frames;
    uint64_t received_frames;
    int ready;
} p2p_noise_backend_session_t;

int p2p_noise_backend_init(p2p_noise_backend_handshake_t *handshake,
                           int is_initiator,
                           const uint8_t local_private_key[P2P_KEY_SIZE],
                           const uint8_t *prologue,
                           size_t prologue_len);

int p2p_noise_backend_init_with_provider(
    p2p_noise_backend_handshake_t *handshake,
    int is_initiator,
    const uint8_t local_public_key[P2P_KEY_SIZE],
    const p2p_private_key_provider_v3_t *provider,
    const uint8_t *prologue,
    size_t prologue_len);

int p2p_noise_backend_init_with_blocking_provider(
    p2p_noise_backend_handshake_t *handshake,
    int is_initiator,
    const uint8_t local_public_key[P2P_KEY_SIZE],
    const p2p_blocking_private_key_provider_v4_t *provider,
    const uint8_t *prologue,
    size_t prologue_len);

int p2p_noise_backend_write(p2p_noise_backend_handshake_t *handshake,
                            const uint8_t *payload,
                            size_t payload_len,
                            uint8_t *output,
                            size_t output_capacity,
                            size_t *out_len);

int p2p_noise_backend_write_blocking(
    p2p_noise_backend_handshake_t *handshake,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t monotonic_deadline_ms,
    const p2p_private_key_cancel_v4_t *cancel,
    uint8_t *output,
    size_t output_capacity,
    size_t *out_len);

int p2p_noise_backend_read(p2p_noise_backend_handshake_t *handshake,
                           const uint8_t *message,
                           size_t message_len,
                           uint8_t *payload,
                           size_t payload_capacity,
                           size_t *out_payload_len);

int p2p_noise_backend_is_ready_to_split(
    const p2p_noise_backend_handshake_t *handshake);

int p2p_noise_backend_split(p2p_noise_backend_handshake_t *handshake,
                            p2p_noise_backend_session_t *session);

void p2p_noise_backend_handshake_destroy(
    p2p_noise_backend_handshake_t *handshake);
void p2p_noise_backend_session_destroy(p2p_noise_backend_session_t *session);

int p2p_noise_backend_encrypt(p2p_noise_backend_session_t *session,
                              const uint8_t *plaintext,
                              size_t plaintext_len,
                              uint8_t *ciphertext,
                              size_t ciphertext_capacity,
                              size_t *out_ciphertext_len);

int p2p_noise_backend_decrypt(p2p_noise_backend_session_t *session,
                              const uint8_t *ciphertext,
                              size_t ciphertext_len,
                              uint8_t *plaintext,
                              size_t plaintext_capacity,
                              size_t *out_plaintext_len);

int p2p_noise_backend_blake2s(const uint8_t *data, size_t data_len,
                              uint8_t output[P2P_NOISE_HANDSHAKE_HASH_SIZE]);

#endif
