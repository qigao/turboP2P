#ifndef TURBO_P2P_NOISE_C_PLATFORM_H
#define TURBO_P2P_NOISE_C_PLATFORM_H

#include <noise/protocol.h>

#include <stdint.h>

typedef int (*p2p_noise_x25519_provider_fn)(
    void *context, const uint8_t remote_public_key[32],
    uint8_t shared_key_out[32]);

int p2p_noise_curve25519_set_provider(
    NoiseDHState *state, const uint8_t public_key[32],
    p2p_noise_x25519_provider_fn calculate, void *context);

int p2p_noise_curve25519_take_provider_error(NoiseDHState *state);

#endif
