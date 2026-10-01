/*
 * Product platform adapter for the pinned Noise-C state machine.
 * Only the fixed XX/25519/ChaChaPoly/BLAKE2s profile is enabled.
 */

#include "protocol/internal.h"
#include "p2p_noise_c_platform.h"

#include <salts/random.h>
#include <openssl/evp.h>

#include <string.h>

typedef struct {
    struct NoiseDHState_s parent;
    uint8_t private_key[32];
    uint8_t public_key[32];
    p2p_noise_x25519_provider_fn provider_calculate;
    void *provider_context;
    int provider_error;
} p2p_noise_curve25519_state_t;

static int p2p_noise_x25519_public(uint8_t public_key[32],
                                  const uint8_t private_key[32]) {
    EVP_PKEY *key = NULL;
    size_t public_size = 32u;
    int ok = 0;
    if (!public_key || !private_key) return 0;
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32u);
    if (key &&
        EVP_PKEY_get_raw_public_key(key, public_key, &public_size) == 1 &&
        public_size == 32u) {
        ok = 1;
    }
    EVP_PKEY_free(key);
    if (!ok) noise_clean(public_key, 32u);
    return ok;
}

static int p2p_noise_x25519_shared(uint8_t shared_key[32],
                                  const uint8_t private_key[32],
                                  const uint8_t public_key[32]) {
    EVP_PKEY *private_handle = NULL;
    EVP_PKEY *public_handle = NULL;
    EVP_PKEY_CTX *context = NULL;
    size_t shared_size = 32u;
    int ok = 0;
    if (!shared_key || !private_key || !public_key) return 0;
    private_handle =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32u);
    public_handle =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, public_key, 32u);
    if (private_handle && public_handle) {
        context = EVP_PKEY_CTX_new(private_handle, NULL);
    }
    if (context && EVP_PKEY_derive_init(context) == 1 &&
        EVP_PKEY_derive_set_peer(context, public_handle) == 1 &&
        EVP_PKEY_derive(context, shared_key, &shared_size) == 1 &&
        shared_size == 32u) {
        ok = 1;
    }
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(public_handle);
    EVP_PKEY_free(private_handle);
    if (!ok) noise_clean(shared_key, 32u);
    return ok;
}

static void curve25519_clear_provider(
    p2p_noise_curve25519_state_t *curve) {
    curve->provider_calculate = NULL;
    curve->provider_context = NULL;
    curve->provider_error = 0;
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t aggregate = 0;
    size_t index;

    for (index = 0; index < length; index++) {
        aggregate |= bytes[index];
    }
    return aggregate == 0;
}

static int curve25519_generate(NoiseDHState *state,
                               const NoiseDHState *other) {
    p2p_noise_curve25519_state_t *curve =
        (p2p_noise_curve25519_state_t *)state;
    (void)other;

    curve25519_clear_provider(curve);

    if (salts_platform_secure_random(curve->private_key,
                                     sizeof(curve->private_key)) != 0) {
        noise_clean(curve->private_key, sizeof(curve->private_key));
        noise_clean(curve->public_key, sizeof(curve->public_key));
        return NOISE_ERROR_SYSTEM;
    }
    if (!p2p_noise_x25519_public(curve->public_key, curve->private_key) ||
        bytes_are_zero(curve->public_key, sizeof(curve->public_key))) {
        noise_clean(curve->private_key, sizeof(curve->private_key));
        noise_clean(curve->public_key, sizeof(curve->public_key));
        return NOISE_ERROR_SYSTEM;
    }
    return NOISE_ERROR_NONE;
}

static int curve25519_set_keypair(NoiseDHState *state,
                                  const uint8_t *private_key,
                                  const uint8_t *public_key) {
    p2p_noise_curve25519_state_t *curve =
        (p2p_noise_curve25519_state_t *)state;
    uint8_t derived[32];
    int result = NOISE_ERROR_NONE;

    curve25519_clear_provider(curve);
    if (!p2p_noise_x25519_public(derived, private_key) ||
        !noise_is_equal(derived, public_key, sizeof(derived))) {
        result = NOISE_ERROR_INVALID_PUBLIC_KEY;
    } else {
        memcpy(curve->private_key, private_key, sizeof(curve->private_key));
        memcpy(curve->public_key, public_key, sizeof(curve->public_key));
    }
    noise_clean(derived, sizeof(derived));
    return result;
}

static int curve25519_set_private(NoiseDHState *state,
                                  const uint8_t *private_key) {
    p2p_noise_curve25519_state_t *curve =
        (p2p_noise_curve25519_state_t *)state;

    curve25519_clear_provider(curve);
    memcpy(curve->private_key, private_key, sizeof(curve->private_key));
    if (!p2p_noise_x25519_public(curve->public_key, curve->private_key) ||
        bytes_are_zero(curve->public_key, sizeof(curve->public_key))) {
        noise_clean(curve->private_key, sizeof(curve->private_key));
        noise_clean(curve->public_key, sizeof(curve->public_key));
        return NOISE_ERROR_INVALID_PRIVATE_KEY;
    }
    return NOISE_ERROR_NONE;
}

static int curve25519_validate_public(const NoiseDHState *state,
                                      const uint8_t *public_key) {
    (void)state;
    return bytes_are_zero(public_key, 32) ? NOISE_ERROR_INVALID_PUBLIC_KEY
                                         : NOISE_ERROR_NONE;
}

static int curve25519_copy(NoiseDHState *state,
                           const NoiseDHState *from,
                           const NoiseDHState *other) {
    p2p_noise_curve25519_state_t *destination =
        (p2p_noise_curve25519_state_t *)state;
    const p2p_noise_curve25519_state_t *source =
        (const p2p_noise_curve25519_state_t *)from;
    (void)other;

    memcpy(destination->private_key, source->private_key,
           sizeof(destination->private_key));
    memcpy(destination->public_key, source->public_key,
           sizeof(destination->public_key));
    destination->provider_calculate = source->provider_calculate;
    destination->provider_context = source->provider_context;
    destination->provider_error = 0;
    return NOISE_ERROR_NONE;
}

static int curve25519_calculate(const NoiseDHState *private_key_state,
                                 const NoiseDHState *public_key_state,
                                 uint8_t *shared_key) {
    p2p_noise_curve25519_state_t *curve =
        (p2p_noise_curve25519_state_t *)private_key_state;

    curve->provider_error = 0;
    if (curve->provider_calculate) {
        curve->provider_error = curve->provider_calculate(
            curve->provider_context, public_key_state->public_key, shared_key);
        if (curve->provider_error != 0) {
            noise_clean(shared_key, 32);
            return NOISE_ERROR_SYSTEM;
        }
    } else if (!p2p_noise_x25519_shared(shared_key,
                                         private_key_state->private_key,
                                         public_key_state->public_key)) {
        noise_clean(shared_key, 32);
        return NOISE_ERROR_INVALID_PUBLIC_KEY;
    }
    if (bytes_are_zero(shared_key, 32)) {
        noise_clean(shared_key, 32);
        return NOISE_ERROR_INVALID_PUBLIC_KEY;
    }
    return NOISE_ERROR_NONE;
}

NoiseDHState *noise_curve25519_new(void) {
    p2p_noise_curve25519_state_t *state =
        noise_new(p2p_noise_curve25519_state_t);
    if (!state) {
        return NULL;
    }
    state->parent.dh_id = NOISE_DH_CURVE25519;
    state->parent.private_key_len = 32;
    state->parent.public_key_len = 32;
    state->parent.shared_key_len = 32;
    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = curve25519_generate;
    state->parent.set_keypair = curve25519_set_keypair;
    state->parent.set_keypair_private = curve25519_set_private;
    state->parent.validate_public_key = curve25519_validate_public;
    state->parent.copy = curve25519_copy;
    state->parent.calculate = curve25519_calculate;
    return &state->parent;
}

int p2p_noise_curve25519_set_provider(
    NoiseDHState *state, const uint8_t public_key[32],
    p2p_noise_x25519_provider_fn calculate, void *context) {
    p2p_noise_curve25519_state_t *curve;

    if (!state || state->dh_id != NOISE_DH_CURVE25519 || !public_key ||
        !calculate || bytes_are_zero(public_key, 32)) {
        return NOISE_ERROR_INVALID_PARAM;
    }
    curve = (p2p_noise_curve25519_state_t *)state;
    noise_clean(curve->private_key, sizeof(curve->private_key));
    memcpy(curve->public_key, public_key, sizeof(curve->public_key));
    curve->provider_calculate = calculate;
    curve->provider_context = context;
    curve->provider_error = 0;
    state->key_type = NOISE_KEY_TYPE_KEYPAIR;
    return NOISE_ERROR_NONE;
}

int p2p_noise_curve25519_take_provider_error(NoiseDHState *state) {
    p2p_noise_curve25519_state_t *curve;
    int error;

    if (!state || state->dh_id != NOISE_DH_CURVE25519) {
        return 0;
    }
    curve = (p2p_noise_curve25519_state_t *)state;
    error = curve->provider_error;
    curve->provider_error = 0;
    return error;
}

/* Noise-C's registry requires these symbols.  Returning NULL deliberately
 * rejects every primitive outside the single compiled production suite. */
NoiseCipherState *noise_aesgcm_new(void) { return NULL; }
NoiseDHState *noise_curve448_new(void) { return NULL; }
NoiseDHState *noise_newhope_new(void) { return NULL; }
NoiseHashState *noise_blake2b_new(void) { return NULL; }
NoiseHashState *noise_sha256_new(void) { return NULL; }
NoiseHashState *noise_sha512_new(void) { return NULL; }
