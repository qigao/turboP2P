#include "security/p2p_cookie.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    FUZZ_COOKIE_INPUT_MAX = 256,
};

static uint32_t fuzz_read_u32(const uint8_t *data, size_t size,
                              size_t offset) {
    uint32_t value = 0;
    size_t available;

    if (!data || offset >= size) {
        return 0;
    }
    available = size - offset;
    if (available > sizeof(value)) {
        available = sizeof(value);
    }
    memcpy(&value, data + offset, available);
    return value;
}

static uint64_t fuzz_read_u64(const uint8_t *data, size_t size,
                              size_t offset) {
    uint64_t value = 0;
    size_t available;

    if (!data || offset >= size) {
        return 0;
    }
    available = size - offset;
    if (available > sizeof(value)) {
        available = sizeof(value);
    }
    memcpy(&value, data + offset, available);
    return value;
}

static void fuzz_copy(uint8_t *output, size_t output_size,
                      const uint8_t *data, size_t size, size_t offset) {
    size_t available = 0;

    memset(output, 0, output_size);
    if (data && offset < size) {
        available = size - offset;
        if (available > output_size) {
            available = output_size;
        }
        memcpy(output, data + offset, available);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char *const sources[] = {
        "127.0.0.1",
        "2001:db8::1",
        "not-an-ip",
    };
    uint8_t master_secret[P2P_COOKIE_SECRET_SIZE];
    uint8_t network_id[P2P_COOKIE_SECRET_SIZE];
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t challenge[P2P_COOKIE_PACKET_SIZE];
    uint8_t response[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];
    const char *source;
    uint64_t now_ms;
    uint32_t lifetime_ms;
    uint32_t rotation_ms;

    if ((!data && size != 0) || size > FUZZ_COOKIE_INPUT_MAX) {
        return 0;
    }
    fuzz_copy(master_secret, sizeof(master_secret), data, size, 0);
    fuzz_copy(network_id, sizeof(network_id), data, size, 32);
    fuzz_copy(preface, sizeof(preface), data, size, 64);
    fuzz_copy(challenge, sizeof(challenge), data, size, 108);
    fuzz_copy(response, sizeof(response), data, size, 156);
    now_ms = fuzz_read_u64(data, size, 204);
    lifetime_ms = fuzz_read_u32(data, size, 212);
    rotation_ms = fuzz_read_u32(data, size, 216);
    source = sources[fuzz_read_u32(data, size, 220) %
                     (sizeof(sources) / sizeof(sources[0]))];

    (void)p2p_secure_preface_validate(network_id, preface);
    (void)p2p_cookie_build_response(challenge, response, binding);
    (void)p2p_cookie_build_challenge(
        master_secret, source, preface, now_ms, lifetime_ms, rotation_ms,
        challenge);
    (void)p2p_cookie_verify_response(
        master_secret, source, preface, now_ms, lifetime_ms, rotation_ms,
        response, binding);
    return 0;
}
