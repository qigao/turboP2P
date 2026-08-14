#include "p2p_cookie.h"

#include "../crypto/p2p_crypto.h"
#include "../../include/p2p.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <string.h>

static const uint8_t P2P_PREFACE_MAGIC[4] = {'T', 'P', 'N', '2'};
static const uint8_t P2P_COOKIE_MAGIC[4] = {'T', 'P', 'C', '2'};
static const uint8_t P2P_COOKIE_KEY_DOMAIN[] = "turbo-p2p-cookie-key-v2";
static const uint8_t P2P_COOKIE_MAC_DOMAIN[] = "turbo-p2p-cookie-v2";

enum {
    P2P_COOKIE_VERSION = 2,
    P2P_COOKIE_HEADER_SIZE = 16,
    P2P_COOKIE_MAC_SIZE = 32,
    P2P_COOKIE_ADDRESS_MAX = 16,
};

static void cookie_write_be16(uint8_t output[2], uint16_t value) {
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static uint16_t cookie_read_be16(const uint8_t input[2]) {
    return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

static void cookie_write_be64(uint8_t output[8], uint64_t value) {
    size_t index;
    for (index = 0; index < 8; ++index) {
        output[index] = (uint8_t)(value >> (56U - index * 8U));
    }
}

static uint64_t cookie_read_be64(const uint8_t input[8]) {
    uint64_t value = 0;
    size_t index;
    for (index = 0; index < 8; ++index) {
        value = (value << 8) | input[index];
    }
    return value;
}

static int cookie_config_valid(uint32_t lifetime_ms, uint32_t rotation_ms) {
    return lifetime_ms != 0 && rotation_ms >= lifetime_ms &&
           rotation_ms % lifetime_ms == 0;
}

static int cookie_parse_source(const char *source_ip, uint8_t *family,
                               uint8_t address[P2P_COOKIE_ADDRESS_MAX],
                               size_t *address_len) {
    struct in_addr address4;
    struct in6_addr address6;

    if (!source_ip || !family || !address || !address_len) {
        return P2P_ERR_INVALID_ARG;
    }
    memset(address, 0, P2P_COOKIE_ADDRESS_MAX);
    if (inet_pton(AF_INET, source_ip, &address4) == 1) {
        *family = 4;
        *address_len = sizeof(address4);
        memcpy(address, &address4, sizeof(address4));
        return P2P_OK;
    }
    if (inet_pton(AF_INET6, source_ip, &address6) == 1) {
        *family = 6;
        *address_len = sizeof(address6);
        memcpy(address, &address6, sizeof(address6));
        return P2P_OK;
    }
    return P2P_ERR_INVALID_ARG;
}

static int cookie_compute_mac(
    const uint8_t master_secret[P2P_COOKIE_SECRET_SIZE], const char *source_ip,
    const uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE], uint64_t bucket,
    uint32_t lifetime_ms, uint32_t rotation_ms,
    uint8_t mac[P2P_COOKIE_MAC_SIZE]) {
    uint8_t key_input[sizeof(P2P_COOKIE_KEY_DOMAIN) - 1 + 8];
    uint8_t mac_input[sizeof(P2P_COOKIE_MAC_DOMAIN) - 1 + 1 +
                      P2P_COOKIE_ADDRESS_MAX + 8 + P2P_SECURE_PREFACE_SIZE];
    uint8_t effective_key[P2P_COOKIE_SECRET_SIZE];
    uint8_t address[P2P_COOKIE_ADDRESS_MAX];
    uint8_t family = 0;
    size_t address_len = 0;
    size_t offset = 0;
    uint64_t buckets_per_rotation;
    uint64_t key_epoch;
    int ret;

    if (!master_secret || !initiator_preface || !mac ||
        !cookie_config_valid(lifetime_ms, rotation_ms)) {
        return P2P_ERR_INVALID_ARG;
    }
    ret = cookie_parse_source(source_ip, &family, address, &address_len);
    if (ret != P2P_OK) {
        return ret;
    }
    buckets_per_rotation = rotation_ms / lifetime_ms;
    key_epoch = bucket / buckets_per_rotation;

    memcpy(key_input, P2P_COOKIE_KEY_DOMAIN,
           sizeof(P2P_COOKIE_KEY_DOMAIN) - 1);
    cookie_write_be64(key_input + sizeof(P2P_COOKIE_KEY_DOMAIN) - 1,
                      key_epoch);
    ret = p2p_crypto_hmac_sha256(master_secret, P2P_COOKIE_SECRET_SIZE,
                                 key_input, sizeof(key_input), effective_key);
    if (ret != P2P_OK) {
        goto cleanup;
    }

    memcpy(mac_input + offset, P2P_COOKIE_MAC_DOMAIN,
           sizeof(P2P_COOKIE_MAC_DOMAIN) - 1);
    offset += sizeof(P2P_COOKIE_MAC_DOMAIN) - 1;
    mac_input[offset++] = family;
    memcpy(mac_input + offset, address, address_len);
    offset += address_len;
    cookie_write_be64(mac_input + offset, bucket);
    offset += 8;
    memcpy(mac_input + offset, initiator_preface, P2P_SECURE_PREFACE_SIZE);
    offset += P2P_SECURE_PREFACE_SIZE;
    ret = p2p_crypto_hmac_sha256(effective_key, sizeof(effective_key),
                                 mac_input, offset, mac);

cleanup:
    p2p_crypto_wipe(effective_key, sizeof(effective_key));
    p2p_crypto_wipe(key_input, sizeof(key_input));
    p2p_crypto_wipe(mac_input, sizeof(mac_input));
    p2p_crypto_wipe(address, sizeof(address));
    return ret;
}

void p2p_secure_preface_build(const uint8_t network_id_hash[32],
                              uint8_t preface[P2P_SECURE_PREFACE_SIZE]) {
    if (!network_id_hash || !preface) {
        return;
    }
    memset(preface, 0, P2P_SECURE_PREFACE_SIZE);
    memcpy(preface, P2P_PREFACE_MAGIC, sizeof(P2P_PREFACE_MAGIC));
    preface[4] = P2P_SECURE_WIRE_VERSION_V2;
    cookie_write_be16(preface + 6, 1);
    memcpy(preface + 12, network_id_hash, P2P_SECURITY_ID_SIZE);
}

int p2p_secure_preface_validate(const uint8_t network_id_hash[32],
                                const uint8_t preface[P2P_SECURE_PREFACE_SIZE]) {
    uint8_t expected[P2P_SECURE_PREFACE_SIZE];
    int valid;

    if (!network_id_hash || !preface) {
        return P2P_ERR_INVALID_ARG;
    }
    p2p_secure_preface_build(network_id_hash, expected);
    valid = p2p_crypto_verify(expected, preface, sizeof(expected));
    p2p_crypto_wipe(expected, sizeof(expected));
    return valid ? P2P_OK : P2P_ERR_PROTOCOL;
}

int p2p_cookie_build_challenge(
    const uint8_t master_secret[P2P_COOKIE_SECRET_SIZE], const char *source_ip,
    const uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE], uint64_t now_ms,
    uint32_t lifetime_ms, uint32_t rotation_ms,
    uint8_t packet[P2P_COOKIE_PACKET_SIZE]) {
    uint64_t bucket;
    int ret;

    if (!packet || !cookie_config_valid(lifetime_ms, rotation_ms)) {
        return P2P_ERR_INVALID_ARG;
    }
    bucket = now_ms / lifetime_ms;
    memset(packet, 0, P2P_COOKIE_PACKET_SIZE);
    memcpy(packet, P2P_COOKIE_MAGIC, sizeof(P2P_COOKIE_MAGIC));
    cookie_write_be16(packet + 4, P2P_COOKIE_VERSION);
    packet[6] = P2P_COOKIE_CHALLENGE;
    cookie_write_be64(packet + 8, bucket);
    ret = cookie_compute_mac(master_secret, source_ip, initiator_preface,
                             bucket, lifetime_ms, rotation_ms,
                             packet + P2P_COOKIE_HEADER_SIZE);
    if (ret != P2P_OK) {
        p2p_crypto_wipe(packet, P2P_COOKIE_PACKET_SIZE);
    }
    return ret;
}

int p2p_cookie_build_response(
    const uint8_t challenge[P2P_COOKIE_PACKET_SIZE],
    uint8_t response[P2P_COOKIE_PACKET_SIZE],
    uint8_t binding[P2P_COOKIE_BINDING_SIZE]) {
    if (!challenge || !response || !binding ||
        memcmp(challenge, P2P_COOKIE_MAGIC, sizeof(P2P_COOKIE_MAGIC)) != 0 ||
        cookie_read_be16(challenge + 4) != P2P_COOKIE_VERSION ||
        challenge[6] != P2P_COOKIE_CHALLENGE || challenge[7] != 0) {
        return P2P_ERR_PROTOCOL;
    }
    memcpy(response, challenge, P2P_COOKIE_PACKET_SIZE);
    response[6] = P2P_COOKIE_RESPONSE;
    memcpy(binding, challenge + 8, P2P_COOKIE_BINDING_SIZE);
    return P2P_OK;
}

int p2p_cookie_verify_response(
    const uint8_t master_secret[P2P_COOKIE_SECRET_SIZE], const char *source_ip,
    const uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE], uint64_t now_ms,
    uint32_t lifetime_ms, uint32_t rotation_ms,
    const uint8_t response[P2P_COOKIE_PACKET_SIZE],
    uint8_t binding[P2P_COOKIE_BINDING_SIZE]) {
    uint8_t expected[P2P_COOKIE_MAC_SIZE];
    uint64_t bucket;
    uint64_t current_bucket;
    int ret;

    if (!response || !binding ||
        !cookie_config_valid(lifetime_ms, rotation_ms)) {
        return P2P_ERR_INVALID_ARG;
    }
    memset(binding, 0, P2P_COOKIE_BINDING_SIZE);
    if (memcmp(response, P2P_COOKIE_MAGIC, sizeof(P2P_COOKIE_MAGIC)) != 0 ||
        cookie_read_be16(response + 4) != P2P_COOKIE_VERSION ||
        response[6] != P2P_COOKIE_RESPONSE || response[7] != 0) {
        return P2P_ERR_PROTOCOL;
    }
    bucket = cookie_read_be64(response + 8);
    current_bucket = now_ms / lifetime_ms;
    if (bucket > current_bucket || current_bucket - bucket > 1) {
        return P2P_ERR_TIMEOUT;
    }
    ret = cookie_compute_mac(master_secret, source_ip, initiator_preface,
                             bucket, lifetime_ms, rotation_ms, expected);
    if (ret == P2P_OK &&
        !p2p_crypto_verify(expected, response + P2P_COOKIE_HEADER_SIZE,
                           sizeof(expected))) {
        ret = P2P_ERR_CRYPTO;
    }
    if (ret == P2P_OK) {
        memcpy(binding, response + 8, P2P_COOKIE_BINDING_SIZE);
    }
    p2p_crypto_wipe(expected, sizeof(expected));
    return ret;
}
