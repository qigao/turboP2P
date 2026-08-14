#ifndef P2P_COOKIE_H
#define P2P_COOKIE_H

#include <stddef.h>
#include <stdint.h>

enum {
    P2P_SECURE_PREFACE_SIZE = 44,
    P2P_COOKIE_PACKET_SIZE = 48,
    P2P_COOKIE_BINDING_SIZE = 40,
    P2P_COOKIE_SECRET_SIZE = 32,
};

typedef enum {
    P2P_COOKIE_CHALLENGE = 1,
    P2P_COOKIE_RESPONSE = 2,
} p2p_cookie_packet_type_t;

/* Canonical preface codec; output is caller-owned and validation is exact. */
void p2p_secure_preface_build(const uint8_t network_id_hash[32],
                              uint8_t preface[P2P_SECURE_PREFACE_SIZE]);
int p2p_secure_preface_validate(const uint8_t network_id_hash[32],
                                const uint8_t preface[P2P_SECURE_PREFACE_SIZE]);

/* Build a source-IP/preface-bound challenge for the monotonic time bucket. */
int p2p_cookie_build_challenge(
    const uint8_t master_secret[P2P_COOKIE_SECRET_SIZE],
    const char *source_ip,
    const uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE],
    uint64_t now_ms, uint32_t lifetime_ms, uint32_t rotation_ms,
    uint8_t packet[P2P_COOKIE_PACKET_SIZE]);

/* Convert a validated challenge to a response and copy its 40-byte binding. */
int p2p_cookie_build_response(
    const uint8_t challenge[P2P_COOKIE_PACKET_SIZE],
    uint8_t response[P2P_COOKIE_PACKET_SIZE],
    uint8_t binding[P2P_COOKIE_BINDING_SIZE]);

/* Accept only current/previous buckets and clear binding on every failure. */
int p2p_cookie_verify_response(
    const uint8_t master_secret[P2P_COOKIE_SECRET_SIZE],
    const char *source_ip,
    const uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE],
    uint64_t now_ms, uint32_t lifetime_ms, uint32_t rotation_ms,
    const uint8_t response[P2P_COOKIE_PACKET_SIZE],
    uint8_t binding[P2P_COOKIE_BINDING_SIZE]);

#endif
