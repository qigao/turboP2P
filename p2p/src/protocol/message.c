/**
 * message.c - Professional Message Serialization
 * Truncated and optimized for robust Kademlia P2P
 */

#include "message.h"
#include "../../src/internal.h"
#include <stdlib.h>
#include <string.h>

/* =============================================================================
 * Initialization
 * ============================================================================= */

void p2p_message_init(p2p_message_t *msg, p2p_msg_type_t type) {
    if (!msg) return;
    memset(msg, 0, sizeof(p2p_message_t));
    msg->header.type = (uint8_t)type;
}

uint32_t p2p_generate_request_id(void) {
    static uint32_t g_rid = 1;
    return g_rid++; /* Simplified for now */
}

/* =============================================================================
 * Serialization Logic
 * ============================================================================= */

int p2p_message_serialize(const p2p_message_t *msg, uint8_t **out, size_t *out_len) {
    if (!msg || !out || !out_len) return P2P_ERR_INVALID_ARG;

    /* Simple binary serialization: [Header][Payload] */
    size_t total_len = sizeof(p2p_msg_header_t) + msg->header.payload_len;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return P2P_ERR_NO_MEM;

    memcpy(buf, &msg->header, sizeof(p2p_msg_header_t));
    if (msg->header.payload_len > 0) {
        memcpy(buf + sizeof(p2p_msg_header_t), &msg->payload, msg->header.payload_len);
    }

    *out = buf;
    *out_len = total_len;
    return P2P_OK;
}

int p2p_message_deserialize(const uint8_t *data, size_t len,
                             p2p_message_t *msg, size_t *consumed) {
    if (!data || len < sizeof(p2p_msg_header_t) || !msg || !consumed) {
        return P2P_ERR_INVALID_ARG;
    }

    p2p_msg_header_t header;
    memcpy(&header, data, sizeof(p2p_msg_header_t));

    if (len < sizeof(p2p_msg_header_t) + header.payload_len) {
        return P2P_ERR_INVALID_ARG; /* Need more data */
    }

    msg->header = header;
    if (header.payload_len > 0) {
        memcpy(&msg->payload, data + sizeof(p2p_msg_header_t), header.payload_len);
    }

    *consumed = sizeof(p2p_msg_header_t) + header.payload_len;
    return P2P_OK;
}

/* =============================================================================
 * Helpers
 * ============================================================================= */

const char* p2p_message_type_name(p2p_msg_type_t type) {
    switch (type) {
        case P2P_MSG_PING: return "PING";
        case P2P_MSG_PONG: return "PONG";
        default:           return "UNKNOWN";
    }
}

void p2p_id_to_hex(const p2p_id_t id, char *buf, size_t buf_len) {
    if (!id || !buf || buf_len < 41) return;
    for (int i = 0; i < 20; i++) {
        snprintf(buf + (i * 2), buf_len - (i * 2), "%02x", id[i]);
    }
    buf[40] = '\0';
}
