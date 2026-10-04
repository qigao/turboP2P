#include "peer.h"
#include "../internal.h"
#include "../security/p2p_cookie.h"
#include "../security/p2p_private_key_executor.h"
#include <salts/clock.h>
#include <tlog.h>
#include <platform.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <time.h>

#define RECV_BUF_INITIAL 4096
#define P2P_RECV_BUFFER_LIMIT (256U * 1024U)
#define P2P_HANDSHAKE_BUFFER_LIMIT (16U * 1024U)

enum {
    P2P_SECURE_READY_SIZE = 136,
    P2P_APPLICATION_PROTOCOL_VERSION = 2,
};

static const uint8_t P2P_SECURE_READY_MAGIC[4] = {'R', 'D', 'Y', '2'};
static const uint8_t P2P_SECURE_PROLOGUE_DOMAIN[] =
    "TurboP2P secure wire v2";
static const uint8_t P2P_SECURE_SESSION_DOMAIN[] =
    "turbo-p2p-session-v2";

static void p2p_peer_finalize(p2p_peer_t *peer);
static int p2p_peer_connect_is_suppressed(p2p_peer_t *peer);
static void p2p_peer_reset_security_state(p2p_peer_t *peer);
static int p2p_peer_process_security(p2p_peer_t *peer, size_t *consumed);
static int peer_process_buffer(p2p_peer_t *peer);
static int peer_begin_noise(p2p_peer_t *peer);
static int peer_finish_noise(p2p_peer_t *peer);

enum {
    PEER_SEND_NONE,
    PEER_SEND_PREFACE_OUT,
    PEER_SEND_COOKIE,
    PEER_SEND_PREFACE_IN,
    PEER_SEND_NOISE_1,
    PEER_SEND_NOISE_2,
    PEER_SEND_NOISE_3,
    PEER_SEND_READY
};

static uint64_t peer_next_handshake_generation(uint64_t generation) {
    generation++;
    return generation == 0 ? 1 : generation;
}

static int peer_security_latency_stage(
    uint8_t security_stage, p2p_security_latency_stage_t *latency_stage) {
    if (!latency_stage) {
        return 0;
    }
    switch (security_stage) {
        case P2P_SECURITY_STAGE_COOKIE:
            *latency_stage = P2P_SECURITY_LATENCY_COOKIE;
            return 1;
        case P2P_SECURITY_STAGE_PREFACE:
            *latency_stage = P2P_SECURITY_LATENCY_PREFACE;
            return 1;
        case P2P_SECURITY_STAGE_NOISE:
            *latency_stage = P2P_SECURITY_LATENCY_NOISE;
            return 1;
        case P2P_SECURITY_STAGE_READY:
            *latency_stage = P2P_SECURITY_LATENCY_READY;
            return 1;
        default:
            return 0;
    }
}

static void peer_security_transition(p2p_peer_t *peer,
                                     p2p_security_stage_t next_stage) {
    p2p_security_latency_stage_t latency_stage;
    uint64_t now_ms;

    if (!peer || !peer->node || peer->security_stage == next_stage) {
        return;
    }
    now_ms = salts_hrtime() / 1000000U;
    if (peer_security_latency_stage(peer->security_stage, &latency_stage)) {
        p2p_node_record_handshake_latency(
            peer->node,
            peer->security_initiator ? P2P_SECURITY_ROLE_INITIATOR
                                     : P2P_SECURITY_ROLE_RESPONDER,
            latency_stage, peer->security_stage_started_ms, now_ms);
    }
    peer->security_stage = (uint8_t)next_stage;
    peer->security_stage_started_ms =
        peer_security_latency_stage(next_stage, &latency_stage) ? now_ms : 0;
}

static int peer_session_admit_wire_bytes(const p2p_peer_t *peer,
                                         uint64_t used_bytes,
                                         size_t wire_bytes) {
    uint64_t now_ms;
    uint64_t age_limit;
    uint64_t byte_limit;

    if (!peer || !peer->node || peer->session_started_ms == 0) {
        return P2P_ERR_INVALID_STATE;
    }
    now_ms = salts_hrtime() / 1000000U;
    age_limit = peer->node->security_config.session_max_age_ms;
    byte_limit =
        peer->node->security_config.session_max_bytes_per_direction;
    if (now_ms < peer->session_started_ms ||
        now_ms - peer->session_started_ms >= age_limit ||
        used_bytes > byte_limit ||
        (uint64_t)wire_bytes > byte_limit - used_bytes) {
        return P2P_ERR_KEY_EXHAUSTED;
    }
    return P2P_OK;
}

/* =============================================================================
 * Peer State String
 * ============================================================================= */

const char* p2p_peer_state_str(p2p_peer_state_t state) {
    switch (state) {
        case P2P_PEER_STATE_DISCONNECTED: return "DISCONNECTED";
        case P2P_PEER_STATE_CONNECTING:   return "CONNECTING";
        case P2P_PEER_STATE_HANDSHAKING:  return "HANDSHAKING";
        case P2P_PEER_STATE_CONNECTED:    return "CONNECTED";
        case P2P_PEER_STATE_CLOSING:      return "CLOSING";
        default:                          return "UNKNOWN";
    }
}

/* =============================================================================
 * Peer Lifecycle
 * ============================================================================= */

CXX_C_API p2p_peer_t* p2p_peer_create(p2p_node_t *node, const char *ip, int port) {
    if(ip == NULL)
        return NULL;
    p2p_peer_t *peer = (p2p_peer_t *)calloc(1, sizeof(p2p_peer_t));
    if (!peer) {
        TLOG_ERROR("[P2P] p2p_peer_create: out of memory");
        return NULL;
    }

    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->port = port;
    peer->node = node;
    peer->state = P2P_PEER_STATE_DISCONNECTED;

    /* Allocate receive buffer */
    peer->recv_buf = (uint8_t *)malloc(RECV_BUF_INITIAL);
    if (!peer->recv_buf) {
        free(peer);
        return NULL;
    }
    peer->recv_cap = RECV_BUF_INITIAL;
    peer->recv_len = 0;

    return peer;
}

CXX_C_API void p2p_peer_destroy(p2p_peer_t *peer) {
    int should_finalize = 0;

    if (!peer) return;

    p2p_node_t *node = peer->node;
    if (node) {
        salts_mutex_lock(&node->mutex);
    }

    if (peer->destroying) {
        if (node) salts_mutex_unlock(&node->mutex);
        return;
    }
    peer->destroying = 1;
    should_finalize = (peer->callback_refs == 0);

    if (node) {
        salts_mutex_unlock(&node->mutex);
    }

    p2p_peer_disconnect(peer);
    if (!should_finalize) {
        return;
    }

    p2p_peer_finalize(peer);
}

static void p2p_peer_finalize(p2p_peer_t *peer) {
    if (!peer) {
        return;
    }

    /* Clean up crypto state */
    if (peer->handshake) {
        p2p_noise_handshake_destroy(peer->handshake);
        free(peer->handshake);
        peer->handshake = NULL;
    }
    p2p_crypto_session_destroy(&peer->crypto);

    if (peer->recv_buf) {
        free(peer->recv_buf);
    }

    free(peer);
}

int p2p_peer_hold_locked(p2p_peer_t *peer) {
    if (!peer) {
        return 0;
    }

    if (!peer->destroying) {
        peer->callback_refs++;
        return 1;
    }

    return 0;
}

int p2p_peer_hold(p2p_peer_t *peer) {
    p2p_node_t *node = NULL;
    int held = 0;

    if (!peer) {
        return 0;
    }

    node = peer->node;
    if (node) {
        salts_mutex_lock(&node->mutex);
    }

    held = p2p_peer_hold_locked(peer);

    if (node) {
        salts_mutex_unlock(&node->mutex);
    }

    return held;
}

void p2p_peer_release(p2p_peer_t *peer) {
    p2p_node_t *node = NULL;
    int should_finalize = 0;

    if (!peer) {
        return;
    }

    node = peer->node;
    if (node) {
        salts_mutex_lock(&node->mutex);
    }

    if (peer->callback_refs > 0) {
        peer->callback_refs--;
    }
    if (peer->destroying && peer->callback_refs == 0 && peer->conn == NULL) {
        should_finalize = 1;
    }

    if (node) {
        salts_mutex_unlock(&node->mutex);
    }

    if (should_finalize) {
        p2p_peer_finalize(peer);
    }
}

int p2p_peer_prepare_connect(p2p_peer_t *peer, int *start) {
    if (!start) return P2P_ERR_INVALID_ARG;
    *start = 0;
    uint64_t now_ms = 0;
    int capacity_ret;

    if (!peer || !peer->node) {
        return P2P_ERR_INVALID_ARG;
    }
    if (peer->destroying) return P2P_ERR_INVALID_STATE;
    if (peer->private_key_operation || peer->security_send_action) {
        return P2P_ERR_INVALID_STATE;
    }

    if (p2p_peer_connect_is_suppressed(peer)) {
        return P2P_ERR_NETWORK;
    }

    if (peer->state == P2P_PEER_STATE_CONNECTING ||
        peer->state == P2P_PEER_STATE_HANDSHAKING ||
        peer->state == P2P_PEER_STATE_CONNECTED) {
        return P2P_OK;
    }

    now_ms = salts_hrtime() / 1000000;
    if (peer->reconnect_after_ms > now_ms) {
        return P2P_OK;
    }

    p2p_peer_reset_security_state(peer);

    capacity_ret =
        p2p_node_reserve_transport_send_capacity(peer->node, peer);
    if (capacity_ret != P2P_OK) {
        return capacity_ret;
    }

    *start = 1;
    return P2P_OK;
}

static int p2p_peer_connect_is_suppressed(p2p_peer_t *peer) {
    p2p_connect_suppression_t *suppression = NULL;
    char key[96];
    uint64_t now_ms = 0;
    int blocked = 0;
    p2p_node_t *node = NULL;

    if (!peer || !peer->node) {
        return 0;
    }

    node = peer->node;
    p2p_endpoint_to_key(key, sizeof(key), peer->ip, peer->port);
    now_ms = salts_hrtime() / 1000000;

    salts_mutex_lock(&node->mutex);
    HASH_FIND_STR(node->connect_suppressions, key, suppression);
    if (suppression) {
        if (suppression->until_ms > now_ms) {
            blocked = 1;
        } else {
            HASH_DEL(node->connect_suppressions, suppression);
            free(suppression);
        }
    }
    salts_mutex_unlock(&node->mutex);

    return blocked;
}

static void p2p_peer_reset_security_state(p2p_peer_t *peer) {
    if (!peer) {
        return;
    }

    if (peer->private_key_operation) {
        peer->deferred_security_reset = 1;
        p2p_private_key_executor_cancel_peer(peer);
        return;
    }

    if (peer->handshake) {
        p2p_noise_handshake_destroy(peer->handshake);
        free(peer->handshake);
        peer->handshake = NULL;
    }
    p2p_crypto_session_destroy(&peer->crypto);
    memset(peer->remote_public_key, 0, sizeof(peer->remote_public_key));
    peer->remote_public_key_ready = 0;
    p2p_crypto_wipe(peer->remote_credential,
                    sizeof(peer->remote_credential));
    peer->remote_credential_len = 0;
    p2p_crypto_wipe(&peer->authenticated_identity,
                    sizeof(peer->authenticated_identity));
    p2p_crypto_wipe(peer->channel_binding,
                    sizeof(peer->channel_binding));
    memset(peer->local_preface, 0, sizeof(peer->local_preface));
    memset(peer->remote_preface, 0, sizeof(peer->remote_preface));
    p2p_crypto_wipe(peer->cookie_binding, sizeof(peer->cookie_binding));
    peer->security_stage = P2P_SECURITY_STAGE_NONE;
    peer->security_stage_started_ms = 0;
    peer->noise_step = 0;
    peer->security_send_action = PEER_SEND_NONE;
    peer->security_send_bytes = 0;
    peer->security_send_generation = 0;
    peer->security_initiator = 0;
    peer->ready_sent = 0;
    peer->ready_received = 0;
    peer->security_deadline_ms = 0;
    peer->session_started_ms = 0;
    peer->sent_bytes = 0;
    peer->received_bytes = 0;
    peer->deferred_security_reset = 0;
    peer->handshake_generation =
        peer_next_handshake_generation(peer->handshake_generation);
}

void p2p_peer_disconnect(p2p_peer_t *peer) {
    if (!peer) return;
    if (!peer->conn) {
        if (peer->node) {
            p2p_node_release_transport_send_capacity(peer->node, peer);
        }
        return;
    }

    peer->state = P2P_PEER_STATE_CLOSING;

    /* Destroy unified connection (handles client/server automatically) */
    p2p_connection_t *conn = peer->conn;
    peer->conn = NULL;
    peer->is_connected = 0;
    
    if (conn) {
        p2p_connection_destroy(conn);
    }
    if (peer->node) {
        p2p_node_release_transport_send_capacity(peer->node, peer);
    }

    peer->state = P2P_PEER_STATE_DISCONNECTED;
    peer->recv_len = 0;
    p2p_peer_reset_security_state(peer);
}

/* =============================================================================
 * Peer I/O
 * ============================================================================= */

static int peer_send_raw(p2p_peer_t *peer, const uint8_t *data, size_t len) {
    int result;

    if (!peer || !peer->conn) return P2P_ERR_NETWORK;
    result = p2p_connection_send(peer->conn, data, len);
    if (result == 0) return P2P_OK;
    return result == P2P_ERR_RESOURCE_EXHAUSTED ? P2P_ERR_RESOURCE_EXHAUSTED
                                  : P2P_ERR_NETWORK;
}

int p2p_peer_send(p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!peer || !msg) {
        return P2P_ERR_INVALID_ARG;
    }

    if (peer->state != P2P_PEER_STATE_CONNECTED ||
        peer->security_stage != P2P_SECURITY_STAGE_ESTABLISHED ||
        !p2p_crypto_session_is_ready(&peer->crypto)) {
        TLOG_DEBUGF("[P2P] peer_send: peer not connected (state={})",
                 p2p_peer_state_str(peer->state));
        return P2P_ERR_NETWORK;
    }

    /* Serialize message to frame */
    uint8_t *frame_buf = NULL;
    size_t frame_len = 0;

    int ret = p2p_message_serialize(msg, &frame_buf, &frame_len);
    if (ret != P2P_OK) {
        return ret;
    }

    /* Application frames exist only inside an established Noise session. */
    if (p2p_crypto_session_is_ready(&peer->crypto)) {

        size_t ct_len;
        uint8_t *ct_buf;
        uint8_t *ct_storage;

        if (frame_len > P2P_NOISE_MAX_PLAINTEXT_SIZE) {
            free(frame_buf);
            return P2P_ERR_PROTOCOL;
        }
        ct_len = frame_len + P2P_NOISE_TAG_SIZE;
        ret = peer_session_admit_wire_bytes(peer, peer->sent_bytes,
                                            ct_len + 2U);
        if (ret != P2P_OK) {
            free(frame_buf);
            p2p_node_record_security_failure(peer->node,
                                             peer->security_stage, ret);
            p2p_peer_disconnect(peer);
            return ret;
        }
        /* Leave padding before the two-byte wire prefix so Noise-C's private
         * ChaCha word loads see aligned ciphertext. The sent frame is unchanged
         * and requires no additional copy. Keep the allocation base for free. */
        ct_storage = (uint8_t *)malloc(ct_len + sizeof(uint32_t));
        if (!ct_storage) {
            free(frame_buf);
            return P2P_ERR_NO_MEM;
        }
        ct_buf = ct_storage + sizeof(uint32_t) - 2U;

        ct_buf[0] = (uint8_t)((ct_len >> 8) & 0xFF);
        ct_buf[1] = (uint8_t)(ct_len & 0xFF);

        size_t encrypted_len = 0;
        ret = p2p_crypto_encrypt(&peer->crypto, frame_buf, frame_len,
                                  ct_buf + 2, &encrypted_len);
        free(frame_buf);

        if (ret != P2P_OK) {
            free(ct_storage);
            TLOG_ERROR("[P2P] peer_send: encryption failed");
            p2p_node_record_security_failure(peer->node,
                                             peer->security_stage, ret);
            p2p_peer_disconnect(peer);
            return ret;
        }

        ret = peer_send_raw(peer, ct_buf, encrypted_len + 2);
        free(ct_storage);
        if (ret != P2P_OK) {
            /* CipherState advanced before the transport admitted the frame.
             * Continuing or retrying would permanently desynchronize nonces. */
            p2p_node_record_security_failure(peer->node,
                                             peer->security_stage, ret);
            p2p_peer_disconnect(peer);
            return ret;
        }
        peer->sent_bytes += (uint64_t)encrypted_len + 2U;
        return ret;
    }

    free(frame_buf);
    return P2P_ERR_INVALID_STATE;
}

int p2p_peer_on_data(p2p_peer_t *peer, const void *data, size_t len) {
    size_t receive_limit;

    if (!peer || !data || len == 0) {
        return P2P_ERR_INVALID_ARG;
    }

    receive_limit = peer->security_stage == P2P_SECURITY_STAGE_ESTABLISHED
                        ? P2P_RECV_BUFFER_LIMIT
                        : P2P_HANDSHAKE_BUFFER_LIMIT;
    if (peer->recv_len > receive_limit || len > receive_limit - peer->recv_len) {
        return P2P_ERR_PROTOCOL;
    }

    /* Append to receive buffer */
    if (peer->recv_len + len > peer->recv_cap) {
        size_t new_cap = peer->recv_cap * 2;
        while (new_cap < peer->recv_len + len) {
            new_cap *= 2;
        }
        if (new_cap > receive_limit) {
            new_cap = receive_limit;
        }
        uint8_t *new_buf = (uint8_t *)realloc(peer->recv_buf, new_cap);
        if (!new_buf) {
            TLOG_ERROR("[P2P] peer_on_data: realloc failed");
            return P2P_ERR_NO_MEM;
        }
        peer->recv_buf = new_buf;
        peer->recv_cap = new_cap;
    }

    memcpy(peer->recv_buf + peer->recv_len, data, len);
    peer->recv_len += len;
    peer->last_seen = salts_hrtime();

    return peer_process_buffer(peer);
}

static int peer_process_buffer_inner(p2p_peer_t *peer) {
    while (peer->recv_len > 0) {
        size_t consumed = 0;
        int ret = P2P_OK;

        if (peer->private_key_operation || peer->security_send_action) {
            break;
        }

        if (peer->security_stage != P2P_SECURITY_STAGE_ESTABLISHED) {
            ret = p2p_peer_process_security(peer, &consumed);
            if (ret == P2P_ERR_INVALID_ARG) {
                break;
            }
            if (peer->destroying || !peer->conn) return ret;
            if (ret != P2P_OK || consumed == 0 ||
                consumed > peer->recv_len) {
                return ret == P2P_OK ? P2P_ERR_PROTOCOL : ret;
            }
            peer->recv_len -= consumed;
            if (peer->recv_len > 0) {
                memmove(peer->recv_buf, peer->recv_buf + consumed,
                        peer->recv_len);
            }
            if (peer->private_key_operation || peer->security_send_action) {
                break;
            }
            continue;
        }

        p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
        if (!msg) return P2P_ERR_NO_MEM;
        uint8_t *plain_buf = NULL;
        size_t plain_len = 0;

        if (p2p_crypto_session_is_ready(&peer->crypto)) {
            size_t encrypted_len = 0;

            if (peer->recv_len < 2) {
                free(msg);
                break;
            }

            encrypted_len = ((size_t)peer->recv_buf[0] << 8) |
                            (size_t)peer->recv_buf[1];
            if (encrypted_len < P2P_NOISE_TAG_SIZE ||
                encrypted_len > P2P_NOISE_MAX_FRAME_SIZE) {
                free(msg);
                return P2P_ERR_PROTOCOL;
            }
            if (peer->recv_len < 2 + encrypted_len) {
                free(msg);
                break;
            }
            ret = peer_session_admit_wire_bytes(peer, peer->received_bytes,
                                                encrypted_len + 2U);
            if (ret != P2P_OK) {
                free(msg);
                return ret;
            }

            plain_buf = (uint8_t *)malloc(encrypted_len);
            if (!plain_buf) {
                free(msg);
                return P2P_ERR_NO_MEM;
            }
            ret = p2p_crypto_decrypt(&peer->crypto,
                                     peer->recv_buf + 2,
                                     encrypted_len,
                                     plain_buf,
                                     encrypted_len,
                                     &plain_len);
            if (ret != P2P_OK) {
                free(plain_buf);
                free(msg);
                return ret;
            }
            peer->received_bytes += (uint64_t)encrypted_len + 2U;

            ret = p2p_message_deserialize(plain_buf, plain_len, msg, &consumed);
            if (ret == P2P_OK && consumed != plain_len) {
                ret = P2P_ERR_PROTOCOL;
            }
            free(plain_buf);
            plain_buf = NULL;
            consumed = 2 + encrypted_len;
        } else {
            free(msg);
            return P2P_ERR_INVALID_STATE;
        }
        if (ret == P2P_ERR_INVALID_ARG) {
            /* Need more data */
            free(msg);
            break;
        }
        if (ret != P2P_OK) {
            TLOG_DEBUGF("[P2P] peer_on_data: invalid frame from {}:{} (code: {})",
                      peer->ip, peer->port, ret);
            free(msg);
            return ret;
        }

        if (consumed == 0 || consumed > peer->recv_len) {
            TLOG_DEBUGF("[P2P] peer_on_data: corrupt frame accounting from {}:{} (consumed={}, recv_len={})",
                      peer->ip, peer->port, consumed, peer->recv_len);
            free(msg);
            return P2P_ERR_PROTOCOL;
        }

        peer->recv_len -= consumed;
        if (peer->recv_len > 0) {
            memmove(peer->recv_buf, peer->recv_buf + consumed, peer->recv_len);
        }

        /* Dispatch message */
        p2p_node_dispatch_message(peer->node, peer, msg);
        free(msg);

        if (peer->destroying) {
            break;
        }
    }

    return P2P_OK;
}

static int peer_process_buffer(p2p_peer_t *peer) {
    int result;
    if (peer->processing_input) return P2P_OK;
    peer->processing_input = 1;
    result = peer_process_buffer_inner(peer);
    peer->processing_input = 0;
    return result;
}

/* =============================================================================
 * Peer Utilities
 * ============================================================================= */

void p2p_peer_set_id(p2p_peer_t *peer, const p2p_id_t id) {
    if (peer && id) {
        memcpy(peer->id, id, P2P_HASH_SIZE);
    }
}

bool p2p_peer_is_connected(const p2p_peer_t *peer) {
    return peer && peer->state == P2P_PEER_STATE_CONNECTED;
}

bool p2p_peer_addr_equals(const p2p_peer_t *peer, const char *ip, int port) {
    if (!peer || !ip) return false;
    return (strcmp(peer->ip, ip) == 0) && (peer->port == port);
}

int p2p_peer_id_cmp(const p2p_peer_t *a, const p2p_peer_t *b) {
    if (!a || !b) return 0;
    return memcmp(a->id, b->id, P2P_HASH_SIZE);
}

/* =============================================================================
 * Noise Protocol Handshake
 * ============================================================================= */

static void p2p_write_be16(uint8_t output[2], uint16_t value) {
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static uint16_t p2p_read_be16(const uint8_t input[2]) {
    return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

static int peer_bytes_are_zero(const uint8_t *bytes, size_t length) {
    uint8_t combined = 0;

    for (size_t index = 0; index < length; ++index) {
        combined |= bytes[index];
    }
    return combined == 0;
}

static int peer_constant_time_equal(const uint8_t *left,
                                    const uint8_t *right,
                                    size_t length) {
    uint8_t difference = 0;

    for (size_t index = 0; index < length; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0;
}

static void peer_security_send_complete(void *context, int status) {
    p2p_peer_t *peer = context;
    int action, ret = status;
    size_t wire_bytes;
    if (!p2p_peer_hold(peer)) return;
    if (!peer->conn || !peer->security_send_action ||
        peer->security_send_generation != peer->handshake_generation) {
        p2p_peer_release(peer);
        return;
    }
    if (ret == P2P_OK && peer->security_deadline_ms &&
        salts_monotonic_ms() >= peer->security_deadline_ms) ret = P2P_ERR_TIMEOUT;
    action = peer->security_send_action;
    wire_bytes = peer->security_send_bytes;
    peer->security_send_action = PEER_SEND_NONE;
    peer->security_send_bytes = 0;
    if (ret == P2P_OK) {
        switch (action) {
        case PEER_SEND_COOKIE:
            peer_security_transition(peer, P2P_SECURITY_STAGE_PREFACE);
            break;
        case PEER_SEND_PREFACE_IN:
            ret = peer_begin_noise(peer);
            break;
        case PEER_SEND_NOISE_1: peer->noise_step = 1; break;
        case PEER_SEND_NOISE_2: peer->noise_step = 2; break;
        case PEER_SEND_NOISE_3:
            peer->noise_step = 3;
            ret = peer_finish_noise(peer);
            break;
        case PEER_SEND_READY:
            peer->ready_sent = 1;
            peer->sent_bytes += wire_bytes;
            break;
        case PEER_SEND_PREFACE_OUT: break;
        default: ret = P2P_ERR_INVALID_STATE; break;
        }
    }
    if (ret == P2P_OK && !peer->destroying && peer->conn &&
        !peer->security_send_action && !peer->private_key_operation) {
        /* A previous receive may already contain READY/application bytes.
         * Drain them before requesting more input, even if no new packet comes. */
        ret = peer_process_buffer(peer);
        if (ret == P2P_OK && !peer->destroying && peer->conn &&
            !peer->security_send_action && !peer->private_key_operation)
            ret = p2p_connection_pause(peer->conn, 0);
    }
    if (ret != P2P_OK && !peer->destroying) {
        p2p_node_record_security_failure(peer->node, peer->security_stage, ret);
        p2p_peer_transport_closed(peer, peer->keep_entry ? 0 : 1);
    }
    p2p_peer_release(peer);
}

static int peer_send_security(p2p_peer_t *peer, const uint8_t *data,
                              size_t length, int action) {
    int ret;
    if (!peer || !peer->conn) return P2P_ERR_NETWORK;
    if (peer->security_send_action) return P2P_ERR_INVALID_STATE;
    ret = p2p_connection_pause(peer->conn, 1);
    if (ret != P2P_OK) return ret;
    peer->security_send_generation = peer->handshake_generation;
    peer->security_send_bytes = length;
    peer->security_send_action = action;
    ret = p2p_connection_send_completed(peer->conn, data, length,
                                       peer_security_send_complete, peer);
    if (ret != P2P_OK) {
        peer->security_send_action = PEER_SEND_NONE;
        peer->security_send_bytes = 0;
    }
    /* Completion owns admitted errors, including inline legacy completion. */
    return ret;
}

static int peer_send_security_frame(p2p_peer_t *peer, const uint8_t *data,
                                    size_t len, int action) {
    uint8_t *frame;
    int ret;

    if (!peer || !data || len == 0 || len > UINT16_MAX) {
        return P2P_ERR_INVALID_ARG;
    }
    frame = (uint8_t *)malloc(len + 2);
    if (!frame) {
        return P2P_ERR_NO_MEM;
    }
    p2p_write_be16(frame, (uint16_t)len);
    memcpy(frame + 2, data, len);
    ret = peer_send_security(peer, frame, len + 2, action);
    p2p_crypto_wipe(frame, len + 2);
    free(frame);
    return ret;
}

static int peer_send_ready(p2p_peer_t *peer) {
    uint8_t plain[P2P_SECURE_READY_SIZE] = {0};
    uint8_t session_input[sizeof(P2P_SECURE_SESSION_DOMAIN) - 1 +
                          P2P_SECURITY_ID_SIZE];
    uint8_t encrypted[P2P_SECURE_READY_SIZE + P2P_NOISE_TAG_SIZE];
    uint8_t session_id[P2P_SECURITY_ID_SIZE];
    size_t encrypted_len = 0;
    int ret;

    memcpy(session_input, P2P_SECURE_SESSION_DOMAIN,
           sizeof(P2P_SECURE_SESSION_DOMAIN) - 1);
    memcpy(session_input + sizeof(P2P_SECURE_SESSION_DOMAIN) - 1,
           peer->channel_binding, P2P_SECURITY_ID_SIZE);
    ret = p2p_noise_backend_blake2s(session_input, sizeof(session_input),
                                    session_id);
    if (ret != P2P_OK) {
        goto cleanup;
    }
    memcpy(plain, P2P_SECURE_READY_MAGIC, sizeof(P2P_SECURE_READY_MAGIC));
    p2p_write_be16(plain + 4, P2P_SECURE_WIRE_VERSION_V2);
    p2p_write_be16(plain + 6, P2P_APPLICATION_PROTOCOL_VERSION);
    memcpy(plain + 8, peer->node->local_authenticated_identity.principal_id,
           P2P_SECURITY_ID_SIZE);
    memcpy(plain + 40, peer->node->local_authenticated_identity.routing_id,
           P2P_SECURITY_ID_SIZE);
    memcpy(plain + 72,
           peer->node->local_authenticated_identity.credential_digest,
           P2P_SECURITY_ID_SIZE);
    memcpy(plain + 104, session_id, P2P_SECURITY_ID_SIZE);
    ret = p2p_crypto_encrypt(&peer->crypto, plain, sizeof(plain), encrypted,
                             &encrypted_len);
    if (ret == P2P_OK) {
        ret = peer_send_security_frame(peer, encrypted, encrypted_len, PEER_SEND_READY);
    }

cleanup:
    p2p_crypto_wipe(plain, sizeof(plain));
    p2p_crypto_wipe(encrypted, sizeof(encrypted));
    p2p_crypto_wipe(session_input, sizeof(session_input));
    p2p_crypto_wipe(session_id, sizeof(session_id));
    return ret;
}

static int peer_finish_noise(p2p_peer_t *peer) {
    p2p_authenticated_identity_v2_t identity = {0};
    uint64_t now_ms = (uint64_t)time(NULL) * 1000U;
    int ret;

    if (!peer || !peer->handshake || !p2p_noise_is_complete(peer->handshake)) {
        return P2P_ERR_INVALID_STATE;
    }
    ret = p2p_noise_split(peer->handshake, &peer->crypto);
    if (ret != P2P_OK) {
        return ret;
    }
    memcpy(peer->remote_public_key,
           peer->handshake->remote_static_public, P2P_KEY_SIZE);
    memcpy(peer->channel_binding, peer->handshake->handshake_hash,
           P2P_SECURITY_ID_SIZE);
    peer->remote_public_key_ready = 1;

    ret = peer->node->security_config.identity_provider.verify_remote_credential(
        peer->node->security_config.identity_provider.context,
        peer->remote_public_key, peer->channel_binding,
        peer->remote_credential, peer->remote_credential_len, now_ms,
        &identity);
    if (ret != P2P_OK ||
        peer_bytes_are_zero(identity.principal_id,
                            sizeof(identity.principal_id)) ||
        peer_bytes_are_zero(identity.routing_id,
                            sizeof(identity.routing_id)) ||
        peer_bytes_are_zero(identity.credential_digest,
                            sizeof(identity.credential_digest))) {
        p2p_crypto_wipe(&identity, sizeof(identity));
        return P2P_ERR_UNTRUSTED_IDENTITY;
    }
    peer->authenticated_identity = identity;
    memcpy(peer->id, identity.routing_id, P2P_HASH_SIZE);
    p2p_crypto_wipe(&identity, sizeof(identity));

    p2p_noise_handshake_destroy(peer->handshake);
    free(peer->handshake);
    peer->handshake = NULL;
    peer_security_transition(peer, P2P_SECURITY_STAGE_READY);
    peer->security_deadline_ms = salts_hrtime() / 1000000U +
                                 peer->node->security_config.ready_timeout_ms;
    return peer_send_ready(peer);
}

static int peer_handle_noise_frame(p2p_peer_t *peer, const uint8_t *frame,
                                   size_t frame_len) {
    uint8_t reply[P2P_SECURITY_HANDSHAKE_FRAME_MAX];
    size_t reply_len = 0;
    size_t credential_len = 0;
    int ret;

    if (!peer || !peer->node || !peer->handshake ||
        peer->private_key_operation) {
        return P2P_ERR_INVALID_STATE;
    }

    if (!peer->security_initiator && peer->noise_step == 0) {
        ret = p2p_noise_read_message_with_payload(
            peer->handshake, frame, frame_len, peer->remote_credential,
            peer->node->security_config.credential_limit, &credential_len);
        if (ret != P2P_OK || credential_len != 0) {
            return ret == P2P_OK ? P2P_ERR_PROTOCOL : ret;
        }
        if (peer->node->crypto.identity.uses_blocking_private_key_provider) {
            ret = p2p_connection_pause(peer->conn, 1);
            if (ret != P2P_OK) return ret;
            return p2p_private_key_executor_submit(
                peer, peer->node->local_credential,
                peer->node->local_credential_len, 2, 0);
        }
        ret = p2p_noise_write_message_with_payload(
            peer->handshake, peer->node->local_credential,
            peer->node->local_credential_len, reply, &reply_len,
            peer->node->security_config.handshake_frame_limit);
        if (ret == P2P_OK) {
            ret = peer_send_security_frame(peer, reply, reply_len, PEER_SEND_NOISE_2);
        }
        return ret;
    }

    if (peer->security_initiator && peer->noise_step == 1) {
        ret = p2p_noise_read_message_with_payload(
            peer->handshake, frame, frame_len, peer->remote_credential,
            peer->node->security_config.credential_limit, &credential_len);
        if (ret != P2P_OK) {
            return ret;
        }
        peer->remote_credential_len = credential_len;
        if (peer->node->crypto.identity.uses_blocking_private_key_provider) {
            ret = p2p_connection_pause(peer->conn, 1);
            if (ret != P2P_OK) return ret;
            return p2p_private_key_executor_submit(
                peer, peer->node->local_credential,
                peer->node->local_credential_len, 3, 1);
        }
        ret = p2p_noise_write_message_with_payload(
            peer->handshake, peer->node->local_credential,
            peer->node->local_credential_len, reply, &reply_len,
            peer->node->security_config.handshake_frame_limit);
        if (ret == P2P_OK) {
            ret = peer_send_security_frame(peer, reply, reply_len, PEER_SEND_NOISE_3);
        }
        return ret;
    }

    if (!peer->security_initiator && peer->noise_step == 2) {
        ret = p2p_noise_read_message_with_payload(
            peer->handshake, frame, frame_len, peer->remote_credential,
            peer->node->security_config.credential_limit, &credential_len);
        if (ret != P2P_OK) {
            return ret;
        }
        peer->remote_credential_len = credential_len;
        return peer_finish_noise(peer);
    }
    return P2P_ERR_PROTOCOL;
}

void p2p_peer_complete_private_key_operation(
    p2p_private_key_operation_t *operation, int was_current) {
    p2p_peer_t *peer;
    int valid;
    int ret;

    if (!operation || !operation->peer) {
        return;
    }
    peer = operation->peer;
    if (!was_current ||
        operation->handshake_generation != peer->handshake_generation ||
        operation->handshake != peer->handshake) {
        /* This completion belongs to an earlier handshake generation.  It
         * must not reset, advance, or transmit from the peer's current
         * security state. */
        return;
    }
    valid = !peer->destroying && peer->conn && peer->handshake &&
            peer->state == P2P_PEER_STATE_HANDSHAKING &&
            peer->security_stage == P2P_SECURITY_STAGE_NOISE &&
            !p2p_private_key_executor_is_closing(operation->executor);
    if (!valid) {
        p2p_peer_reset_security_state(peer);
        return;
    }

    ret = operation->result;
    if (ret == P2P_OK) {
        ret = peer_send_security_frame(peer, operation->output,
            operation->output_len, operation->finish_noise ?
            PEER_SEND_NOISE_3 : PEER_SEND_NOISE_2);
    }
    if (ret != P2P_OK) {
        p2p_node_record_security_failure(peer->node, peer->security_stage, ret);
        p2p_peer_disconnect(peer);
    }
}

static int peer_begin_noise(p2p_peer_t *peer) {
    uint8_t prologue[sizeof(P2P_SECURE_PROLOGUE_DOMAIN) - 1 +
                     P2P_SECURE_PREFACE_SIZE * 2 + P2P_COOKIE_BINDING_SIZE];
    uint8_t message[P2P_SECURITY_HANDSHAKE_FRAME_MAX];
    size_t message_len = 0;
    size_t offset = 0;
    int ret;

    memcpy(prologue + offset, P2P_SECURE_PROLOGUE_DOMAIN,
           sizeof(P2P_SECURE_PROLOGUE_DOMAIN) - 1);
    offset += sizeof(P2P_SECURE_PROLOGUE_DOMAIN) - 1;
    memcpy(prologue + offset,
           peer->security_initiator ? peer->local_preface
                                    : peer->remote_preface,
           P2P_SECURE_PREFACE_SIZE);
    offset += P2P_SECURE_PREFACE_SIZE;
    memcpy(prologue + offset,
           peer->security_initiator ? peer->remote_preface
                                    : peer->local_preface,
           P2P_SECURE_PREFACE_SIZE);
    offset += P2P_SECURE_PREFACE_SIZE;
    memcpy(prologue + offset, peer->cookie_binding,
           P2P_COOKIE_BINDING_SIZE);

    peer->handshake = (p2p_noise_handshake_t *)calloc(1, sizeof(*peer->handshake));
    if (!peer->handshake) {
        return P2P_ERR_NO_MEM;
    }
    ret = p2p_noise_init_v2(peer->handshake, &peer->node->crypto.identity,
                            peer->security_initiator, prologue,
                            sizeof(prologue));
    p2p_crypto_wipe(prologue, sizeof(prologue));
    if (ret != P2P_OK) {
        return ret;
    }
    peer_security_transition(peer, P2P_SECURITY_STAGE_NOISE);
    if (!peer->security_initiator) {
        peer->noise_step = 0;
        return P2P_OK;
    }
    ret = p2p_noise_write_message(peer->handshake, message, &message_len,
                                  peer->node->security_config.handshake_frame_limit);
    if (ret == P2P_OK) {
        ret = peer_send_security_frame(peer, message, message_len, PEER_SEND_NOISE_1);
    }
    p2p_crypto_wipe(message, sizeof(message));
    return ret;
}

int p2p_peer_start_handshake(p2p_peer_t *peer) {
    if (!peer || !peer->node || !peer->conn) {
        return P2P_ERR_INVALID_ARG;
    }
    if (!peer->node->security_configured) {
        return P2P_ERR_AUTH_REQUIRED;
    }
    if (peer->private_key_operation || peer->security_send_action)
        return P2P_ERR_INVALID_STATE;
    p2p_peer_reset_security_state(peer);
    peer->security_initiator = peer->conn->type == P2P_CONN_OUTBOUND;
    if (!peer->security_initiator) {
        return P2P_ERR_INVALID_STATE;
    }
    peer_security_transition(peer, P2P_SECURITY_STAGE_COOKIE);
    peer->state = P2P_PEER_STATE_HANDSHAKING;
    peer->security_deadline_ms = salts_hrtime() / 1000000U +
                                 peer->node->security_config.handshake_timeout_ms;
    p2p_secure_preface_build(peer->node->security_config.network_id_hash,
                             peer->local_preface);
    return peer_send_security(peer, peer->local_preface,
                         P2P_SECURE_PREFACE_SIZE, PEER_SEND_PREFACE_OUT);
}

int p2p_peer_start_inbound_handshake_after_cookie(
    p2p_peer_t *peer,
    const uint8_t initiator_preface[P2P_SECURE_PREFACE_SIZE],
    const uint8_t cookie_binding[P2P_COOKIE_BINDING_SIZE]) {
    int ret;

    if (!peer || !peer->node || !peer->conn || !initiator_preface ||
        !cookie_binding || !peer->node->security_configured ||
        peer->conn->type != P2P_CONN_INBOUND) {
        return P2P_ERR_INVALID_ARG;
    }
    if (peer->private_key_operation || peer->security_send_action)
        return P2P_ERR_INVALID_STATE;
    p2p_peer_reset_security_state(peer);
    peer->security_initiator = 0;
    peer->state = P2P_PEER_STATE_HANDSHAKING;
    peer->security_deadline_ms = salts_hrtime() / 1000000U +
                                 peer->node->security_config.handshake_timeout_ms;
    memcpy(peer->remote_preface, initiator_preface,
           P2P_SECURE_PREFACE_SIZE);
    memcpy(peer->cookie_binding, cookie_binding, P2P_COOKIE_BINDING_SIZE);
    p2p_secure_preface_build(peer->node->security_config.network_id_hash,
                             peer->local_preface);
    ret = peer_send_security(peer, peer->local_preface,
                        P2P_SECURE_PREFACE_SIZE, PEER_SEND_PREFACE_IN);
    return ret;
}

static int peer_process_ready_frame(p2p_peer_t *peer, const uint8_t *frame,
                                    size_t frame_len) {
    uint8_t plain[P2P_SECURE_READY_SIZE + P2P_NOISE_TAG_SIZE];
    uint8_t session_input[sizeof(P2P_SECURE_SESSION_DOMAIN) - 1 +
                          P2P_SECURITY_ID_SIZE];
    uint8_t expected_session_id[P2P_SECURITY_ID_SIZE];
    size_t plain_len = 0;
    int ret;

    if (!peer->ready_sent) return P2P_ERR_INVALID_STATE;
    if (frame_len != P2P_SECURE_READY_SIZE + P2P_NOISE_TAG_SIZE) {
        return P2P_ERR_PROTOCOL;
    }
    ret = p2p_crypto_decrypt(&peer->crypto, frame, frame_len, plain,
                             sizeof(plain), &plain_len);
    if (ret != P2P_OK || plain_len != P2P_SECURE_READY_SIZE) {
        return ret == P2P_OK ? P2P_ERR_PROTOCOL : ret;
    }
    memcpy(session_input, P2P_SECURE_SESSION_DOMAIN,
           sizeof(P2P_SECURE_SESSION_DOMAIN) - 1);
    memcpy(session_input + sizeof(P2P_SECURE_SESSION_DOMAIN) - 1,
           peer->channel_binding, P2P_SECURITY_ID_SIZE);
    ret = p2p_noise_backend_blake2s(session_input, sizeof(session_input),
                                    expected_session_id);
    if (ret == P2P_OK &&
        (memcmp(plain, P2P_SECURE_READY_MAGIC, 4) != 0 ||
         p2p_read_be16(plain + 4) != P2P_SECURE_WIRE_VERSION_V2 ||
         p2p_read_be16(plain + 6) != P2P_APPLICATION_PROTOCOL_VERSION ||
         !peer_constant_time_equal(
             plain + 8, peer->authenticated_identity.principal_id,
             P2P_SECURITY_ID_SIZE) ||
         !peer_constant_time_equal(
             plain + 40, peer->authenticated_identity.routing_id,
             P2P_SECURITY_ID_SIZE) ||
         !peer_constant_time_equal(
             plain + 72, peer->authenticated_identity.credential_digest,
             P2P_SECURITY_ID_SIZE) ||
         !peer_constant_time_equal(plain + 104, expected_session_id,
                                   P2P_SECURITY_ID_SIZE))) {
        ret = P2P_ERR_UNTRUSTED_IDENTITY;
    }
    p2p_crypto_wipe(plain, sizeof(plain));
    p2p_crypto_wipe(session_input, sizeof(session_input));
    p2p_crypto_wipe(expected_session_id, sizeof(expected_session_id));
    if (ret != P2P_OK) {
        return ret;
    }
    peer->ready_received = 1;
    peer->received_bytes += (uint64_t)frame_len + 2U;
    peer_security_transition(peer, P2P_SECURITY_STAGE_ESTABLISHED);
    peer->security_deadline_ms = 0;
    peer->session_started_ms = salts_hrtime() / 1000000U;
    p2p_node_on_peer_authenticated(peer->node, peer);
    return P2P_OK;
}

static int p2p_peer_process_security(p2p_peer_t *peer, size_t *consumed) {
    size_t frame_len;
    int ret;

    if (!peer || !consumed) {
        return P2P_ERR_INVALID_ARG;
    }
    *consumed = 0;
    if (peer->security_stage == P2P_SECURITY_STAGE_COOKIE) {
        uint8_t response[P2P_COOKIE_PACKET_SIZE];

        if (peer->recv_len < P2P_COOKIE_PACKET_SIZE) {
            return P2P_ERR_INVALID_ARG;
        }
        ret = p2p_cookie_build_response(peer->recv_buf, response,
                                        peer->cookie_binding);
        if (ret != P2P_OK) {
            return ret;
        }
        ret = peer_send_security(peer, response, sizeof(response), PEER_SEND_COOKIE);
        p2p_crypto_wipe(response, sizeof(response));
        if (ret != P2P_OK) {
            return ret;
        }
        *consumed = P2P_COOKIE_PACKET_SIZE;
        return P2P_OK;
    }
    if (peer->security_stage == P2P_SECURITY_STAGE_PREFACE) {
        if (peer->recv_len < P2P_SECURE_PREFACE_SIZE) {
            return P2P_ERR_INVALID_ARG;
        }
        memcpy(peer->remote_preface, peer->recv_buf,
               P2P_SECURE_PREFACE_SIZE);
        if (p2p_secure_preface_validate(
                peer->node->security_config.network_id_hash,
                peer->remote_preface) != P2P_OK) {
            return P2P_ERR_PROTOCOL;
        }
        ret = peer_begin_noise(peer);
        if (ret != P2P_OK) {
            return ret;
        }
        *consumed = P2P_SECURE_PREFACE_SIZE;
        return P2P_OK;
    }
    if (peer->security_stage != P2P_SECURITY_STAGE_NOISE &&
        peer->security_stage != P2P_SECURITY_STAGE_READY) {
        return P2P_ERR_INVALID_STATE;
    }
    if (peer->recv_len < 2) {
        return P2P_ERR_INVALID_ARG;
    }
    frame_len = p2p_read_be16(peer->recv_buf);
    if (frame_len == 0 ||
        (peer->security_stage == P2P_SECURITY_STAGE_NOISE &&
         frame_len > peer->node->security_config.handshake_frame_limit) ||
        (peer->security_stage == P2P_SECURITY_STAGE_READY &&
         frame_len != P2P_SECURE_READY_SIZE + P2P_NOISE_TAG_SIZE)) {
        return P2P_ERR_PROTOCOL;
    }
    if (peer->recv_len < frame_len + 2) {
        return P2P_ERR_INVALID_ARG;
    }
    ret = peer->security_stage == P2P_SECURITY_STAGE_NOISE
              ? peer_handle_noise_frame(peer, peer->recv_buf + 2, frame_len)
              : peer_process_ready_frame(peer, peer->recv_buf + 2, frame_len);
    if (ret == P2P_OK) {
        *consumed = frame_len + 2;
    }
    return ret;
}

void p2p_peer_transport_closed(p2p_peer_t *peer, int destroy_peer) {
    uint64_t now_ms = 0;

    if (!peer || !peer->node) return;

    p2p_node_t *node = peer->node;
    if (peer->state == P2P_PEER_STATE_DISCONNECTED) {
        return;
    }

    now_ms = salts_hrtime() / 1000000;
    if (peer->keep_entry && !destroy_peer) {
        peer->reconnect_after_ms = now_ms + P2P_CONNECT_RETRY_MS;
    }

    p2p_peer_disconnect(peer);

    p2p_node_on_peer_disconnected(node, peer);

    if (destroy_peer) {
        p2p_peer_destroy(peer);
    }
}


void p2p_peer_transport_connected(p2p_peer_t *peer) {
    p2p_node_t *node = peer->node;
    salts_mutex_lock(&node->mutex);
    peer->is_connected = 0;
    peer->reconnect_after_ms = 0;
    peer->state = P2P_PEER_STATE_HANDSHAKING;
    peer->connect_time = salts_hrtime();
    peer->last_seen = peer->connect_time;
    peer->avg_rtt_ms = 0;
    peer->rttvar_ms = 0;
    peer->last_rtt_sample_ms = 0;
    peer->last_ping_sent_ms = 0;
    peer->outstanding_ping_ms = 0;
    peer->rtt_sample_count = 0;
    salts_mutex_unlock(&node->mutex);
    p2p_node_on_peer_connected(node, peer);
}
