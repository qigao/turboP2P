#include "peer.h"
#include "node.h"
#include "../internal.h"
#include <tlog.h>
#include <platform.h>
#include <stdlib.h>
#include <string.h>

#define RECV_BUF_INITIAL 4096

/* Forward declaration for client callback */
static void peer_client_event_cb(async_client_t *client,
                                  const async_client_event_t *event,
                                  void *user_data);

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
    if (!peer) return;
    
    p2p_node_t *node = peer->node;
    if (node) {
        turbo_mutex_lock(&node->mutex);
    }
    
    if (peer->destroying) {
        if (node) turbo_mutex_unlock(&node->mutex);
        return;
    }
    peer->destroying = 1;

    if (node) {
        turbo_mutex_unlock(&node->mutex);
    }

    p2p_peer_disconnect(peer);

    /* Clean up crypto state */
    if (peer->handshake) {
        p2p_crypto_wipe(peer->handshake, sizeof(*peer->handshake));
        free(peer->handshake);
        peer->handshake = NULL;
    }
    p2p_crypto_session_destroy(&peer->crypto);

    if (peer->recv_buf) {
        free(peer->recv_buf);
    }

    free(peer);
}

int p2p_peer_connect(p2p_peer_t *peer) {
    if (!peer || !peer->node) {
        return P2P_ERR_INVALID_ARG;
    }

    if (peer->is_connected) {
        return P2P_OK;
    }

    /* Create async client for outbound connection */
    async_client_t *client = async_client_create(peer_client_event_cb, peer);
    if (!client) {
        TLOG_ERROR("[P2P] peer_connect: failed to create async client");
        return P2P_ERR_NO_MEM;
    }

    /* Create unified connection abstraction */
    peer->conn = p2p_connection_create_outbound(client);
    if (!peer->conn) {
        async_client_destroy(client);
        return P2P_ERR_NO_MEM;
    }

    /* Format connection URL (e.g., tcp://127.0.0.1:8080) */
    char url[128];
    snprintf(url, sizeof(url), "tcp://%s:%d", peer->ip, peer->port);

    async_client_status_t status = async_client_connect(client, url);
    if (status != ASYNC_CLIENT_STATUS_OK) {
        TLOG_ERROR("[P2P] peer_connect: connect to %s failed", url);
        p2p_connection_destroy(peer->conn);
        peer->conn = NULL;
        return P2P_ERR_NETWORK;
    }

    peer->is_connected = 1;
    TLOG_DEBUG("[P2P] peer_connect: connecting to {}", url);
    return P2P_OK;
}

void p2p_peer_disconnect(p2p_peer_t *peer) {
    if (!peer || !peer->conn) return;

    peer->state = P2P_PEER_STATE_CLOSING;

    /* Destroy unified connection (handles client/server automatically) */
    p2p_connection_t *conn = peer->conn;
    peer->conn = NULL;
    peer->is_connected = 0;
    
    if (conn) {
        p2p_connection_destroy(conn);
    }

    peer->state = P2P_PEER_STATE_DISCONNECTED;
    peer->recv_len = 0;
}

/* =============================================================================
 * Peer I/O
 * ============================================================================= */

static int peer_send_raw(p2p_peer_t *peer, const uint8_t *data, size_t len) {
    if (!peer || !peer->conn) return P2P_ERR_NETWORK;
    return (p2p_connection_send(peer->conn, data, len) == 0) ? P2P_OK : P2P_ERR_NETWORK;
}

int p2p_peer_send(p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!peer || !msg) {
        return P2P_ERR_INVALID_ARG;
    }

    if (peer->state != P2P_PEER_STATE_CONNECTED &&
        peer->state != P2P_PEER_STATE_HANDSHAKING) {
        TLOG_WARN("[P2P] peer_send: peer not connected (state={})",
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

    /* Encrypt if crypto session is ready (skip for handshake messages) */
    if (p2p_crypto_session_is_ready(&peer->crypto) &&
        msg->header.type != P2P_MSG_NOISE_HANDSHAKE) {

        /* Allocate buffer for ciphertext (plaintext + tag) */
        size_t ct_len = frame_len + P2P_TAG_SIZE;
        uint8_t *ct_buf = (uint8_t *)malloc(ct_len + 4);  /* +4 for length prefix */
        if (!ct_buf) {
            free(frame_buf);
            return P2P_ERR_NO_MEM;
        }

        /* Prepend encrypted frame length (little-endian) */
        ct_buf[0] = (uint8_t)(ct_len & 0xFF);
        ct_buf[1] = (uint8_t)((ct_len >> 8) & 0xFF);
        ct_buf[2] = (uint8_t)((ct_len >> 16) & 0xFF);
        ct_buf[3] = (uint8_t)((ct_len >> 24) & 0xFF);

        size_t encrypted_len = 0;
        ret = p2p_crypto_encrypt(&peer->crypto, frame_buf, frame_len,
                                  ct_buf + 4, &encrypted_len);
        free(frame_buf);

        if (ret != P2P_OK) {
            free(ct_buf);
            TLOG_ERROR("[P2P] peer_send: encryption failed");
            return ret;
        }

        ret = peer_send_raw(peer, ct_buf, encrypted_len + 4);
        free(ct_buf);
        return ret;
    }

    /* Send unencrypted */
    ret = peer_send_raw(peer, frame_buf, frame_len);
    free(frame_buf);
    return ret;
}

int p2p_peer_on_data(p2p_peer_t *peer, const void *data, size_t len) {
    if (!peer || !data || len == 0) {
        return P2P_ERR_INVALID_ARG;
    }

    /* Append to receive buffer */
    if (peer->recv_len + len > peer->recv_cap) {
        size_t new_cap = peer->recv_cap * 2;
        while (new_cap < peer->recv_len + len) {
            new_cap *= 2;
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
    peer->last_seen = turbo_hrtime();

    /* Try to parse complete messages */
    while (peer->recv_len > 0) {
        p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
        if (!msg) return P2P_ERR_NO_MEM;
        
        size_t consumed = 0;

        int ret = p2p_message_deserialize(peer->recv_buf, peer->recv_len,
                                           msg, &consumed);
        if (ret == P2P_ERR_INVALID_ARG) {
            /* Need more data */
            free(msg);
            break;
        }
        if (ret != P2P_OK) {
            TLOG_ERROR("[P2P] peer_on_data: invalid frame from {}:{}",
                      peer->ip, peer->port);
            free(msg);
            return ret;
        }

        /* Dispatch message */
        p2p_node_dispatch_message(peer->node, peer, msg);
        free(msg);

        /* Remove consumed bytes */
        if (consumed < peer->recv_len) {
            memmove(peer->recv_buf, peer->recv_buf + consumed,
                    peer->recv_len - consumed);
        }
        peer->recv_len -= consumed;
    }

    return P2P_OK;
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

/* Send a handshake message */
static int peer_send_handshake(p2p_peer_t *peer, uint8_t step, const uint8_t *data, size_t len) {
    p2p_message_t *msg = (p2p_message_t *)calloc(1, sizeof(p2p_message_t));
    if (!msg) return P2P_ERR_NO_MEM;

    p2p_message_init(msg, P2P_MSG_NOISE_HANDSHAKE);
    msg->payload.noise_handshake.step = step;
    msg->payload.noise_handshake.data_len = (uint8_t)len;
    if (len > 0 && len <= sizeof(msg->payload.noise_handshake.data)) {
        memcpy(msg->payload.noise_handshake.data, data, len);
    }
    int ret = p2p_peer_send(peer, msg);
    free(msg);
    return ret;
}

/* Start Noise XX handshake as initiator */
int p2p_peer_start_handshake(p2p_peer_t *peer) {
    if (!peer || !peer->node) return P2P_ERR_INVALID_ARG;

    /* Check if encryption is enabled */
    if (!peer->node->encryption_enabled) {
        TLOG_DEBUG("[P2P] handshake: encryption disabled, skipping");
        return P2P_OK;
    }

    /* Allocate handshake state */
    peer->handshake = (p2p_noise_handshake_t *)calloc(1, sizeof(p2p_noise_handshake_t));
    if (!peer->handshake) {
        return P2P_ERR_NO_MEM;
    }

    /* Initialize as initiator */
    int ret = p2p_noise_init_initiator(peer->handshake,
                                        &peer->node->crypto.identity,
                                        NULL);  /* No pre-known remote key */
    if (ret != P2P_OK) {
        free(peer->handshake);
        peer->handshake = NULL;
        return ret;
    }

    /* Create message 1: -> e */
    uint8_t msg_buf[P2P_HANDSHAKE_MAX];
    size_t msg_len = 0;

    ret = p2p_noise_write_message(peer->handshake, msg_buf, &msg_len, sizeof(msg_buf));
    if (ret != P2P_OK) {
        free(peer->handshake);
        peer->handshake = NULL;
        return ret;
    }

    TLOG_DEBUG("[P2P] handshake: initiator sending step 1 ({} bytes)", msg_len);

    return peer_send_handshake(peer, 1, msg_buf, msg_len);
}

/* Handle incoming handshake message */
int p2p_peer_handle_handshake(p2p_peer_t *peer, const p2p_message_t *msg) {
    if (!peer || !msg || !peer->node) return P2P_ERR_INVALID_ARG;

    uint8_t step = msg->payload.noise_handshake.step;
    const uint8_t *data = msg->payload.noise_handshake.data;
    size_t data_len = msg->payload.noise_handshake.data_len;

    TLOG_DEBUG("[P2P] handshake: received step %u ({} bytes) from {}:{}",
              step, data_len, peer->ip, peer->port);

    /* Responder receiving step 1 (no handshake state yet) */
    if (step == 1 && !peer->handshake) {
        if (!peer->node->encryption_enabled) {
            TLOG_DEBUG("[P2P] handshake: encryption disabled, ignoring");
            return P2P_OK;
        }

        /* Initialize as responder */
        peer->handshake = (p2p_noise_handshake_t *)calloc(1, sizeof(p2p_noise_handshake_t));
        if (!peer->handshake) {
            return P2P_ERR_NO_MEM;
        }

        int ret = p2p_noise_init_responder(peer->handshake, &peer->node->crypto.identity);
        if (ret != P2P_OK) {
            free(peer->handshake);
            peer->handshake = NULL;
            return ret;
        }

        /* Process message 1: -> e */
        ret = p2p_noise_read_message(peer->handshake, data, data_len);
        if (ret != P2P_OK) {
            TLOG_ERROR("[P2P] handshake: failed to process step 1");
            free(peer->handshake);
            peer->handshake = NULL;
            return ret;
        }

        /* Create message 2: <- e, ee, s, es */
        uint8_t reply_buf[P2P_HANDSHAKE_MAX];
        size_t reply_len = 0;

        ret = p2p_noise_write_message(peer->handshake, reply_buf, &reply_len, sizeof(reply_buf));
        if (ret != P2P_OK) {
            free(peer->handshake);
            peer->handshake = NULL;
            return ret;
        }

        TLOG_DEBUG("[P2P] handshake: responder sending step 2 ({} bytes)", reply_len);
        return peer_send_handshake(peer, 2, reply_buf, reply_len);
    }

    /* Initiator receiving step 2 */
    if (step == 2 && peer->handshake && peer->handshake->is_initiator) {
        /* Process message 2: <- e, ee, s, es */
        int ret = p2p_noise_read_message(peer->handshake, data, data_len);
        if (ret != P2P_OK) {
            TLOG_ERROR("[P2P] handshake: failed to process step 2");
            return ret;
        }

        /* Create message 3: -> s, se */
        uint8_t reply_buf[P2P_HANDSHAKE_MAX];
        size_t reply_len = 0;

        ret = p2p_noise_write_message(peer->handshake, reply_buf, &reply_len, sizeof(reply_buf));
        if (ret != P2P_OK) {
            return ret;
        }

        TLOG_DEBUG("[P2P] handshake: initiator sending step 3 ({} bytes)", reply_len);

        ret = peer_send_handshake(peer, 3, reply_buf, reply_len);
        if (ret != P2P_OK) {
            return ret;
        }

        /* Handshake complete - derive session keys */
        if (p2p_noise_is_complete(peer->handshake)) {
            ret = p2p_noise_split(peer->handshake, &peer->crypto);
            if (ret != P2P_OK) {
                TLOG_ERROR("[P2P] handshake: key derivation failed");
                return ret;
            }

            TLOG_INFO("[P2P] handshake: initiator complete with {}:{}", peer->ip, peer->port);

            /* Clean up handshake state */
            p2p_crypto_wipe(peer->handshake, sizeof(*peer->handshake));
            free(peer->handshake);
            peer->handshake = NULL;

            /* Handover to node for identification and authorization */
            p2p_node_on_peer_authenticated(peer->node, peer);
        }

        return P2P_OK;
    }

    /* Responder receiving step 3 */
    if (step == 3 && peer->handshake && !peer->handshake->is_initiator) {
        /* Process message 3: -> s, se */
        int ret = p2p_noise_read_message(peer->handshake, data, data_len);
        if (ret != P2P_OK) {
            TLOG_ERROR("[P2P] handshake: failed to process step 3");
            return ret;
        }

        /* Handshake complete - derive session keys */
        if (p2p_noise_is_complete(peer->handshake)) {
            ret = p2p_noise_split(peer->handshake, &peer->crypto);
            if (ret != P2P_OK) {
                TLOG_ERROR("[P2P] handshake: key derivation failed");
                return ret;
            }

            TLOG_INFO("[P2P] handshake: responder complete with {}:{}", peer->ip, peer->port);

            /* Clean up handshake state */
            p2p_crypto_wipe(peer->handshake, sizeof(*peer->handshake));
            free(peer->handshake);
            peer->handshake = NULL;

            /* Handover to node for identification and authorization */
            p2p_node_on_peer_authenticated(peer->node, peer);
        }

        return P2P_OK;
    }

    TLOG_WARN("[P2P] handshake: unexpected step %u", step);
    return P2P_ERR_INVALID_ARG;
}

/* =============================================================================
 * Async Client Callback
 * ============================================================================= */

static void peer_client_event_cb(async_client_t *client,
                                  const async_client_event_t *event,
                                  void *user_data) {
    (void)client;
    p2p_peer_t *peer = (p2p_peer_t *)user_data;
    if (!peer || !peer->node) return;

    p2p_node_t *node = peer->node;

    switch (event->type) {
        case ASYNC_CLIENT_EVENT_CONNECTED:
            TLOG_DEBUG("[P2P] peer connected: {}:{}", peer->ip, peer->port);
            turbo_mutex_lock(&node->mutex);
            peer->state = P2P_PEER_STATE_HANDSHAKING;
            peer->connect_time = turbo_hrtime();
            peer->last_seen = peer->connect_time;

            /* Notify node to start handshake */
            p2p_node_on_peer_connected(node, peer);
            turbo_mutex_unlock(&node->mutex);
            break;

        case ASYNC_CLIENT_EVENT_DATA:
            /* p2p_peer_on_data calls dispatch_message which handles locking */
            p2p_peer_on_data(peer, event->data, event->length);
            break;

        case ASYNC_CLIENT_EVENT_ERROR:
            TLOG_ERROR("[P2P] peer error {}:{}: {}",
                      peer->ip, peer->port, event->message ? event->message : "unknown");
            turbo_mutex_lock(&node->mutex);
            peer->state = P2P_PEER_STATE_DISCONNECTED;
            p2p_node_on_peer_disconnected(node, peer);
            turbo_mutex_unlock(&node->mutex);
            break;

        case ASYNC_CLIENT_EVENT_CLOSED:
            TLOG_DEBUG("[P2P] peer disconnected: {}:{}", peer->ip, peer->port);
            turbo_mutex_lock(&node->mutex);
            peer->state = P2P_PEER_STATE_DISCONNECTED;
            p2p_node_on_peer_disconnected(node, peer);
            turbo_mutex_unlock(&node->mutex);
            break;
    }
}
