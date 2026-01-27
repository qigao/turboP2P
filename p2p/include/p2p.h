#ifndef P2P_H
#define P2P_H

#include <stddef.h>
#include "platform.h"
#include "p2p_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles - forward declarations only */
typedef struct p2p_node_s p2p_node_t;
typedef struct p2p_peer_s p2p_peer_t;

/* Error codes - Simple and clear */
typedef enum {
    P2P_OK = 0,
    P2P_ERR_INVALID_ARG = -1,
    P2P_ERR_NO_MEM = -2,
    P2P_ERR_NETWORK = -3,
    P2P_ERR_TIMEOUT = -4,
    P2P_ERR_NOT_FOUND = -5,
    P2P_ERR_IO = -6,
    P2P_ERR_INVALID_STATE = -7,
    P2P_ERR_CRYPTO = -8,
    P2P_ERR_PROTOCOL = -9,
    P2P_ERR_INVALID = -10,
} p2p_error_t;

/* =============================================================================
 * Node Lifecycle
 * ============================================================================= */

/**
 * Create a new P2P node
 * @param ip IP to bind (e.g., "0.0.0.0")
 * @param port Port to bind
 * @return Handle or NULL
 */
CXX_C_API p2p_node_t *p2p_create(const char *ip, int port);

/**
 * Destroy node
 */
CXX_C_API void p2p_destroy(p2p_node_t *node);

/**
 * Start the node (blocking event loop)
 */
CXX_C_API int p2p_start(p2p_node_t *node);

/**
 * Start server and gossip (non-blocking)
 * Use this with p2p_get_loop() + uv_run() for custom event loop integration
 */
CXX_C_API int p2p_start_nonblocking(p2p_node_t *node);

/**
 * Get the event loop for integration
 */
CXX_C_API struct uv_loop_s *p2p_get_loop(p2p_node_t *node);

/**
 * Connect to bootstrap peer
 */
CXX_C_API int p2p_connect(p2p_node_t *node, const char *ip, int port);

/* =============================================================================
 * Message Callbacks
 * ============================================================================= */

/**
 * Message receive callback
 * @param node The node
 * @param peer The peer (NULL for broadcast)
 * @param data Message data
 * @param len Message length
 * @param user_data User data
 */
typedef void (*p2p_on_message_fn)(p2p_node_t *node, p2p_peer_t *peer,
                                  const void *data, size_t len, void *user_data);

/**
 * Set message handler
 */
CXX_C_API void p2p_set_message_handler(p2p_node_t *node, p2p_on_message_fn fn, void *user_data);

/**
 * Set peer connection callbacks
 * @param node The node
 * @param on_connected Callback when peer connects (can be NULL)
 * @param on_disconnected Callback when peer disconnects (can be NULL)
 * @param user_data User data passed to callbacks
 */
CXX_C_API void p2p_set_peer_callbacks(p2p_node_t *node,
                             void (*on_connected)(p2p_peer_t *peer, void *user_data),
                             void (*on_disconnected)(p2p_peer_t *peer, void *user_data),
                             void *user_data);

/**
 * Get peer address information
 * @param peer The peer
 * @param ip_out Buffer to store IP (must be at least 16 bytes)
 * @param port_out Pointer to store port
 * @return P2P_OK on success
 */
CXX_C_API int p2p_peer_get_address(p2p_peer_t *peer, char *ip_out, int *port_out);

/**
 * Send message to peer
 */
CXX_C_API int p2p_send(p2p_node_t *node, p2p_peer_t *peer, const void *data, size_t len);

/**
 * Send typed message
 */
CXX_C_API int p2p_send_message(p2p_node_t *node, p2p_peer_t *peer, p2p_msg_type_t type,
                               const void *payload, size_t len);

/**
 * Broadcast to all peers
 */
CXX_C_API int p2p_broadcast(p2p_node_t *node, const void *data, size_t len);

/* =============================================================================
 * File Sharing
 * ============================================================================= */

/**
 * Put file (returns hash key)
 * @param node Node
 * @param filepath File path
 * @param key_out Buffer for hash key (must be 65 bytes for null terminator)
 * @return P2P_OK on success
 */
CXX_C_API int p2p_put_file(p2p_node_t *node, const char *filepath, char key_out[65]);

/**
 * Get file by hash key
 * @param node Node
 * @param key 65-byte hash key (64 hex chars + null terminator)
 * @param output_path Where to save
 * @return P2P_OK on success
 */
CXX_C_API int p2p_get_file(p2p_node_t *node, const char key[65], const char *output_path);

/* =============================================================================
 * Pub/Sub
 * ============================================================================= */

/**
 * Subscribe to topic
 */
CXX_C_API int p2p_subscribe(p2p_node_t *node, const char *topic);

/**
 * Unsubscribe from topic
 */
CXX_C_API int p2p_unsubscribe(p2p_node_t *node, const char *topic);

/**
 * Publish message to topic
 */
CXX_C_API int p2p_publish(p2p_node_t *node, const char *topic, const void *data, size_t len);

/* =============================================================================
 * DHT (Distributed Hash Table)
 * ============================================================================= */

/**
 * Store value in DHT network
 * @param node Node
 * @param key Key (string)
 * @param data Value data
 * @param len Value length
 * @return P2P_OK on success
 */
CXX_C_API int p2p_dht_put(p2p_node_t *node, const char *key, const void *data, size_t len);

/**
 * Get value from DHT network
 * @param node Node
 * @param key Key (string)
 * @param buf Buffer for value
 * @param buf_len Buffer length (input/output)
 * @return P2P_OK on success
 */
CXX_C_API int p2p_dht_get(p2p_node_t *node, const char *key, void *buf, size_t *buf_len);

/* =============================================================================
 * Peer Information
 * ============================================================================= */

/**
 * Peer information structure
 */
typedef struct {
    char ip[16];
    int port;
    int is_connected;
} p2p_peer_info_t;

/**
 * Get peer count
 */
CXX_C_API int p2p_get_peer_count(p2p_node_t *node);

/**
 * Get peer info by index
 * @param node Node
 * @param index Peer index (0 to count-1)
 * @param info Output peer info
 * @return P2P_OK on success
 */
CXX_C_API int p2p_get_peer_info(p2p_node_t *node, int index, p2p_peer_info_t *info);

/* =============================================================================
 * Utility
 * ============================================================================= */

CXX_C_API const char *p2p_error_str(int error);

#ifdef __cplusplus
}
#endif

#endif /* P2P_H */
