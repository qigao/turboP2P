/**
 * P2P Core Types
 * Complete type definitions for the P2P module
 */
#ifndef P2P_TYPES_H
#define P2P_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Forward declarations */
typedef struct p2p_node_s p2p_node_t;
typedef struct p2p_peer_s p2p_peer_t;
typedef struct p2p_file_s p2p_file_t;
typedef struct p2p_transfer_s p2p_transfer_t;
typedef struct p2p_transfer_manager_s p2p_transfer_manager_t;

/* Callback types */
typedef void (*p2p_transfer_progress_cb)(p2p_transfer_t *transfer, size_t bytes_transferred,
                                          size_t total_size, void *user_data);
typedef void (*p2p_transfer_complete_cb)(p2p_transfer_t *transfer, int success,
                                          const char *error_msg, void *user_data);

/* =============================================================================
 * Constants
 * ============================================================================= */

#define P2P_HASH_SIZE           20      /* SHA-1 for node IDs (Chord) */
#define P2P_SHA256_SIZE         32      /* SHA-256 for file hashes */
#define P2P_MAX_FILEPATH        512
#define P2P_MAX_FILENAME        256
#define P2P_MAX_IP              64
#define P2P_KEY_SIZE            32      /* X25519 static key material */

#define P2P_FINGER_COUNT        20      /* Chord finger table size (log2 of ID space) */
#define P2P_SUCCESSOR_LIST_SIZE 8       /* Successor list for fault tolerance */

#define VIVALDI_DIMENSIONS      4       /* Vivaldi coordinate dimensions */

/* =============================================================================
 * Error Codes
 * ============================================================================= */

/* Error codes are now defined as an enum in p2p.h.
 * This file only contains types and constants, not error codes. */
/* =============================================================================
 * Message Types
 * ============================================================================= */

typedef enum {
    P2P_MSG_PING = 1,
    P2P_MSG_PONG = 2,
    P2P_MSG_FILE_PUT = 3,
    P2P_MSG_FILE_GET = 4,
    P2P_MSG_FILE_DATA = 5,
    P2P_MSG_PUBSUB_SUB = 6,
    P2P_MSG_PUBSUB_UNSUB = 7,
    P2P_MSG_PUBSUB_PUBLISH = 8,
    P2P_MSG_GOSSIP = 9,
    P2P_MSG_DHT_PUT = 10,
    P2P_MSG_DHT_GET = 11,
    P2P_MSG_DHT_RESPONSE = 12,
    P2P_MSG_CHUNK_REQUEST = 13,
    P2P_MSG_CHUNK_DATA = 14,
    P2P_MSG_FILE_ACK = 15,
    P2P_MSG_RESERVED_LEGACY_HANDSHAKE = 16,
    P2P_MSG_DHT_FIND_NODE = 17,
    P2P_MSG_CUSTOM = 100,
} p2p_msg_type_t;

/* =============================================================================
 * Basic Types
 * ============================================================================= */

typedef uint8_t p2p_id_t[P2P_HASH_SIZE];

/* Vivaldi coordinate for latency estimation */
#ifndef P2P_VIVALDI_COORD_DEFINED
#define P2P_VIVALDI_COORD_DEFINED
typedef struct {
    double coords[VIVALDI_DIMENSIONS];
    double height;
    double error;
} vivaldi_coord_t;
#endif

/* Transfer status for public API */
typedef struct {
    uint32_t id;
    char filename[256];
    size_t file_size;
    size_t bytes_transferred;
    int state;
    int error_code;
} p2p_transfer_status_t;

#endif /* P2P_TYPES_H */
