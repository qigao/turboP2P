/**
 * Internal structures - NOT exposed to users
 * Professional version based on Kademlia DHT and unified connections
 */

#ifndef P2P_INTERNAL_H
#define P2P_INTERNAL_H

#include <platform.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef CXX_C_API
#ifdef _WIN32
#ifdef SHARED_CXX
#define CXX_C_API __declspec(dllexport)
#else
#define CXX_C_API __declspec(dllimport)
#endif
#else
#define CXX_C_API
#endif
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "../include/p2p.h"
#include "uthash.h"
#include "crypto/p2p_crypto.h"
#include "dht/kademlia.h"
#include <turbo_thread.h>
typedef struct turbo_stream_listener_s turbo_stream_listener_t;

/* =============================================================================
 * Constants
 * ============================================================================= */

#define P2P_MAX_MESSAGE_SIZE (64 * 1024) 
#define P2P_PEER_TIMEOUT_MS 30000        
#define P2P_GOSSIP_INTERVAL 5000         
#define P2P_CONNECT_RETRY_MS 3000
#define P2P_MANUAL_DISCONNECT_SUPPRESS_MS 5000
#define P2P_DHT_GET_TIMEOUT_MS 1000
#ifndef P2P_PENDING_PEER_LIMIT
#define P2P_PENDING_PEER_LIMIT 128
#endif
#ifndef P2P_RTT_PROBE_INTERVAL_MS
#define P2P_RTT_PROBE_INTERVAL_MS 15000U
#endif
#ifndef P2P_RTT_SAMPLE_MAX_MS
#define P2P_RTT_SAMPLE_MAX_MS P2P_PEER_TIMEOUT_MS
#endif
#ifndef P2P_RTT_METRIC_FRESH_MS
#define P2P_RTT_METRIC_FRESH_MS P2P_PEER_TIMEOUT_MS
#endif
#define P2P_DHT_KEY_SIZE 20              
#define P2P_MAX_IP 64

/* =============================================================================
 * Internal Enumerations
 * ============================================================================= */

typedef enum {
    P2P_PEER_STATE_DISCONNECTED = 0,
    P2P_PEER_STATE_CONNECTING,
    P2P_PEER_STATE_HANDSHAKING,
    P2P_PEER_STATE_CONNECTED,
    P2P_PEER_STATE_CLOSING,
} p2p_peer_state_t;

typedef enum {
    P2P_TRANSFER_STATE_IDLE = 0,
    P2P_TRANSFER_STATE_PENDING,
    P2P_TRANSFER_STATE_ACTIVE,
    P2P_TRANSFER_STATE_PAUSED,
    P2P_TRANSFER_STATE_COMPLETED,
    P2P_TRANSFER_STATE_FAILED,
} p2p_transfer_state_t;

/* =============================================================================
 * Message Structures
 * ============================================================================= */

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t payload_len;
    uint32_t request_id;
} p2p_msg_header_t;

typedef struct {
    uint8_t node_id[P2P_DHT_KEY_SIZE];
    char ip[P2P_MAX_IP];
    uint16_t port;
    uint64_t timestamp;
    double coords[4]; 
    double height;
    double error;
} p2p_ping_payload_t;

typedef struct {
    uint8_t id[P2P_DHT_KEY_SIZE];
} p2p_find_payload_t;

typedef struct {
    uint8_t id[P2P_DHT_KEY_SIZE];
    char ip[P2P_MAX_IP];
    uint16_t port;
} p2p_kad_contact_t;

typedef struct {
    uint8_t target_id[P2P_DHT_KEY_SIZE];
} p2p_dht_find_node_payload_t;

typedef struct {
    uint8_t key[P2P_DHT_KEY_SIZE];
    uint16_t data_len;
    uint8_t data[1024]; /* Inline data for simplicity, or pointer + ref ? */
} p2p_dht_store_payload_t;

typedef struct {
    uint8_t found; /* 1 if found, 0 if close nodes returned */
    uint8_t node_count;
    p2p_kad_contact_t nodes[KADEMLIA_K];
    uint16_t data_len;
    uint8_t data[1024];
} p2p_dht_response_payload_t;

typedef struct {
    uint8_t file_id[P2P_DHT_KEY_SIZE];
    char filename[256];
    uint64_t size;
    uint8_t hash[32];
    char owner_ip[P2P_MAX_IP];
    uint16_t owner_port;
} p2p_file_info_payload_t;

typedef struct {
    uint8_t file_id[P2P_DHT_KEY_SIZE];
    uint64_t file_size;
    uint32_t total_chunks;
    uint8_t file_hash[32];
} p2p_file_response_payload_t;

typedef struct {
    uint32_t transfer_id;
    uint32_t chunk_index;
} p2p_chunk_request_payload_t;

typedef struct {
    uint32_t transfer_id;
    uint32_t chunk_index;
    uint16_t data_len;
    uint8_t chunk_hash[32];
    uint8_t data[65536 - 128]; /* Inline buffer to fit in message_t */
} p2p_chunk_data_payload_t;

typedef struct {
    uint32_t transfer_id;
    int success;
} p2p_file_ack_payload_t;

typedef struct {
    uint8_t step;
    uint8_t data_len;
    uint8_t data[P2P_HANDSHAKE_MAX];
} p2p_noise_handshake_payload_t;

typedef struct {
    p2p_msg_header_t header;
    union {
        p2p_ping_payload_t ping;
        p2p_find_payload_t find;
        p2p_file_info_payload_t file_info;
        p2p_file_response_payload_t file_response;
        p2p_chunk_request_payload_t chunk_request;
        p2p_chunk_data_payload_t chunk_data;
        p2p_file_ack_payload_t file_ack;
        p2p_noise_handshake_payload_t noise_handshake;
        p2p_dht_find_node_payload_t dht_find_node;
        p2p_dht_store_payload_t dht_store;
        p2p_dht_response_payload_t dht_response;
        uint8_t raw[65536];
    } payload;
} p2p_message_t;

#define KADEMLIA_MAX_LOOKUP_NODES 32

typedef struct {
    uint8_t id[P2P_DHT_KEY_SIZE];
    char ip[P2P_MAX_IP];
    uint16_t port;
    int contacted;
} kad_lookup_node_t;

typedef struct {
    uint32_t request_id;
    uint8_t target[P2P_DHT_KEY_SIZE];
    kad_lookup_node_t candidates[KADEMLIA_MAX_LOOKUP_NODES];
    int candidate_count;
    int active_requests;
    p2p_msg_type_t type; /* FIND_NODE or FIND_VALUE */
    void (*callback)(void *result, void *user_data);
    void (*cleanup)(void *user_data);
    void *user_data;
    struct UT_hash_handle hh;
} p2p_dht_lookup_t;

typedef struct p2p_connect_suppression_s {
    char key[96];
    char ip[P2P_MAX_IP];
    int port;
    uint64_t until_ms;
    struct UT_hash_handle hh;
} p2p_connect_suppression_t;

/* Professional Core Modules */
#include "crypto/p2p_crypto.h"
#include "protocol/message.h"
#include "protocol/handlers.h"
#include "core/connection.h"
#include "core/peer_table.h"
#include "core/vivaldi.h"

/* =============================================================================
 * Type Definitions
 * ============================================================================= */

struct p2p_peer_s {
  char ip[P2P_MAX_IP];
  int port;
  p2p_connection_t *conn;
  int is_connected;
  p2p_peer_state_t state;

  /* Analytics & DHT */
  uint8_t id[P2P_DHT_KEY_SIZE];
  uint64_t last_seen;
  uint64_t connect_time;
  uint64_t reconnect_after_ms;
  uint64_t avg_rtt_ms;
  uint64_t rttvar_ms;
  uint64_t last_rtt_sample_ms;
  uint64_t last_ping_sent_ms;
  uint64_t outstanding_ping_ms;
  uint32_t rtt_sample_count;
  vivaldi_coord_t coord;

  /* I/O & Crypto */
  uint8_t *recv_buf;
  size_t recv_len;
  size_t recv_cap;

  p2p_crypto_session_t crypto;
  p2p_noise_handshake_t *handshake;
  uint8_t remote_public_key[P2P_KEY_SIZE];
  int remote_public_key_ready;

  struct p2p_node_s *node;
  struct p2p_peer_s *next_peer;
  int keep_entry;
  int counted;
  int callback_refs;
  int destroying;
};

/* =============================================================================
 * Topic structure (for pub/sub)
 * ============================================================================= */

typedef struct p2p_topic_s {
  char name[256];
  struct p2p_peer_s **subscribers;
  int subscriber_count;
  int max_subscribers;
  struct p2p_topic_s *next_topic;
} p2p_topic_t;

/* =============================================================================
 * Local file registry
 * ============================================================================= */

struct p2p_file_s {
  char hash[65];     
  char filename[256]; 
  char filepath[512]; 
  size_t size;
  size_t chunk_size;
  uint32_t num_chunks;
  uint32_t available_chunks;
  uint64_t last_seen;
  char owner_ip[P2P_MAX_IP];
  uint16_t owner_port;
  int is_local;
  uint8_t id[P2P_DHT_KEY_SIZE];
  struct p2p_file_s *next_file;
  struct p2p_file_s *next; 
};

/* =============================================================================
 * Download tracking
 * ============================================================================= */

typedef struct p2p_download_s {
  char hash[65]; 
  char output_path[512];
  FILE *fp;
  size_t bytes_received;
  int completed;
  struct p2p_download_s *next;
} p2p_download_t;

struct p2p_node_s {
  char ip[P2P_MAX_IP];
  int port;
  uint8_t id[P2P_DHT_KEY_SIZE];
  coro_context_t *ctx;
  turbo_stream_listener_t *server;
  p2p_peer_entry_t *peers_table;
  int peer_count;

  /* Crypto */
  int encryption_enabled;
  struct {
    p2p_identity_t identity;
  } crypto;

  /* Callbacks */
  p2p_on_message_fn on_message;
  void *user_data;
  void (*on_peer_connected)(struct p2p_peer_s *peer, void *user_data);
  void (*on_peer_disconnected)(struct p2p_peer_s *peer, void *user_data);
  void *peer_user_data;

  struct p2p_file_s *local_files;
  struct p2p_file_s *dht_files;
  p2p_topic_t *topics;
  p2p_download_t *downloads;
  p2p_transfer_manager_t *transfers;
  turbo_timer_t *gossip_timer;
  kademlia_dht_t *kad_dht;
  p2p_dht_lookup_t *dht_lookups;
  p2p_connect_suppression_t *connect_suppressions;
  vivaldi_coord_t coord;
  turbo_mutex_t mutex;
};

/* =============================================================================
 * Function Prototypes
 * ============================================================================= */

/* Handlers */
int p2p_handle_ping(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_pong(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_dht_find_node(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_dht_store(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_dht_get(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_handle_dht_response(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
p2p_dht_lookup_t *p2p_dht_lookup_start(p2p_node_t *node, const uint8_t *target, p2p_msg_type_t type);
int p2p_dht_lookup_on_response(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);
void p2p_dht_lookup_try_progress(p2p_node_t *node);
int p2p_connect_candidate(p2p_node_t *node, const char *ip, int port);
void p2p_dht_lookup_finish(p2p_node_t *node, p2p_dht_lookup_t *lookup);
p2p_dht_lookup_t *p2p_dht_lookup_find(p2p_node_t *node, uint32_t request_id);

/* Lifecycle */
CXX_C_API p2p_peer_t *p2p_peer_create(p2p_node_t *node, const char *ip, int port);
CXX_C_API void p2p_peer_destroy(p2p_peer_t *peer);
CXX_C_API p2p_peer_t* p2p_peer_find(p2p_node_t *node, const char *ip, int port);
int p2p_peer_connect(p2p_peer_t *peer);
void p2p_peer_disconnect(p2p_peer_t *peer);
int p2p_peer_on_data(p2p_peer_t *peer, const void *data, size_t len);
int p2p_peer_send(p2p_peer_t *peer, const p2p_message_t *msg);
int p2p_peer_hold(p2p_peer_t *peer);
int p2p_peer_hold_locked(p2p_peer_t *peer);
void p2p_peer_release(p2p_peer_t *peer);
int p2p_peer_record_rtt_sample_locked(p2p_peer_t *peer,
                                      uint64_t sent_ms,
                                      uint64_t received_ms);

/* Messaging */
int p2p_send_message(p2p_node_t *node, p2p_peer_t *peer, p2p_msg_type_t type, const void *payload, size_t len);
void p2p_handlers_dispatch(p2p_node_t *node, p2p_peer_t *peer, const p2p_message_t *msg);

/* Pub/Sub operations */
p2p_topic_t *p2p_topic_find(p2p_node_t *node, const char *name);
p2p_topic_t *p2p_topic_find_or_create(p2p_node_t *node, const char *name);
int p2p_topic_exists(p2p_node_t *node, const char *name);
void p2p_topic_deliver(p2p_node_t *node, p2p_topic_t *topic, const void *data, size_t len);
void p2p_topic_destroy(p2p_topic_t *topic);
int p2p_node_remove_topic(p2p_node_t *node, const char *name);
p2p_topic_t *p2p_node_detach_topics(p2p_node_t *node);

/* Infrastructure */
CXX_C_API int p2p_node_start_server(p2p_node_t *node);
void p2p_node_stop_server(p2p_node_t *node);
void p2p_gossip_start(p2p_node_t *node);
void node_maintenance_cb(turbo_timer_t *timer);

/* Lifecycle and Events */
void p2p_node_on_peer_connected(p2p_node_t *node, p2p_peer_t *peer);
void p2p_node_on_peer_disconnected(p2p_node_t *node, p2p_peer_t *peer);
void p2p_node_on_peer_authenticated(p2p_node_t *node, p2p_peer_t *peer);
void p2p_node_dispatch_message(p2p_node_t *node, p2p_peer_t *peer, p2p_message_t *msg);

void p2p_destroy_clean(p2p_node_t *node);
void p2p_peer_set_id(p2p_peer_t *peer, const uint8_t *id);
p2p_file_t* p2p_file_find_by_id(p2p_file_t *list, const uint8_t *id);
p2p_file_t* p2p_node_find_local_file_by_id(p2p_node_t *node, const uint8_t *id);
p2p_file_t* p2p_node_find_local_file_by_id_locked(p2p_node_t *node, const uint8_t *id);
void p2p_node_add_dht_file(p2p_node_t *node, p2p_file_t *file);
int p2p_node_search_dht_files(p2p_node_t *node, const char *filename,
                              p2p_file_t **results, int max_results);
p2p_file_t *p2p_node_detach_local_files(p2p_node_t *node);
p2p_file_t *p2p_node_detach_dht_files(p2p_node_t *node);
p2p_download_t *p2p_node_detach_downloads(p2p_node_t *node);
int p2p_file_list_add(p2p_file_t **list, p2p_file_t *file);
void p2p_file_free(p2p_file_t *file);
void p2p_node_add_file(p2p_node_t *node, p2p_file_t *file);
void p2p_node_remove_file(p2p_node_t *node, const char *key);
void p2p_node_broadcast(p2p_node_t *node, p2p_message_t *msg);
p2p_peer_t **p2p_node_snapshot_connected_peers(p2p_node_t *node, size_t *count_out);
p2p_peer_info_t *p2p_node_snapshot_peer_info(p2p_node_t *node, size_t *count_out);
p2p_peer_info_ex_t *p2p_node_snapshot_peer_info_ex(p2p_node_t *node, size_t *count_out);
void p2p_peer_fill_info_ex_locked(const p2p_peer_t *peer, p2p_peer_info_ex_t *info);
CXX_C_API void p2p_node_add_peer_locked(p2p_node_t *node, p2p_peer_t *peer);
CXX_C_API p2p_peer_t *p2p_node_find_peer_by_endpoint_locked(p2p_node_t *node, const char *ip, int port);
CXX_C_API int p2p_node_pending_peer_capacity_available_locked(p2p_node_t *node);
CXX_C_API void p2p_node_remove_peer_by_endpoint_locked(p2p_node_t *node, const char *ip, int port);
int p2p_id_is_zero(const uint8_t *id);
void p2p_endpoint_to_key(char *buf, size_t buf_size, const char *ip, int port);
void p2p_endpoint_to_id(const char *ip, int port, kad_id_t *id);
void p2p_init_kad_node(kad_node_t *node, const uint8_t *id, const char *ip, int port);
CXX_C_API void p2p_node_add_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port);
CXX_C_API void p2p_node_remove_route_locked(p2p_node_t *node, const uint8_t *id, const char *ip, int port);
int p2p_file_list_remove(p2p_file_t **list, const uint8_t *id);
void p2p_file_list_destroy(p2p_file_t *list);

p2p_file_t* p2p_file_create(const char *key, const char *filepath);
int p2p_file_announce(p2p_node_t *node, p2p_file_t *file);

#endif
