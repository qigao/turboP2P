#ifndef TURBO_P2P_MESH_MGMT_ENDPOINT_POOL_H
#define TURBO_P2P_MESH_MGMT_ENDPOINT_POOL_H

#include <p2p.h>
#include <turbo_vec.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_ENDPOINT_POOL_MAX_ENDPOINTS 64u
#define MESH_MGMT_ENDPOINT_HOST_MAX 64u
#define MESH_MGMT_ENDPOINT_RETRY_MAX_MS 86400000u
#define MESH_MGMT_ENDPOINT_CONNECT_TIMEOUT_MAX_MS 300000u

typedef enum {
  MESH_MGMT_ENDPOINT_POOL_OK = 0,
  MESH_MGMT_ENDPOINT_POOL_INVALID_ARG = -1,
  MESH_MGMT_ENDPOINT_POOL_INVALID_STATE = -2,
  MESH_MGMT_ENDPOINT_POOL_RESOURCE_EXHAUSTED = -3,
  MESH_MGMT_ENDPOINT_POOL_RANDOM_FAILED = -4,
  MESH_MGMT_ENDPOINT_POOL_NOT_FOUND = -5,
  MESH_MGMT_ENDPOINT_POOL_CONFLICT = -6,
  MESH_MGMT_ENDPOINT_POOL_STALE = -7,
  MESH_MGMT_ENDPOINT_POOL_EXPIRED = -8,
} mesh_mgmt_endpoint_pool_result_t;

typedef enum {
  MESH_MGMT_ENDPOINT_SOURCE_STATIC = 1,
  MESH_MGMT_ENDPOINT_SOURCE_VERIFIED_RECORD = 2,
} mesh_mgmt_endpoint_source_t;

typedef enum {
  MESH_MGMT_ENDPOINT_IDLE = 0,
  MESH_MGMT_ENDPOINT_DIALING = 1,
  MESH_MGMT_ENDPOINT_ACTIVE = 2,
  MESH_MGMT_ENDPOINT_BACKOFF = 3,
  MESH_MGMT_ENDPOINT_QUARANTINED = 4,
  MESH_MGMT_ENDPOINT_EXPIRED = 5,
} mesh_mgmt_endpoint_state_t;

typedef enum {
  MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT = 1,
  MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL = 2,
} mesh_mgmt_endpoint_failure_t;

typedef int (*mesh_mgmt_endpoint_connect_fn)(void *context, p2p_node_t *node, const char *host,
                                             uint16_t port);
typedef int (*mesh_mgmt_endpoint_random_fn)(void *context, uint8_t *output, size_t output_len);

typedef struct {
  uint8_t transport_peer_id[P2P_KEY_SIZE];
  char host[MESH_MGMT_ENDPOINT_HOST_MAX];
  uint16_t port;
  mesh_mgmt_endpoint_source_t source;
  uint64_t record_epoch;
  uint64_t expires_at_ms;
} mesh_mgmt_endpoint_record_v1_t;

typedef struct {
  p2p_node_t *node;
  size_t capacity;
  uint64_t retry_base_ms;
  uint64_t retry_max_ms;
  uint64_t connect_timeout_ms;
  uint32_t protocol_failure_limit;
  mesh_mgmt_endpoint_connect_fn connect_peer;
  mesh_mgmt_endpoint_random_fn random_bytes;
  void *callback_context;
} mesh_mgmt_endpoint_pool_config_v1_t;

typedef struct {
  mesh_mgmt_endpoint_record_v1_t record;
  mesh_mgmt_endpoint_state_t state;
  uint64_t next_attempt_ms;
  uint64_t connect_deadline_ms;
  uint32_t transport_failures;
  uint32_t protocol_failures;
  int last_connect_result;
  uint8_t occupied;
  uint8_t retire_on_close;
} mesh_mgmt_endpoint_entry_v1_t;

typedef struct {
  p2p_node_t *node;
  turbo_vec_t entries;
  size_t capacity;
  size_t count;
  uint64_t retry_base_ms;
  uint64_t retry_max_ms;
  uint64_t connect_timeout_ms;
  uint32_t protocol_failure_limit;
  mesh_mgmt_endpoint_connect_fn connect_peer;
  mesh_mgmt_endpoint_random_fn random_bytes;
  void *callback_context;
  mesh_mgmt_endpoint_pool_result_t last_error;
  uint8_t initialized;
  uint8_t running;
  uint8_t in_api;
} mesh_mgmt_endpoint_pool_v1_t;

typedef struct {
  mesh_mgmt_endpoint_record_v1_t record;
  mesh_mgmt_endpoint_state_t state;
  uint64_t next_attempt_ms;
  uint64_t connect_deadline_ms;
  uint32_t transport_failures;
  uint32_t protocol_failures;
  int last_connect_result;
} mesh_mgmt_endpoint_snapshot_v1_t;

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_init_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                const mesh_mgmt_endpoint_pool_config_v1_t *config);

void mesh_mgmt_endpoint_pool_destroy_v1(mesh_mgmt_endpoint_pool_v1_t *pool);

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_add_static_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                      const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                      const char *host, uint16_t port);

/**
 * Apply an endpoint record only after the caller has verified its MMP envelope,
 * signer authority, mesh scope, epoch and expiry. This boundary never reads
 * raw DHT bytes and a verified record cannot replace a local static endpoint.
 */
mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_apply_verified_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                          const mesh_mgmt_endpoint_record_v1_t *record,
                                          uint64_t now_ms);

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_start_v1(mesh_mgmt_endpoint_pool_v1_t *pool);

void mesh_mgmt_endpoint_pool_stop_v1(mesh_mgmt_endpoint_pool_v1_t *pool);

/** Run due connect attempts and connect-timeout transitions on the owner loop. */
mesh_mgmt_endpoint_pool_result_t mesh_mgmt_endpoint_pool_tick_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                                                 uint64_t now_ms);

/**
 * Bind a completed signed MMP session to its configured transport identity.
 * NOT_FOUND is a policy decision point, never implicit admission: a strict
 * outbound bootstrap owner must reject that session, while a listener may
 * consult a separate signed membership policy before accepting it.
 */
mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_mark_authenticated_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                              const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                              uint64_t now_ms);

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_mark_failed_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                       const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                       mesh_mgmt_endpoint_failure_t failure, uint64_t now_ms);

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_reset_v1(mesh_mgmt_endpoint_pool_v1_t *pool,
                                 const uint8_t transport_peer_id[P2P_KEY_SIZE]);

mesh_mgmt_endpoint_pool_result_t
mesh_mgmt_endpoint_pool_snapshot_v1(const mesh_mgmt_endpoint_pool_v1_t *pool,
                                    const uint8_t transport_peer_id[P2P_KEY_SIZE],
                                    mesh_mgmt_endpoint_snapshot_v1_t *out_snapshot);

#ifdef __cplusplus
}
#endif

#endif
