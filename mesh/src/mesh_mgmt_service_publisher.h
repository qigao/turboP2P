#ifndef TURBO_P2P_MESH_MGMT_SERVICE_PUBLISHER_H
#define TURBO_P2P_MESH_MGMT_SERVICE_PUBLISHER_H

#include "mesh_mgmt_record_epoch.h"
#include "mesh_mgmt_peer_signer.h"
#include "mesh_mgmt_service_record.h"

#include <p2p.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_SERVICE_FRAME_V1_MAX                                                        \
  (MESH_MGMT_PREFIX_SIZE + MESH_MGMT_HEADER_V1_ENCODED_SIZE +                                \
   MESH_MGMT_SERVICE_RECORD_V1_MAX_SIZE + MESH_MGMT_SIGNATURE_SIZE)

typedef enum {
  MESH_MGMT_SERVICE_PUBLISHER_OK = 0,
  MESH_MGMT_SERVICE_PUBLISHER_INVALID_ARG = -1,
  MESH_MGMT_SERVICE_PUBLISHER_INVALID_STATE = -2,
  MESH_MGMT_SERVICE_PUBLISHER_IDENTITY_FAILED = -3,
  MESH_MGMT_SERVICE_PUBLISHER_ENCODE_FAILED = -4,
  MESH_MGMT_SERVICE_PUBLISHER_RANDOM_FAILED = -5,
  MESH_MGMT_SERVICE_PUBLISHER_SIGN_FAILED = -6,
  MESH_MGMT_SERVICE_PUBLISHER_P2P_FAILED = -7,
  MESH_MGMT_SERVICE_PUBLISHER_RESOURCE_EXHAUSTED = -8,
  MESH_MGMT_SERVICE_PUBLISHER_EPOCH_FAILED = -9,
} mesh_mgmt_service_publisher_result_t;

typedef enum {
  MESH_MGMT_SERVICE_PUBLISHER_UNINITIALIZED = 0,
  MESH_MGMT_SERVICE_PUBLISHER_READY = 1,
} mesh_mgmt_service_publisher_state_t;

typedef struct {
  uint8_t address_family;
  uint8_t virtual_address[16];
  /** Borrowed NUL-terminated canonical lowercase DNS name; empty is allowed. */
  const char *dns_name;
  uint16_t port;
} mesh_mgmt_service_publish_v1_t;

/**
 * Single-event-loop owner for the local signed RPC service fact. The P2P node
 * is borrowed. The signer owns and wipes its copied management seed.
 */
typedef struct {
  p2p_node_t *node;
  mesh_mgmt_peer_signer_v1_t signer;
  uint64_t certificate_expires_at_ms;
  uint64_t next_record_epoch;
  mesh_mgmt_record_epoch_allocate_fn allocate_record_epoch;
  void *record_epoch_context;
  mesh_mgmt_service_publisher_state_t state;
  mesh_mgmt_service_publisher_result_t last_error;
  mesh_mgmt_service_record_result_t last_record_result;
  mesh_mgmt_envelope_result_t last_envelope_result;
  int last_random_result;
  int last_p2p_result;
  uint8_t sequence_exhausted;
  uint8_t in_api;
} mesh_mgmt_service_publisher_v1_t;

mesh_mgmt_service_publisher_result_t
mesh_mgmt_service_publisher_init_v1(mesh_mgmt_service_publisher_v1_t *publisher, p2p_node_t *node,
                                    const mesh_mgmt_peer_signer_config_v1_t *signer_config,
                                    uint64_t first_record_epoch);

mesh_mgmt_service_publisher_result_t mesh_mgmt_service_publisher_set_epoch_allocator_v1(
    mesh_mgmt_service_publisher_v1_t *publisher,
    mesh_mgmt_record_epoch_allocate_fn allocate_record_epoch,
    void *record_epoch_context);

/**
 * Sign and cache the next RPC virtual-service record, then push it to currently
 * connected peers. This function performs no iterative DHT lookup.
 */
mesh_mgmt_service_publisher_result_t
mesh_mgmt_service_publisher_publish_cached_v1(mesh_mgmt_service_publisher_v1_t *publisher,
                                              const mesh_mgmt_service_publish_v1_t *service,
                                              uint64_t *out_record_epoch);

void mesh_mgmt_service_publisher_destroy_v1(mesh_mgmt_service_publisher_v1_t *publisher);

#ifdef __cplusplus
}
#endif

#endif
