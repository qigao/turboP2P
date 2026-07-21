#ifndef TURBO_P2P_MESH_MGMT_ENDPOINT_PUBLISHER_H
#define TURBO_P2P_MESH_MGMT_ENDPOINT_PUBLISHER_H

#include "mesh_mgmt_endpoint_record.h"
#include "mesh_mgmt_peer_signer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_ENDPOINT_FRAME_V1_MAX                                                            \
  (MESH_MGMT_PREFIX_SIZE + MESH_MGMT_HEADER_V1_ENCODED_SIZE +                                      \
   MESH_MGMT_ENDPOINT_RECORD_IPV6_V1_SIZE + MESH_MGMT_SIGNATURE_SIZE)

typedef enum {
  MESH_MGMT_ENDPOINT_PUBLISHER_OK = 0,
  MESH_MGMT_ENDPOINT_PUBLISHER_INVALID_ARG = -1,
  MESH_MGMT_ENDPOINT_PUBLISHER_INVALID_STATE = -2,
  MESH_MGMT_ENDPOINT_PUBLISHER_IDENTITY_FAILED = -3,
  MESH_MGMT_ENDPOINT_PUBLISHER_ENCODE_FAILED = -4,
  MESH_MGMT_ENDPOINT_PUBLISHER_RANDOM_FAILED = -5,
  MESH_MGMT_ENDPOINT_PUBLISHER_SIGN_FAILED = -6,
  MESH_MGMT_ENDPOINT_PUBLISHER_P2P_FAILED = -7,
  MESH_MGMT_ENDPOINT_PUBLISHER_RESOURCE_EXHAUSTED = -8,
} mesh_mgmt_endpoint_publisher_result_t;

typedef enum {
  MESH_MGMT_ENDPOINT_PUBLISHER_UNINITIALIZED = 0,
  MESH_MGMT_ENDPOINT_PUBLISHER_READY = 1,
} mesh_mgmt_endpoint_publisher_state_t;

typedef struct {
  uint8_t address_family;
  uint8_t address[16];
  uint16_t port;
} mesh_mgmt_endpoint_publish_v1_t;

/**
 * Single-event-loop owner for the local signed endpoint fact. The P2P node is
 * borrowed. The validated signer owns and wipes its copied management seed.
 */
typedef struct {
  p2p_node_t *node;
  mesh_mgmt_peer_signer_v1_t signer;
  uint8_t local_transport_peer_id[P2P_KEY_SIZE];
  uint64_t certificate_expires_at_ms;
  uint64_t next_record_epoch;
  mesh_mgmt_endpoint_publisher_state_t state;
  mesh_mgmt_endpoint_publisher_result_t last_error;
  mesh_mgmt_endpoint_record_result_t last_record_result;
  mesh_mgmt_envelope_result_t last_envelope_result;
  int last_random_result;
  int last_p2p_result;
  uint8_t sequence_exhausted;
  uint8_t in_api;
} mesh_mgmt_endpoint_publisher_v1_t;

mesh_mgmt_endpoint_publisher_result_t
mesh_mgmt_endpoint_publisher_init_v1(mesh_mgmt_endpoint_publisher_v1_t *publisher, p2p_node_t *node,
                                     const mesh_mgmt_peer_signer_config_v1_t *signer_config,
                                     uint64_t first_record_epoch);

/**
 * Sign and store the next local endpoint record, then push it to currently
 * connected peers. This does not run or wait for an iterative DHT lookup.
 * out_record_epoch is zeroed on failure.
 */
mesh_mgmt_endpoint_publisher_result_t
mesh_mgmt_endpoint_publisher_publish_cached_v1(mesh_mgmt_endpoint_publisher_v1_t *publisher,
                                               const mesh_mgmt_endpoint_publish_v1_t *endpoint,
                                               uint64_t *out_record_epoch);

void mesh_mgmt_endpoint_publisher_destroy_v1(mesh_mgmt_endpoint_publisher_v1_t *publisher);

#ifdef __cplusplus
}
#endif

#endif
