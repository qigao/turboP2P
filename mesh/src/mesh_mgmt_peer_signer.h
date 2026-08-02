#ifndef TURBO_P2P_MESH_MGMT_PEER_SIGNER_H
#define TURBO_P2P_MESH_MGMT_PEER_SIGNER_H

#include "mesh_mgmt_peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_PEER_SIGNER_FRAME_TTL_MAX_MS 60000u

typedef enum {
  MESH_MGMT_PEER_SIGNER_OK = 0,
  MESH_MGMT_PEER_SIGNER_INVALID_ARG = -1,
  MESH_MGMT_PEER_SIGNER_INVALID_STATE = -2,
  MESH_MGMT_PEER_SIGNER_IDENTITY_FAILED = -3,
  MESH_MGMT_PEER_SIGNER_RANDOM_FAILED = -4,
  MESH_MGMT_PEER_SIGNER_ENCODE_FAILED = -5,
  MESH_MGMT_PEER_SIGNER_SIGN_FAILED = -6,
} mesh_mgmt_peer_signer_result_t;

typedef enum {
  MESH_MGMT_PEER_SIGNER_UNINITIALIZED = 0,
  MESH_MGMT_PEER_SIGNER_READY = 1,
} mesh_mgmt_peer_signer_state_t;

typedef uint64_t (*mesh_mgmt_peer_signer_now_fn)(void *context);
typedef int (*mesh_mgmt_peer_signer_random_fn)(void *context, uint8_t *output, size_t output_len);

typedef struct {
  uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE];
  uint8_t trusted_issuer_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint8_t expected_mesh_id_hash[32];
  uint8_t local_transport_peer_id[32];
  mesh_mgmt_hello_v1_t hello;
  uint8_t session_id[16];
  uint64_t incarnation;
  uint64_t first_sequence;
  uint64_t frame_ttl_ms;
  mesh_mgmt_peer_signer_now_fn now_ms;
  mesh_mgmt_peer_signer_random_fn random_bytes;
  void *callback_context;
} mesh_mgmt_peer_signer_config_v1_t;

/**
 * Single event-loop owner for local HELLO/ACK construction. The signer copies
 * the management seed and wipes it on destroy; persistence remains external.
 */
typedef struct {
  uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE];
  uint8_t mesh_id_hash[32];
  uint8_t origin_node_id[32];
  uint8_t session_id[16];
  mesh_mgmt_hello_v1_t hello;
  uint64_t principal_epoch;
  uint64_t incarnation;
  uint64_t certificate_serial;
  uint64_t next_sequence;
  uint64_t frame_ttl_ms;
  mesh_mgmt_peer_signer_now_fn now_ms;
  mesh_mgmt_peer_signer_random_fn random_bytes;
  void *callback_context;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  size_t frame_len;
  mesh_mgmt_peer_signer_state_t state;
  mesh_mgmt_peer_signer_result_t last_error;
  mesh_mgmt_identity_result_t last_identity_result;
  mesh_mgmt_session_result_t last_session_result;
  mesh_mgmt_envelope_result_t last_envelope_result;
  int last_random_result;
  uint8_t hello_built;
  uint8_t ack_built;
  uint8_t in_build;
} mesh_mgmt_peer_signer_v1_t;

mesh_mgmt_peer_signer_result_t
mesh_mgmt_peer_signer_init_v1(mesh_mgmt_peer_signer_v1_t *signer,
                              const mesh_mgmt_peer_signer_config_v1_t *config);

void mesh_mgmt_peer_signer_destroy_v1(mesh_mgmt_peer_signer_v1_t *signer);

/** mesh_mgmt_peer_build_hello_fn-compatible callback. */
int mesh_mgmt_peer_signer_build_hello_v1(void *context, const uint8_t **out_frame,
                                         size_t *out_frame_len);

/** mesh_mgmt_peer_build_ack_fn-compatible callback. */
int mesh_mgmt_peer_signer_build_ack_v1(void *context, const mesh_mgmt_hello_ack_v1_t *ack,
                                       const uint8_t **out_frame, size_t *out_frame_len);

/**
 * Build one signed targeted MMP frame after the local HELLO and ACK have been
 * built. Feature and typed-payload authorization remain the connection's
 * responsibility.
 */
mesh_mgmt_peer_signer_result_t mesh_mgmt_peer_signer_build_targeted_v1(
    mesh_mgmt_peer_signer_v1_t *signer,
    uint8_t kind,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t **out_frame,
    size_t *out_frame_len);

#ifdef __cplusplus
}
#endif

#endif
