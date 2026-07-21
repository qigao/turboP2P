#ifndef TURBO_P2P_MESH_MGMT_PEER_H
#define TURBO_P2P_MESH_MGMT_PEER_H

#include "mesh_mgmt_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_PEER_BUILDER_INVALID_OUTPUT (-1001)
#define MESH_MGMT_PEER_BUILDER_INVALID_HELLO (-1002)
#define MESH_MGMT_PEER_BUILDER_INVALID_ACK (-1003)

typedef enum {
  MESH_MGMT_PEER_OK = 0,
  MESH_MGMT_PEER_INVALID_ARG = -1,
  MESH_MGMT_PEER_INVALID_STATE = -2,
  MESH_MGMT_PEER_BUILD_FAILED = -3,
  MESH_MGMT_PEER_CONNECTION_FAILED = -4,
} mesh_mgmt_peer_result_t;

typedef enum {
  MESH_MGMT_PEER_UNINITIALIZED = 0,
  MESH_MGMT_PEER_READY = 1,
  MESH_MGMT_PEER_TERMINAL = 2,
} mesh_mgmt_peer_state_t;

/**
 * Build a signed HELLO frame. The returned frame remains builder-owned and is
 * borrowed only for the synchronous send performed before this call returns.
 */
typedef int (*mesh_mgmt_peer_build_hello_fn)(void *context, const uint8_t **out_frame,
                                             size_t *out_frame_len);

/**
 * Build a signed HELLO_ACK from the accepted negotiation result. The returned
 * frame has the same synchronous borrowed lifetime as build_hello output.
 */
typedef int (*mesh_mgmt_peer_build_ack_fn)(void *context, const mesh_mgmt_hello_ack_v1_t *ack,
                                           const uint8_t **out_frame, size_t *out_frame_len);

typedef struct {
  mesh_mgmt_connection_config_v1_t connection;
  uint8_t local_transport_peer_id[32];
  mesh_mgmt_peer_build_hello_fn build_hello;
  mesh_mgmt_peer_build_ack_fn build_ack;
  void *builder_context;
} mesh_mgmt_peer_config_v1_t;

/** Single event-loop owner; no internal locking and no socket ownership. */
typedef struct {
  mesh_mgmt_connection_v1_t connection;
  mesh_mgmt_connection_event_fn on_event;
  void *event_context;
  mesh_mgmt_peer_build_hello_fn build_hello;
  mesh_mgmt_peer_build_ack_fn build_ack;
  void *builder_context;
  mesh_mgmt_hello_ack_v1_t pending_ack;
  mesh_mgmt_header_v1_t local_header;
  uint8_t local_transport_peer_id[32];
  mesh_mgmt_peer_state_t state;
  mesh_mgmt_peer_result_t last_error;
  mesh_mgmt_connection_result_t last_connection_result;
  int last_builder_result;
  int started;
  int ack_pending;
  int in_event_callback;
  int in_builder_callback;
} mesh_mgmt_peer_v1_t;

mesh_mgmt_peer_result_t mesh_mgmt_peer_init_v1(mesh_mgmt_peer_v1_t *peer,
                                               const mesh_mgmt_peer_config_v1_t *config);

void mesh_mgmt_peer_destroy_v1(mesh_mgmt_peer_v1_t *peer);

/** Validate, then synchronously send, the local HELLO exactly once. */
mesh_mgmt_peer_result_t mesh_mgmt_peer_start_v1(mesh_mgmt_peer_v1_t *peer, uint64_t now_ms);

/**
 * Deliver one frame. An accepted HELLO is committed before its signed ACK is
 * built and sent. Any builder or connection ambiguity is terminal.
 */
mesh_mgmt_peer_result_t mesh_mgmt_peer_pump_once_v1(mesh_mgmt_peer_v1_t *peer, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif
