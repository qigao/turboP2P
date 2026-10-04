#ifndef TURBO_P2P_MESH_STREAM_CNET_ADAPTER_H
#define TURBO_P2P_MESH_STREAM_CNET_ADAPTER_H

#include "mesh_stream_bind.h"
#include "mesh_stream_channel.h"
#include <cnet/cnet.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_STREAM_CNET_UNINITIALIZED = 0,
  MESH_STREAM_CNET_READY,
  MESH_STREAM_CNET_INIT_PENDING,
  MESH_STREAM_CNET_WAIT_ACCEPT,
  MESH_STREAM_CNET_ACCEPT_PENDING,
  MESH_STREAM_CNET_WAIT_CONFIRM,
  MESH_STREAM_CNET_CONFIRM_PENDING,
  MESH_STREAM_CNET_AUTHENTICATED,
  MESH_STREAM_CNET_FAILED,
} mesh_stream_cnet_state_v1_t;

typedef enum {
  MESH_STREAM_CNET_ROLE_INITIATOR = 1,
  MESH_STREAM_CNET_ROLE_RESPONDER = 2,
} mesh_stream_cnet_role_v1_t;

/** Single event-loop owner, bound to one borrowed, connected TLS 1.3 handle.
 * All writes on this connection belong exclusively to this owner until bind
 * finishes. Route on_send to complete_send and CLOSED/FAILED to abort. There
 * is exactly one pending write; admission does not publish authorization.
 * The caller frames incoming bytes and calls confirm/finish only after the
 * preceding write terminal (buffer early replies with a fixed handshake-size
 * bound). These functions do not consume application stream bytes.
 * Zero-initialize before init. Quiesce callbacks, abort, then zero the object
 * before reuse; a client wrapper must not be destroyed/reinitialized while
 * bound. The borrowed responder store must outlive abort/finish. */
typedef struct {
  cnet_client *client;
  cnet_connection connection;
  mesh_stream_bind_store_v1_t *store;
  mesh_stream_bind_initiator_v1_t initiator;
  mesh_stream_bind_ticket_v1_t ticket;
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  uint8_t accepted_init[MESH_STREAM_BIND_INIT_SIZE];
  size_t pending_bytes;
  uint8_t challenge_live;
  mesh_stream_cnet_state_v1_t state;
  mesh_stream_cnet_role_v1_t role;
  mesh_stream_bind_result_t last_result;
} mesh_stream_cnet_bind_v1_t;

mesh_stream_bind_result_t mesh_stream_cnet_bind_init_v1(
    mesh_stream_cnet_bind_v1_t *bind, cnet_client *client, cnet_connection connection,
    mesh_stream_cnet_role_v1_t role, mesh_stream_bind_store_v1_t *responder_store);
mesh_stream_bind_result_t mesh_stream_cnet_bind_start_v1(
    mesh_stream_cnet_bind_v1_t *bind, const mesh_stream_bind_ticket_v1_t *ticket,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], uint64_t now_ms);
mesh_stream_bind_result_t mesh_stream_cnet_bind_accept_v1(
    mesh_stream_cnet_bind_v1_t *bind, const uint8_t *init, size_t len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], uint64_t now_ms);
mesh_stream_bind_result_t mesh_stream_cnet_bind_confirm_v1(
    mesh_stream_cnet_bind_v1_t *bind, const uint8_t *accept, size_t len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], uint64_t now_ms);
mesh_stream_bind_result_t mesh_stream_cnet_bind_finish_v1(
    mesh_stream_cnet_bind_v1_t *bind, const uint8_t *confirm, size_t len, uint64_t now_ms);

/** Route one full logical-write on_send (SALTS_OK), or a terminal write error.
 * A different/stale connection or duplicate terminal cannot advance state. */
mesh_stream_bind_result_t mesh_stream_cnet_bind_complete_send_v1(
    mesh_stream_cnet_bind_v1_t *bind, cnet_connection connection, int status,
    size_t bytes, uint64_t now_ms);
/** Clear authorization and tombstone an accepted INIT, including after ACCEPT
 * succeeded but before CONFIRM. Call before requesting an asynchronous close,
 * as already queued writes may still complete. Idempotent; does not close the borrowed handle.
 * After any terminal bind error the caller must close it and quiesce callbacks. */
mesh_stream_bind_result_t mesh_stream_cnet_bind_abort_v1(
    mesh_stream_cnet_bind_v1_t *bind, cnet_connection connection, uint64_t now_ms);

/** Gate admission against this exact live connection, exporter, ticket lifetime,
 * remote peer, stream ID/epoch and authenticated lifecycle generation. */
int mesh_stream_cnet_bind_authorizes_v1(
    const mesh_stream_cnet_bind_v1_t *bind,
    const mesh_stream_channel_admission_v1_t *admission, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
