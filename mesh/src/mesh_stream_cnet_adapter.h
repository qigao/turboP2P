#ifndef TURBO_P2P_MESH_STREAM_CNET_ADAPTER_H
#define TURBO_P2P_MESH_STREAM_CNET_ADAPTER_H

#include "mesh_stream_bind.h"
#include "mesh_stream_registry.h"
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

/** Authenticated receiver channel on the exact borrowed binding connection.
 * Zero-initialize before init.
 * The embedding event-loop owner routes receive bytes and logical send
 * terminals here. It must serialize all calls, keep the binding/client/policy
 * context alive, and must not reenter from application callbacks.
 *
 * The policy IO contains only set_send_hwm/set_receive_timeout/context. These
 * callbacks must apply or verify the actual policy used to create the CNet
 * client; CNet has no per-connection setters for these fields. Mismatch must
 * fail, never silently accept an unenforced limit.
 *
 * Request one receive at a time. Pause further demand while send_pending is
 * set; already received bytes use the transport's max_frame_size bound. All
 * connection writes belong to this receiver, with one pending control. Capture
 * its token before calling complete_send (which can queue the next control).
 * CNet guarantees one on_send per logical write; do not mix unregistered writes.
 *
 * This adapter does not submit receive demand or close the borrowed handle.
 * Close/revoke here before cnet_close, and again on CLOSED/FAILED. After a
 * terminal error, close the connection and quiesce callbacks before destroy or
 * reusing any binding/client/channel object. Never call the nested channel
 * directly: its generic entry points do not perform the TLS authorization gate.
 */
typedef struct {
  /* Used only in standalone mode. Registered mode leaves this zero and
   * resolves the unique registry-owned storage through its generation handle. */
  mesh_stream_channel_v1_t channel;
  mesh_stream_registry_v1_t *registry;
  mesh_stream_channel_handle_v1_t registry_handle;
  mesh_stream_cnet_bind_v1_t *binding;
  cnet_client *client;
  cnet_connection connection;
  mesh_stream_transport_io_v1_t policy;
  mesh_stream_transport_event_fn on_event;
  void *event_context;
} mesh_stream_cnet_channel_v1_t;

mesh_stream_channel_result_t mesh_stream_cnet_channel_init_v1(
    mesh_stream_cnet_channel_v1_t *adapter, mesh_stream_cnet_bind_v1_t *binding,
    const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config,
    const mesh_stream_transport_io_v1_t *policy, uint64_t now_ms,
    mesh_stream_transport_event_fn on_event, void *event_context);

/** Register one authenticated receiver in the bounded registry. The registry
 * owns channel storage; this route and all borrowed binding/policy contexts
 * must outlive retirement. Calls remain serialized and nonreentrant.
 * Registry close/revoke/destroy retires binding authorization immediately.
 * Route receive/send only through this adapter, never generic registry data IO.
 * Stop/quiesce callbacks before releasing its slot, destroying the registry,
 * or reusing the route. The registry object itself must outlive this route.
 * Quota/duplicate/config failures do not consume a slot or retire the binding.
 * out_handle must not alias the route's internal registry_handle field. */
mesh_stream_registry_result_t mesh_stream_cnet_channel_register_v1(
    mesh_stream_cnet_channel_v1_t *adapter, mesh_stream_registry_v1_t *registry,
    mesh_stream_cnet_bind_v1_t *binding, const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config,
    const mesh_stream_transport_io_v1_t *policy, uint64_t now_ms,
    mesh_stream_transport_event_fn on_event, void *event_context,
    mesh_stream_channel_handle_v1_t *out_handle);

/** Internal owner-call inspection only. NULL if the registered handle retired
 * and was released or the registry storage was destroyed. Do not retain it. */
mesh_stream_channel_v1_t *mesh_stream_cnet_channel_borrow_v1(
    const mesh_stream_cnet_channel_v1_t *adapter);

mesh_stream_channel_result_t mesh_stream_cnet_channel_feed_v1(
    mesh_stream_cnet_channel_v1_t *adapter, cnet_connection connection,
    uint64_t admission_generation, const uint8_t *bytes, size_t len,
    uint64_t now_ms, size_t *out_frames);

mesh_stream_channel_result_t mesh_stream_cnet_channel_complete_send_v1(
    mesh_stream_cnet_channel_v1_t *adapter, cnet_connection connection,
    uint64_t admission_generation, uint64_t token, int status, size_t bytes,
    uint64_t now_ms, size_t *out_frames);

/** Idempotent matching-lifetime shutdown. Revokes binding authorization before
 * the caller submits close; obsolete connection/generation cannot touch it. */
mesh_stream_channel_result_t mesh_stream_cnet_channel_close_v1(
    mesh_stream_cnet_channel_v1_t *adapter, cnet_connection connection,
    uint64_t admission_generation, uint64_t now_ms);

/** Quiesce CNet callbacks first. Standalone mode frees channel storage;
 * registered mode retires the slot (explicit registry release remains required).
 * A stale route cannot touch a reused slot or replacement binding. Never closes
 * or destroys the borrowed client. */
void mesh_stream_cnet_channel_destroy_v1(mesh_stream_cnet_channel_v1_t *adapter);

#ifdef __cplusplus
}
#endif
#endif
