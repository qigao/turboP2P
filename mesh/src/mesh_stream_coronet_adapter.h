#ifndef TURBO_P2P_MESH_STREAM_CORONET_ADAPTER_H
#define TURBO_P2P_MESH_STREAM_CORONET_ADAPTER_H

#include "mesh_stream_bind.h"
#include "mesh_stream_registry.h"

#include <CoroNet/turbo_coro_socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_STREAM_CORONET_ROLE_INITIATOR = 1,
  MESH_STREAM_CORONET_ROLE_RESPONDER = 2,
} mesh_stream_coronet_role_v1_t;

/**
 * Internal proof that the three-message identity bind completed on one exact
 * TLS 1.3 connection. It is valid only while that connection and ticket are
 * both live and is cleared explicitly when the channel closes.
 */
typedef struct {
  mesh_stream_bind_ticket_v1_t ticket;
  uint8_t channel_binding[MESH_STREAM_BIND_CHANNEL_BINDING_SIZE];
  mesh_stream_coronet_role_v1_t local_role;
  uint8_t authenticated;
} mesh_stream_coronet_authorization_v1_t;

void mesh_stream_coronet_authorization_clear_v1(
    mesh_stream_coronet_authorization_v1_t *authorization);

/** Derive the exporter, build INIT, and send it exactly once on @p socket. */
mesh_stream_bind_result_t mesh_stream_bind_initiator_start_coronet_v1(
    mesh_stream_bind_initiator_v1_t *initiator, const mesh_stream_bind_ticket_v1_t *ticket,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], coro_socket_t *socket,
    uint8_t output[MESH_STREAM_BIND_INIT_SIZE]);

/** Verify ACCEPT, build/send CONFIRM, then publish initiator authorization. */
mesh_stream_bind_result_t mesh_stream_bind_initiator_confirm_coronet_v1(
    mesh_stream_bind_initiator_v1_t *initiator, const uint8_t *input, size_t input_len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], coro_socket_t *socket,
    uint8_t output[MESH_STREAM_BIND_CONFIRM_SIZE],
    mesh_stream_coronet_authorization_v1_t *out_authorization);

/** Verify INIT, build/send ACCEPT, and tombstone its ticket on send ambiguity. */
mesh_stream_bind_result_t mesh_stream_bind_responder_accept_coronet_v1(
    mesh_stream_bind_store_v1_t *store, const uint8_t *input, size_t input_len,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE], coro_socket_t *socket,
    uint64_t now_ms, uint8_t output[MESH_STREAM_BIND_ACCEPT_SIZE]);

/** Verify CONFIRM on the current TLS connection and publish responder authorization. */
mesh_stream_bind_result_t mesh_stream_bind_responder_finish_coronet_v1(
    mesh_stream_bind_store_v1_t *store, const uint8_t *input, size_t input_len,
    coro_socket_t *socket, uint64_t now_ms,
    mesh_stream_coronet_authorization_v1_t *out_authorization);

/**
 * Bind a non-owned, connected TLS 1.3 CoroNet socket. This low-level transport
 * primitive verifies the exporter but does not replace identity authorization.
 * Calls must run from the socket's owning coroutine/event-loop context.
 */
mesh_stream_transport_result_t mesh_stream_transport_init_coronet_v1(
    mesh_stream_transport_v1_t *transport, const mesh_stream_transport_config_v1_t *config,
    coro_socket_t *socket, mesh_stream_transport_event_fn on_event, void *event_context);

/** Bind the same non-owned socket through the authenticated channel owner. */
mesh_stream_channel_result_t mesh_stream_channel_init_coronet_v1(
    mesh_stream_channel_v1_t *channel, const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config,
    const mesh_stream_coronet_authorization_v1_t *authorization, uint64_t now_ms,
    coro_socket_t *socket,
    mesh_stream_transport_event_fn on_event, void *event_context);

/** Open one registry channel over a non-owned, connected CoroNet socket. */
mesh_stream_registry_result_t mesh_stream_registry_open_coronet_v1(
    mesh_stream_registry_v1_t *registry, const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config,
    const mesh_stream_coronet_authorization_v1_t *authorization, uint64_t now_ms,
    coro_socket_t *socket,
    mesh_stream_transport_event_fn on_event, void *event_context,
    mesh_stream_channel_handle_v1_t *out_handle);

#ifdef __cplusplus
}
#endif

#endif
