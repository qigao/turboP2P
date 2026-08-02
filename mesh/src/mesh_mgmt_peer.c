#include "mesh_mgmt_peer.h"

#include "mesh_mgmt_crypto.h"

#include <string.h>

static mesh_mgmt_peer_result_t peer_fail(mesh_mgmt_peer_v1_t *peer,
                                         mesh_mgmt_peer_result_t result) {
  peer->ack_pending = 0;
  memset(&peer->pending_ack, 0, sizeof(peer->pending_ack));
  peer->state = MESH_MGMT_PEER_TERMINAL;
  peer->last_error = result;
  return result;
}

static mesh_mgmt_peer_result_t require_ready(mesh_mgmt_peer_v1_t *peer) {
  if (!peer)
    return MESH_MGMT_PEER_INVALID_ARG;
  if (peer->state == MESH_MGMT_PEER_TERMINAL)
    return peer->last_error;
  if (peer->state != MESH_MGMT_PEER_READY || peer->in_event_callback || peer->in_builder_callback)
    return MESH_MGMT_PEER_INVALID_STATE;
  return MESH_MGMT_PEER_OK;
}

static int peer_event(void *context, const mesh_mgmt_dispatch_event_v1_t *event) {
  mesh_mgmt_peer_v1_t *peer = (mesh_mgmt_peer_v1_t *)context;
  int result;

  if (!peer || !event || peer->in_event_callback)
    return -1;
  if (event->type == MESH_MGMT_DISPATCH_EVENT_HELLO_ACK_REQUIRED) {
    if (peer->ack_pending)
      return -1;
    peer->pending_ack = event->hello_ack;
    peer->ack_pending = 1;
  }

  peer->in_event_callback = 1;
  result = peer->on_event(peer->event_context, event);
  peer->in_event_callback = 0;
  return result;
}

static int valid_built_frame(const uint8_t *frame, size_t frame_len) {
  return frame && frame_len != 0u && frame_len <= MESH_MGMT_FRAME_MAX;
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  size_t index;
  uint8_t combined = 0u;

  for (index = 0u; index < length; index++)
    combined |= bytes[index];
  return combined == 0u;
}

/* RFC 1982 ordering over the 64-bit origin sequence space. */
static int sequence_is_newer(uint64_t candidate, uint64_t current) {
  uint64_t distance = candidate - current;
  return distance != 0u && distance < (UINT64_C(1) << 63);
}

static int envelope_time_is_locally_sendable(
    const mesh_mgmt_verified_envelope_v1_t *envelope,
    uint64_t sampled_before_build_ms) {
  return envelope->header.issued_at_ms < envelope->header.expires_at_ms &&
         envelope->header.expires_at_ms > sampled_before_build_ms;
}

static int hello_matches_local_config(const mesh_mgmt_peer_v1_t *peer,
                                      const mesh_mgmt_hello_v1_t *hello) {
  const mesh_mgmt_session_config_v1_t *config = &peer->connection.dispatcher.session.config;
  return hello->major == MESH_MGMT_MAJOR_V1 && hello->min_minor == config->min_minor &&
         hello->max_minor == config->max_minor && hello->features == config->features &&
         mesh_mgmt_crypto_equal_16(hello->connection_id, config->connection_id) &&
         hello->max_frame == config->max_frame &&
         hello->max_digest_entries == config->max_digest_entries &&
         hello->max_delta_batch == config->max_delta_batch;
}

static int validate_local_hello(mesh_mgmt_peer_v1_t *peer, const uint8_t *frame, size_t frame_len,
                                uint64_t now_ms) {
  mesh_mgmt_verified_envelope_v1_t envelope;
  mesh_mgmt_certificate_v1_t certificate;
  mesh_mgmt_hello_v1_t hello;
  uint8_t issuer_hash[32];
  const mesh_mgmt_session_config_v1_t *config = &peer->connection.dispatcher.session.config;

  if (mesh_mgmt_envelope_verify_v1(frame, frame_len, &envelope) != MESH_MGMT_ENVELOPE_OK ||
      envelope.frame.kind != MESH_MGMT_KIND_HELLO ||
      mesh_mgmt_hello_decode_v1(envelope.frame.payload, envelope.frame.payload_len, &hello) !=
          MESH_MGMT_SESSION_OK ||
      mesh_mgmt_certificate_verify_v1(hello.certificate, sizeof(hello.certificate),
                                      config->trusted_issuer_key, config->expected_mesh_id_hash,
                                      now_ms, &certificate) != MESH_MGMT_IDENTITY_OK ||
      !envelope_time_is_locally_sendable(&envelope, now_ms) ||
      mesh_mgmt_blake2b_256(config->trusted_issuer_key, 32, issuer_hash) != MESH_MGMT_CRYPTO_OK ||
      !hello_matches_local_config(peer, &hello) ||
      !mesh_mgmt_crypto_equal_32(issuer_hash, hello.issuer_chain_hash) ||
      hello.principal_type != certificate.principal_type ||
      !mesh_mgmt_crypto_equal_32(hello.management_key, certificate.management_key) ||
      !mesh_mgmt_crypto_equal_32(hello.managed_node_id, certificate.managed_node_id) ||
      !mesh_mgmt_crypto_equal_32(peer->local_transport_peer_id, certificate.transport_peer_id) ||
      !mesh_mgmt_crypto_equal_32(envelope.header.mesh_id_hash, config->expected_mesh_id_hash) ||
      !mesh_mgmt_crypto_equal_32(envelope.header.origin_principal_key,
                                 certificate.management_key) ||
      !mesh_mgmt_crypto_equal_32(envelope.header.origin_node_id, certificate.managed_node_id) ||
      !bytes_are_zero(envelope.header.target_node_id, sizeof(envelope.header.target_node_id)) ||
      bytes_are_zero(envelope.header.session_id, sizeof(envelope.header.session_id)) ||
      bytes_are_zero(envelope.header.message_id, sizeof(envelope.header.message_id)) ||
      envelope.header.incarnation == 0u || envelope.header.forward_budget != 0u ||
      envelope.header.certificate_serial != certificate.serial ||
      envelope.header.principal_epoch != certificate.principal_epoch) {
    memset(issuer_hash, 0, sizeof(issuer_hash));
    return 0;
  }
  memset(issuer_hash, 0, sizeof(issuer_hash));
  peer->local_header = envelope.header;
  return 1;
}

static int ack_values_equal(const mesh_mgmt_hello_ack_v1_t *left,
                            const mesh_mgmt_hello_ack_v1_t *right) {
  return left->selected_major == right->selected_major &&
         left->selected_minor == right->selected_minor && left->features == right->features &&
         left->max_frame == right->max_frame &&
         left->max_digest_entries == right->max_digest_entries &&
         left->max_delta_batch == right->max_delta_batch &&
         mesh_mgmt_crypto_equal_16(left->peer_connection_id, right->peer_connection_id);
}

static int header_matches_local_session(const mesh_mgmt_header_v1_t *header,
                                        const mesh_mgmt_header_v1_t *hello) {
  return mesh_mgmt_crypto_equal_32(header->mesh_id_hash, hello->mesh_id_hash) &&
         mesh_mgmt_crypto_equal_32(header->origin_principal_key, hello->origin_principal_key) &&
         mesh_mgmt_crypto_equal_32(header->origin_node_id, hello->origin_node_id) &&
         mesh_mgmt_crypto_equal_16(header->session_id, hello->session_id) &&
         header->principal_epoch == hello->principal_epoch &&
         header->incarnation == hello->incarnation &&
         header->certificate_serial == hello->certificate_serial &&
         sequence_is_newer(header->origin_sequence, hello->origin_sequence) &&
         !mesh_mgmt_crypto_equal_16(header->message_id, hello->message_id) &&
         header->issued_at_ms >= hello->issued_at_ms;
}

static int validate_local_ack(mesh_mgmt_peer_v1_t *peer, const uint8_t *frame, size_t frame_len,
                              uint64_t now_ms) {
  mesh_mgmt_verified_envelope_v1_t envelope;
  mesh_mgmt_hello_ack_v1_t ack;

  return mesh_mgmt_envelope_verify_v1(frame, frame_len, &envelope) == MESH_MGMT_ENVELOPE_OK &&
         envelope.frame.kind == MESH_MGMT_KIND_HELLO_ACK &&
         mesh_mgmt_hello_ack_decode_v1(envelope.frame.payload, envelope.frame.payload_len, &ack) ==
             MESH_MGMT_SESSION_OK &&
         envelope_time_is_locally_sendable(&envelope, now_ms) &&
         header_matches_local_session(&envelope.header, &peer->local_header) &&
         bytes_are_zero(envelope.header.target_node_id, sizeof(envelope.header.target_node_id)) &&
         envelope.header.forward_budget == 0u && ack_values_equal(&ack, &peer->pending_ack);
}

static mesh_mgmt_peer_result_t builder_fail(mesh_mgmt_peer_v1_t *peer, int builder_result) {
  peer->last_builder_result = builder_result;
  peer->last_connection_result = mesh_mgmt_connection_abort_v1(&peer->connection);
  return peer_fail(peer, MESH_MGMT_PEER_BUILD_FAILED);
}

static mesh_mgmt_peer_result_t connection_fail(mesh_mgmt_peer_v1_t *peer,
                                               mesh_mgmt_connection_result_t result) {
  peer->last_connection_result = result;
  if (peer->connection.state == MESH_MGMT_CONNECTION_READY)
    (void)mesh_mgmt_connection_abort_v1(&peer->connection);
  return peer_fail(peer, MESH_MGMT_PEER_CONNECTION_FAILED);
}

mesh_mgmt_peer_result_t mesh_mgmt_peer_init_v1(mesh_mgmt_peer_v1_t *peer,
                                               const mesh_mgmt_peer_config_v1_t *config) {
  mesh_mgmt_connection_config_v1_t connection_config;
  mesh_mgmt_connection_result_t connection_result;

  if (!peer || !config || !config->connection.on_event || !config->build_hello ||
      !config->build_ack ||
      bytes_are_zero(config->local_transport_peer_id, sizeof(config->local_transport_peer_id)))
    return MESH_MGMT_PEER_INVALID_ARG;
  if (peer->state != MESH_MGMT_PEER_UNINITIALIZED ||
      peer->connection.state != MESH_MGMT_CONNECTION_UNINITIALIZED)
    return MESH_MGMT_PEER_INVALID_STATE;

  memset(peer, 0, sizeof(*peer));
  peer->on_event = config->connection.on_event;
  peer->event_context = config->connection.event_context;
  peer->build_hello = config->build_hello;
  peer->build_ack = config->build_ack;
  peer->builder_context = config->builder_context;
  memcpy(peer->local_transport_peer_id, config->local_transport_peer_id,
         sizeof(peer->local_transport_peer_id));
  connection_config = config->connection;
  connection_config.on_event = peer_event;
  connection_config.event_context = peer;
  connection_result = mesh_mgmt_connection_init_v1(&peer->connection, &connection_config);
  peer->last_connection_result = connection_result;
  if (connection_result != MESH_MGMT_CONNECTION_OK) {
    memset(peer, 0, sizeof(*peer));
    return MESH_MGMT_PEER_CONNECTION_FAILED;
  }

  peer->state = MESH_MGMT_PEER_READY;
  peer->last_error = MESH_MGMT_PEER_OK;
  return MESH_MGMT_PEER_OK;
}

void mesh_mgmt_peer_destroy_v1(mesh_mgmt_peer_v1_t *peer) {
  if (!peer || peer->in_event_callback || peer->in_builder_callback)
    return;
  mesh_mgmt_connection_destroy_v1(&peer->connection);
  memset(peer, 0, sizeof(*peer));
}

mesh_mgmt_peer_result_t mesh_mgmt_peer_start_v1(mesh_mgmt_peer_v1_t *peer, uint64_t now_ms) {
  const uint8_t *frame = NULL;
  size_t frame_len = 0u;
  mesh_mgmt_peer_result_t result = require_ready(peer);
  mesh_mgmt_connection_result_t connection_result;
  int builder_result;

  if (result != MESH_MGMT_PEER_OK)
    return result;
  if (peer->started)
    return MESH_MGMT_PEER_INVALID_STATE;

  peer->in_builder_callback = 1;
  builder_result = peer->build_hello(peer->builder_context, &frame, &frame_len);
  peer->in_builder_callback = 0;
  if (builder_result != 0)
    return builder_fail(peer, builder_result);
  if (!valid_built_frame(frame, frame_len))
    return builder_fail(peer, MESH_MGMT_PEER_BUILDER_INVALID_OUTPUT);
  if (!validate_local_hello(peer, frame, frame_len, now_ms))
    return builder_fail(peer, MESH_MGMT_PEER_BUILDER_INVALID_HELLO);

  connection_result = mesh_mgmt_connection_send_hello_v1(&peer->connection, frame, frame_len);
  if (connection_result != MESH_MGMT_CONNECTION_OK)
    return connection_fail(peer, connection_result);
  peer->last_connection_result = MESH_MGMT_CONNECTION_OK;
  peer->started = 1;
  peer->last_error = MESH_MGMT_PEER_OK;
  return MESH_MGMT_PEER_OK;
}

mesh_mgmt_peer_result_t mesh_mgmt_peer_pump_once_v1(mesh_mgmt_peer_v1_t *peer, uint64_t now_ms) {
  const uint8_t *frame = NULL;
  size_t frame_len = 0u;
  mesh_mgmt_peer_result_t result = require_ready(peer);
  mesh_mgmt_connection_result_t connection_result;
  int builder_result;

  if (result != MESH_MGMT_PEER_OK)
    return result;
  if (!peer->started)
    return MESH_MGMT_PEER_INVALID_STATE;

  connection_result = mesh_mgmt_connection_pump_once_v1(&peer->connection, now_ms);
  if (connection_result != MESH_MGMT_CONNECTION_OK)
    return connection_fail(peer, connection_result);
  peer->last_connection_result = MESH_MGMT_CONNECTION_OK;
  if (!peer->ack_pending)
    return MESH_MGMT_PEER_OK;

  peer->in_builder_callback = 1;
  builder_result = peer->build_ack(peer->builder_context, &peer->pending_ack, &frame, &frame_len);
  peer->in_builder_callback = 0;
  if (builder_result != 0)
    return builder_fail(peer, builder_result);
  if (!valid_built_frame(frame, frame_len))
    return builder_fail(peer, MESH_MGMT_PEER_BUILDER_INVALID_OUTPUT);
  if (!validate_local_ack(peer, frame, frame_len, now_ms))
    return builder_fail(peer, MESH_MGMT_PEER_BUILDER_INVALID_ACK);

  connection_result = mesh_mgmt_connection_send_hello_ack_v1(&peer->connection, frame, frame_len);
  peer->ack_pending = 0;
  memset(&peer->pending_ack, 0, sizeof(peer->pending_ack));
  if (connection_result != MESH_MGMT_CONNECTION_OK)
    return connection_fail(peer, connection_result);
  peer->last_connection_result = MESH_MGMT_CONNECTION_OK;
  peer->last_error = MESH_MGMT_PEER_OK;
  return MESH_MGMT_PEER_OK;
}
