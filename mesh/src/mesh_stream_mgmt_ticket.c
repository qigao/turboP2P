#include "mesh_stream_mgmt_ticket.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_wire.h"

#include <string.h>

enum {
  REQUEST_FIELD_STREAM_ID = 1,
  REQUEST_FIELD_STREAM_EPOCH = 2,
  REQUEST_FIELD_ADMISSION_GENERATION = 3,
  REQUEST_FIELD_TTL_MS = 4,
};

enum {
  TICKET_FIELD_REQUEST_MESSAGE_ID = 1,
  TICKET_FIELD_TICKET_ID = 2,
  TICKET_FIELD_MESH_ID_HASH = 3,
  TICKET_FIELD_INITIATOR_NODE_ID = 4,
  TICKET_FIELD_INITIATOR_PRINCIPAL_KEY = 5,
  TICKET_FIELD_RESPONDER_NODE_ID = 6,
  TICKET_FIELD_RESPONDER_PRINCIPAL_KEY = 7,
  TICKET_FIELD_STREAM_ID = 8,
  TICKET_FIELD_STREAM_EPOCH = 9,
  TICKET_FIELD_ADMISSION_GENERATION = 10,
  TICKET_FIELD_ISSUED_AT_MS = 11,
  TICKET_FIELD_EXPIRES_AT_MS = 12,
};

static int bytes_are_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0;
  size_t index = 0;

  if (!bytes)
    return 0;
  for (index = 0; index < length; index++)
    aggregate |= bytes[index];
  return aggregate != 0;
}

static int request_is_valid(const mesh_stream_mgmt_ticket_request_v1_t *request) {
  return request && bytes_are_nonzero(request->stream_id, sizeof(request->stream_id)) &&
         request->stream_epoch != 0u && request->admission_generation != 0u &&
         request->ttl_ms != 0u && request->ttl_ms <= MESH_STREAM_BIND_MAX_TTL_MS;
}

static int read_exact_field(mesh_mgmt_tlv_reader_t *reader, uint16_t field_id, size_t length,
                            mesh_mgmt_tlv_view_t *field) {
  return mesh_mgmt_wire_read_field(reader, field_id, length, field);
}

static size_t write_u64_field(uint8_t *output, uint16_t field_id, uint64_t value) {
  uint8_t bytes[sizeof(value)];

  mesh_mgmt_wire_write_u64(bytes, value);
  return mesh_mgmt_wire_write_tlv(output, field_id, bytes, sizeof(bytes));
}

static int event_matches_session(const mesh_mgmt_dispatcher_v1_t *dispatcher,
                                 const mesh_mgmt_dispatch_event_v1_t *event, uint8_t expected_kind,
                                 mesh_mgmt_dispatch_event_type_t expected_type) {
  const mesh_mgmt_session_v1_t *session;

  if (!dispatcher || !event || event->kind != expected_kind || event->type != expected_type)
    return 0;
  session = &dispatcher->session;
  return session->state == MESH_MGMT_SESSION_ESTABLISHED &&
         (session->negotiated.features & MESH_MGMT_FEATURE_STREAM_TICKET) != 0u &&
         session->remote_certificate.principal_type == MESH_MGMT_PRINCIPAL_NODE &&
         (session->remote_certificate.roles & MESH_MGMT_ROLE_OPERATOR) != 0u &&
         event->envelope.frame.kind == expected_kind &&
         mesh_mgmt_crypto_equal_32(event->envelope.header.mesh_id_hash,
                                   session->config.expected_mesh_id_hash) &&
         mesh_mgmt_crypto_equal_32(event->envelope.header.origin_node_id,
                                   session->remote_certificate.managed_node_id) &&
         mesh_mgmt_crypto_equal_32(event->envelope.header.origin_principal_key,
                                   session->remote_certificate.management_key) &&
         event->envelope.header.certificate_serial == session->remote_certificate.serial &&
         event->envelope.header.principal_epoch == session->remote_certificate.principal_epoch &&
         event->envelope.header.incarnation == session->remote_incarnation &&
         mesh_mgmt_crypto_equal_16(event->envelope.header.session_id, session->remote_session_id);
}

static mesh_stream_mgmt_ticket_result_t map_bind_result(mesh_stream_bind_result_t result) {
  switch (result) {
  case MESH_STREAM_BIND_OK:
    return MESH_STREAM_MGMT_TICKET_OK;
  case MESH_STREAM_BIND_RESOURCE_EXHAUSTED:
    return MESH_STREAM_MGMT_TICKET_RESOURCE_EXHAUSTED;
  case MESH_STREAM_BIND_RANDOM_FAILURE:
    return MESH_STREAM_MGMT_TICKET_RANDOM_FAILURE;
  case MESH_STREAM_BIND_EXPIRED:
    return MESH_STREAM_MGMT_TICKET_EXPIRED;
  case MESH_STREAM_BIND_INVALID_STATE:
  case MESH_STREAM_BIND_REPLAY:
    return MESH_STREAM_MGMT_TICKET_INVALID_STATE;
  case MESH_STREAM_BIND_AUTH_FAILED:
  case MESH_STREAM_BIND_CHANNEL_MISMATCH:
    return MESH_STREAM_MGMT_TICKET_AUTH_FAILED;
  case MESH_STREAM_BIND_INVALID_ARG:
  case MESH_STREAM_BIND_NOT_FOUND:
  case MESH_STREAM_BIND_CRYPTO_FAILURE:
  case MESH_STREAM_BIND_INVALID_FRAME:
  case MESH_STREAM_BIND_TLS_REQUIRED:
  case MESH_STREAM_BIND_CHANNEL_EXPORT_FAILED:
  case MESH_STREAM_BIND_IO_FAILED:
  default:
    return MESH_STREAM_MGMT_TICKET_INVALID_ARG;
  }
}

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_request_encode_v1(const mesh_stream_mgmt_ticket_request_v1_t *request,
                                          uint8_t *output, size_t output_capacity,
                                          size_t *out_len) {
  size_t offset = 0;

  if (!request || !out_len)
    return MESH_STREAM_MGMT_TICKET_INVALID_ARG;
  *out_len = MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE;
  if (!request_is_valid(request))
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  if (!output || output_capacity < MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE)
    return MESH_STREAM_MGMT_TICKET_RESOURCE_EXHAUSTED;
  offset += mesh_mgmt_wire_write_tlv(output + offset, REQUEST_FIELD_STREAM_ID, request->stream_id,
                                     sizeof(request->stream_id));
  offset += write_u64_field(output + offset, REQUEST_FIELD_STREAM_EPOCH, request->stream_epoch);
  offset += write_u64_field(output + offset, REQUEST_FIELD_ADMISSION_GENERATION,
                            request->admission_generation);
  offset += write_u64_field(output + offset, REQUEST_FIELD_TTL_MS, request->ttl_ms);
  return offset == MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE ? MESH_STREAM_MGMT_TICKET_OK
                                                           : MESH_STREAM_MGMT_TICKET_INVALID_STATE;
}

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_request_decode_v1(const uint8_t *payload, size_t payload_len,
                                          mesh_stream_mgmt_ticket_request_v1_t *out_request) {
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;

  if (!out_request)
    return MESH_STREAM_MGMT_TICKET_INVALID_ARG;
  memset(out_request, 0, sizeof(*out_request));
  if (!payload || payload_len != MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE)
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  mesh_mgmt_tlv_reader_init(&reader, payload, payload_len);
  if (!read_exact_field(&reader, REQUEST_FIELD_STREAM_ID, sizeof(out_request->stream_id), &field))
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  memcpy(out_request->stream_id, field.value, sizeof(out_request->stream_id));
  if (!read_exact_field(&reader, REQUEST_FIELD_STREAM_EPOCH, sizeof(uint64_t), &field))
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  out_request->stream_epoch = mesh_mgmt_wire_read_u64(field.value);
  if (!read_exact_field(&reader, REQUEST_FIELD_ADMISSION_GENERATION, sizeof(uint64_t), &field))
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  out_request->admission_generation = mesh_mgmt_wire_read_u64(field.value);
  if (!read_exact_field(&reader, REQUEST_FIELD_TTL_MS, sizeof(uint64_t), &field))
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  out_request->ttl_ms = mesh_mgmt_wire_read_u64(field.value);
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0 || !request_is_valid(out_request)) {
    memset(out_request, 0, sizeof(*out_request));
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  }
  return MESH_STREAM_MGMT_TICKET_OK;
}

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_issued_encode_v1(const uint8_t request_message_id[16],
                                         const mesh_stream_bind_ticket_v1_t *ticket,
                                         uint8_t *output, size_t output_capacity, size_t *out_len) {
  size_t offset = 0;

  if (!request_message_id || !ticket || !out_len)
    return MESH_STREAM_MGMT_TICKET_INVALID_ARG;
  *out_len = MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE;
  if (!bytes_are_nonzero(request_message_id, 16) ||
      !bytes_are_nonzero(ticket->ticket_id, sizeof(ticket->ticket_id)) ||
      !bytes_are_nonzero(ticket->claims.mesh_id_hash, sizeof(ticket->claims.mesh_id_hash)) ||
      !bytes_are_nonzero(ticket->claims.initiator_node_id,
                         sizeof(ticket->claims.initiator_node_id)) ||
      !bytes_are_nonzero(ticket->claims.initiator_principal_key,
                         sizeof(ticket->claims.initiator_principal_key)) ||
      !bytes_are_nonzero(ticket->claims.responder_node_id,
                         sizeof(ticket->claims.responder_node_id)) ||
      !bytes_are_nonzero(ticket->claims.responder_principal_key,
                         sizeof(ticket->claims.responder_principal_key)) ||
      !bytes_are_nonzero(ticket->claims.stream_id, sizeof(ticket->claims.stream_id)) ||
      ticket->claims.stream_epoch == 0u || ticket->claims.admission_generation == 0u ||
      ticket->issued_at_ms >= ticket->expires_at_ms ||
      mesh_mgmt_crypto_equal_32(ticket->claims.initiator_node_id,
                                ticket->claims.responder_node_id) ||
      mesh_mgmt_crypto_equal_32(ticket->claims.initiator_principal_key,
                                ticket->claims.responder_principal_key)) {
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  }
  if (!output || output_capacity < MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE)
    return MESH_STREAM_MGMT_TICKET_RESOURCE_EXHAUSTED;
  offset += mesh_mgmt_wire_write_tlv(output + offset, TICKET_FIELD_REQUEST_MESSAGE_ID,
                                     request_message_id, 16);
#define WRITE_BYTES(field_id, value)                                                               \
  offset += mesh_mgmt_wire_write_tlv(output + offset, (field_id), (value), sizeof(value))
  WRITE_BYTES(TICKET_FIELD_TICKET_ID, ticket->ticket_id);
  WRITE_BYTES(TICKET_FIELD_MESH_ID_HASH, ticket->claims.mesh_id_hash);
  WRITE_BYTES(TICKET_FIELD_INITIATOR_NODE_ID, ticket->claims.initiator_node_id);
  WRITE_BYTES(TICKET_FIELD_INITIATOR_PRINCIPAL_KEY, ticket->claims.initiator_principal_key);
  WRITE_BYTES(TICKET_FIELD_RESPONDER_NODE_ID, ticket->claims.responder_node_id);
  WRITE_BYTES(TICKET_FIELD_RESPONDER_PRINCIPAL_KEY, ticket->claims.responder_principal_key);
  WRITE_BYTES(TICKET_FIELD_STREAM_ID, ticket->claims.stream_id);
#undef WRITE_BYTES
  offset +=
      write_u64_field(output + offset, TICKET_FIELD_STREAM_EPOCH, ticket->claims.stream_epoch);
  offset += write_u64_field(output + offset, TICKET_FIELD_ADMISSION_GENERATION,
                            ticket->claims.admission_generation);
  offset += write_u64_field(output + offset, TICKET_FIELD_ISSUED_AT_MS, ticket->issued_at_ms);
  offset += write_u64_field(output + offset, TICKET_FIELD_EXPIRES_AT_MS, ticket->expires_at_ms);
  return offset == MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE ? MESH_STREAM_MGMT_TICKET_OK
                                                          : MESH_STREAM_MGMT_TICKET_INVALID_STATE;
}

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_issued_decode_v1(const uint8_t *payload, size_t payload_len,
                                         uint8_t out_request_message_id[16],
                                         mesh_stream_bind_ticket_v1_t *out_ticket) {
  mesh_mgmt_tlv_reader_t reader;
  mesh_mgmt_tlv_view_t field;

  if (!out_request_message_id || !out_ticket)
    return MESH_STREAM_MGMT_TICKET_INVALID_ARG;
  memset(out_request_message_id, 0, 16);
  memset(out_ticket, 0, sizeof(*out_ticket));
  if (!payload || payload_len != MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE)
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  mesh_mgmt_tlv_reader_init(&reader, payload, payload_len);
  if (!read_exact_field(&reader, TICKET_FIELD_REQUEST_MESSAGE_ID, 16, &field))
    goto invalid_schema;
  memcpy(out_request_message_id, field.value, 16);
#define READ_BYTES(field_id, destination)                                                          \
  do {                                                                                             \
    if (!read_exact_field(&reader, (field_id), sizeof(destination), &field))                       \
      goto invalid_schema;                                                                         \
    memcpy((destination), field.value, sizeof(destination));                                       \
  } while (0)
  READ_BYTES(TICKET_FIELD_TICKET_ID, out_ticket->ticket_id);
  READ_BYTES(TICKET_FIELD_MESH_ID_HASH, out_ticket->claims.mesh_id_hash);
  READ_BYTES(TICKET_FIELD_INITIATOR_NODE_ID, out_ticket->claims.initiator_node_id);
  READ_BYTES(TICKET_FIELD_INITIATOR_PRINCIPAL_KEY, out_ticket->claims.initiator_principal_key);
  READ_BYTES(TICKET_FIELD_RESPONDER_NODE_ID, out_ticket->claims.responder_node_id);
  READ_BYTES(TICKET_FIELD_RESPONDER_PRINCIPAL_KEY, out_ticket->claims.responder_principal_key);
  READ_BYTES(TICKET_FIELD_STREAM_ID, out_ticket->claims.stream_id);
#undef READ_BYTES
#define READ_U64(field_id, destination)                                                            \
  do {                                                                                             \
    if (!read_exact_field(&reader, (field_id), sizeof(uint64_t), &field))                          \
      goto invalid_schema;                                                                         \
    (destination) = mesh_mgmt_wire_read_u64(field.value);                                          \
  } while (0)
  READ_U64(TICKET_FIELD_STREAM_EPOCH, out_ticket->claims.stream_epoch);
  READ_U64(TICKET_FIELD_ADMISSION_GENERATION, out_ticket->claims.admission_generation);
  READ_U64(TICKET_FIELD_ISSUED_AT_MS, out_ticket->issued_at_ms);
  READ_U64(TICKET_FIELD_EXPIRES_AT_MS, out_ticket->expires_at_ms);
#undef READ_U64
  if (mesh_mgmt_tlv_reader_next(&reader, &field) != 0 ||
      !bytes_are_nonzero(out_request_message_id, 16) ||
      !bytes_are_nonzero(out_ticket->ticket_id, sizeof(out_ticket->ticket_id)) ||
      !bytes_are_nonzero(out_ticket->claims.mesh_id_hash,
                         sizeof(out_ticket->claims.mesh_id_hash)) ||
      !bytes_are_nonzero(out_ticket->claims.initiator_node_id,
                         sizeof(out_ticket->claims.initiator_node_id)) ||
      !bytes_are_nonzero(out_ticket->claims.initiator_principal_key,
                         sizeof(out_ticket->claims.initiator_principal_key)) ||
      !bytes_are_nonzero(out_ticket->claims.responder_node_id,
                         sizeof(out_ticket->claims.responder_node_id)) ||
      !bytes_are_nonzero(out_ticket->claims.responder_principal_key,
                         sizeof(out_ticket->claims.responder_principal_key)) ||
      !bytes_are_nonzero(out_ticket->claims.stream_id, sizeof(out_ticket->claims.stream_id)) ||
      out_ticket->claims.stream_epoch == 0u || out_ticket->claims.admission_generation == 0u ||
      out_ticket->issued_at_ms >= out_ticket->expires_at_ms ||
      mesh_mgmt_crypto_equal_32(out_ticket->claims.initiator_node_id,
                                out_ticket->claims.responder_node_id) ||
      mesh_mgmt_crypto_equal_32(out_ticket->claims.initiator_principal_key,
                                out_ticket->claims.responder_principal_key)) {
    goto invalid_schema;
  }
  return MESH_STREAM_MGMT_TICKET_OK;

invalid_schema:
  memset(out_request_message_id, 0, 16);
  memset(out_ticket, 0, sizeof(*out_ticket));
  return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
}

mesh_stream_mgmt_ticket_result_t mesh_stream_mgmt_ticket_issue_from_event_v1(
    mesh_stream_bind_store_v1_t *store, const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    const uint8_t responder_node_id[MESH_STREAM_BIND_NODE_ID_SIZE],
    const uint8_t responder_principal_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE], uint64_t now_ms,
    uint8_t *output, size_t output_capacity, size_t *out_len,
    mesh_stream_bind_ticket_v1_t *out_ticket) {
  mesh_stream_mgmt_ticket_request_v1_t request;
  mesh_stream_bind_claims_v1_t claims;
  mesh_stream_bind_result_t bind_result;
  mesh_stream_mgmt_ticket_result_t result;

  if (out_ticket)
    memset(out_ticket, 0, sizeof(*out_ticket));
  if (!store || !dispatcher || !event || !responder_node_id || !responder_principal_key ||
      !out_len || !out_ticket)
    return MESH_STREAM_MGMT_TICKET_INVALID_ARG;
  *out_len = MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE;
  if (!output || output_capacity < MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE)
    return MESH_STREAM_MGMT_TICKET_RESOURCE_EXHAUSTED;
  if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED)
    return MESH_STREAM_MGMT_TICKET_INVALID_STATE;
  if ((dispatcher->session.negotiated.features & MESH_MGMT_FEATURE_STREAM_TICKET) == 0u)
    return MESH_STREAM_MGMT_TICKET_UNSUPPORTED_FEATURE;
  if (!event_matches_session(dispatcher, event, MESH_MGMT_KIND_STREAM_TICKET_REQUEST,
                             MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_REQUEST))
    return MESH_STREAM_MGMT_TICKET_AUTH_FAILED;
  if (event->envelope.header.issued_at_ms > now_ms ||
      now_ms >= event->envelope.header.expires_at_ms)
    return MESH_STREAM_MGMT_TICKET_EXPIRED;
  result = mesh_stream_mgmt_ticket_request_decode_v1(event->envelope.frame.payload,
                                                     event->envelope.frame.payload_len, &request);
  if (result != MESH_STREAM_MGMT_TICKET_OK)
    return result;
  memset(&claims, 0, sizeof(claims));
  memcpy(claims.mesh_id_hash, dispatcher->session.config.expected_mesh_id_hash, 32);
  memcpy(claims.initiator_node_id, dispatcher->session.remote_certificate.managed_node_id, 32);
  memcpy(claims.initiator_principal_key, dispatcher->session.remote_certificate.management_key, 32);
  memcpy(claims.responder_node_id, responder_node_id, 32);
  memcpy(claims.responder_principal_key, responder_principal_key, 32);
  memcpy(claims.stream_id, request.stream_id, sizeof(claims.stream_id));
  claims.stream_epoch = request.stream_epoch;
  claims.admission_generation = request.admission_generation;
  bind_result =
      mesh_stream_bind_ticket_issue_v1(store, &claims, now_ms, request.ttl_ms, out_ticket);
  if (bind_result != MESH_STREAM_BIND_OK)
    return map_bind_result(bind_result);
  result = mesh_stream_mgmt_ticket_issued_encode_v1(event->envelope.header.message_id, out_ticket,
                                                    output, output_capacity, out_len);
  if (result != MESH_STREAM_MGMT_TICKET_OK) {
    (void)mesh_stream_bind_ticket_invalidate_v1(store, out_ticket->ticket_id, now_ms);
    memset(out_ticket, 0, sizeof(*out_ticket));
  }
  return result;
}

mesh_stream_mgmt_ticket_result_t mesh_stream_mgmt_ticket_accept_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher, const mesh_mgmt_dispatch_event_v1_t *event,
    const uint8_t initiator_node_id[MESH_STREAM_BIND_NODE_ID_SIZE],
    const uint8_t initiator_principal_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const uint8_t request_message_id[16], const mesh_stream_mgmt_ticket_request_v1_t *request,
    uint64_t max_ttl_ms, uint64_t now_ms, mesh_stream_bind_ticket_v1_t *out_ticket) {
  uint8_t correlation_id[16];
  mesh_stream_bind_ticket_v1_t ticket;
  mesh_stream_mgmt_ticket_result_t result;

  if (out_ticket)
    memset(out_ticket, 0, sizeof(*out_ticket));
  if (!dispatcher || !event || !initiator_node_id || !initiator_principal_key ||
      !request_message_id || !request || !out_ticket || max_ttl_ms == 0u ||
      max_ttl_ms > MESH_STREAM_BIND_MAX_TTL_MS)
    return MESH_STREAM_MGMT_TICKET_INVALID_ARG;
  if (!request_is_valid(request))
    return MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA;
  if (dispatcher->session.state != MESH_MGMT_SESSION_ESTABLISHED)
    return MESH_STREAM_MGMT_TICKET_INVALID_STATE;
  if ((dispatcher->session.negotiated.features & MESH_MGMT_FEATURE_STREAM_TICKET) == 0u)
    return MESH_STREAM_MGMT_TICKET_UNSUPPORTED_FEATURE;
  if (!event_matches_session(dispatcher, event, MESH_MGMT_KIND_STREAM_TICKET_ISSUED,
                             MESH_MGMT_DISPATCH_EVENT_STREAM_TICKET_ISSUED))
    return MESH_STREAM_MGMT_TICKET_AUTH_FAILED;
  if (event->envelope.header.issued_at_ms > now_ms ||
      now_ms >= event->envelope.header.expires_at_ms)
    return MESH_STREAM_MGMT_TICKET_EXPIRED;
  result = mesh_stream_mgmt_ticket_issued_decode_v1(
      event->envelope.frame.payload, event->envelope.frame.payload_len, correlation_id, &ticket);
  if (result != MESH_STREAM_MGMT_TICKET_OK)
    return result;
  if (!mesh_mgmt_crypto_equal_16(correlation_id, request_message_id) ||
      !mesh_mgmt_crypto_equal_32(ticket.claims.mesh_id_hash,
                                 dispatcher->session.config.expected_mesh_id_hash) ||
      !mesh_mgmt_crypto_equal_32(ticket.claims.initiator_node_id, initiator_node_id) ||
      !mesh_mgmt_crypto_equal_32(ticket.claims.initiator_principal_key, initiator_principal_key) ||
      !mesh_mgmt_crypto_equal_32(ticket.claims.responder_node_id,
                                 dispatcher->session.remote_certificate.managed_node_id) ||
      !mesh_mgmt_crypto_equal_32(ticket.claims.responder_principal_key,
                                 dispatcher->session.remote_certificate.management_key) ||
      memcmp(ticket.claims.stream_id, request->stream_id, sizeof(request->stream_id)) != 0 ||
      ticket.claims.stream_epoch != request->stream_epoch ||
      ticket.claims.admission_generation != request->admission_generation) {
    return MESH_STREAM_MGMT_TICKET_AUTH_FAILED;
  }
  if (ticket.issued_at_ms > now_ms || now_ms >= ticket.expires_at_ms)
    return MESH_STREAM_MGMT_TICKET_EXPIRED;
  if (event->envelope.header.issued_at_ms < ticket.issued_at_ms ||
      event->envelope.header.issued_at_ms >= ticket.expires_at_ms)
    return MESH_STREAM_MGMT_TICKET_AUTH_FAILED;
  if (ticket.expires_at_ms - ticket.issued_at_ms > max_ttl_ms ||
      ticket.expires_at_ms - ticket.issued_at_ms > request->ttl_ms) {
    return MESH_STREAM_MGMT_TICKET_AUTH_FAILED;
  }
  *out_ticket = ticket;
  return MESH_STREAM_MGMT_TICKET_OK;
}
