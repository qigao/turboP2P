#ifndef TURBO_P2P_MESH_STREAM_MGMT_TICKET_H
#define TURBO_P2P_MESH_STREAM_MGMT_TICKET_H

#include "mesh_mgmt_dispatch.h"
#include "mesh_stream_bind.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_MGMT_TICKET_REQUEST_V1_SIZE 56u
#define MESH_STREAM_MGMT_TICKET_ISSUED_V1_SIZE 304u

typedef enum {
  MESH_STREAM_MGMT_TICKET_OK = 0,
  MESH_STREAM_MGMT_TICKET_INVALID_ARG = -1,
  MESH_STREAM_MGMT_TICKET_INVALID_SCHEMA = -2,
  MESH_STREAM_MGMT_TICKET_AUTH_FAILED = -3,
  MESH_STREAM_MGMT_TICKET_EXPIRED = -4,
  MESH_STREAM_MGMT_TICKET_UNSUPPORTED_FEATURE = -5,
  MESH_STREAM_MGMT_TICKET_RESOURCE_EXHAUSTED = -6,
  MESH_STREAM_MGMT_TICKET_RANDOM_FAILURE = -7,
  MESH_STREAM_MGMT_TICKET_INVALID_STATE = -8,
} mesh_stream_mgmt_ticket_result_t;

typedef struct {
  uint8_t stream_id[MESH_STREAM_ID_SIZE];
  uint64_t stream_epoch;
  uint64_t admission_generation;
  uint64_t ttl_ms;
} mesh_stream_mgmt_ticket_request_v1_t;

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_request_encode_v1(const mesh_stream_mgmt_ticket_request_v1_t *request,
                                          uint8_t *output, size_t output_capacity, size_t *out_len);

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_request_decode_v1(const uint8_t *payload, size_t payload_len,
                                          mesh_stream_mgmt_ticket_request_v1_t *out_request);

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_issued_encode_v1(const uint8_t request_message_id[16],
                                         const mesh_stream_bind_ticket_v1_t *ticket,
                                         uint8_t *output, size_t output_capacity, size_t *out_len);

mesh_stream_mgmt_ticket_result_t
mesh_stream_mgmt_ticket_issued_decode_v1(const uint8_t *payload, size_t payload_len,
                                         uint8_t out_request_message_id[16],
                                         mesh_stream_bind_ticket_v1_t *out_ticket);

/**
 * Validate one authenticated request event, issue into the responder-owned
 * store, and encode the response payload. The caller still owns MMP signing
 * and sending; a later send failure must invalidate out_ticket->ticket_id.
 */
mesh_stream_mgmt_ticket_result_t mesh_stream_mgmt_ticket_issue_from_event_v1(
    mesh_stream_bind_store_v1_t *store, const mesh_mgmt_dispatcher_v1_t *dispatcher,
    const mesh_mgmt_dispatch_event_v1_t *event,
    const uint8_t responder_node_id[MESH_STREAM_BIND_NODE_ID_SIZE],
    const uint8_t responder_principal_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE], uint64_t now_ms,
    uint8_t *output, size_t output_capacity, size_t *out_len,
    mesh_stream_bind_ticket_v1_t *out_ticket);

/** Validate a delivered ticket against the initiating request and MMP peer. */
mesh_stream_mgmt_ticket_result_t mesh_stream_mgmt_ticket_accept_from_event_v1(
    const mesh_mgmt_dispatcher_v1_t *dispatcher, const mesh_mgmt_dispatch_event_v1_t *event,
    const uint8_t initiator_node_id[MESH_STREAM_BIND_NODE_ID_SIZE],
    const uint8_t initiator_principal_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const uint8_t request_message_id[16], const mesh_stream_mgmt_ticket_request_v1_t *request,
    uint64_t max_ttl_ms, uint64_t now_ms, mesh_stream_bind_ticket_v1_t *out_ticket);

#ifdef __cplusplus
}
#endif

#endif
