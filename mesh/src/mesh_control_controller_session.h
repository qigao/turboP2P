#ifndef MESH_CONTROL_CONTROLLER_SESSION_H
#define MESH_CONTROL_CONTROLLER_SESSION_H

#include "mesh_control_agent_sync.h"
#include "mesh_control_durable_outbox_worker.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef mesh_control_result_t (*mesh_control_controller_identity_fn)(
    void *context,
    const uint8_t claimed_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t actual_tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE],
    mesh_control_agent_sync_hello_policy_v1_t *out_policy);

typedef struct {
  mesh_control_durable_outbox_config_v1_t outbox;
  size_t session_capacity;
  uint64_t claim_lease_ms;
  uint64_t maximum_clock_skew_ms;
  uint64_t maximum_hello_lifetime_ms;
  mesh_control_controller_identity_fn authorize_identity;
  void *identity_context;
} mesh_control_controller_session_config_v1_t;

typedef struct {
  uint64_t received;
  uint64_t responses;
  uint64_t activated;
  uint64_t commands;
  uint64_t durable_receipts;
  uint64_t outbox_submitted;
  uint64_t fenced;
  uint64_t rejected_auth;
  uint64_t rejected_protocol;
  uint64_t rejected_busy;
  size_t active_sessions;
  uint8_t accepting;
  uint8_t persistence_busy;
  uint8_t response_ready;
} mesh_control_controller_session_stats_v1_t;

typedef struct {
  uint64_t request_token;
  mesh_control_durable_outbox_result_t store_result;
  mesh_control_durable_outbox_view_v1_t view;
} mesh_control_controller_submit_completion_v1_t;

typedef struct mesh_control_controller_session_record_v1
    mesh_control_controller_session_record_v1_t;

/**
 * Single-owner Controller session domain. Iris callbacks copy complete frames
 * into receive_v1; disk mutations run only on the durable outbox worker.
 * Exactly one durable mutation and one response are retained at a time, so
 * FULL is explicit backpressure rather than unbounded buffering.
 */
typedef struct {
  mesh_control_durable_outbox_worker_v1_t worker;
  mesh_control_controller_session_record_v1_t *sessions;
  mesh_control_controller_session_config_v1_t config;
  mesh_control_agent_sync_message_v1_t pending;
  uint8_t pending_tls_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t pending_payload[MESH_CONTROL_AGENT_SYNC_MAX_PAYLOAD_V1];
  uint8_t response[MESH_CONTROL_MAX_FRAME_SIZE_V1];
  /** Owned poll scratch; kept off the bounded CoroNet coroutine stack. */
  uint8_t *worker_payload;
  size_t worker_payload_capacity;
  size_t response_size;
  uint64_t next_request_token;
  uint64_t pending_worker_token;
  uint64_t pending_identity_policy_generation;
  mesh_control_controller_submit_completion_v1_t submit_completion;
  size_t session_count;
  mesh_control_controller_session_stats_v1_t counters;
  uint8_t pending_operation;
  uint8_t initialized;
  uint8_t accepting;
  uint8_t response_ready;
  uint8_t response_abandoned;
  uint8_t submit_completion_ready;
  uint8_t submit_abandoned;
  uint8_t pending_source;
  uint8_t faulted;
} mesh_control_controller_session_v1_t;

mesh_control_result_t mesh_control_controller_session_init_v1(
    mesh_control_controller_session_v1_t *controller,
    const mesh_control_controller_session_config_v1_t *config,
    size_t *out_recovered_claims);

/** actual TLS digest must come from the verified transport, never a header. */
mesh_control_result_t mesh_control_controller_session_receive_v1(
    mesh_control_controller_session_v1_t *controller,
    const uint8_t actual_tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE],
    const uint8_t *frame, size_t frame_size, uint64_t now_ms);

/**
 * Validates and asynchronously persists one signed MMP command. The returned
 * token identifies the later durable completion. Exactly one session or
 * submit mutation may be in flight; RESOURCE_EXHAUSTED is backpressure.
 */
mesh_control_result_t mesh_control_controller_session_try_submit_v1(
    mesh_control_controller_session_v1_t *controller,
    const mesh_control_durable_outbox_message_v1_t *message,
    uint64_t *out_request_token);

/** Takes the current submit completion; EMPTY means persistence is pending. */
mesh_control_result_t mesh_control_controller_session_try_take_submit_v1(
    mesh_control_controller_session_v1_t *controller,
    mesh_control_controller_submit_completion_v1_t *out_completion);

/** Persistence continues; poll discards the completion for this timed-out caller. */
mesh_control_result_t mesh_control_controller_session_abandon_submit_v1(
    mesh_control_controller_session_v1_t *controller,
    uint64_t request_token);

/** Advances at most one persistence completion and materializes one response. */
mesh_control_result_t mesh_control_controller_session_poll_v1(
    mesh_control_controller_session_v1_t *controller, size_t *out_progress);

/** Copies and consumes the current response; EMPTY means no response is ready. */
mesh_control_result_t mesh_control_controller_session_try_take_response_v1(
    mesh_control_controller_session_v1_t *controller, uint8_t *output,
    size_t output_capacity, size_t *out_size);

/**
 * Marks the current agent response as no longer observable by its HTTP
 * request. The durable mutation is still completed; poll then discards only
 * the response bytes so the owner cannot remain wedged after a timeout.
 */
mesh_control_result_t mesh_control_controller_session_abandon_response_v1(
    mesh_control_controller_session_v1_t *controller);

mesh_control_result_t mesh_control_controller_session_get_stats_v1(
    mesh_control_controller_session_v1_t *controller,
    mesh_control_controller_session_stats_v1_t *out_stats);

mesh_control_result_t mesh_control_controller_session_shutdown_v1(
    mesh_control_controller_session_v1_t *controller);

void mesh_control_controller_session_destroy_v1(
    mesh_control_controller_session_v1_t *controller);

#ifdef __cplusplus
}
#endif

#endif
