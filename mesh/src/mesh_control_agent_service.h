#ifndef MESH_CONTROL_AGENT_SERVICE_H
#define MESH_CONTROL_AGENT_SERVICE_H

#include "mesh_control_agent.h"
#include "mesh_control_agent_http_client.h"
#include "mesh_certificate_lifecycle.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef mesh_control_result_t (*mesh_control_agent_service_exchange_fn)(
    void *context, const uint8_t *request, size_t request_size,
    uint8_t *response, size_t response_capacity, size_t *out_response_size);
typedef int (*mesh_control_agent_service_random_fn)(
    void *context, uint8_t *output, size_t output_size);
typedef mesh_control_result_t (*mesh_control_agent_service_poll_local_fn)(
    void *context, size_t *out_progress);
typedef mesh_control_result_t (*mesh_control_agent_service_ingest_fn)(
    void *context, const uint8_t *signed_mmp, size_t signed_mmp_size);
typedef mesh_control_result_t (*mesh_control_agent_service_receipt_fn)(
    void *context, const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
    uint8_t output[MESH_CONTROL_RECEIPT_SIZE_V1], size_t *out_size);

typedef struct {
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t management_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  /** Caller-owned secure key storage; the service never logs or frees it. */
  const uint8_t *management_private_key;
  uint8_t tls_certificate_sha256[MESH_CONTROL_DIGEST_SIZE];
  uint64_t certificate_serial;
  uint64_t certificate_policy_generation;
  /** Short-lived signed HELLO proof window, not the X.509 leaf lifetime. */
  uint64_t hello_lifetime_ms;
  uint64_t claim_interval_ms;
  mesh_control_agent_now_ms_fn now_ms;
  void *now_context;
  mesh_control_agent_service_random_fn random_bytes;
  void *random_context;
  mesh_control_agent_service_exchange_fn exchange;
  void *exchange_context;
  mesh_control_agent_service_poll_local_fn poll_local;
  mesh_control_agent_service_ingest_fn ingest;
  mesh_control_agent_service_receipt_fn receipt;
  void *local_context;
} mesh_control_agent_service_config_v1_t;

typedef enum {
  MESH_CONTROL_AGENT_SERVICE_DISCONNECTED = 1,
  MESH_CONTROL_AGENT_SERVICE_READY = 2,
  MESH_CONTROL_AGENT_SERVICE_WAITING_DURABLE_RECEIPT = 3,
  MESH_CONTROL_AGENT_SERVICE_CLOSED = 4
} mesh_control_agent_service_state_v1_t;

typedef struct {
  uint64_t hellos;
  uint64_t claims;
  uint64_t commands;
  uint64_t receipts;
  uint64_t reconnects;
  uint64_t certificate_rotations;
  uint64_t transport_failures;
  uint64_t protocol_failures;
  uint64_t local_failures;
  uint64_t session_generation;
  uint64_t lease_generation;
  mesh_control_agent_service_state_v1_t state;
} mesh_control_agent_service_stats_v1_t;

/**
 * Single-owner outbound agent state machine. One poll performs at most one
 * Controller exchange and one bounded local poll. A COMMAND is acknowledged
 * only after receipt() returns the canonical durable WAL receipt.
 */
typedef struct {
  mesh_control_agent_service_config_v1_t config;
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  uint8_t claimed_message_id[MESH_CONTROL_ID_SIZE];
  uint64_t session_generation;
  uint64_t lease_generation;
  uint64_t request_token;
  uint64_t next_claim_at_ms;
  uint64_t certificate_policy_generation;
  mesh_control_agent_service_stats_v1_t counters;
  /** Owned bounded request+response scratch; never retained across a poll. */
  uint8_t *exchange_storage;
  mesh_control_agent_service_state_v1_t state;
  uint8_t initialized;
  uint8_t accepting;
} mesh_control_agent_service_v1_t;

mesh_control_result_t mesh_control_agent_service_init_v1(
    mesh_control_agent_service_v1_t *service,
    const mesh_control_agent_service_config_v1_t *config);

/** Convenience wiring for a real agent domain and HTTP/2 client. */
mesh_control_result_t mesh_control_agent_service_init_http_v1(
    mesh_control_agent_service_v1_t *service,
    mesh_control_agent_v1_t *agent,
    mesh_control_agent_http_client_v1_t *http_client,
    const mesh_control_agent_service_config_v1_t *identity_config);

mesh_control_result_t mesh_control_agent_service_poll_v1(
    mesh_control_agent_service_v1_t *service, size_t *out_progress);

mesh_control_result_t mesh_control_agent_service_close_v1(
    mesh_control_agent_service_v1_t *service);

/**
 * Recreates the H2 pool with a validated lifecycle snapshot, then commits the
 * new HELLO identity and reconnects. Lifecycle generations may not roll back.
 */
mesh_control_result_t mesh_control_agent_service_rotate_certificate_v1(
    mesh_control_agent_service_v1_t *service,
    mesh_control_agent_http_client_v1_t *http_client,
    const mesh_certificate_lifecycle_v1_t *lifecycle,
    const turbo_tls_client_config_t *tls_template);

mesh_control_result_t mesh_control_agent_service_get_stats_v1(
    const mesh_control_agent_service_v1_t *service,
    mesh_control_agent_service_stats_v1_t *out_stats);

void mesh_control_agent_service_destroy_v1(
    mesh_control_agent_service_v1_t *service);

#ifdef __cplusplus
}
#endif

#endif
