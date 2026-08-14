#ifndef MESH_CONTROL_AGENT_H
#define MESH_CONTROL_AGENT_H

#include "mesh_control_iris.h"
#include "mesh_control_network_provider.h"
#include "mesh_control_owner.h"
#include "mesh_control_policy.h"
#include "mesh_control_reconciler.h"
#include "mesh_network_reconciler.h"
#include "mesh_control_status.h"
#include "mesh_control_wal_worker.h"

#include <CoroNet.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_AGENT_HOST_MAX_V1 255u
#define MESH_CONTROL_AGENT_STATUS_PATH_V1 "/v1/control/status"
#define MESH_CONTROL_AGENT_EVENTS_PATH_V1 "/v1/control/events"
#define MESH_CONTROL_AGENT_RECEIPTS_PATH_V1 "/v1/control/receipts"

typedef uint64_t (*mesh_control_agent_now_ms_fn)(void *context);

typedef struct {
  const char *host;
  uint16_t port;
  const turbo_tls_server_config_t *tls;
  const char *controller_tls_certificate_sha256;
  uint8_t controller_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint64_t controller_certificate_serial;
  uint64_t controller_permissions;
  mesh_control_node_policy_v1_t node_policy;
  mesh_control_reconciler_config_v1_t function_reconciler;
  /**
   * Optional Network executor. Both fields are zero to disable it. fabric is
   * caller-owned, must initially have no attached Networks, and must outlive
   * the agent. The agent owns every Network it attaches and detaches them
   * during stop.
   */
  mesh_fabric_t *network_fabric;
  /**
   * Optional cross-process Network provider. It is mutually exclusive with
   * network_fabric. The descriptor is copied; its context remains caller-owned.
   */
  const mesh_control_network_provider_v1_t *network_provider;
  size_t network_capacity;
  mesh_control_owner_config_v1_t owner;
  /** Optional production durability. Zero retains the legacy in-memory path. */
  uint8_t durability_enabled;
  mesh_control_wal_config_v1_t wal;
  /** Optional checkpoint+compact gate; both values must be set together. */
  const char *checkpoint_path;
  size_t checkpoint_interval_records;
  size_t channel_capacity;
  size_t channel_retained_bytes;
  size_t channel_max_payload;
  size_t max_commands_per_poll;
  size_t max_provider_completions_per_poll;
  size_t max_provider_starts_per_poll;
  size_t status_page_resource_limit;
  size_t status_page_operation_limit;
  size_t status_event_limit;
  uint64_t shutdown_drain_timeout_ms;
  mesh_control_agent_now_ms_fn now_ms;
  void *now_context;
} mesh_control_agent_config_v1_t;

typedef struct {
  coro_context_t *context;
  coro_socket_t *listener;
  iris_app_t *app;
  mesh_control_channel_v1_t inbound;
  mesh_control_iris_v1_t iris;
  mesh_control_owner_v1_t owner;
  mesh_control_reconciler_v1_t function_reconciler;
  mesh_network_reconciler_v1_t network_reconciler;
  mesh_control_network_provider_v1_t network_provider;
  mesh_control_wal_worker_v1_t wal_worker;
  mesh_control_agent_config_v1_t config;
  char host[MESH_CONTROL_AGENT_HOST_MAX_V1 + 1u];
  char controller_tls_certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  uint8_t running;
  uint8_t function_reconciler_initialized;
  uint8_t network_reconciler_initialized;
  uint8_t network_provider_initialized;
  uint8_t wal_worker_initialized;
  uint8_t persistence_fault;
  uint8_t network_result_persisting;
  uint8_t network_provider_active;
  uint8_t network_provider_ack_pending;
  uint8_t network_provider_restore_active;
  uint8_t network_provider_restore_pending;
  uint8_t network_recovery_pending;
  uint8_t provider_result_persisting;
  uint8_t provider_result_ack_pending;
  uint8_t checkpoint_persisting;
  uint64_t provider_result_log_index;
  mesh_control_wal_operation_result_v1_t network_pending_result;
  mesh_control_operation_v1_t network_active_operation;
  size_t network_restore_scan_index;
  mesh_control_resource_status_v1_t *network_resource_scan;
  mesh_control_operation_v1_t *network_operation_scan;
  uint64_t last_checkpoint_index;
  uint64_t checkpoint_generation_pending;
  uint64_t last_checkpoint_generation;
} mesh_control_agent_v1_t;

/**
 * Starts an mTLS-only Iris H1/H2 WebSocket endpoint and the single-owner
 * control domain. Prestaged function providers are injected explicitly;
 * provider descriptors are copied but their contexts remain caller-owned.
 * Native/WASM providers must be explicitly prestaged and independently
 * enabled by local runtime policy. The listener never falls back to
 * plaintext. agent must be
 * zero-initialized. config is copied, but TLS files, ALPN strings, callbacks
 * and callback context remain caller-owned and must outlive stop. Returns
 * INVALID_ARG for an invalid/active instance or unsafe configuration, and
 * INVALID_STATE when allocation, registration or listener startup fails.
 */
mesh_control_result_t mesh_control_agent_start_v1(mesh_control_agent_v1_t *agent,
                                                  const mesh_control_agent_config_v1_t *config);

/**
 * Pumps CoroNet once, applies at most max_commands_per_poll messages, then
 * advances bounded provider completions and starts on the same owner thread.
 */
mesh_control_result_t mesh_control_agent_poll_v1(mesh_control_agent_v1_t *agent,
                                                 size_t *out_processed);

/**
 * Stops ingress, rejects queued unstarted commands, closes the listener and
 * drains managed CoroNet tasks. Returns INVALID_STATE if tasks do not quiesce
 * within the fixed drain budget; call again after subsequent poll/drain work.
 */
mesh_control_result_t mesh_control_agent_stop_v1(mesh_control_agent_v1_t *agent);

const mesh_control_state_v1_t *mesh_control_agent_state_v1(const mesh_control_agent_v1_t *agent);

/**
 * Encodes one bounded status page from the single-owner state. Call only from
 * the same thread that calls poll. expected_generation=0 starts a snapshot;
 * later pages must use the returned generation encoded in the response.
 */
mesh_control_result_t mesh_control_agent_status_page_v1(mesh_control_agent_v1_t *agent,
                                                        uint64_t expected_generation,
                                                        size_t resource_offset,
                                                        size_t operation_offset, uint8_t *output,
                                                        size_t output_capacity, size_t *out_size);

/** Encodes retained operation events strictly after cursor. */
mesh_control_result_t mesh_control_agent_event_page_v1(mesh_control_agent_v1_t *agent,
                                                       uint64_t cursor, uint8_t *output,
                                                       size_t output_capacity, size_t *out_size);

/** Returns a queryable durable receipt for one committed message/operation ID. */
mesh_control_result_t
mesh_control_agent_receipt_v1(mesh_control_agent_v1_t *agent,
                              const uint8_t operation_id[MESH_CONTROL_ID_SIZE],
                              uint8_t output[MESH_CONTROL_RECEIPT_SIZE_V1], size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif
