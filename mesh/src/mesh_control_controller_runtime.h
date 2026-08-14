#ifndef MESH_CONTROL_CONTROLLER_RUNTIME_H
#define MESH_CONTROL_CONTROLLER_RUNTIME_H

#include "mesh_control_controller_identity.h"
#include "mesh_control_controller_iris.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_CONTROLLER_HOST_MAX_V1 255u

typedef struct {
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t management_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  mesh_certificate_lifecycle_config_v1_t certificate;
  uint64_t identity_policy_generation;
} mesh_control_controller_runtime_identity_config_v1_t;

typedef struct {
  /** Exact mTLS leaf permitted to submit already-signed MMP commands. */
  const char *submitter_tls_certificate_sha256;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t controller_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t controller_management_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE];
  uint64_t principal_epoch;
  uint64_t incarnation;
  uint64_t certificate_serial;
  uint64_t maximum_clock_skew_ms;
  uint64_t maximum_command_lifetime_ms;
} mesh_control_controller_submit_policy_v1_t;

typedef struct {
  const char *host;
  uint16_t port;
  mesh_certificate_lifecycle_config_v1_t server_certificate;
  /** CA used by the mTLS listener to verify agent client leaves. */
  const char *agent_client_ca_file;
  const char *server_key_password;
  const mesh_control_controller_runtime_identity_config_v1_t *identities;
  size_t identity_count;
  size_t identity_capacity;
  mesh_control_controller_identity_now_fn now_ms;
  void *now_context;
  mesh_control_controller_session_config_v1_t session;
  /** A NULL submitter digest disables the northbound durable-submit route. */
  mesh_control_controller_submit_policy_v1_t submit_policy;
  uint64_t persistence_timeout_ms;
  uint64_t shutdown_drain_timeout_ms;
} mesh_control_controller_runtime_config_v1_t;

/**
 * Single-owner Controller composition root. It owns the CoroNet/Iris server,
 * durable outbox worker, online-session fencing state, identity registry and
 * immutable certificate snapshots. Configuration strings are borrowed until
 * stop; identity records and lifecycle snapshots are copied during init.
 */
typedef struct {
  coro_context_t *context;
  coro_socket_t *listener;
  iris_app_t *app;
  mesh_certificate_lifecycle_v1_t server_certificate;
  mesh_certificate_lifecycle_v1_t *client_certificates;
  mesh_control_controller_identity_registry_v1_t identities;
  mesh_control_controller_session_v1_t session;
  mesh_control_controller_submit_policy_v1_t submit_policy;
  mesh_control_controller_iris_v1_t iris;
  turbo_tls_server_config_t server_tls;
  char host[MESH_CONTROL_CONTROLLER_HOST_MAX_V1 + 1u];
  size_t identity_count;
  uint64_t shutdown_drain_timeout_ms;
  uint8_t session_started;
  uint8_t iris_started;
  uint8_t initialized;
  uint8_t stopped;
} mesh_control_controller_runtime_v1_t;

mesh_control_result_t mesh_control_controller_runtime_init_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    const mesh_control_controller_runtime_config_v1_t *config,
    size_t *out_recovered_claims);

/** Pumps the Controller event loop once. All calls are from the owner thread. */
mesh_control_result_t mesh_control_controller_runtime_poll_v1(
    mesh_control_controller_runtime_v1_t *runtime, size_t *out_progress);

/** Asynchronously persists one already-authenticated signed MMP envelope. */
mesh_control_result_t mesh_control_controller_runtime_try_submit_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    const mesh_control_durable_outbox_message_v1_t *message,
    uint64_t *out_request_token);

mesh_control_result_t mesh_control_controller_runtime_try_take_submit_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    mesh_control_controller_submit_completion_v1_t *out_completion);

/**
 * Atomically replaces one agent's current/next client-leaf policy. A higher
 * policy generation immediately fences sessions established under the old
 * HELLO policy; no transport-provided identity field is trusted.
 */
mesh_control_result_t mesh_control_controller_runtime_rotate_identity_v1(
    mesh_control_controller_runtime_v1_t *runtime,
    const mesh_control_controller_runtime_identity_config_v1_t *config);

/** Stops admission, drains callbacks/persistence and closes the listener. */
mesh_control_result_t mesh_control_controller_runtime_stop_v1(
    mesh_control_controller_runtime_v1_t *runtime);

/** Requires a stopped runtime; an active runtime is intentionally retained. */
void mesh_control_controller_runtime_destroy_v1(
    mesh_control_controller_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
