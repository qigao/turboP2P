#ifndef MESH_CONTROL_AGENT_RUNTIME_H
#define MESH_CONTROL_AGENT_RUNTIME_H

#include "mesh_certificate_lifecycle.h"
#include "mesh_control_agent_service.h"
#include "mesh_mgmt_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  mesh_control_agent_config_v1_t local_agent;
  mesh_certificate_lifecycle_config_v1_t server_certificate;
  /** Trust anchor used by the local mTLS status/compatibility listener. */
  const char *controller_client_ca_file;
  const char *server_key_password;
  mesh_certificate_lifecycle_config_v1_t client_certificate;
  /** Its ca_file verifies the Controller server and is not replaced on rotation. */
  turbo_tls_client_config_t controller_tls;
  const char *controller_sync_url;
  uint64_t controller_timeout_ms;
  mesh_control_agent_service_config_v1_t identity;
} mesh_control_agent_runtime_config_v1_t;

typedef struct {
  mesh_control_agent_v1_t agent;
  mesh_control_agent_http_client_v1_t http_client;
  mesh_control_agent_service_v1_t service;
  mesh_certificate_lifecycle_v1_t server_certificate;
  mesh_certificate_lifecycle_v1_t client_certificate;
  turbo_tls_server_config_t server_tls;
  turbo_tls_client_config_t client_tls;
  turbo_tls_client_config_t controller_tls_template;
  uint8_t management_private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE];
  uint8_t agent_started;
  uint8_t http_started;
  uint8_t service_started;
  uint8_t service_task_running;
  uint8_t service_task_accepting;
  mesh_control_result_t service_task_result;
  size_t service_task_progress;
  uint8_t initialized;
  uint8_t stopped;
} mesh_control_agent_runtime_v1_t;

/**
 * Production composition root for the local durable agent and outbound H2
 * Controller session. The runtime copies the management seed and wipes it on
 * destroy. All APIs are single-owner.
 */
mesh_control_result_t mesh_control_agent_runtime_init_v1(
    mesh_control_agent_runtime_v1_t *runtime,
    const mesh_control_agent_runtime_config_v1_t *config);

mesh_control_result_t mesh_control_agent_runtime_poll_v1(
    mesh_control_agent_runtime_v1_t *runtime, size_t *out_progress);

/** Atomically activates a newer validated outbound client leaf. */
mesh_control_result_t mesh_control_agent_runtime_rotate_client_v1(
    mesh_control_agent_runtime_v1_t *runtime,
    const mesh_certificate_lifecycle_config_v1_t *config);

/** Stops Controller admission, destroys the H2 pool, then drains local state. */
mesh_control_result_t mesh_control_agent_runtime_stop_v1(
    mesh_control_agent_runtime_v1_t *runtime);

/** Requires a stopped runtime; an active runtime is intentionally retained. */
void mesh_control_agent_runtime_destroy_v1(
    mesh_control_agent_runtime_v1_t *runtime);

#ifdef __cplusplus
}
#endif

#endif
