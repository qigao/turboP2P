#ifndef MESH_CONTROL_AGENT_HTTP_CLIENT_H
#define MESH_CONTROL_AGENT_HTTP_CLIENT_H

#include "mesh_control_agent_sync.h"

#include <CoroNet.h>
#include <turbo_http.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const char *sync_url;
  const turbo_tls_client_config_t *tls;
  uint64_t timeout_ms;
} mesh_control_agent_http_client_config_v1_t;

typedef struct {
  turbo_http_t *http;
  coro_context_t *context;
  char sync_url[2048];
  uint64_t timeout_ms;
  uint64_t exchanged;
  uint64_t transport_failures;
  uint64_t protocol_failures;
  uint8_t initialized;
  uint8_t closed;
} mesh_control_agent_http_client_v1_t;

/** Creates an mTLS HTTP/2-only client on the caller-owned CoroNet context. */
mesh_control_result_t mesh_control_agent_http_client_init_v1(
    mesh_control_agent_http_client_v1_t *client, coro_context_t *context,
    const mesh_control_agent_http_client_config_v1_t *config);

/**
 * One serialized POST exchange. POST is never automatically retried because
 * UNKNOWN_COMMIT must be resolved by the typed request token/session state.
 */
mesh_control_result_t mesh_control_agent_http_client_exchange_v1(
    mesh_control_agent_http_client_v1_t *client, const uint8_t *request,
    size_t request_size, uint8_t *response, size_t response_capacity,
    size_t *out_response_size);

mesh_control_result_t mesh_control_agent_http_client_close_v1(
    mesh_control_agent_http_client_v1_t *client);

/**
 * Atomically replaces the H2 client after validating and deep-copying new
 * credentials. Existing pooled TLS sessions are destroyed only after the
 * replacement is ready, so a failed reload leaves the old client active.
 */
mesh_control_result_t mesh_control_agent_http_client_reload_tls_v1(
    mesh_control_agent_http_client_v1_t *client,
    const turbo_tls_client_config_t *tls);

void mesh_control_agent_http_client_destroy_v1(
    mesh_control_agent_http_client_v1_t *client);

#ifdef __cplusplus
}
#endif

#endif
