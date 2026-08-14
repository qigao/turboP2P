#include "mesh_control_iris.h"

#include <string.h>

#define MESH_CONTROL_WS_CLOSE_POLICY_VIOLATION 1008u
#define MESH_CONTROL_WS_CLOSE_UNSUPPORTED_DATA 1003u
#define MESH_CONTROL_WS_CLOSE_TOO_LARGE 1009u
#define MESH_CONTROL_WS_CLOSE_SERVER_ERROR 1011u
#define MESH_CONTROL_WS_CLOSE_TRY_AGAIN 1013u

static mesh_control_iris_v1_t *mesh_control_iris_from_request(Req *req) {
  if (req == NULL || req->app == NULL) {
    return NULL;
  }
  return (mesh_control_iris_v1_t *)iris_app_lookup_rpc_context(req->app, MESH_CONTROL_IRIS_PATH_V1);
}

static void mesh_control_iris_on_message(iris_websocket_t *websocket,
                                         iris_websocket_opcode_t opcode, const void *data,
                                         size_t len, void *user_data) {
  mesh_control_iris_v1_t *adapter = (mesh_control_iris_v1_t *)user_data;
  mesh_control_result_t result;

  if (adapter == NULL || adapter->initialized == 0u) {
    (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_SERVER_ERROR,
                        "control adapter unavailable");
    return;
  }
  if (opcode != IRIS_WS_BINARY) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u, memory_order_relaxed);
    (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_UNSUPPORTED_DATA,
                        "binary MMP frames required");
    return;
  }
  if (len > MESH_MGMT_FRAME_MAX) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u, memory_order_relaxed);
    (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_TOO_LARGE, "control frame too large");
    return;
  }
  result = mesh_control_iris_receive_frame_v1(adapter, (const uint8_t *)data, len);
  if (result == MESH_CONTROL_OK) {
    return;
  }
  if (result == MESH_CONTROL_RESOURCE_EXHAUSTED) {
    (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_TRY_AGAIN, "control queue full");
  } else {
    (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_POLICY_VIOLATION,
                        "control frame rejected");
  }
}

static void mesh_control_iris_handler(Req *req, Res *res) {
  mesh_control_iris_v1_t *adapter = mesh_control_iris_from_request(req);
  iris_websocket_t *websocket = iris_ws(req);
  char peer_certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY];

  (void)res;
  memset(peer_certificate_sha256, 0, sizeof(peer_certificate_sha256));
  if (adapter == NULL || adapter->initialized == 0u || websocket == NULL ||
      !atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    if (websocket != NULL) {
      (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_SERVER_ERROR,
                          "control adapter unavailable");
    }
    return;
  }
  if (req_get_verified_tls_peer_certificate_sha256(req, peer_certificate_sha256) != 0 ||
      adapter->config.authorize_transport(adapter->config.auth_context, peer_certificate_sha256) !=
          MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_transport, 1u, memory_order_relaxed);
    (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_POLICY_VIOLATION,
                        "verified client certificate required");
    return;
  }
  if (iris_ws_on_message(websocket, mesh_control_iris_on_message, adapter) != 0) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u, memory_order_relaxed);
    (void)iris_ws_close(websocket, MESH_CONTROL_WS_CLOSE_SERVER_ERROR,
                        "control callback unavailable");
  }
}

mesh_control_result_t mesh_control_iris_register_v1(mesh_control_iris_v1_t *adapter,
                                                    iris_app_t *app,
                                                    const mesh_control_iris_config_v1_t *config) {
  mesh_control_channel_stats_v1_t channel_stats;

  if (adapter == NULL || app == NULL || config == NULL || config->inbound == NULL ||
      config->authorize_transport == NULL || config->admit == NULL ||
      mesh_control_channel_get_stats_v1(config->inbound, &channel_stats) != MESH_CONTROL_OK) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(adapter, 0, sizeof(*adapter));
  adapter->app = app;
  adapter->config = *config;
  atomic_init(&adapter->accepting, true);
  atomic_init(&adapter->received, 0u);
  atomic_init(&adapter->queued, 0u);
  atomic_init(&adapter->rejected_transport, 0u);
  atomic_init(&adapter->rejected_protocol, 0u);
  atomic_init(&adapter->rejected_admission, 0u);
  atomic_init(&adapter->rejected_backpressure, 0u);
  adapter->initialized = 1u;
  if (iris_app_bind_rpc_context(app, MESH_CONTROL_IRIS_PATH_V1, adapter) != 0) {
    memset(adapter, 0, sizeof(*adapter));
    return MESH_CONTROL_CONFLICT;
  }
  iris_app_ws(app, MESH_CONTROL_IRIS_PATH_V1, mesh_control_iris_handler);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_iris_receive_frame_v1(mesh_control_iris_v1_t *adapter,
                                                         const uint8_t *frame, size_t frame_size) {
  mesh_mgmt_verified_envelope_v1_t verified;
  mesh_control_envelope_v1_t envelope;
  const uint8_t *body = NULL;
  size_t body_size = 0u;
  mesh_control_result_t result;

  if (adapter == NULL || adapter->initialized == 0u || frame == NULL || frame_size == 0u ||
      frame_size > MESH_MGMT_FRAME_MAX) {
    return MESH_CONTROL_INVALID_ARG;
  }
  if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    return MESH_CONTROL_CLOSED;
  }
  atomic_fetch_add_explicit(&adapter->received, 1u, memory_order_relaxed);
  if (mesh_mgmt_envelope_verify_v1(frame, frame_size, &verified) != MESH_MGMT_ENVELOPE_OK ||
      mesh_control_mmp_payload_decode_v1(&verified, &envelope, &body, &body_size) !=
          MESH_CONTROL_MMP_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u, memory_order_relaxed);
    return MESH_CONTROL_INVALID_ARG;
  }
  result =
      adapter->config.admit(adapter->config.auth_context, &verified, &envelope, body, body_size);
  if (result != MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_admission, 1u, memory_order_relaxed);
    return result;
  }
  result = mesh_control_channel_try_push_signed_v1(adapter->config.inbound, &envelope, body,
                                                   body_size, frame, frame_size);
  if (result != MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_backpressure, 1u, memory_order_relaxed);
    return result;
  }
  atomic_fetch_add_explicit(&adapter->queued, 1u, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_iris_close_v1(mesh_control_iris_v1_t *adapter) {
  if (adapter == NULL || adapter->initialized == 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }
  atomic_store_explicit(&adapter->accepting, false, memory_order_release);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_iris_get_stats_v1(const mesh_control_iris_v1_t *adapter,
                                                     mesh_control_iris_stats_v1_t *out_stats) {
  if (adapter == NULL || out_stats == NULL || adapter->initialized == 0u) {
    return MESH_CONTROL_INVALID_ARG;
  }
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->accepting = atomic_load_explicit(&adapter->accepting, memory_order_acquire);
  out_stats->received = atomic_load_explicit(&adapter->received, memory_order_relaxed);
  out_stats->queued = atomic_load_explicit(&adapter->queued, memory_order_relaxed);
  out_stats->rejected_transport =
      atomic_load_explicit(&adapter->rejected_transport, memory_order_relaxed);
  out_stats->rejected_protocol =
      atomic_load_explicit(&adapter->rejected_protocol, memory_order_relaxed);
  out_stats->rejected_admission =
      atomic_load_explicit(&adapter->rejected_admission, memory_order_relaxed);
  out_stats->rejected_backpressure =
      atomic_load_explicit(&adapter->rejected_backpressure, memory_order_relaxed);
  return MESH_CONTROL_OK;
}

void mesh_control_iris_destroy_v1(mesh_control_iris_v1_t *adapter) {
  if (adapter == NULL) {
    return;
  }
  if (adapter->initialized != 0u) {
    (void)mesh_control_iris_close_v1(adapter);
    if (adapter->app != NULL) {
      (void)iris_app_unbind_rpc_context(adapter->app, MESH_CONTROL_IRIS_PATH_V1, adapter);
    }
  }
  memset(adapter, 0, sizeof(*adapter));
}
