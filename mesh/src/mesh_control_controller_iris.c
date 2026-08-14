#include "mesh_control_controller_iris.h"

#include "platform.h"

#include <CoroNet.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_certificate_digest(
    const char *value, uint8_t output[MESH_CONTROL_DIGEST_SIZE]) {
  static const char prefix[] = "sha256:";
  size_t index;
  if (!value || !output || strncmp(value, prefix, sizeof(prefix) - 1u) != 0 ||
      strlen(value) != sizeof(prefix) - 1u + MESH_CONTROL_DIGEST_SIZE * 2u)
    return 0;
  for (index = 0u; index < MESH_CONTROL_DIGEST_SIZE; ++index) {
    int high = hex_value(value[sizeof(prefix) - 1u + index * 2u]);
    int low = hex_value(value[sizeof(prefix) + index * 2u]);
    if (high < 0 || low < 0) {
      memset(output, 0, MESH_CONTROL_DIGEST_SIZE);
      return 0;
    }
    output[index] = (uint8_t)((high << 4) | low);
  }
  return 1;
}

static mesh_control_controller_iris_v1_t *from_request(Req *req,
                                                       const char *path) {
  if (!req || !req->app) return NULL;
  return (mesh_control_controller_iris_v1_t *)iris_app_lookup_rpc_context(
      req->app, path);
}

static void finish_callback(mesh_control_controller_iris_v1_t *adapter) {
  atomic_fetch_sub_explicit(&adapter->active_callbacks, 1u,
                            memory_order_release);
}

static int http_status(mesh_control_result_t result) {
  switch (result) {
    case MESH_CONTROL_UNAUTHORIZED:
      return 403;
    case MESH_CONTROL_RESOURCE_EXHAUSTED:
      return 503;
    case MESH_CONTROL_TIMEOUT:
      return 504;
    case MESH_CONTROL_STALE_EPOCH:
    case MESH_CONTROL_CONFLICT:
      return 409;
    case MESH_CONTROL_CLOSED:
      return 503;
    default:
      return 400;
  }
}

static void maintenance_task(coro_t *coroutine, void *argument) {
  mesh_control_controller_iris_v1_t *adapter =
      (mesh_control_controller_iris_v1_t *)argument;
  (void)coroutine;
  if (!adapter) return;
  adapter->maintenance_running = 1u;
  for (;;) {
    mesh_control_controller_session_v1_t *controller =
        adapter->config.controller;
    size_t progress = 0u;
    if (mesh_control_controller_session_poll_v1(controller, &progress) !=
        MESH_CONTROL_OK)
      break;
    if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire) &&
        atomic_load_explicit(&adapter->active_callbacks,
                             memory_order_acquire) == 0u &&
        !controller->pending_operation && !controller->response_ready &&
        !controller->submit_completion_ready)
      break;
    coro_sleep(adapter->config.context, 1u);
  }
  adapter->maintenance_running = 0u;
}

static void sync_handler(Req *req, Res *res) {
  mesh_control_controller_iris_v1_t *adapter =
      from_request(req, MESH_CONTROL_CONTROLLER_SYNC_PATH_V1);
  char certificate[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  uint8_t certificate_digest[MESH_CONTROL_DIGEST_SIZE];
  size_t response_size = 0u;
  uint64_t expected_callbacks = 0u;
  uint64_t started_at_ms;
  uint64_t protocol_now_ms;
  coro_context_t *context;
  mesh_control_result_t result;
  if (!adapter || !adapter->initialized) {
    static const char message[] = "controller unavailable";
    reply(res, 503, "text/plain", message, sizeof(message) - 1u);
    return;
  }
  if (!atomic_compare_exchange_strong_explicit(
          &adapter->active_callbacks, &expected_callbacks, 1u,
          memory_order_acq_rel, memory_order_acquire)) {
    static const char message[] = "controller busy";
    atomic_fetch_add_explicit(&adapter->rejected_busy, 1u,
                              memory_order_relaxed);
    reply(res, 503, "text/plain", message, sizeof(message) - 1u);
    return;
  }
  if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    static const char message[] = "controller unavailable";
    reply(res, 503, "text/plain", message, sizeof(message) - 1u);
    finish_callback(adapter);
    return;
  }
  atomic_fetch_add_explicit(&adapter->received, 1u, memory_order_relaxed);
  memset(certificate, 0, sizeof(certificate));
  memset(certificate_digest, 0, sizeof(certificate_digest));
  if (req_get_verified_tls_peer_certificate_sha256(req, certificate) != 0 ||
      !parse_certificate_digest(certificate, certificate_digest)) {
    atomic_fetch_add_explicit(&adapter->rejected_transport, 1u,
                              memory_order_relaxed);
    static const char message[] = "verified client certificate required";
    reply(res, 403, "text/plain", message, sizeof(message) - 1u);
    finish_callback(adapter);
    return;
  }
  if (!req->body || req->body_len == 0u ||
      req->body_len > MESH_CONTROL_MAX_FRAME_SIZE_V1) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u,
                              memory_order_relaxed);
    static const char message[] = "invalid sync frame";
    reply(res, 400, "text/plain", message, sizeof(message) - 1u);
    finish_callback(adapter);
    return;
  }
  started_at_ms = turbo_monotonic_ms();
  protocol_now_ms = adapter->config.now_ms(adapter->config.now_context);
  if (protocol_now_ms == 0u) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u,
                              memory_order_relaxed);
    static const char message[] = "controller clock unavailable";
    reply(res, 503, "text/plain", message, sizeof(message) - 1u);
    finish_callback(adapter);
    return;
  }
  result = mesh_control_controller_session_receive_v1(
      adapter->config.controller, certificate_digest,
      (const uint8_t *)req->body, req->body_len, protocol_now_ms);
  if (result != MESH_CONTROL_OK) {
    if (result == MESH_CONTROL_RESOURCE_EXHAUSTED)
      atomic_fetch_add_explicit(&adapter->rejected_busy, 1u,
                                memory_order_relaxed);
    else
      atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u,
                                memory_order_relaxed);
    static const char message[] = "sync frame rejected";
    reply(res, http_status(result), "text/plain", message,
          sizeof(message) - 1u);
    finish_callback(adapter);
    return;
  }
  context = coro_context_current();
  if (!context) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u,
                              memory_order_relaxed);
    static const char message[] = "request coroutine required";
    reply(res, 500, "text/plain", message, sizeof(message) - 1u);
    finish_callback(adapter);
    return;
  }
  for (;;) {
    result = mesh_control_controller_session_try_take_response_v1(
        adapter->config.controller, adapter->response_storage,
        MESH_CONTROL_MAX_FRAME_SIZE_V1,
        &response_size);
    if (result != MESH_CONTROL_EMPTY) break;
    if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
      result = MESH_CONTROL_CLOSED;
      break;
    }
    if (turbo_monotonic_ms() - started_at_ms >=
        adapter->config.persistence_timeout_ms) {
      atomic_fetch_add_explicit(&adapter->timed_out, 1u,
                                memory_order_relaxed);
      result = MESH_CONTROL_TIMEOUT;
      (void)mesh_control_controller_session_abandon_response_v1(
          adapter->config.controller);
      break;
    }
    coro_sleep(context, 1u);
  }
  if (result != MESH_CONTROL_OK) {
    static const char message[] = "sync persistence failed";
    reply(res, http_status(result), "text/plain", message,
          sizeof(message) - 1u);
    finish_callback(adapter);
    return;
  }
  atomic_fetch_add_explicit(&adapter->succeeded, 1u, memory_order_relaxed);
  reply(res, 200, MESH_CONTROL_CONTROLLER_SYNC_MEDIA_TYPE_V1,
        adapter->response_storage, response_size);
  finish_callback(adapter);
}

static void submit_handler(Req *req, Res *res) {
  mesh_control_controller_iris_v1_t *adapter =
      from_request(req, MESH_CONTROL_CONTROLLER_SUBMIT_PATH_V1);
  mesh_mgmt_verified_envelope_v1_t verified;
  mesh_control_envelope_v1_t envelope;
  mesh_control_durable_outbox_message_v1_t message;
  mesh_control_controller_submit_completion_v1_t completion;
  const uint8_t *body = NULL;
  const char *content_type;
  char certificate[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
  size_t body_size = 0u;
  uint64_t expected_callbacks = 0u;
  uint64_t request_token = 0u;
  uint64_t now_ms;
  uint64_t started_at_ms;
  mesh_control_result_t result;
  if (!adapter || !adapter->initialized ||
      !adapter->config.authorize_submit) {
    reply(res, 404, "text/plain", NULL, 0u);
    return;
  }
  if (!atomic_compare_exchange_strong_explicit(
          &adapter->active_callbacks, &expected_callbacks, 1u,
          memory_order_acq_rel, memory_order_acquire)) {
    atomic_fetch_add_explicit(&adapter->rejected_busy, 1u,
                              memory_order_relaxed);
    reply(res, 503, "text/plain", "controller busy", 15u);
    return;
  }
  if (!atomic_load_explicit(&adapter->accepting, memory_order_acquire)) {
    reply(res, 503, "text/plain", "controller unavailable", 22u);
    finish_callback(adapter);
    return;
  }
  content_type = get_headers(req, "Content-Type");
  if (!content_type) content_type = get_headers(req, "content-type");
  memset(certificate, 0, sizeof(certificate));
  if (!content_type ||
      strcmp(content_type, MESH_CONTROL_CONTROLLER_SUBMIT_MEDIA_TYPE_V1) != 0 ||
      req_get_verified_tls_peer_certificate_sha256(req, certificate) != 0 ||
      strcmp(certificate,
             adapter->config.submit_peer_certificate_sha256) != 0) {
    atomic_fetch_add_explicit(&adapter->rejected_transport, 1u,
                              memory_order_relaxed);
    reply(res, 403, "text/plain", "submitter mTLS identity required", 32u);
    finish_callback(adapter);
    return;
  }
  if (!req->body || req->body_len == 0u ||
      req->body_len > MESH_CONTROL_MAX_FRAME_SIZE_V1 ||
      mesh_mgmt_envelope_verify_v1((const uint8_t *)req->body, req->body_len,
                                   &verified) != MESH_MGMT_ENVELOPE_OK ||
      verified.frame.kind != MESH_MGMT_KIND_CONTROL_FRAME ||
      mesh_control_mmp_payload_decode_v1(&verified, &envelope, &body,
                                         &body_size) != MESH_CONTROL_MMP_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u,
                              memory_order_relaxed);
    reply(res, 400, "text/plain", "invalid signed MMP command", 26u);
    finish_callback(adapter);
    return;
  }
  now_ms = adapter->config.now_ms(adapter->config.now_context);
  result = now_ms == 0u
               ? MESH_CONTROL_INVALID_STATE
               : adapter->config.authorize_submit(
                     adapter->config.submit_context, &verified, &envelope,
                     now_ms);
  if (result != MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->rejected_protocol, 1u,
                              memory_order_relaxed);
    reply(res, http_status(result), "text/plain",
          "signed MMP command rejected", 27u);
    finish_callback(adapter);
    return;
  }
  memset(&message, 0, sizeof(message));
  memcpy(message.target_node_id, envelope.target_node_id,
         sizeof(message.target_node_id));
  memcpy(message.message_id, envelope.message_id, sizeof(message.message_id));
  memcpy(message.request_id, envelope.request_id, sizeof(message.request_id));
  message.sequence = envelope.sequence;
  message.payload = (const uint8_t *)req->body;
  message.payload_size = req->body_len;
  message.created_at_ms = now_ms;
  result = mesh_control_controller_session_try_submit_v1(
      adapter->config.controller, &message, &request_token);
  if (result != MESH_CONTROL_OK) {
    if (result == MESH_CONTROL_RESOURCE_EXHAUSTED)
      atomic_fetch_add_explicit(&adapter->rejected_busy, 1u,
                                memory_order_relaxed);
    reply(res, http_status(result), "text/plain", "outbox submit rejected",
          22u);
    finish_callback(adapter);
    return;
  }
  started_at_ms = turbo_monotonic_ms();
  for (;;) {
    result = mesh_control_controller_session_try_take_submit_v1(
        adapter->config.controller, &completion);
    if (result != MESH_CONTROL_EMPTY) break;
    if (turbo_monotonic_ms() - started_at_ms >=
        adapter->config.persistence_timeout_ms) {
      (void)mesh_control_controller_session_abandon_submit_v1(
          adapter->config.controller, request_token);
      atomic_fetch_add_explicit(&adapter->timed_out, 1u,
                                memory_order_relaxed);
      result = MESH_CONTROL_UNKNOWN_COMMIT;
      break;
    }
    coro_sleep(adapter->config.context, 1u);
  }
  if (result == MESH_CONTROL_OK &&
      (completion.request_token != request_token ||
       completion.store_result != MESH_CONTROL_DURABLE_OUTBOX_OK))
    result = completion.store_result ==
                     MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED
                 ? MESH_CONTROL_RESOURCE_EXHAUSTED
                 : MESH_CONTROL_INVALID_STATE;
  if (result == MESH_CONTROL_OK) {
    atomic_fetch_add_explicit(&adapter->submitted, 1u, memory_order_relaxed);
    reply(res, 202, "text/plain", NULL, 0u);
  } else {
    reply(res, result == MESH_CONTROL_UNKNOWN_COMMIT ? 503
                                                     : http_status(result),
          "text/plain",
          result == MESH_CONTROL_UNKNOWN_COMMIT ? "UNKNOWN_COMMIT"
                                                : "outbox persistence failed",
          result == MESH_CONTROL_UNKNOWN_COMMIT ? 14u : 25u);
  }
  finish_callback(adapter);
}

mesh_control_result_t mesh_control_controller_iris_register_v1(
    mesh_control_controller_iris_v1_t *adapter, iris_app_t *app,
    const mesh_control_controller_iris_config_v1_t *config) {
  mesh_control_controller_session_stats_v1_t stats;
  if (!adapter || adapter->initialized || !app || !config ||
      !config->controller || !config->context ||
      !config->now_ms ||
      config->persistence_timeout_ms == 0u ||
      ((config->submit_peer_certificate_sha256 != NULL) !=
       (config->authorize_submit != NULL)) ||
      (config->submit_peer_certificate_sha256 &&
       !parse_certificate_digest(config->submit_peer_certificate_sha256,
                                 (uint8_t[MESH_CONTROL_DIGEST_SIZE]){0})) ||
      mesh_control_controller_session_get_stats_v1(config->controller,
                                                    &stats) !=
          MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_ARG;
  memset(adapter, 0, sizeof(*adapter));
  adapter->response_storage =
      (uint8_t *)calloc(1u, MESH_CONTROL_MAX_FRAME_SIZE_V1);
  if (!adapter->response_storage)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  adapter->app = app;
  adapter->config = *config;
  atomic_init(&adapter->accepting, true);
  atomic_init(&adapter->received, 0u);
  atomic_init(&adapter->succeeded, 0u);
  atomic_init(&adapter->rejected_transport, 0u);
  atomic_init(&adapter->rejected_protocol, 0u);
  atomic_init(&adapter->rejected_busy, 0u);
  atomic_init(&adapter->timed_out, 0u);
  atomic_init(&adapter->submitted, 0u);
  atomic_init(&adapter->active_callbacks, 0u);
  adapter->initialized = 1u;
  if (iris_app_bind_rpc_context(app, MESH_CONTROL_CONTROLLER_SYNC_PATH_V1,
                                adapter) != 0) {
    free(adapter->response_storage);
    memset(adapter, 0, sizeof(*adapter));
    return MESH_CONTROL_CONFLICT;
  }
  if (config->authorize_submit &&
      iris_app_bind_rpc_context(app, MESH_CONTROL_CONTROLLER_SUBMIT_PATH_V1,
                                adapter) != 0) {
    (void)iris_app_unbind_rpc_context(
        app, MESH_CONTROL_CONTROLLER_SYNC_PATH_V1, adapter);
    free(adapter->response_storage);
    memset(adapter, 0, sizeof(*adapter));
    return MESH_CONTROL_CONFLICT;
  }
  iris_app_post(app, MESH_CONTROL_CONTROLLER_SYNC_PATH_V1, sync_handler);
  if (config->authorize_submit)
    iris_app_post(app, MESH_CONTROL_CONTROLLER_SUBMIT_PATH_V1,
                  submit_handler);
  if (coro_context_spawn(config->context, maintenance_task, adapter) != 0) {
    if (config->authorize_submit)
      (void)iris_app_unbind_rpc_context(
          app, MESH_CONTROL_CONTROLLER_SUBMIT_PATH_V1, adapter);
    (void)iris_app_unbind_rpc_context(
        app, MESH_CONTROL_CONTROLLER_SYNC_PATH_V1, adapter);
    free(adapter->response_storage);
    memset(adapter, 0, sizeof(*adapter));
    return MESH_CONTROL_INVALID_STATE;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_iris_close_v1(
    mesh_control_controller_iris_v1_t *adapter) {
  if (!adapter || !adapter->initialized) return MESH_CONTROL_INVALID_ARG;
  atomic_store_explicit(&adapter->accepting, false, memory_order_release);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_control_controller_iris_get_stats_v1(
    const mesh_control_controller_iris_v1_t *adapter,
    mesh_control_controller_iris_stats_v1_t *out_stats) {
  if (!adapter || !adapter->initialized || !out_stats)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  out_stats->received = atomic_load_explicit(&adapter->received,
                                             memory_order_relaxed);
  out_stats->succeeded = atomic_load_explicit(&adapter->succeeded,
                                              memory_order_relaxed);
  out_stats->rejected_transport = atomic_load_explicit(
      &adapter->rejected_transport, memory_order_relaxed);
  out_stats->rejected_protocol = atomic_load_explicit(
      &adapter->rejected_protocol, memory_order_relaxed);
  out_stats->rejected_busy = atomic_load_explicit(&adapter->rejected_busy,
                                                  memory_order_relaxed);
  out_stats->timed_out = atomic_load_explicit(&adapter->timed_out,
                                              memory_order_relaxed);
  out_stats->submitted = atomic_load_explicit(&adapter->submitted,
                                              memory_order_relaxed);
  out_stats->active_callbacks = atomic_load_explicit(
      &adapter->active_callbacks, memory_order_acquire);
  out_stats->accepting = atomic_load_explicit(&adapter->accepting,
                                              memory_order_acquire);
  return MESH_CONTROL_OK;
}

void mesh_control_controller_iris_destroy_v1(
    mesh_control_controller_iris_v1_t *adapter) {
  if (!adapter) return;
  if (adapter->initialized && adapter->app)
    (void)iris_app_unbind_rpc_context(
        adapter->app, MESH_CONTROL_CONTROLLER_SYNC_PATH_V1, adapter);
  if (adapter->initialized && adapter->app &&
      adapter->config.authorize_submit)
    (void)iris_app_unbind_rpc_context(
        adapter->app, MESH_CONTROL_CONTROLLER_SUBMIT_PATH_V1, adapter);
  if (adapter->response_storage) {
    memset(adapter->response_storage, 0, MESH_CONTROL_MAX_FRAME_SIZE_V1);
    free(adapter->response_storage);
  }
  memset(adapter, 0, sizeof(*adapter));
}
