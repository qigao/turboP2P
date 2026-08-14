#include "mesh_node_ipc_flowmq.h"

#include <turbo_error.h>

#include <stdlib.h>
#include <string.h>

#define MESH_NODE_IPC_CERTIFICATE_SHA256_PREFIX "sha256:"
#define MESH_NODE_IPC_CERTIFICATE_SHA256_HEX_SIZE 64u
#define MESH_NODE_IPC_CERTIFICATE_SHA256_SIZE \
  ((sizeof(MESH_NODE_IPC_CERTIFICATE_SHA256_PREFIX) - 1u) + \
   MESH_NODE_IPC_CERTIFICATE_SHA256_HEX_SIZE)

struct mesh_node_ipc_flowmq_send_request_v1_s {
  flowmq_router_route_t route;
  uint64_t completion_id;
};

static int nonempty(const char *value) { return value && value[0] != '\0'; }

static int certificate_sha256_valid(const char *value) {
  size_t index;
  if (!value || strlen(value) != MESH_NODE_IPC_CERTIFICATE_SHA256_SIZE ||
      memcmp(value, MESH_NODE_IPC_CERTIFICATE_SHA256_PREFIX,
             sizeof(MESH_NODE_IPC_CERTIFICATE_SHA256_PREFIX) - 1u) != 0)
    return 0;
  for (index = sizeof(MESH_NODE_IPC_CERTIFICATE_SHA256_PREFIX) - 1u;
       index < MESH_NODE_IPC_CERTIFICATE_SHA256_SIZE; ++index) {
    if (!((value[index] >= '0' && value[index] <= '9') ||
          (value[index] >= 'a' && value[index] <= 'f')))
      return 0;
  }
  return 1;
}

static int loopback_host(const char *host) {
  return host && (strcmp(host, "127.0.0.1") == 0 ||
                  strcmp(host, "::1") == 0 ||
                  strcmp(host, "localhost") == 0);
}

static int finite_timeout(uint64_t value) { return value != 0u; }

static int mesh_identity_valid(const char *identity) {
  size_t size;
  if (!nonempty(identity)) return 0;
  size = strlen(identity);
  if (size > FLOWMQ_PROTOCOL_MAX_IDENTITY_SIZE || identity[0] == ' ' ||
      identity[size - 1u] == ' ')
    return 0;
  for (size_t i = 0u; i < size; ++i) {
    unsigned char value = (unsigned char)identity[i];
    if (value < 0x20u || value > 0x7eu) return 0;
  }
  return 1;
}

static int text_view_equal(tstr_v view, const char *text) {
  size_t text_size = text ? strlen(text) : 0u;
  return view.len == text_size &&
         (text_size == 0u || memcmp(view.data, text, text_size) == 0);
}

static mesh_control_result_t map_flow_status(int status) {
  switch (status) {
    case TURBO_OK: return MESH_CONTROL_OK;
    case TURBO_EINVAL:
    case TURBO_ERANGE:
    case TURBO_EPROTO:
    case TURBO_EMSGSIZE: return MESH_CONTROL_INVALID_ARG;
    case TURBO_ENOMEM:
    case TURBO_ENOSPC:
    case TURBO_EBUSY: return MESH_CONTROL_RESOURCE_EXHAUSTED;
    case TURBO_ENOTCONN: return MESH_CONTROL_PROVIDER_UNAVAILABLE;
    case TURBO_ETIMEDOUT: return MESH_CONTROL_TIMEOUT;
    case TURBO_EPERM: return MESH_CONTROL_UNAUTHORIZED;
    case TURBO_ECANCELED:
    case TURBO_ESHUTDOWN: return MESH_CONTROL_CLOSED;
    default: return MESH_CONTROL_INVALID_STATE;
  }
}

static int map_receive_status(mesh_control_result_t result) {
  switch (result) {
    case MESH_CONTROL_OK: return TURBO_OK;
    case MESH_CONTROL_RESOURCE_EXHAUSTED: return TURBO_ENOSPC;
    case MESH_CONTROL_CLOSED: return TURBO_ECANCELED;
    case MESH_CONTROL_UNAUTHORIZED: return TURBO_EPERM;
    default: return TURBO_EPROTO;
  }
}

static int receive_payload(mesh_node_ipc_flowmq_v1_t *adapter,
                           const flowmq_protocol_frame_t *frame) {
  mesh_control_result_t result;
  if (!adapter || !frame || adapter->initialized == 0u ||
      frame->kind != FLOWMQ_PROTOCOL_FRAME_DATA)
    return TURBO_EPROTO;
  result = mesh_node_ipc_channel_try_push_v1(
      adapter->inbound, (const uint8_t *)frame->payload.data,
      frame->payload.len);
  if (result == MESH_CONTROL_OK)
    atomic_fetch_add_explicit(&adapter->received, 1u, memory_order_relaxed);
  else
    atomic_fetch_add_explicit(&adapter->receive_rejected, 1u,
                              memory_order_relaxed);
  return map_receive_status(result);
}

static int router_receive(void *context, const flowmq_router_route_t *route,
                          tstr_v peer_identity, tstr_v peer_topic,
                          const flowmq_protocol_frame_t *frame) {
  mesh_node_ipc_flowmq_v1_t *adapter =
      (mesh_node_ipc_flowmq_v1_t *)context;
  (void)peer_topic;
  if (!adapter || !route ||
      !text_view_equal(peer_identity, adapter->expected_peer_identity))
    return TURBO_EPERM;
  atomic_store_explicit(&adapter->route_generation, 0u, memory_order_release);
  atomic_store_explicit(&adapter->route_endpoint_id, route->endpoint_id,
                        memory_order_relaxed);
  atomic_store_explicit(&adapter->route_session_id, route->session_id,
                        memory_order_relaxed);
  atomic_store_explicit(&adapter->route_generation, route->generation,
                        memory_order_release);
  return receive_payload(adapter, frame);
}

static void router_event(void *context,
                         const flowmq_router_endpoint_event_t *event) {
  mesh_node_ipc_flowmq_v1_t *adapter =
      (mesh_node_ipc_flowmq_v1_t *)context;
  uint64_t generation;
  if (!adapter || !event) return;
  if (event->kind != FLOWMQ_ROUTER_EVENT_PEER_DISCONNECTED &&
      event->kind != FLOWMQ_ROUTER_EVENT_HEARTBEAT_TIMEOUT)
    return;
  generation = atomic_load_explicit(&adapter->route_generation,
                                    memory_order_acquire);
  if (generation != event->route.generation ||
      atomic_load_explicit(&adapter->route_endpoint_id,
                           memory_order_relaxed) !=
          event->route.endpoint_id ||
      atomic_load_explicit(&adapter->route_session_id,
                           memory_order_relaxed) != event->route.session_id)
    return;
  (void)atomic_compare_exchange_strong_explicit(
      &adapter->route_generation, &generation, 0u, memory_order_release,
      memory_order_relaxed);
}

static int connect_receive(void *context, const flowmq_protocol_frame_t *frame,
                           uint64_t generation) {
  mesh_node_ipc_flowmq_v1_t *adapter =
      (mesh_node_ipc_flowmq_v1_t *)context;
  (void)generation;
  if (!adapter || !frame ||
      !text_view_equal(frame->identity, adapter->expected_peer_identity))
    return TURBO_EPERM;
  return receive_payload(adapter, frame);
}

static void send_complete(void *context, uint64_t completion_id, int status) {
  mesh_node_ipc_flowmq_v1_t *adapter =
      (mesh_node_ipc_flowmq_v1_t *)context;
  if (!adapter) return;
  atomic_store_explicit(&adapter->send_completion_id, completion_id,
                        memory_order_relaxed);
  atomic_store_explicit(&adapter->send_completion_status, status,
                        memory_order_relaxed);
  atomic_store_explicit(&adapter->send_completion_done, 1,
                        memory_order_release);
}

static void send_request_destroy(mesh_node_ipc_flowmq_send_request_v1_t *request) {
  if (!request) return;
  free(request);
}

static int endpoint_profile_common(flowmq_coronet_transport_t transport,
                                   const char *host, int port, const char *path,
                                   const char *topic,
                                   size_t max_frame_size,
                                   const flowmq_coronet_timeout_config_t *timeouts,
                                   uint64_t heartbeat_interval_ms,
                                   uint64_t heartbeat_timeout_ms) {
  return transport == FLOWMQ_TRANSPORT_TLS && loopback_host(host) && port > 0 &&
         port <= 65535 && nonempty(path) && nonempty(topic) &&
         max_frame_size == MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1 &&
         timeouts && finite_timeout(timeouts->timeout_ms) &&
         finite_timeout(timeouts->connect_timeout_ms) &&
         finite_timeout(timeouts->send_timeout_ms) &&
         finite_timeout(timeouts->recv_timeout_ms) &&
         finite_timeout(timeouts->handshake_timeout_ms) &&
         heartbeat_interval_ms != 0u &&
         heartbeat_timeout_ms > heartbeat_interval_ms;
}

mesh_control_result_t mesh_node_ipc_flowmq_profile_validate_v1(
    const mesh_node_ipc_flowmq_config_v1_t *config) {
  if (!config || !config->inbound || !config->outbound ||
      !mesh_identity_valid(config->expected_peer_identity) ||
      !certificate_sha256_valid(
          config->expected_peer_certificate_sha256) ||
      (nonempty(config->expected_peer_certificate_sha256_next) &&
       !certificate_sha256_valid(
           config->expected_peer_certificate_sha256_next)) ||
      config->identity_policy_generation == 0u ||
      !flowmq_coronet_tls_is_tls13_only())
    return MESH_CONTROL_INVALID_ARG;
  if (config->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1) {
    const flowmq_router_endpoint_config_t *endpoint = config->bind_endpoint;
    const flowmq_coronet_tls_server_config_t *tls;
    if (!endpoint || config->connect_endpoint ||
        endpoint->size != sizeof(*endpoint) ||
        !endpoint_profile_common(endpoint->transport, endpoint->host,
                                 endpoint->port, endpoint->path, endpoint->topic,
                                 endpoint->max_frame_size,
                                 &endpoint->timeouts,
                                 endpoint->heartbeat_interval_ms,
                                 endpoint->heartbeat_timeout_ms) ||
        endpoint->max_connections != 1u || !nonempty(endpoint->identity) ||
        !(tls = endpoint->tls) || !nonempty(tls->ca_file) ||
        !nonempty(tls->cert_file) || !nonempty(tls->key_file) ||
        tls->require_client_certificate != 1 ||
        endpoint->verify_peer_identity || endpoint->verify_peer_identity_ctx)
      return MESH_CONTROL_INVALID_ARG;
  } else if (config->mode == MESH_NODE_IPC_FLOWMQ_CONNECT_V1) {
    const flowmq_connect_endpoint_config_t *endpoint = config->connect_endpoint;
    const flowmq_coronet_tls_client_config_t *tls;
    if (!endpoint || config->bind_endpoint ||
        endpoint->size != sizeof(*endpoint) ||
        endpoint->pattern != FLOWMQ_PROTOCOL_DEALER ||
        !endpoint_profile_common(endpoint->transport, endpoint->host,
                                 endpoint->port, endpoint->path, endpoint->topic,
                                 endpoint->max_frame_size,
                                 &endpoint->timeouts,
                                 endpoint->heartbeat_interval_ms,
                                 endpoint->heartbeat_timeout_ms) ||
        !nonempty(endpoint->identity) || !(tls = endpoint->tls) ||
        !nonempty(tls->ca_file) || !nonempty(tls->cert_file) ||
        !nonempty(tls->key_file) || !nonempty(tls->server_name) ||
        tls->verify_peer != 1 || endpoint->reconnect_initial_ms == 0u ||
        endpoint->reconnect_max_ms < endpoint->reconnect_initial_ms ||
        endpoint->verify_peer_identity || endpoint->verify_peer_identity_ctx)
      return MESH_CONTROL_INVALID_ARG;
  } else {
    return MESH_CONTROL_INVALID_ARG;
  }
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_flowmq_init_v1(
    mesh_node_ipc_flowmq_v1_t *adapter,
    const mesh_node_ipc_flowmq_config_v1_t *config) {
  flowmq_tls_identity_binding_t bindings[2];
  flowmq_tls_identity_map_config_t map_config =
      FLOWMQ_TLS_IDENTITY_MAP_CONFIG_INIT;
  size_t binding_count = 1u;
  int status;
  if (!adapter || adapter->initialized != 0u ||
      mesh_node_ipc_flowmq_profile_validate_v1(config) != MESH_CONTROL_OK)
    return MESH_CONTROL_INVALID_ARG;
  memset(adapter, 0, sizeof(*adapter));
  adapter->mode = (uint8_t)config->mode;
  adapter->inbound = config->inbound;
  adapter->outbound = config->outbound;
  {
    const char *own_identity =
        config->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1
            ? config->bind_endpoint->identity
            : config->connect_endpoint->identity;
    memcpy(adapter->own_identity, own_identity, strlen(own_identity) + 1u);
  }
  memcpy(adapter->expected_peer_identity, config->expected_peer_identity,
         strlen(config->expected_peer_identity) + 1u);
  memset(bindings, 0, sizeof(bindings));
  bindings[0].size = sizeof(bindings[0]);
  bindings[0].certificate_sha256 =
      config->expected_peer_certificate_sha256;
  bindings[0].hello_identity = config->expected_peer_identity;
  if (nonempty(config->expected_peer_certificate_sha256_next)) {
    bindings[1].size = sizeof(bindings[1]);
    bindings[1].certificate_sha256 =
        config->expected_peer_certificate_sha256_next;
    bindings[1].hello_identity = config->expected_peer_identity;
    binding_count = 2u;
  }
  map_config.bindings = bindings;
  map_config.binding_count = binding_count;
  map_config.policy_generation = config->identity_policy_generation;
  status = flowmq_tls_identity_map_create(&map_config, &adapter->identity_map);
  if (status != TURBO_OK) {
    mesh_node_ipc_flowmq_destroy_v1(adapter);
    return map_flow_status(status);
  }
  atomic_init(&adapter->route_endpoint_id, 0u);
  atomic_init(&adapter->route_session_id, 0u);
  atomic_init(&adapter->route_generation, 0u);
  atomic_init(&adapter->received, 0u);
  atomic_init(&adapter->receive_rejected, 0u);
  atomic_init(&adapter->next_message_id, 0u);
  atomic_init(&adapter->send_completion_id, 0u);
  atomic_init(&adapter->send_completion_status, TURBO_EBUSY);
  atomic_init(&adapter->send_completion_done, 0);
  if (config->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1) {
    flowmq_router_endpoint_config_t endpoint = *config->bind_endpoint;
    endpoint.context = NULL;
    endpoint.drive_context = 1;
    endpoint.own_context = 1;
    endpoint.on_frame = router_receive;
    endpoint.on_event = router_event;
    endpoint.callback_ctx = adapter;
    endpoint.verify_peer_identity = flowmq_tls_identity_map_verify;
    endpoint.verify_peer_identity_ctx = adapter->identity_map;
    endpoint.send_admission.capacity = 1u;
    endpoint.send_admission.capacity_bytes =
        MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1;
    endpoint.send_admission.on_complete = send_complete;
    endpoint.send_admission.completion_ctx = adapter;
    adapter->send_timeout_ms = endpoint.timeouts.send_timeout_ms;
    status = flowmq_router_endpoint_create(&endpoint, &adapter->router);
  } else {
    flowmq_connect_endpoint_config_t endpoint = *config->connect_endpoint;
    endpoint.context = NULL;
    endpoint.drive_context = 1;
    endpoint.own_context = 1;
    endpoint.on_frame = connect_receive;
    endpoint.callback_ctx = adapter;
    endpoint.verify_peer_identity = flowmq_tls_identity_map_verify;
    endpoint.verify_peer_identity_ctx = adapter->identity_map;
    endpoint.send_admission.capacity = 1u;
    endpoint.send_admission.capacity_bytes =
        MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1;
    endpoint.send_admission.on_complete = send_complete;
    endpoint.send_admission.completion_ctx = adapter;
    adapter->send_timeout_ms = endpoint.timeouts.send_timeout_ms;
    status = flowmq_connect_endpoint_create(&endpoint, &adapter->connect);
  }
  adapter->last_flow_status = status;
  if (status != TURBO_OK) {
    mesh_node_ipc_flowmq_destroy_v1(adapter);
    return map_flow_status(status);
  }
  adapter->initialized = 1u;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_flowmq_start_v1(
    mesh_node_ipc_flowmq_v1_t *adapter) {
  uint64_t timeout_ns;
  int status;
  if (!adapter || adapter->initialized == 0u || adapter->started ||
      adapter->stopped || adapter->send_timeout_ms > UINT64_MAX / 1000000u)
    return MESH_CONTROL_INVALID_ARG;
  timeout_ns = adapter->send_timeout_ms * 1000000u;
  status = adapter->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1
               ? flowmq_router_endpoint_start(adapter->router, timeout_ns)
               : flowmq_connect_endpoint_start(adapter->connect, timeout_ns);
  adapter->last_flow_status = status;
  if (status != TURBO_OK) return map_flow_status(status);
  adapter->started = 1u;
  return MESH_CONTROL_OK;
}

static mesh_control_result_t finish_send(mesh_node_ipc_flowmq_v1_t *adapter,
                                         size_t *sent) {
  mesh_node_ipc_flowmq_send_request_v1_t *request = adapter->send_request;
  mesh_control_result_t result;
  int status;
  if (!request ||
      !atomic_load_explicit(&adapter->send_completion_done,
                            memory_order_acquire))
    return MESH_CONTROL_TIMEOUT;
  if (atomic_load_explicit(&adapter->send_completion_id,
                           memory_order_relaxed) != request->completion_id)
    return MESH_CONTROL_INVALID_STATE;
  status = atomic_load_explicit(&adapter->send_completion_status,
                                memory_order_relaxed);
  adapter->last_flow_status = status;
  send_request_destroy(request);
  adapter->send_request = NULL;
  if (status != TURBO_OK) {
    adapter->send_failed++;
    return map_flow_status(status);
  }
  result = mesh_node_ipc_channel_consume_v1(adapter->outbound);
  if (result != MESH_CONTROL_OK) return MESH_CONTROL_INVALID_STATE;
  adapter->sent++;
  (*sent)++;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_flowmq_pump_send_v1(
    mesh_node_ipc_flowmq_v1_t *adapter, size_t budget, size_t *out_sent) {
  mesh_node_ipc_frame_view_v1_t view;
  mesh_control_result_t result;
  size_t sent = 0u;
  if (!adapter || !out_sent || adapter->initialized == 0u ||
      !adapter->started || adapter->stopped || budget == 0u)
    return MESH_CONTROL_INVALID_ARG;
  *out_sent = 0u;
  while (sent < budget) {
    if (adapter->send_request) {
      result = finish_send(adapter, &sent);
      if (result == MESH_CONTROL_TIMEOUT) {
        *out_sent = sent;
        return result;
      }
      if (result != MESH_CONTROL_OK) {
        *out_sent = sent;
        return result;
      }
      continue;
    }
    result = mesh_node_ipc_channel_peek_v1(adapter->outbound, &view);
    if (result == MESH_CONTROL_EMPTY) break;
    if (result != MESH_CONTROL_OK) return result;
    {
      flowmq_protocol_frame_t frame;
      mesh_node_ipc_flowmq_send_request_v1_t *request =
          (mesh_node_ipc_flowmq_send_request_v1_t *)calloc(1u, sizeof(*request));
      tstr_t encoded = NULL;
      int status;
      if (!request) return MESH_CONTROL_RESOURCE_EXHAUSTED;
      memset(&frame, 0, sizeof(frame));
      frame.kind = FLOWMQ_PROTOCOL_FRAME_DATA;
      frame.pattern = adapter->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1
                          ? FLOWMQ_PROTOCOL_ROUTER
                          : FLOWMQ_PROTOCOL_DEALER;
      frame.message_id = atomic_fetch_add_explicit(
                             &adapter->next_message_id, 1u,
                             memory_order_relaxed) +
                         1u;
      frame.identity = tstr_v_from_cstr(adapter->own_identity);
      frame.payload = tstr_v_from_buf((const char *)view.frame,
                                      view.frame_size);
      status = flowmq_protocol_encode_frame(
          &frame, MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1, &encoded);
      if (status != TURBO_OK) {
        send_request_destroy(request);
        return map_flow_status(status);
      }
      request->completion_id = frame.message_id;
      if (adapter->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1) {
        uint64_t before = atomic_load_explicit(&adapter->route_generation,
                                               memory_order_acquire);
        request->route.endpoint_id = atomic_load_explicit(
            &adapter->route_endpoint_id, memory_order_relaxed);
        request->route.session_id = atomic_load_explicit(
            &adapter->route_session_id, memory_order_relaxed);
        request->route.generation = before;
        if (before == 0u || before != atomic_load_explicit(
                                       &adapter->route_generation,
                                       memory_order_acquire)) {
          tstr_freep(&encoded);
          send_request_destroy(request);
          return MESH_CONTROL_PROVIDER_UNAVAILABLE;
        }
      }
      adapter->send_request = request;
      atomic_store_explicit(&adapter->send_completion_done, 0,
                            memory_order_relaxed);
      status = adapter->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1
                   ? flowmq_router_endpoint_send_copy(
                         adapter->router, request->route,
                         request->completion_id, encoded, tstr_len(encoded))
                   : flowmq_connect_endpoint_send_copy(
                         adapter->connect, request->completion_id, encoded,
                         tstr_len(encoded));
      tstr_freep(&encoded);
      if (status != TURBO_OK) {
        adapter->send_request = NULL;
        send_request_destroy(request);
        adapter->last_flow_status = status;
        adapter->send_failed++;
        return map_flow_status(status);
      }
    }
    /* FlowMQ owns the bounded copied send. Never wait in the caller's
     * domain-owner lane; a later pump observes its local completion and
     * consumes the exact queue head. */
    result = finish_send(adapter, &sent);
    if (result != MESH_CONTROL_OK) {
      *out_sent = sent;
      return result;
    }
  }
  *out_sent = sent;
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_flowmq_stop_v1(
    mesh_node_ipc_flowmq_v1_t *adapter) {
  mesh_node_ipc_channel_stats_v1_t outbound;
  if (!adapter || adapter->initialized == 0u)
    return MESH_CONTROL_INVALID_ARG;
  if (adapter->stopped) return MESH_CONTROL_OK;
  if (adapter->send_request ||
      mesh_node_ipc_channel_get_stats_v1(adapter->outbound, &outbound) !=
          MESH_CONTROL_OK)
    return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (outbound.pending != 0u) return MESH_CONTROL_RESOURCE_EXHAUSTED;
  if (adapter->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1)
    flowmq_router_endpoint_stop(adapter->router);
  else
    flowmq_connect_endpoint_stop(adapter->connect);
  atomic_store_explicit(&adapter->route_generation, 0u, memory_order_release);
  adapter->stopped = 1u;
  (void)mesh_node_ipc_channel_close_v1(adapter->inbound);
  (void)mesh_node_ipc_channel_close_v1(adapter->outbound);
  return MESH_CONTROL_OK;
}

mesh_control_result_t mesh_node_ipc_flowmq_get_stats_v1(
    const mesh_node_ipc_flowmq_v1_t *adapter,
    mesh_node_ipc_flowmq_stats_v1_t *out_stats) {
  flowmq_send_admission_stats_t send_stats;
  if (!adapter || !out_stats || adapter->initialized == 0u)
    return MESH_CONTROL_INVALID_ARG;
  memset(out_stats, 0, sizeof(*out_stats));
  memset(&send_stats, 0, sizeof(send_stats));
  if (adapter->mode == MESH_NODE_IPC_FLOWMQ_BIND_V1)
    flowmq_router_endpoint_send_stats(adapter->router, &send_stats);
  else
    flowmq_connect_endpoint_send_stats(adapter->connect, &send_stats);
  out_stats->started = adapter->started;
  out_stats->stopped = adapter->stopped;
  out_stats->received = atomic_load_explicit(&adapter->received,
                                             memory_order_relaxed);
  out_stats->receive_rejected = atomic_load_explicit(
      &adapter->receive_rejected, memory_order_relaxed);
  out_stats->sent = adapter->sent;
  out_stats->send_failed = adapter->send_failed;
  out_stats->send_pending = send_stats.pending;
  out_stats->send_pending_bytes = send_stats.pending_bytes;
  out_stats->send_high_water = send_stats.high_water;
  out_stats->send_high_water_bytes = send_stats.high_water_bytes;
  out_stats->send_rejected_full = send_stats.rejected_full;
  out_stats->send_completed = send_stats.completed;
  out_stats->send_admission_failed = send_stats.failed;
  out_stats->route_generation = atomic_load_explicit(
      &adapter->route_generation, memory_order_acquire);
  out_stats->last_flow_status = adapter->last_flow_status;
  return MESH_CONTROL_OK;
}

void mesh_node_ipc_flowmq_destroy_v1(mesh_node_ipc_flowmq_v1_t *adapter) {
  if (!adapter) return;
  if (adapter->router) flowmq_router_endpoint_destroy(adapter->router);
  if (adapter->connect) flowmq_connect_endpoint_destroy(adapter->connect);
  flowmq_tls_identity_map_destroy(adapter->identity_map);
  if (adapter->send_request)
    send_request_destroy(adapter->send_request);
  if (adapter->initialized) {
    (void)mesh_node_ipc_channel_close_v1(adapter->inbound);
    (void)mesh_node_ipc_channel_close_v1(adapter->outbound);
  }
  memset(adapter, 0, sizeof(*adapter));
}
