#include "mesh_mgmt_agent_runtime.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_mesh_bridge.h"

#include <CoroNet/turbo_coro_context.h>
#include <platform.h>

#include <string.h>

static int runtime_host_is_valid(const char *host) {
  size_t length = 0u;

  if (!host)
    return 0;
  while (length < P2P_MAX_IP && host[length] != '\0')
    length++;
  return length > 0u && length < P2P_MAX_IP;
}

static mesh_mgmt_agent_runtime_result_t runtime_fail(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                     mesh_mgmt_agent_runtime_result_t result) {
  runtime->last_error = result;
  runtime->in_api = 0u;
  return result;
}

static int runtime_event(void *context, p2p_peer_t *peer,
                         const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
                         const mesh_mgmt_dispatch_event_v1_t *event) {
  mesh_mgmt_agent_runtime_v1_t *runtime = (mesh_mgmt_agent_runtime_v1_t *)context;

  if (!runtime || !peer || !remote_transport_peer_id || !event ||
      runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING)
    return -1;
  if (event->type == MESH_MGMT_DISPATCH_EVENT_SESSION_ESTABLISHED) {
    runtime->last_endpoint_result = mesh_mgmt_endpoint_pool_mark_authenticated_v1(
        &runtime->endpoint_pool, remote_transport_peer_id, turbo_monotonic_ms());
    if (runtime->last_endpoint_result == MESH_MGMT_ENDPOINT_POOL_NOT_FOUND) {
      if (!runtime->admit_peer || runtime->admit_peer(runtime->callback_context, peer,
                                                      remote_transport_peer_id, event) != 0)
        return -1;
    } else if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK) {
      return -1;
    }
  }
  return runtime->on_event
             ? runtime->on_event(runtime->callback_context, peer, remote_transport_peer_id, event)
             : 0;
}

static void runtime_non_mmp(void *context, p2p_node_t *node, p2p_peer_t *peer, const void *bytes,
                            size_t length) {
  mesh_mgmt_agent_runtime_v1_t *runtime = (mesh_mgmt_agent_runtime_v1_t *)context;

  if (runtime && runtime->on_non_mmp)
    runtime->on_non_mmp(runtime->callback_context, node, peer, bytes, length);
}

static void runtime_failure(void *context, p2p_peer_t *peer,
                            mesh_mgmt_agent_router_result_t router_result,
                            mesh_mgmt_p2p_peer_result_t peer_result) {
  mesh_mgmt_agent_runtime_v1_t *runtime = (mesh_mgmt_agent_runtime_v1_t *)context;

  if (!runtime)
    return;
  runtime->last_router_result = router_result;
  if (runtime->on_failure)
    runtime->on_failure(runtime->callback_context, peer, router_result, peer_result);
}

static void runtime_peer_closed(void *context, p2p_peer_t *peer,
                                const uint8_t remote_transport_peer_id[P2P_KEY_SIZE],
                                mesh_mgmt_agent_router_close_reason_t reason) {
  mesh_mgmt_agent_runtime_v1_t *runtime = (mesh_mgmt_agent_runtime_v1_t *)context;

  if (!runtime)
    return;
  if (reason != MESH_MGMT_AGENT_ROUTER_CLOSE_LOCAL_STOP) {
    mesh_mgmt_endpoint_failure_t failure = reason == MESH_MGMT_AGENT_ROUTER_CLOSE_PROTOCOL
                                               ? MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL
                                               : MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT;
    runtime->last_endpoint_result = mesh_mgmt_endpoint_pool_mark_failed_v1(
        &runtime->endpoint_pool, remote_transport_peer_id, failure, turbo_monotonic_ms());
  }
  if (runtime->on_peer_closed)
    runtime->on_peer_closed(runtime->callback_context, peer, remote_transport_peer_id, reason);
}

static void runtime_release_initialized(mesh_mgmt_agent_runtime_v1_t *runtime) {
  mesh_mgmt_service_publisher_destroy_v1(&runtime->service_publisher);
  mesh_mgmt_endpoint_publisher_destroy_v1(&runtime->endpoint_publisher);
  mesh_mgmt_endpoint_pool_destroy_v1(&runtime->endpoint_pool);
  mesh_mgmt_agent_router_destroy_v1(&runtime->router);
  if (runtime->node && runtime->owns_node) {
    p2p_destroy(runtime->node);
  }
  runtime->node = NULL;
  runtime->shared_mesh = NULL;
  runtime->owns_node = 0u;
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_init_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                const mesh_mgmt_agent_runtime_config_v1_t *config) {
  mesh_mgmt_agent_router_config_v1_t router_config;
  mesh_mgmt_endpoint_pool_config_v1_t endpoint_config;
  int shared_mode;
  size_t index;

  if (!runtime || !config)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  shared_mode = config->shared_mesh != NULL;
  if ((!shared_mode &&
       (!runtime_host_is_valid(config->listen_host) || config->listen_port == 0u ||
        !config->p2p_private_key)) ||
      (shared_mode &&
       (config->listen_host || config->listen_port != 0u || config->p2p_private_key ||
        config->bootstrap_count != 0u)) ||
      config->max_peers == 0u ||
      config->max_peers > MESH_MGMT_AGENT_ROUTER_MAX_PEERS || !config->signer_template ||
      !config->dispatch_template || config->endpoint_capacity == 0u ||
      config->endpoint_capacity > MESH_MGMT_ENDPOINT_POOL_MAX_ENDPOINTS ||
      config->first_endpoint_record_epoch == 0u || config->first_service_record_epoch == 0u ||
      config->bootstrap_count > config->endpoint_capacity ||
      (config->bootstrap_count > 0u && !config->bootstraps))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED || runtime->node ||
      runtime->router.slots.data || runtime->endpoint_pool.entries.data ||
      runtime->endpoint_publisher.state != MESH_MGMT_ENDPOINT_PUBLISHER_UNINITIALIZED ||
      runtime->service_publisher.state != MESH_MGMT_SERVICE_PUBLISHER_UNINITIALIZED)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  memset(runtime, 0, sizeof(*runtime));
  runtime->last_p2p_result = P2P_OK;
  runtime->last_router_result = MESH_MGMT_AGENT_ROUTER_OK;
  runtime->last_endpoint_result = MESH_MGMT_ENDPOINT_POOL_OK;
  runtime->last_endpoint_record_result = MESH_MGMT_ENDPOINT_RECORD_OK;
  runtime->last_service_record_result = MESH_MGMT_SERVICE_RECORD_OK;
  runtime->last_publisher_result = MESH_MGMT_ENDPOINT_PUBLISHER_OK;
  runtime->last_service_publisher_result = MESH_MGMT_SERVICE_PUBLISHER_OK;
  if (shared_mode) {
    runtime->shared_mesh = config->shared_mesh;
    runtime->node = mesh_mgmt_mesh_borrow_p2p_node_v1(config->shared_mesh);
    if (!runtime->node) {
      runtime->last_error = MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
      return runtime->last_error;
    }
  } else {
    runtime->owns_node = 1u;
    runtime->node = p2p_create(config->listen_host, (int)config->listen_port);
    if (!runtime->node) {
      runtime->last_error = MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED;
      return runtime->last_error;
    }
    runtime->last_p2p_result = p2p_node_set_private_key(runtime->node, config->p2p_private_key);
    if (runtime->last_p2p_result != P2P_OK) {
      runtime_release_initialized(runtime);
      runtime->last_error = MESH_MGMT_AGENT_RUNTIME_P2P_FAILED;
      return runtime->last_error;
    }
  }

  runtime->admit_peer = config->admit_peer;
  runtime->on_event = config->on_event;
  runtime->on_non_mmp = config->on_non_mmp;
  runtime->on_failure = config->on_failure;
  runtime->on_peer_closed = config->on_peer_closed;
  runtime->callback_context = config->callback_context;

  memset(&router_config, 0, sizeof(router_config));
  router_config.node = runtime->node;
  router_config.max_peers = config->max_peers;
  router_config.signer_template = config->signer_template;
  router_config.dispatch_template = config->dispatch_template;
  router_config.random_bytes = config->random_bytes;
  router_config.random_context = config->random_context;
  router_config.on_event = runtime_event;
  router_config.on_non_mmp = runtime_non_mmp;
  router_config.on_failure = runtime_failure;
  router_config.on_peer_closed = runtime_peer_closed;
  router_config.callback_context = runtime;
  runtime->last_router_result = mesh_mgmt_agent_router_init_v1(&runtime->router, &router_config);
  if (runtime->last_router_result != MESH_MGMT_AGENT_ROUTER_OK) {
    runtime_release_initialized(runtime);
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED;
    return runtime->last_error;
  }

  runtime->last_publisher_result = mesh_mgmt_endpoint_publisher_init_v1(
      &runtime->endpoint_publisher, runtime->node, config->signer_template,
      config->first_endpoint_record_epoch);
  if (runtime->last_publisher_result != MESH_MGMT_ENDPOINT_PUBLISHER_OK) {
    runtime_release_initialized(runtime);
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED;
    return runtime->last_error;
  }

  runtime->last_service_publisher_result = mesh_mgmt_service_publisher_init_v1(
      &runtime->service_publisher, runtime->node, config->signer_template,
      config->first_service_record_epoch);
  if (runtime->last_service_publisher_result != MESH_MGMT_SERVICE_PUBLISHER_OK) {
    runtime_release_initialized(runtime);
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED;
    return runtime->last_error;
  }

  if (config->allocate_record_epoch &&
      (mesh_mgmt_endpoint_publisher_set_epoch_allocator_v1(
           &runtime->endpoint_publisher, config->allocate_record_epoch,
           config->record_epoch_context) != MESH_MGMT_ENDPOINT_PUBLISHER_OK ||
       mesh_mgmt_service_publisher_set_epoch_allocator_v1(
           &runtime->service_publisher, config->allocate_record_epoch,
           config->record_epoch_context) != MESH_MGMT_SERVICE_PUBLISHER_OK)) {
    runtime_release_initialized(runtime);
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED;
    return runtime->last_error;
  }

  memset(&endpoint_config, 0, sizeof(endpoint_config));
  endpoint_config.node = runtime->node;
  endpoint_config.capacity = config->endpoint_capacity;
  endpoint_config.retry_base_ms = config->retry_base_ms;
  endpoint_config.retry_max_ms = config->retry_max_ms;
  endpoint_config.connect_timeout_ms = config->connect_timeout_ms;
  endpoint_config.protocol_failure_limit = config->protocol_failure_limit;
  endpoint_config.random_bytes = config->random_bytes;
  endpoint_config.callback_context = config->random_context;
  runtime->last_endpoint_result =
      mesh_mgmt_endpoint_pool_init_v1(&runtime->endpoint_pool, &endpoint_config);
  if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK) {
    runtime_release_initialized(runtime);
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED;
    return runtime->last_error;
  }
  for (index = 0u; index < config->bootstrap_count; index++) {
    const mesh_mgmt_agent_bootstrap_v1_t *bootstrap = &config->bootstraps[index];
    runtime->last_endpoint_result = mesh_mgmt_endpoint_pool_add_static_v1(
        &runtime->endpoint_pool, bootstrap->transport_peer_id, bootstrap->host, bootstrap->port);
    if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK) {
      runtime_release_initialized(runtime);
      runtime->last_error = MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED;
      return runtime->last_error;
    }
  }
  runtime->state = MESH_MGMT_AGENT_RUNTIME_READY;
  runtime->last_error = MESH_MGMT_AGENT_RUNTIME_OK;
  return MESH_MGMT_AGENT_RUNTIME_OK;
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_start_v1(mesh_mgmt_agent_runtime_v1_t *runtime) {
  if (!runtime)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_READY || runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_router_result =
      runtime->shared_mesh
          ? mesh_mgmt_mesh_router_attach_v1(runtime->shared_mesh, &runtime->router)
          : mesh_mgmt_agent_router_install_v1(&runtime->router);
  if (runtime->last_router_result != MESH_MGMT_AGENT_ROUTER_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED);
  runtime->last_endpoint_result = mesh_mgmt_endpoint_pool_start_v1(&runtime->endpoint_pool);
  if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK) {
    if (runtime->shared_mesh)
      (void)mesh_mgmt_mesh_router_detach_v1(runtime->shared_mesh, &runtime->router);
    else
      (void)mesh_mgmt_agent_router_stop_v1(&runtime->router);
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED);
  }
  if (runtime->owns_node) {
    runtime->last_p2p_result = p2p_start_nonblocking(runtime->node);
    if (runtime->last_p2p_result != P2P_OK) {
      mesh_mgmt_endpoint_pool_stop_v1(&runtime->endpoint_pool);
      runtime->last_router_result = mesh_mgmt_agent_router_stop_v1(&runtime->router);
      return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_P2P_FAILED);
    }
  }
  runtime->state = MESH_MGMT_AGENT_RUNTIME_RUNNING;
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_poll_v1(mesh_mgmt_agent_runtime_v1_t *runtime) {
  if (!runtime)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  if (runtime->owns_node) {
    runtime->last_endpoint_result =
        mesh_mgmt_endpoint_pool_tick_v1(&runtime->endpoint_pool, turbo_monotonic_ms());
    if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK)
      return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED);
    (void)coro_context_run(p2p_get_loop(runtime->node), TURBO_RUN_NOWAIT);
  }
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_apply_endpoint_frame_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_endpoint_record_verify_input_v1_t *input) {
  mesh_mgmt_endpoint_record_v1_t record;

  if (!runtime || !input)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if ((runtime->state != MESH_MGMT_AGENT_RUNTIME_READY &&
       runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING) ||
      runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  memset(&record, 0, sizeof(record));
  runtime->last_endpoint_record_result = mesh_mgmt_endpoint_record_verify_v1(input, &record);
  if (runtime->last_endpoint_record_result != MESH_MGMT_ENDPOINT_RECORD_OK) {
    mesh_mgmt_crypto_wipe(&record, sizeof(record));
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_RECORD_FAILED);
  }
  runtime->last_endpoint_result =
      mesh_mgmt_endpoint_pool_apply_verified_v1(&runtime->endpoint_pool, &record, input->now_ms);
  mesh_mgmt_crypto_wipe(&record, sizeof(record));
  if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED);
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_apply_cached_endpoint_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime, const mesh_mgmt_agent_cached_endpoint_v1_t *input) {
  mesh_mgmt_endpoint_record_verify_input_v1_t verify_input;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  char key[MESH_MGMT_ENDPOINT_DHT_KEY_V1_SIZE];
  size_t frame_len = sizeof(frame);
  size_t key_len = 0u;
  mesh_mgmt_agent_runtime_result_t result;

  if (!runtime || !input || !input->mesh_id_hash || !input->owner_node_id || !input->certificate ||
      !input->trusted_issuer_key)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if ((runtime->state != MESH_MGMT_AGENT_RUNTIME_READY &&
       runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING) ||
      runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->last_endpoint_record_result = mesh_mgmt_endpoint_dht_key_build_v1(
      input->mesh_id_hash, input->owner_node_id, key, sizeof(key), &key_len);
  if (runtime->last_endpoint_record_result != MESH_MGMT_ENDPOINT_RECORD_OK ||
      key_len != MESH_MGMT_ENDPOINT_DHT_KEY_V1_LENGTH)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_RECORD_FAILED);

  runtime->last_p2p_result = p2p_dht_get_cached(runtime->node, key, frame, &frame_len);
  if (runtime->last_p2p_result != P2P_OK) {
    mesh_mgmt_crypto_wipe(frame, sizeof(frame));
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED);
  }

  memset(&verify_input, 0, sizeof(verify_input));
  verify_input.frame = frame;
  verify_input.frame_len = frame_len;
  verify_input.certificate = input->certificate;
  verify_input.certificate_len = input->certificate_len;
  verify_input.trusted_issuer_key = input->trusted_issuer_key;
  verify_input.expected_mesh_id_hash = input->mesh_id_hash;
  verify_input.expected_owner_node_id = input->owner_node_id;
  verify_input.now_ms = input->now_ms;
  verify_input.max_ttl_ms = input->max_ttl_ms;
  result = mesh_mgmt_agent_runtime_apply_endpoint_frame_v1(runtime, &verify_input);
  mesh_mgmt_crypto_wipe(frame, sizeof(frame));
  return result;
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_read_cached_service_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                               const mesh_mgmt_agent_cached_service_v1_t *input,
                                               mesh_mgmt_service_record_v1_t *out_record) {
  mesh_mgmt_service_record_verify_input_v1_t verify_input;
  mesh_mgmt_service_record_v1_t record;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  char key[MESH_MGMT_SERVICE_DHT_KEY_V1_SIZE];
  size_t frame_len = sizeof(frame);
  size_t key_len = 0u;

  if (!out_record)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  memset(out_record, 0, sizeof(*out_record));
  if (!runtime || !input || !input->mesh_id_hash || !input->owner_node_id ||
      !input->certificate || !input->trusted_issuer_key)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if ((runtime->state != MESH_MGMT_AGENT_RUNTIME_READY &&
       runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING) ||
      runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_service_record_result = mesh_mgmt_service_dht_key_build_v1(
      input->mesh_id_hash, input->owner_node_id, key, sizeof(key), &key_len);
  if (runtime->last_service_record_result != MESH_MGMT_SERVICE_RECORD_OK ||
      key_len != MESH_MGMT_SERVICE_DHT_KEY_V1_LENGTH)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_SERVICE_RECORD_FAILED);

  runtime->last_p2p_result = p2p_dht_get_cached(runtime->node, key, frame, &frame_len);
  if (runtime->last_p2p_result != P2P_OK) {
    mesh_mgmt_crypto_wipe(frame, sizeof(frame));
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED);
  }

  memset(&verify_input, 0, sizeof(verify_input));
  verify_input.frame = frame;
  verify_input.frame_len = frame_len;
  verify_input.certificate = input->certificate;
  verify_input.certificate_len = input->certificate_len;
  verify_input.trusted_issuer_key = input->trusted_issuer_key;
  verify_input.expected_mesh_id_hash = input->mesh_id_hash;
  verify_input.expected_owner_node_id = input->owner_node_id;
  verify_input.now_ms = input->now_ms;
  verify_input.max_ttl_ms = input->max_ttl_ms;
  memset(&record, 0, sizeof(record));
  runtime->last_service_record_result =
      mesh_mgmt_service_record_verify_v1(&verify_input, &record);
  mesh_mgmt_crypto_wipe(frame, sizeof(frame));
  if (runtime->last_service_record_result != MESH_MGMT_SERVICE_RECORD_OK) {
    mesh_mgmt_crypto_wipe(&record, sizeof(record));
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_SERVICE_RECORD_FAILED);
  }

  memcpy(out_record, &record, sizeof(*out_record));
  mesh_mgmt_crypto_wipe(&record, sizeof(record));
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_resolve_cached_service_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                  const uint8_t owner_node_id[32],
                                                  uint64_t now_ms, uint64_t max_ttl_ms,
                                                  mesh_mgmt_service_record_v1_t *out_record) {
  mesh_mgmt_agent_router_identity_snapshot_v1_t identity;
  mesh_mgmt_agent_cached_service_v1_t input;
  mesh_mgmt_agent_runtime_result_t result;

  if (!out_record)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  memset(out_record, 0, sizeof(*out_record));
  if (!runtime || !owner_node_id || now_ms == 0u || max_ttl_ms == 0u)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if ((runtime->state != MESH_MGMT_AGENT_RUNTIME_READY &&
       runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING) ||
      runtime->in_api || !runtime->node || !runtime->router.dispatch_template)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  memset(&identity, 0, sizeof(identity));
  runtime->last_router_result = mesh_mgmt_agent_router_identity_snapshot_v1(
      &runtime->router, owner_node_id, &identity);
  if (runtime->last_router_result != MESH_MGMT_AGENT_ROUTER_OK) {
    mesh_mgmt_crypto_wipe(&identity, sizeof(identity));
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED);
  }

  memset(&input, 0, sizeof(input));
  input.mesh_id_hash =
      runtime->router.dispatch_template->session.expected_mesh_id_hash;
  input.owner_node_id = identity.managed_node_id;
  input.certificate = identity.certificate;
  input.certificate_len = identity.certificate_len;
  input.trusted_issuer_key =
      runtime->router.dispatch_template->session.trusted_issuer_key;
  input.now_ms = now_ms;
  input.max_ttl_ms = max_ttl_ms;
  result = mesh_mgmt_agent_runtime_read_cached_service_v1(runtime, &input, out_record);
  mesh_mgmt_crypto_wipe(&identity, sizeof(identity));
  return result;
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_publish_cached_endpoint_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                   const mesh_mgmt_endpoint_publish_v1_t *endpoint,
                                                   uint64_t *out_record_epoch) {
  if (!runtime || !endpoint || !out_record_epoch)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  *out_record_epoch = 0u;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_publisher_result = mesh_mgmt_endpoint_publisher_publish_cached_v1(
      &runtime->endpoint_publisher, endpoint, out_record_epoch);
  if (runtime->last_publisher_result != MESH_MGMT_ENDPOINT_PUBLISHER_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_publish_cached_service_v1(mesh_mgmt_agent_runtime_v1_t *runtime,
                                                  const mesh_mgmt_service_publish_v1_t *service,
                                                  uint64_t *out_record_epoch) {
  if (!runtime || !service || !out_record_epoch)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  *out_record_epoch = 0u;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_service_publisher_result = mesh_mgmt_service_publisher_publish_cached_v1(
      &runtime->service_publisher, service, out_record_epoch);
  if (runtime->last_service_publisher_result != MESH_MGMT_SERVICE_PUBLISHER_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_stop_v1(mesh_mgmt_agent_runtime_v1_t *runtime) {
  if (!runtime)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  mesh_mgmt_endpoint_pool_stop_v1(&runtime->endpoint_pool);
  runtime->last_router_result =
      runtime->shared_mesh
          ? mesh_mgmt_mesh_router_detach_v1(runtime->shared_mesh, &runtime->router)
          : mesh_mgmt_agent_router_stop_v1(&runtime->router);
  if (runtime->last_router_result != MESH_MGMT_AGENT_ROUTER_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED);
  if (runtime->owns_node)
    p2p_destroy(runtime->node);
  runtime->node = NULL;
  runtime->shared_mesh = NULL;
  runtime->owns_node = 0u;
  runtime->state = MESH_MGMT_AGENT_RUNTIME_STOPPED;
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

void mesh_mgmt_agent_runtime_destroy_v1(mesh_mgmt_agent_runtime_v1_t *runtime) {
  if (!runtime || runtime->in_api)
    return;
  if (runtime->state == MESH_MGMT_AGENT_RUNTIME_RUNNING &&
      mesh_mgmt_agent_runtime_stop_v1(runtime) != MESH_MGMT_AGENT_RUNTIME_OK)
    return;
  runtime_release_initialized(runtime);
  mesh_mgmt_crypto_wipe(runtime, sizeof(*runtime));
}

mesh_mgmt_execution_consumer_result_t
mesh_mgmt_agent_runtime_execution_command_from_event_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms,
    mesh_mgmt_execution_shadow_command_v1_t *out_command) {
  if (!runtime || !peer || !event || !out_command || now_ms == 0u)
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING)
    return MESH_MGMT_EXECUTION_CONSUMER_INVALID_STATE;
  return mesh_mgmt_agent_router_execution_command_from_event_v1(
      &runtime->router, peer, event, now_ms, out_command);
}

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_runtime_send_execution_status_from_command_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_execution_shadow_command_v1_t *command,
    uint16_t status_code) {
  if (!runtime || !peer || !command)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  return mesh_mgmt_agent_router_send_execution_status_from_command_v1(
      &runtime->router, peer, command, status_code);
}

mesh_mgmt_execution_response_consumer_result_t
mesh_mgmt_agent_runtime_execution_response_from_event_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    mesh_mgmt_execution_response_v1_t *out_response) {
  if (!runtime || !peer || !event || !out_response)
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING)
    return MESH_MGMT_EXECUTION_RESPONSE_CONSUMER_INVALID_STATE;
  return mesh_mgmt_agent_router_execution_response_from_event_v1(
      &runtime->router, peer, event, out_response);
}

mesh_mgmt_execution_disabled_responder_result_t
mesh_mgmt_agent_runtime_send_execution_disabled_from_event_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    p2p_peer_t *peer,
    const mesh_mgmt_dispatch_event_v1_t *event,
    uint64_t now_ms) {
  if (!runtime || !peer || !event || now_ms == 0u)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING)
    return MESH_MGMT_EXECUTION_DISABLED_RESPONDER_INVALID_STATE;
  return mesh_mgmt_agent_router_send_execution_disabled_from_event_v1(
      &runtime->router, peer, event, now_ms);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_send_execution_request_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len) {
  mesh_mgmt_agent_router_result_t router_result;

  if (!runtime || !target_node_id || !payload || payload_len == 0u)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api ||
      !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  router_result = mesh_mgmt_agent_router_send_execution_request_v1(
      &runtime->router, target_node_id, payload, payload_len);
  runtime->last_router_result = router_result;
  runtime->in_api = 0u;
  if (router_result == MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND) {
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED;
    return runtime->last_error;
  }
  if (router_result != MESH_MGMT_AGENT_ROUTER_OK) {
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_SEND_FAILED;
    return runtime->last_error;
  }
  runtime->last_error = MESH_MGMT_AGENT_RUNTIME_OK;
  return MESH_MGMT_AGENT_RUNTIME_OK;
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_send_execution_response_v1(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    uint8_t kind,
    const uint8_t target_node_id[32],
    const uint8_t *payload,
    size_t payload_len) {
  mesh_mgmt_agent_router_result_t router_result;

  if (!runtime || !target_node_id || !payload || payload_len == 0u ||
      (kind != MESH_MGMT_KIND_COMMAND_RESULT &&
       kind != MESH_MGMT_KIND_COMMAND_STATUS))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api ||
      !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  router_result = mesh_mgmt_agent_router_send_execution_response_v1(
      &runtime->router, kind, target_node_id, payload, payload_len);
  runtime->last_router_result = router_result;
  runtime->in_api = 0u;
  if (router_result == MESH_MGMT_AGENT_ROUTER_PEER_NOT_FOUND) {
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_DISCOVERY_FAILED;
    return runtime->last_error;
  }
  if (router_result != MESH_MGMT_AGENT_ROUTER_OK) {
    runtime->last_error = MESH_MGMT_AGENT_RUNTIME_SEND_FAILED;
    return runtime->last_error;
  }
  runtime->last_error = MESH_MGMT_AGENT_RUNTIME_OK;
  return MESH_MGMT_AGENT_RUNTIME_OK;
}
