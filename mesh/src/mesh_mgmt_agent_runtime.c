#include "mesh_mgmt_agent_runtime.h"

#include "mesh_mgmt_crypto.h"
#include "mesh_mgmt_agent_runtime_internal.h"
#include "core/peer_cnet.h"

#include <salts/clock.h>

#include <string.h>
#include <stdlib.h>

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


/* The real CNet Manager and ClientPool are the only physical/lease credit
 * authorities. Runtime's bounded index owns callback/teardown association,
 * not a second pool, admission strategy or retry/backoff timer. */
static mesh_mgmt_runtime_pool_record_v3_t *pool_slot_by_peer(
    mesh_mgmt_agent_runtime_v1_t *runtime, const p2p_peer_t *peer) {
  if (!runtime || !runtime->signed_pool_records || !peer) return NULL;
  for (size_t i = 0u; i < runtime->signed_pool_capacity; ++i) {
    mesh_mgmt_runtime_pool_record_v3_t *record = &runtime->signed_pool_records[i];
    if (record->active && record->peer == peer && !record->draining)
      return record;
  }
  return NULL;
}

static mesh_mgmt_runtime_pool_record_v3_t *pool_free_slot(
    mesh_mgmt_agent_runtime_v1_t *runtime) {
  for (size_t i = 0u; i < runtime->signed_pool_capacity; ++i) {
    mesh_mgmt_runtime_pool_record_v3_t *record = &runtime->signed_pool_records[i];
    if (!record->active) return record;
  }
  return NULL;
}

static int runtime_pool_init_for_manager(
    mesh_mgmt_agent_runtime_v1_t *runtime, cnet_manager *manager) {
  cnet_manager_snapshot snapshot = {0};
  cnet_pool_config cfg = {0};
  int status;
  if (runtime->signed_pool.impl)
    return runtime->signed_pool_manager == manager ? SALTS_OK : SALTS_EINVAL;
  status = cnet_manager_get_snapshot(manager, &snapshot);
  if (status != SALTS_OK) return status;
  if (snapshot.sealed ||
      snapshot.connection_capacity < runtime->signed_pool_capacity)
    return SALTS_ENOBUFS;
  cfg.size = sizeof(cfg);
  cfg.version = CNET_CLIENT_POOL_VERSION;
  cfg.manager = manager;
  cfg.owner_id = runtime->signed_pool_owner_id;
  cfg.max_connections = runtime->signed_pool_capacity;
  cfg.max_connecting = runtime->signed_pool_capacity;
  cfg.max_leases = runtime->signed_pool_max_leases;
  status = cnet_pool_init(&runtime->signed_pool, &cfg);
  if (status == SALTS_OK) runtime->signed_pool_manager = manager;
  return status;
}

static int runtime_pool_authenticated(
    mesh_mgmt_agent_runtime_v1_t *runtime, p2p_peer_t *peer) {
  mesh_mgmt_agent_router_ready_v1_t signed_ready = {0};
  p2p_cnet_managed_binding_v1_t exact = {0};
  cnet_pool_connection physical = {0};
  cnet_pool_key key = {0};
  mesh_mgmt_runtime_pool_record_v3_t *record;
  mesh_mgmt_agent_router_result_t auth;
  int status;
  if (!runtime->signed_pool_enabled || runtime->shared_mesh)
    return SALTS_OK;
  if (!peer || !peer->conn) return SALTS_EPROTO;
  /* Outbound P2P numeric CNet is deliberately not Manager-owned yet.
   * Do NOT silently place it under the incoming-side Pool or deny the
   * already valid signed MMP endpoint just for not supporting pooling. */
  if (peer->conn->type == P2P_CONN_OUTBOUND) return SALTS_OK;
  if (pool_slot_by_peer(runtime, peer)) return SALTS_EALREADY;
  if (p2p_peer_cnet_managed_binding_v1(peer, &exact) != P2P_OK)
    return SALTS_EPROTO;
  auth = mesh_mgmt_agent_router_ready_peer_v1(&runtime->router, peer, &signed_ready);
  if (auth != MESH_MGMT_AGENT_ROUTER_OK) return SALTS_EPROTO;
  record = pool_free_slot(runtime);
  if (!record) return SALTS_ENOBUFS;
  status = runtime_pool_init_for_manager(runtime, exact.manager);
  if (status != SALTS_OK) return status;
  /* Router rechecks the signed READY proof and same Manager BOUND CNet
   * generation immediately before/after native CNet Pool reservation. */
  auth = mesh_mgmt_agent_router_pool_bind_ready_v1(
      &runtime->router, peer, signed_ready.remote_transport_peer_id,
      signed_ready.remote_managed_node_id, signed_ready.connection_id,
      exact.manager, &runtime->signed_pool, runtime->signed_pool_owner_id,
      &physical, &key);
  if (auth != MESH_MGMT_AGENT_ROUTER_OK)
    return auth == MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED
      ? SALTS_ENOBUFS : SALTS_EPROTO;
  memset(record, 0, sizeof(*record));
  record->peer = peer;
  record->physical = physical;
  record->managed = exact.managed;
  record->key = key;
  memcpy(record->connection_id, signed_ready.connection_id,
         sizeof(record->connection_id));
  record->active = 1u;
  return SALTS_OK;
}

/* Called from the original Router closed callback while peer storage
 * remains borrowed. Only mark DRAINING here; native Manager may still be
 * BOUND until its real CNet terminal callback returns. Never fabricate
 * a transport terminal or release a session's application lease here. */
static int runtime_pool_drain_record(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    mesh_mgmt_runtime_pool_record_v3_t *record) {
  int status;
  if (!record || !record->active || record->draining) return SALTS_OK;
  status = cnet_pool_begin_drain(&runtime->signed_pool, record->physical);
  if (status != SALTS_OK) return status;
  record->draining = 1u;
  record->peer = NULL; /* cannot dereference after Router returns */
  return SALTS_OK;
}

static int runtime_pool_closed(mesh_mgmt_agent_runtime_v1_t *runtime,
                               p2p_peer_t *peer) {
  if (!runtime->signed_pool_enabled || !runtime->signed_pool.impl)
    return SALTS_OK;
  mesh_mgmt_runtime_pool_record_v3_t *record = pool_slot_by_peer(runtime, peer);
  return runtime_pool_drain_record(runtime, record);
}

/* Run only after the one physical P2P/CNet Owner has advanced. The upstream
 * Manager (not Router's logical close event) authoritatively determines
 * whether an actual CNet physical record reached RETIRED/recycled. */
static int runtime_pool_advance(mesh_mgmt_agent_runtime_v1_t *runtime) {
  if (!runtime->signed_pool.impl) return SALTS_OK;
  for (size_t i = 0u; i < runtime->signed_pool_capacity; ++i) {
    mesh_mgmt_runtime_pool_record_v3_t *record = &runtime->signed_pool_records[i];
    if (!record->active || !record->draining) continue;
    cnet_manager_entry physical = {0};
    int status = cnet_manager_lookup(runtime->signed_pool_manager,
                                    record->managed, &physical);
    if (status == SALTS_OK && physical.state != CNET_MANAGER_RETIRED)
      continue; /* TCP still CONNECTING/CONNECTED/CLOSING, not terminal */
    if (status != SALTS_OK && status != SALTS_ENOENT) return status;
    status = cnet_pool_terminal(&runtime->signed_pool, record->physical);
    if (status != SALTS_OK) return status;
    memset(record, 0, sizeof(*record));
    /* Pool's real lease records retain the old physical generation if a
     * caller still borrows a lease, even after this index can be recycled. */
  }
  return SALTS_OK;
}

static int runtime_pool_seal_and_drain(mesh_mgmt_agent_runtime_v1_t *runtime) {
  int status;
  if (!runtime->signed_pool.impl) return SALTS_OK;
  status = cnet_pool_seal(&runtime->signed_pool);
  if (status != SALTS_OK) return status;
  for (size_t i = 0u; i < runtime->signed_pool_capacity; ++i) {
    status = runtime_pool_drain_record(runtime, &runtime->signed_pool_records[i]);
    if (status != SALTS_OK) return status;
  }
  return SALTS_OK;
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
        &runtime->endpoint_pool, remote_transport_peer_id, cmeta_monotonic_ms());
    if (runtime->last_endpoint_result == MESH_MGMT_ENDPOINT_POOL_NOT_FOUND) {
      if (!runtime->admit_peer || runtime->admit_peer(runtime->callback_context, peer,
                                                      remote_transport_peer_id, event) != 0)
        return -1;
    } else if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK) {
      return -1;
    }
    runtime->signed_pool_status = runtime_pool_authenticated(runtime, peer);
    if (runtime->signed_pool_status != SALTS_OK) return -1;
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
  if (runtime->signed_pool_enabled) {
    const int status = runtime_pool_closed(runtime, peer);
    if (status != SALTS_OK) runtime->signed_pool_status = status;
  }
  if (reason != MESH_MGMT_AGENT_ROUTER_CLOSE_LOCAL_STOP) {
    mesh_mgmt_endpoint_failure_t failure = reason == MESH_MGMT_AGENT_ROUTER_CLOSE_PROTOCOL
                                               ? MESH_MGMT_ENDPOINT_FAILURE_PROTOCOL
                                               : MESH_MGMT_ENDPOINT_FAILURE_TRANSPORT;
    runtime->last_endpoint_result = mesh_mgmt_endpoint_pool_mark_failed_v1(
        &runtime->endpoint_pool, remote_transport_peer_id, failure, cmeta_monotonic_ms());
  }
  if (runtime->on_peer_closed)
    runtime->on_peer_closed(runtime->callback_context, peer, remote_transport_peer_id, reason);
}

static int runtime_is_busy(const mesh_mgmt_agent_runtime_v1_t *runtime) {
  return runtime->in_api || runtime->router.callback_depth != 0u ||
         runtime->endpoint_pool.in_api || runtime->endpoint_publisher.in_api ||
         runtime->service_publisher.in_api;
}

/* Call only after the owned node is gone and the shared router is detached. */
static void runtime_release_initialized(mesh_mgmt_agent_runtime_v1_t *runtime) {
  /* All Pool leases and physical entries were drained and destroyed by
   * runtime_stop_initialized while the P2P Manager was still alive. */
  free(runtime->signed_pool_records);
  runtime->signed_pool_records = NULL;
  mesh_mgmt_service_publisher_destroy_v1(&runtime->service_publisher);
  mesh_mgmt_endpoint_publisher_destroy_v1(&runtime->endpoint_publisher);
  mesh_mgmt_endpoint_pool_destroy_v1(&runtime->endpoint_pool);
  mesh_mgmt_agent_router_destroy_v1(&runtime->router);
  mesh_mgmt_p2p_security_provider_destroy_v2(&runtime->p2p_security_provider);
}

static mesh_mgmt_agent_runtime_result_t runtime_stop_initialized(
    mesh_mgmt_agent_runtime_v1_t *runtime) {
  runtime->state = MESH_MGMT_AGENT_RUNTIME_STOPPING;
  mesh_mgmt_endpoint_pool_stop_v1(&runtime->endpoint_pool);
  if (runtime->signed_pool.impl) {
    runtime->signed_pool_status = runtime_pool_seal_and_drain(runtime);
    if (runtime->signed_pool_status != SALTS_OK)
      return MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
  }
  if (runtime->router.state == MESH_MGMT_AGENT_ROUTER_INSTALLED) {
    runtime->last_router_result = runtime->shared_mesh
        ? runtime->mesh_ops->detach(runtime->shared_mesh, &runtime->router)
        : mesh_mgmt_agent_router_stop_v1(&runtime->router);
    if (runtime->last_router_result != MESH_MGMT_AGENT_ROUTER_OK)
      return MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED;
  }
  if (runtime->signed_pool.impl) {
    cnet_pool_snapshot snapshot = {0};
    /* The Pool borrows the live P2P Manager: real physical terminal MUST
     * progress, and every application lease MUST be released, before
     * P2P's CNet Owner/Manager can be destroyed. No new timer or retry
     * policy; this bounded close-only loop advances the existing Owner.
     * On still-running IO or outstanding leases retain everything and
     * let the caller retry stop after returning its borrowed leases. */
    for (unsigned pass = 0u; pass < 64u; ++pass) {
      runtime->signed_pool_status = runtime_pool_advance(runtime);
      if (runtime->signed_pool_status != SALTS_OK)
        return MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
      runtime->signed_pool_status =
          cnet_pool_get_snapshot(&runtime->signed_pool, &snapshot);
      if (runtime->signed_pool_status != SALTS_OK)
        return MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
      if (snapshot.drained) break;
      int pending_physical = 0;
      for (size_t i = 0u; i < runtime->signed_pool_capacity; ++i)
        if (runtime->signed_pool_records[i].active) pending_physical = 1;
      if (!pending_physical) break; /* only borrowed leases remain */
      if (!runtime->node || !runtime->owns_node)
        return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
      runtime->last_p2p_result = p2p_poll(runtime->node);
      if (runtime->last_p2p_result != P2P_OK)
        return MESH_MGMT_AGENT_RUNTIME_P2P_FAILED;
    }
    runtime->signed_pool_status =
        cnet_pool_get_snapshot(&runtime->signed_pool, &snapshot);
    if (runtime->signed_pool_status != SALTS_OK)
      return MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
    if (!snapshot.drained)
      return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
    runtime->signed_pool_status = cnet_pool_destroy(&runtime->signed_pool);
    if (runtime->signed_pool_status != SALTS_OK)
      return MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
    runtime->signed_pool_manager = NULL;
  }
  if (runtime->node && runtime->owns_node) {
    runtime->last_p2p_result = p2p_destroy_v2(runtime->node);
    if (runtime->last_p2p_result != P2P_OK)
      return MESH_MGMT_AGENT_RUNTIME_P2P_FAILED;
  }
  runtime->node = NULL;
  runtime->shared_mesh = NULL;
  runtime->mesh_ops = NULL;
  runtime->owns_node = 0u;
  runtime->state = MESH_MGMT_AGENT_RUNTIME_STOPPED;
  return MESH_MGMT_AGENT_RUNTIME_OK;
}

static mesh_mgmt_agent_runtime_result_t runtime_init_failed(
    mesh_mgmt_agent_runtime_v1_t *runtime, mesh_mgmt_agent_runtime_result_t cause) {
  int p2p_cause = runtime->last_p2p_result;
  mesh_mgmt_agent_runtime_result_t cleanup = runtime_stop_initialized(runtime);
  if (cleanup != MESH_MGMT_AGENT_RUNTIME_OK)
    return runtime_fail(runtime, cleanup);
  runtime_release_initialized(runtime);
  runtime->state = MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED;
  runtime->last_p2p_result = p2p_cause;
  return runtime_fail(runtime, cause);
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_init_v2(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_agent_runtime_config_v1_t *config,
    const p2p_runtime_config_v2_t *p2p_config) {
  if (!config || config->shared_mesh || !p2p_config ||
      p2p_config->struct_size != sizeof(*p2p_config))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  return mesh_mgmt_agent_runtime_init_bound(runtime, config, p2p_config, NULL);
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_init_bound(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_agent_runtime_config_v1_t *config,
    const p2p_runtime_config_v2_t *p2p_config,
    const mesh_mgmt_agent_mesh_binding_t *binding) {
  mesh_mgmt_agent_router_config_v1_t router_config;
  mesh_mgmt_endpoint_pool_config_v1_t endpoint_config;
  mesh_mgmt_p2p_security_config_v2_t security_config;
  p2p_security_config_v2_t p2p_security_config;
  int shared_mode;
  size_t index;

  if (!runtime || !config)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  shared_mode = config->shared_mesh != NULL;
  if ((!shared_mode &&
       (!runtime_host_is_valid(config->listen_host) || !config->p2p_private_key ||
        !p2p_config || p2p_config->struct_size != sizeof(*p2p_config))) ||
      (shared_mode &&
       (!binding || !binding->node || !binding->ops ||
        !binding->ops->attach || !binding->ops->detach || config->listen_host ||
        config->listen_port != 0u || config->p2p_private_key ||
        config->bootstrap_count != 0u ||
        config->p2p_minimum_principal_epoch != 0u ||
        config->p2p_required_remote_roles != 0u ||
        config->p2p_revoked_certificate_serial_count != 0u)) ||
      config->max_peers == 0u ||
      config->max_peers > MESH_MGMT_AGENT_ROUTER_MAX_PEERS || !config->signer_template ||
      !config->dispatch_template || config->endpoint_capacity == 0u ||
      (config->p2p_revoked_certificate_serial_count > 0u &&
       !config->p2p_revoked_certificate_serials) ||
      config->p2p_revoked_certificate_serial_count >
          MESH_MGMT_P2P_REVOKED_SERIAL_LIMIT ||
      config->endpoint_capacity > MESH_MGMT_ENDPOINT_POOL_MAX_ENDPOINTS ||
      config->first_endpoint_record_epoch == 0u || config->first_service_record_epoch == 0u ||
      config->bootstrap_count > config->endpoint_capacity ||
      (config->bootstrap_count > 0u && !config->bootstraps))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime_is_busy(runtime) ||
      runtime->state != MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED || runtime->node ||
      runtime->router.slots.data || runtime->endpoint_pool.entries.data ||
      runtime->signed_pool.impl || runtime->signed_pool_records ||
      runtime->endpoint_publisher.state != MESH_MGMT_ENDPOINT_PUBLISHER_UNINITIALIZED ||
      runtime->service_publisher.state != MESH_MGMT_SERVICE_PUBLISHER_UNINITIALIZED)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  memset(runtime, 0, sizeof(*runtime));
  runtime->in_api = 1u;
  runtime->last_p2p_result = P2P_OK;
  runtime->last_router_result = MESH_MGMT_AGENT_ROUTER_OK;
  runtime->last_endpoint_result = MESH_MGMT_ENDPOINT_POOL_OK;
  runtime->signed_pool_status = SALTS_OK;
  runtime->last_endpoint_record_result = MESH_MGMT_ENDPOINT_RECORD_OK;
  runtime->last_service_record_result = MESH_MGMT_SERVICE_RECORD_OK;
  runtime->last_publisher_result = MESH_MGMT_ENDPOINT_PUBLISHER_OK;
  runtime->last_service_publisher_result = MESH_MGMT_SERVICE_PUBLISHER_OK;
  if (shared_mode) {
    runtime->shared_mesh = config->shared_mesh;
    runtime->node = binding->node;
    runtime->mesh_ops = binding->ops;
  } else {
    runtime->p2p_config = *p2p_config;
    runtime->owns_node = 1u;
    runtime->last_p2p_result = p2p_create_v2(
        config->listen_host, (int)config->listen_port, &runtime->node);
    if (runtime->last_p2p_result != P2P_OK)
      return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_P2P_FAILED);
    runtime->last_p2p_result = p2p_node_set_private_key(runtime->node, config->p2p_private_key);
    if (runtime->last_p2p_result != P2P_OK) {
      return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_P2P_FAILED);
    }
    memset(&security_config, 0, sizeof(security_config));
    security_config.local_certificate =
        config->signer_template->hello.certificate;
    security_config.local_certificate_len =
        sizeof(config->signer_template->hello.certificate);
    security_config.trusted_issuer_key =
        config->dispatch_template->session.trusted_issuer_key;
    security_config.mesh_id_hash =
        config->dispatch_template->session.expected_mesh_id_hash;
    security_config.minimum_principal_epoch =
        config->p2p_minimum_principal_epoch;
    security_config.required_remote_roles =
        config->p2p_required_remote_roles;
    security_config.revoked_serials =
        config->p2p_revoked_certificate_serials;
    security_config.revoked_serial_count =
        config->p2p_revoked_certificate_serial_count;
    security_config.now_ms = config->signer_template->now_ms;
    security_config.now_context = config->signer_template->callback_context;
    runtime->last_p2p_result = mesh_mgmt_p2p_security_provider_init_v2(
        &runtime->p2p_security_provider, &security_config,
        &p2p_security_config);
    if (runtime->last_p2p_result == P2P_OK) {
      runtime->last_p2p_result = p2p_node_configure_security_v2(
          runtime->node, &p2p_security_config);
    }
    if (runtime->last_p2p_result != P2P_OK) {
      return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_P2P_FAILED);
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
    return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED);
  }

  runtime->last_publisher_result = mesh_mgmt_endpoint_publisher_init_v1(
      &runtime->endpoint_publisher, runtime->node, config->signer_template,
      config->first_endpoint_record_epoch);
  if (runtime->last_publisher_result != MESH_MGMT_ENDPOINT_PUBLISHER_OK) {
    return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  }

  runtime->last_service_publisher_result = mesh_mgmt_service_publisher_init_v1(
      &runtime->service_publisher, runtime->node, config->signer_template,
      config->first_service_record_epoch);
  if (runtime->last_service_publisher_result != MESH_MGMT_SERVICE_PUBLISHER_OK) {
    return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
  }

  if (config->allocate_record_epoch &&
      (mesh_mgmt_endpoint_publisher_set_epoch_allocator_v1(
           &runtime->endpoint_publisher, config->allocate_record_epoch,
           config->record_epoch_context) != MESH_MGMT_ENDPOINT_PUBLISHER_OK ||
       mesh_mgmt_service_publisher_set_epoch_allocator_v1(
           &runtime->service_publisher, config->allocate_record_epoch,
           config->record_epoch_context) != MESH_MGMT_SERVICE_PUBLISHER_OK)) {
    return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_PUBLISH_FAILED);
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
    return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED);
  }
  for (index = 0u; index < config->bootstrap_count; index++) {
    const mesh_mgmt_agent_bootstrap_v1_t *bootstrap = &config->bootstraps[index];
    runtime->last_endpoint_result = mesh_mgmt_endpoint_pool_add_static_v1(
        &runtime->endpoint_pool, bootstrap->transport_peer_id, bootstrap->host, bootstrap->port);
    if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK) {
      return runtime_init_failed(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED);
    }
  }
  runtime->state = MESH_MGMT_AGENT_RUNTIME_READY;
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_start_v1(mesh_mgmt_agent_runtime_v1_t *runtime) {
  if (!runtime)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_READY || runtime_is_busy(runtime) || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_router_result =
      runtime->shared_mesh
          ? runtime->mesh_ops->attach(runtime->shared_mesh, &runtime->router)
          : mesh_mgmt_agent_router_install_v1(&runtime->router);
  if (runtime->last_router_result != MESH_MGMT_AGENT_ROUTER_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ROUTER_FAILED);
  runtime->last_endpoint_result = mesh_mgmt_endpoint_pool_start_v1(&runtime->endpoint_pool);
  if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK) {
    mesh_mgmt_agent_runtime_result_t cleanup = runtime_stop_initialized(runtime);
    return runtime_fail(runtime, cleanup == MESH_MGMT_AGENT_RUNTIME_OK
        ? MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED : cleanup);
  }
  if (runtime->owns_node) {
    runtime->last_p2p_result = p2p_start_nonblocking_v2(runtime->node, &runtime->p2p_config);
    if (runtime->last_p2p_result != P2P_OK) {
      /* Every runtime start attempt is terminal on failure; v2 node startup
       * may already have entered draining, so do not advertise READY. */
      int start_result = runtime->last_p2p_result;
      mesh_mgmt_agent_runtime_result_t cleanup = runtime_stop_initialized(runtime);
      if (cleanup == MESH_MGMT_AGENT_RUNTIME_OK)
        runtime->last_p2p_result = start_result;
      return runtime_fail(runtime, cleanup == MESH_MGMT_AGENT_RUNTIME_OK
          ? MESH_MGMT_AGENT_RUNTIME_P2P_FAILED : cleanup);
    }
  }
  runtime->state = MESH_MGMT_AGENT_RUNTIME_RUNNING;
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}


mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_enable_signed_pool_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime, uint64_t owner_id,
    size_t max_connections, size_t max_leases) {
  mesh_mgmt_runtime_pool_record_v3_t *records;
  if (!runtime || owner_id == 0u || max_connections == 0u ||
      max_leases == 0u || max_connections > MESH_MGMT_AGENT_ROUTER_MAX_PEERS ||
      max_leases > MESH_MGMT_AGENT_ROUTER_MAX_PEERS ||
      max_leases < max_connections)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_READY ||
      runtime->shared_mesh || !runtime->owns_node ||
      !runtime->node || runtime_is_busy(runtime) ||
      runtime->signed_pool_enabled ||
      max_connections > runtime->router.max_peers)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  records = calloc(max_connections, sizeof(*records));
  if (!records) return MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED;
  runtime->signed_pool_records = records;
  runtime->signed_pool_capacity = max_connections;
  runtime->signed_pool_max_leases = max_leases;
  runtime->signed_pool_owner_id = owner_id;
  runtime->signed_pool_status = SALTS_OK;
  runtime->signed_pool_enabled = 1u;
  return MESH_MGMT_AGENT_RUNTIME_OK;
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_signed_pool_acquire_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime, p2p_peer_t *peer,
    cnet_pool_lease *out_lease) {
  mesh_mgmt_runtime_pool_record_v3_t *record;
  mesh_mgmt_agent_router_ready_v1_t signed_ready = {0};
  mesh_mgmt_agent_router_result_t auth;
  if (out_lease) *out_lease = (cnet_pool_lease){0};
  if (!runtime || !peer || !out_lease)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING ||
      runtime_is_busy(runtime) || !runtime->signed_pool.impl)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  record = pool_slot_by_peer(runtime, peer);
  if (!record) return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  auth = mesh_mgmt_agent_router_ready_peer_v1(&runtime->router, peer, &signed_ready);
  if (auth != MESH_MGMT_AGENT_ROUTER_OK ||
      memcmp(signed_ready.connection_id, record->connection_id,
             sizeof(record->connection_id)) != 0)
    return MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
  auth = mesh_mgmt_agent_router_pool_acquire_v1(
      &runtime->router, peer, signed_ready.remote_transport_peer_id,
      signed_ready.remote_managed_node_id, signed_ready.connection_id,
      runtime->signed_pool_manager, &runtime->signed_pool,
      runtime->signed_pool_owner_id, out_lease);
  if (auth == MESH_MGMT_AGENT_ROUTER_RESOURCE_EXHAUSTED)
    return MESH_MGMT_AGENT_RUNTIME_RESOURCE_EXHAUSTED;
  return auth == MESH_MGMT_AGENT_ROUTER_OK
    ? MESH_MGMT_AGENT_RUNTIME_OK : MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_signed_pool_release_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime, cnet_pool_lease lease) {
  if (!runtime || lease.slot == 0u)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (!runtime->signed_pool.impl || !runtime->signed_pool_enabled ||
      (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING &&
       runtime->state != MESH_MGMT_AGENT_RUNTIME_STOPPING) ||
      runtime_is_busy(runtime))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  const int status = cnet_pool_release(&runtime->signed_pool, lease);
  if (status == SALTS_ENOENT)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE; /* duplicate/foreign lease */
  if (status != SALTS_OK) {
    runtime->signed_pool_status = status;
    return MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
  }
  runtime->signed_pool_status = runtime_pool_advance(runtime);
  return runtime->signed_pool_status == SALTS_OK
    ? MESH_MGMT_AGENT_RUNTIME_OK : MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_signed_pool_snapshot_v3(
    mesh_mgmt_agent_runtime_v1_t *runtime, cnet_pool_snapshot *out_snapshot) {
  if (out_snapshot) *out_snapshot = (cnet_pool_snapshot){0};
  if (!runtime || !out_snapshot)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (!runtime->signed_pool_enabled || !runtime->signed_pool.impl)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  if (runtime_is_busy(runtime))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  runtime->signed_pool_status = cnet_pool_get_snapshot(
      &runtime->signed_pool, out_snapshot);
  return runtime->signed_pool_status == SALTS_OK
    ? MESH_MGMT_AGENT_RUNTIME_OK : MESH_MGMT_AGENT_RUNTIME_POOL_FAILED;
}

mesh_mgmt_agent_runtime_result_t mesh_mgmt_agent_runtime_set_client_policy_v2(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_client_destination_policy_v2_t *policy) {
  if (!runtime || !policy)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_READY || runtime_is_busy(runtime) ||
      !runtime->owns_node || runtime->shared_mesh != NULL || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_endpoint_result =
      mesh_mgmt_endpoint_pool_set_client_policy_v2(&runtime->endpoint_pool, policy);
  mesh_mgmt_agent_runtime_result_t status = MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED;
  if (runtime->last_endpoint_result == MESH_MGMT_ENDPOINT_POOL_OK)
    status = MESH_MGMT_AGENT_RUNTIME_OK;
  else if (runtime->last_endpoint_result == MESH_MGMT_ENDPOINT_POOL_INVALID_STATE)
    status = MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  else if (runtime->last_endpoint_result == MESH_MGMT_ENDPOINT_POOL_INVALID_ARG)
    status = MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  return runtime_fail(runtime, status);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_poll_v1(mesh_mgmt_agent_runtime_v1_t *runtime) {
  if (!runtime)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  if (runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING || runtime->in_api || !runtime->node)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  if (runtime->owns_node) {
    runtime->last_endpoint_result = runtime->endpoint_pool.policy_enabled
        ? mesh_mgmt_endpoint_pool_tick_v2(&runtime->endpoint_pool, cmeta_monotonic_ms())
        : mesh_mgmt_endpoint_pool_tick_v1(&runtime->endpoint_pool, cmeta_monotonic_ms());
    if (runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_OK &&
        runtime->last_endpoint_result != MESH_MGMT_ENDPOINT_POOL_NO_SOURCE)
      return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_ENDPOINT_FAILED);
    runtime->last_p2p_result = p2p_poll(runtime->node);
    if (runtime->last_p2p_result != P2P_OK)
      return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_P2P_FAILED);
    runtime->signed_pool_status = runtime_pool_advance(runtime);
    if (runtime->signed_pool_status != SALTS_OK)
      return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_POOL_FAILED);
  }
  if (runtime->signed_pool_status != SALTS_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_POOL_FAILED);
  return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_OK);
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_update_remote_trust_v2(
    mesh_mgmt_agent_runtime_v1_t *runtime,
    const mesh_mgmt_p2p_remote_trust_v2_t *trust,
    p2p_security_revalidation_result_v2_t *out_revalidation) {
  if (!runtime || !trust || !out_revalidation ||
      out_revalidation->struct_size != sizeof(*out_revalidation))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_ARG;
  memset((uint8_t *)out_revalidation + sizeof(out_revalidation->struct_size),
         0, sizeof(*out_revalidation) - sizeof(out_revalidation->struct_size));
  if ((runtime->state != MESH_MGMT_AGENT_RUNTIME_READY &&
       runtime->state != MESH_MGMT_AGENT_RUNTIME_RUNNING) ||
      runtime->in_api || !runtime->node || !runtime->owns_node ||
      !runtime->p2p_security_provider.initialized)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;

  runtime->in_api = 1u;
  runtime->last_p2p_result =
      mesh_mgmt_p2p_security_provider_update_remote_trust_v2(
          &runtime->p2p_security_provider, trust);
  if (runtime->last_p2p_result != P2P_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_P2P_FAILED);

  runtime->last_p2p_result =
      p2p_node_revalidate_security_v2(runtime->node, out_revalidation);
  if (runtime->last_p2p_result != P2P_OK)
    return runtime_fail(runtime, MESH_MGMT_AGENT_RUNTIME_P2P_FAILED);
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
      mesh_mgmt_endpoint_pool_apply_verified_v2(
          &runtime->endpoint_pool, &record, input->now_ms, cmeta_monotonic_ms());
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
  if (runtime_is_busy(runtime) ||
      runtime->state == MESH_MGMT_AGENT_RUNTIME_UNINITIALIZED)
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  runtime->in_api = 1u;
  return runtime_fail(runtime, runtime_stop_initialized(runtime));
}

mesh_mgmt_agent_runtime_result_t
mesh_mgmt_agent_runtime_destroy_v2(mesh_mgmt_agent_runtime_v1_t *runtime) {
  mesh_mgmt_agent_runtime_result_t result;
  if (!runtime)
    return MESH_MGMT_AGENT_RUNTIME_OK;
  if (runtime_is_busy(runtime))
    return MESH_MGMT_AGENT_RUNTIME_INVALID_STATE;
  runtime->in_api = 1u;
  result = runtime_stop_initialized(runtime);
  if (result != MESH_MGMT_AGENT_RUNTIME_OK)
    return runtime_fail(runtime, result);
  runtime_release_initialized(runtime);
  mesh_mgmt_crypto_wipe(runtime, sizeof(*runtime));
  return MESH_MGMT_AGENT_RUNTIME_OK;
}

void mesh_mgmt_agent_runtime_destroy_v1(mesh_mgmt_agent_runtime_v1_t *runtime) {
  /* Compatibility entry point: the checked function preserves all storage
   * on failure. New owners must consume its result before freeing borrows. */
  (void)mesh_mgmt_agent_runtime_destroy_v2(runtime);
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
