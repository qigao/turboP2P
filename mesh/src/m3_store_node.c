#include "m3_store_node.h"

#include <stdio.h>
#include <string.h>

static int bytes_are_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < length; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static int cid_equal(const m3_chunk_cid_v1_t *left,
                     const m3_chunk_cid_v1_t *right) {
  return left && right &&
         left->hash_algorithm == right->hash_algorithm &&
         left->size == right->size &&
         memcmp(left->digest, right->digest, sizeof(left->digest)) == 0;
}

static int config_is_valid(const m3_store_node_config_v1_t *config) {
  return config && config->store_root[0] != '\0' &&
         config->max_chunk_bytes > 0u && config->max_tenant_bytes > 0u &&
         bytes_are_nonzero(config->node_id, sizeof(config->node_id)) &&
         bytes_are_nonzero(config->signing_private_key,
                           sizeof(config->signing_private_key)) &&
         config->failure_domain[0] != '\0' &&
         config->policy.max_ttl_ms > 0u &&
         config->policy.max_read_bytes > 0u &&
         config->policy.max_put_bytes > 0u;
}

static m3_store_node_result_t map_capability_result(
    m3_chunk_capability_result_t result) {
  switch (result) {
  case M3_CHUNK_CAPABILITY_OK:
    return M3_STORE_NODE_OK;
  case M3_CHUNK_CAPABILITY_NOT_YET_VALID:
    return M3_STORE_NODE_NOT_YET_VALID;
  case M3_CHUNK_CAPABILITY_EXPIRED:
    return M3_STORE_NODE_EXPIRED;
  case M3_CHUNK_CAPABILITY_RESOURCE_EXHAUSTED:
    return M3_STORE_NODE_RESOURCE_EXHAUSTED;
  case M3_CHUNK_CAPABILITY_INVALID_ARG:
    return M3_STORE_NODE_INVALID_ARG;
  case M3_CHUNK_CAPABILITY_INVALID_CLAIMS:
  case M3_CHUNK_CAPABILITY_TENANT_MISMATCH:
  case M3_CHUNK_CAPABILITY_AUDIENCE_MISMATCH:
  case M3_CHUNK_CAPABILITY_REQUEST_MISMATCH:
  case M3_CHUNK_CAPABILITY_OPERATION_MISMATCH:
  case M3_CHUNK_CAPABILITY_CID_MISMATCH:
  case M3_CHUNK_CAPABILITY_RANGE_DENIED:
  default:
    return M3_STORE_NODE_AUTH_DENIED;
  }
}

static m3_store_node_result_t map_access_store_result(
    m3_chunk_access_store_result_t result) {
  switch (result) {
  case M3_CHUNK_ACCESS_STORE_OK:
    return M3_STORE_NODE_OK;
  case M3_CHUNK_ACCESS_STORE_INVALID_ARG:
    return M3_STORE_NODE_INVALID_ARG;
  case M3_CHUNK_ACCESS_STORE_INVALID_ACCESS:
    return M3_STORE_NODE_AUTH_DENIED;
  case M3_CHUNK_ACCESS_STORE_EXPIRED:
    return M3_STORE_NODE_EXPIRED;
  case M3_CHUNK_ACCESS_STORE_RESOURCE_EXHAUSTED:
    return M3_STORE_NODE_RESOURCE_EXHAUSTED;
  case M3_CHUNK_ACCESS_STORE_NOT_FOUND:
    return M3_STORE_NODE_NOT_FOUND;
  case M3_CHUNK_ACCESS_STORE_CORRUPT:
    return M3_STORE_NODE_CORRUPT;
  case M3_CHUNK_ACCESS_STORE_DIGEST_MISMATCH:
    return M3_STORE_NODE_DIGEST_MISMATCH;
  case M3_CHUNK_ACCESS_STORE_LOCKED:
    return M3_STORE_NODE_LOCKED;
  case M3_CHUNK_ACCESS_STORE_IO:
    return M3_STORE_NODE_IO;
  case M3_CHUNK_ACCESS_STORE_CSPRNG_FAILED:
  default:
    return M3_STORE_NODE_INTERNAL;
  }
}

static m3_store_node_result_t map_read_service_result(
    m3_chunk_read_service_result_t result) {
  switch (result) {
  case M3_CHUNK_READ_SERVICE_OK:
    return M3_STORE_NODE_OK;
  case M3_CHUNK_READ_SERVICE_INVALID_ARG:
  case M3_CHUNK_READ_SERVICE_MUTATION_DISABLED:
    return M3_STORE_NODE_INVALID_ARG;
  case M3_CHUNK_READ_SERVICE_AUTH_DENIED:
    return M3_STORE_NODE_AUTH_DENIED;
  case M3_CHUNK_READ_SERVICE_NOT_YET_VALID:
    return M3_STORE_NODE_NOT_YET_VALID;
  case M3_CHUNK_READ_SERVICE_EXPIRED:
    return M3_STORE_NODE_EXPIRED;
  case M3_CHUNK_READ_SERVICE_CONFLICT:
    return M3_STORE_NODE_CONFLICT;
  case M3_CHUNK_READ_SERVICE_IN_PROGRESS:
    return M3_STORE_NODE_IN_PROGRESS;
  case M3_CHUNK_READ_SERVICE_RESOURCE_EXHAUSTED:
    return M3_STORE_NODE_RESOURCE_EXHAUSTED;
  case M3_CHUNK_READ_SERVICE_NOT_FOUND:
    return M3_STORE_NODE_NOT_FOUND;
  case M3_CHUNK_READ_SERVICE_CORRUPT:
    return M3_STORE_NODE_CORRUPT;
  case M3_CHUNK_READ_SERVICE_DIGEST_MISMATCH:
    return M3_STORE_NODE_DIGEST_MISMATCH;
  case M3_CHUNK_READ_SERVICE_IO:
    return M3_STORE_NODE_IO;
  case M3_CHUNK_READ_SERVICE_INTERNAL:
  default:
    return M3_STORE_NODE_INTERNAL;
  }
}

static m3_store_node_result_t map_open_result(m3_chunk_store_result_t result) {
  return result == M3_CHUNK_STORE_LOCKED ? M3_STORE_NODE_LOCKED
                                         : M3_STORE_NODE_IO;
}

static m3_store_node_tenant_usage_v1_t *find_or_create_tenant(
    m3_store_node_v1_t *node, const uint8_t tenant_id[32]) {
  for (size_t i = 0u; i < node->tenant_count; i++) {
    if (memcmp(node->tenants[i].tenant_id, tenant_id, 32u) == 0)
      return &node->tenants[i];
  }
  if (node->tenant_count >= M3_STORE_NODE_MAX_TENANTS)
    return NULL;
  memset(&node->tenants[node->tenant_count], 0,
         sizeof(node->tenants[0]));
  memcpy(node->tenants[node->tenant_count].tenant_id, tenant_id, 32u);
  node->tenant_count++;
  return &node->tenants[node->tenant_count - 1u];
}

m3_store_node_result_t m3_store_node_init_v1(
    m3_store_node_v1_t *node, const m3_store_node_config_v1_t *config) {
  m3_store_node_result_t result = M3_STORE_NODE_INTERNAL;

  if (!node || node->initialized || !config_is_valid(config))
    return M3_STORE_NODE_INVALID_ARG;
  memset(node, 0, sizeof(*node));
  node->config = *config;
  {
    m3_chunk_store_result_t open_result = m3_chunk_store_open_v1(
        &node->store, config->store_root, config->max_chunk_bytes);

    if (open_result != M3_CHUNK_STORE_OK) {
      result = map_open_result(open_result);
      memset(node, 0, sizeof(*node));
      return result;
    }
  }
  if (m3_chunk_replay_journal_init_v1(
          &node->replay, M3_STORE_NODE_REPLAY_CAPACITY,
          config->policy.max_ttl_ms) != M3_CHUNK_REPLAY_OK) {
    m3_chunk_store_close_v1(&node->store);
    memset(node, 0, sizeof(*node));
    return M3_STORE_NODE_RESOURCE_EXHAUSTED;
  }
  if (m3_chunk_read_service_init_v1(
          &node->read_service, &node->store, &node->replay,
          &config->policy, config->node_id) != M3_CHUNK_READ_SERVICE_OK) {
    m3_chunk_replay_journal_destroy_v1(&node->replay);
    m3_chunk_store_close_v1(&node->store);
    memset(node, 0, sizeof(*node));
    return M3_STORE_NODE_INTERNAL;
  }
  node->initialized = 1u;
  return M3_STORE_NODE_OK;
}

void m3_store_node_destroy_v1(m3_store_node_v1_t *node) {
  if (!node)
    return;
  if (node->initialized) {
    m3_chunk_read_service_destroy_v1(&node->read_service);
    m3_chunk_replay_journal_destroy_v1(&node->replay);
    m3_chunk_store_close_v1(&node->store);
  }
  memset(node, 0, sizeof(*node));
}

m3_store_node_result_t m3_store_node_put_chunk_v1(
    m3_store_node_v1_t *node,
    const m3_chunk_capability_claims_v1_t *verified_claims,
    const m3_chunk_access_request_v1_t *request, const uint8_t *bytes,
    size_t size, m3_chunk_receipt_v1_t *out_receipt) {
  m3_chunk_access_request_v1_t bound;
  m3_chunk_authorized_access_v1_t access;
  m3_store_node_tenant_usage_v1_t *tenant;
  m3_chunk_capability_result_t capability_result;
  m3_store_node_result_t result;
  uint8_t created = 0u;

  if (out_receipt)
    memset(out_receipt, 0, sizeof(*out_receipt));
  if (!node || !node->initialized || !verified_claims || !request ||
      !out_receipt || (!bytes && size > 0u)) {
    return M3_STORE_NODE_INVALID_ARG;
  }
  if (request->operation != M3_CHUNK_OPERATION_PUT)
    return M3_STORE_NODE_INVALID_ARG;

  bound = *request;
  memcpy(bound.local_node_id, node->config.node_id,
         sizeof(bound.local_node_id));
  capability_result = m3_chunk_capability_authorize_v1(
      verified_claims, &bound, &node->config.policy, &access);

  result = map_capability_result(capability_result);
  if (result != M3_STORE_NODE_OK)
    return result;

  tenant = find_or_create_tenant(node, access.tenant_id);
  if (!tenant)
    return M3_STORE_NODE_RESOURCE_EXHAUSTED;
  if (access.range_length > node->config.max_tenant_bytes ||
      tenant->used_bytes >
          node->config.max_tenant_bytes - access.range_length) {
    return M3_STORE_NODE_QUOTA_EXCEEDED;
  }

  result = map_access_store_result(m3_chunk_access_store_put_v1(
      &node->store, &access, bound.now_ms, bytes, size, &created));
  if (result != M3_STORE_NODE_OK)
    return result;
  if (created)
    tenant->used_bytes += access.range_length;

  memcpy(out_receipt->store_node_id, node->config.node_id,
         sizeof(out_receipt->store_node_id));
  out_receipt->cid = access.cid;
  out_receipt->request_id = access.request_id;
  out_receipt->issued_at_ms = bound.now_ms;
  if (m3_chunk_receipt_sign_v1(node->config.signing_private_key,
                               out_receipt) != M3_CHUNK_RECEIPT_OK) {
    return M3_STORE_NODE_CRYPTO_FAILED;
  }
  return M3_STORE_NODE_OK;
}

m3_store_node_result_t m3_store_node_read_chunk_v1(
    m3_store_node_v1_t *node,
    const m3_chunk_capability_claims_v1_t *verified_claims,
    const m3_chunk_access_request_v1_t *request, uint8_t *buffer,
    size_t buffer_size, size_t *out_read) {
  uint8_t replayed = 0u;

  if (out_read)
    *out_read = 0u;
  if (!node || !node->initialized || !verified_claims || !request ||
      !out_read) {
    return M3_STORE_NODE_INVALID_ARG;
  }
  if (request->operation != M3_CHUNK_OPERATION_READ)
    return M3_STORE_NODE_INVALID_ARG;
  return map_read_service_result(m3_chunk_read_service_execute_v1(
      &node->read_service, verified_claims, request, buffer, buffer_size,
      out_read, &replayed));
}

m3_store_node_result_t m3_store_node_health_v1(
    const m3_store_node_v1_t *node, m3_store_node_health_v1_t *out_health) {
  uint64_t used_bytes = 0u;
  uint64_t min_headroom = UINT64_MAX;

  if (!node || !node->initialized || !out_health)
    return M3_STORE_NODE_INVALID_ARG;
  memset(out_health, 0, sizeof(*out_health));
  snprintf(out_health->failure_domain, sizeof(out_health->failure_domain),
           "%s", node->config.failure_domain);
  out_health->tenant_count = node->tenant_count;
  out_health->quota_limit_bytes =
      node->config.max_tenant_bytes * (uint64_t)node->tenant_count;
  for (size_t i = 0u; i < node->tenant_count; i++) {
    uint64_t headroom;

    used_bytes += node->tenants[i].used_bytes;
    headroom = node->config.max_tenant_bytes > node->tenants[i].used_bytes
                   ? node->config.max_tenant_bytes - node->tenants[i].used_bytes
                   : 0u;
    if (headroom < min_headroom)
      min_headroom = headroom;
  }
  out_health->used_bytes = used_bytes;
  out_health->free_capacity_bytes =
      out_health->quota_limit_bytes > used_bytes
          ? out_health->quota_limit_bytes - used_bytes
          : 0u;
  out_health->min_tenant_headroom_bytes =
      min_headroom == UINT64_MAX ? 0u : min_headroom;
  return M3_STORE_NODE_OK;
}

typedef struct {
  const m3_chunk_cid_v1_t *live;
  size_t live_count;
  uint64_t grace_ms;
  uint64_t now_ms;
  m3_chunk_cid_v1_t *candidates;
  size_t candidate_count;
  size_t candidate_cap;
} m3_gc_context_v1_t;

static int gc_collect_cb(const m3_chunk_cid_v1_t *cid, uint64_t modified_us,
                         void *user_data) {
  m3_gc_context_v1_t *ctx = (m3_gc_context_v1_t *)user_data;
  uint64_t cutoff_us;
  m3_chunk_cid_v1_t *grown;

  for (size_t i = 0u; i < ctx->live_count; i++) {
    if (cid_equal(cid, &ctx->live[i]))
      return 0;
  }
  cutoff_us = ctx->now_ms > ctx->grace_ms ? (ctx->now_ms - ctx->grace_ms) * 1000u
                                          : 0u;
  if (modified_us > cutoff_us)
    return 0;
  if (ctx->candidate_count >= ctx->candidate_cap) {
    size_t new_cap = ctx->candidate_cap == 0u ? 64u : ctx->candidate_cap * 2u;

    grown = (m3_chunk_cid_v1_t *)realloc(ctx->candidates,
                                         new_cap * sizeof(*grown));
    if (!grown)
      return 1;
    ctx->candidates = grown;
    ctx->candidate_cap = new_cap;
  }
  ctx->candidates[ctx->candidate_count++] = *cid;
  return 0;
}

m3_store_node_result_t m3_store_node_gc_v1(
    m3_store_node_v1_t *node, const m3_chunk_cid_v1_t *live_cids,
    size_t live_count, uint64_t grace_ms, uint64_t now_ms,
    uint64_t *out_reclaimed_bytes) {
  m3_gc_context_v1_t ctx;
  m3_chunk_store_result_t store_result;
  uint64_t reclaimed = 0u;

  if (out_reclaimed_bytes)
    *out_reclaimed_bytes = 0u;
  if (!node || !node->initialized || !out_reclaimed_bytes ||
      (live_count > 0u && !live_cids)) {
    return M3_STORE_NODE_INVALID_ARG;
  }
  memset(&ctx, 0, sizeof(ctx));
  ctx.live = live_cids;
  ctx.live_count = live_count;
  ctx.grace_ms = grace_ms;
  ctx.now_ms = now_ms;
  store_result = m3_chunk_store_enumerate_v1(&node->store, gc_collect_cb, &ctx);
  if (store_result != M3_CHUNK_STORE_OK && store_result != M3_CHUNK_STORE_ABORTED) {
    free(ctx.candidates);
    return M3_STORE_NODE_IO;
  }
  for (size_t i = 0u; i < ctx.candidate_count; i++) {
    if (m3_chunk_store_delete_v1(&node->store, &ctx.candidates[i]) ==
        M3_CHUNK_STORE_OK) {
      reclaimed += ctx.candidates[i].size;
    }
  }
  free(ctx.candidates);
  *out_reclaimed_bytes = reclaimed;
  return M3_STORE_NODE_OK;
}
