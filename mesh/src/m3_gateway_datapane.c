#include "m3_gateway_datapane.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

static int bytes_are_nonzero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0u; i < size; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static int policy_is_valid(const m3_chunk_capability_policy_v1_t *policy) {
  return policy && policy->max_ttl_ms > 0u && policy->max_read_bytes > 0u &&
         policy->max_put_bytes > 0u;
}

static void next_request_id(m3_gateway_datapane_v1_t *datapane,
                            size_t chunk_index, size_t store_index,
                            turbo_uuid_t *out) {
  uint64_t seq = datapane->request_seq++;

  memset(out, 0, sizeof(*out));
  for (size_t k = 0u; k < 8u; k++)
    out->bytes[k] = (uint8_t)(seq >> (56u - k * 8u));
  out->bytes[8] = (uint8_t)chunk_index;
  out->bytes[9] = (uint8_t)store_index;
  out->bytes[10] = 0x5au;
}

static void build_put_claims(
    m3_gateway_datapane_v1_t *datapane,
    const m3_gateway_datapane_store_v1_t *store, const m3_chunk_cid_v1_t *cid,
    const turbo_uuid_t *request_id, uint64_t now_ms,
    m3_chunk_capability_claims_v1_t *out_claims) {
  memset(out_claims, 0, sizeof(*out_claims));
  memcpy(out_claims->tenant_id, datapane->tenant_id,
         sizeof(out_claims->tenant_id));
  out_claims->cid = *cid;
  out_claims->operation = M3_CHUNK_OPERATION_PUT;
  out_claims->range_offset = 0u;
  out_claims->range_length = cid->size;
  memcpy(out_claims->audience_node_id, store->node_id,
         sizeof(out_claims->audience_node_id));
  out_claims->request_id = *request_id;
  out_claims->issued_at_ms = now_ms;
  out_claims->expires_at_ms = now_ms + datapane->policy.max_ttl_ms;
}

static void build_put_request(
    m3_gateway_datapane_v1_t *datapane,
    const m3_gateway_datapane_store_v1_t *store, const m3_chunk_cid_v1_t *cid,
    const turbo_uuid_t *request_id, uint64_t now_ms,
    m3_chunk_access_request_v1_t *out_request) {
  memset(out_request, 0, sizeof(*out_request));
  memcpy(out_request->tenant_id, datapane->tenant_id,
         sizeof(out_request->tenant_id));
  out_request->cid = *cid;
  out_request->operation = M3_CHUNK_OPERATION_PUT;
  out_request->range_offset = 0u;
  out_request->range_length = cid->size;
  memcpy(out_request->local_node_id, store->node_id,
         sizeof(out_request->local_node_id));
  out_request->request_id = *request_id;
  out_request->now_ms = now_ms;
}

m3_gateway_datapane_result_t m3_gateway_datapane_init_v1(
    m3_gateway_datapane_v1_t *datapane,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    size_t target_replicas, size_t min_durable_replicas,
    const m3_chunk_capability_policy_v1_t *policy) {
  if (!datapane || !bytes_are_nonzero(tenant_id,
                                      M3_CHUNK_CAPABILITY_TENANT_ID_SIZE) ||
      target_replicas == 0u ||
      target_replicas > M3_GATEWAY_DATAPANE_MAX_STORES ||
      min_durable_replicas == 0u ||
      min_durable_replicas > target_replicas || !policy_is_valid(policy)) {
    return M3_GATEWAY_DATAPANE_INVALID_ARG;
  }
  memset(datapane, 0, sizeof(*datapane));
  memcpy(datapane->tenant_id, tenant_id, sizeof(datapane->tenant_id));
  datapane->target_replicas = target_replicas;
  datapane->min_durable_replicas = min_durable_replicas;
  datapane->policy = *policy;
  return M3_GATEWAY_DATAPANE_OK;
}

void m3_gateway_datapane_destroy_v1(m3_gateway_datapane_v1_t *datapane) {
  if (!datapane)
    return;
  for (size_t i = 0u; i < datapane->store_count; i++) {
    if (datapane->stores[i].transport == 1u)
      m3_chunk_mesh_client_destroy_v1(&datapane->stores[i].mesh);
  }
  if (datapane->mesh_attached)
    m3_chunk_mesh_router_destroy_v1(&datapane->mesh_router);
  memset(datapane, 0, sizeof(*datapane));
}

m3_gateway_datapane_result_t m3_gateway_datapane_register_store_v1(
    m3_gateway_datapane_v1_t *datapane,
    const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    m3_store_node_v1_t *store) {
  if (!datapane || !store ||
      !bytes_are_nonzero(store_node_id, M3_CHUNK_CAPABILITY_NODE_ID_SIZE) ||
      !bytes_are_nonzero(public_key, MESH_MGMT_ED25519_PUBLIC_KEY_SIZE)) {
    return M3_GATEWAY_DATAPANE_INVALID_ARG;
  }
  for (size_t i = 0u; i < datapane->store_count; i++) {
    if (memcmp(datapane->stores[i].node_id, store_node_id,
               M3_CHUNK_CAPABILITY_NODE_ID_SIZE) == 0) {
      return M3_GATEWAY_DATAPANE_INVALID_ARG;
    }
  }
  if (datapane->store_count >= M3_GATEWAY_DATAPANE_MAX_STORES)
    return M3_GATEWAY_DATAPANE_RESOURCE_EXHAUSTED;
  memcpy(datapane->stores[datapane->store_count].node_id, store_node_id,
         M3_CHUNK_CAPABILITY_NODE_ID_SIZE);
  memcpy(datapane->stores[datapane->store_count].public_key, public_key,
         MESH_MGMT_ED25519_PUBLIC_KEY_SIZE);
  datapane->stores[datapane->store_count].store = store;
  datapane->store_count++;
  return M3_GATEWAY_DATAPANE_OK;
}

m3_gateway_datapane_result_t m3_gateway_datapane_attach_mesh_v1(
    m3_gateway_datapane_v1_t *datapane, p2p_node_t *node,
    const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE]) {
  if (!datapane || datapane->mesh_attached || !node || !private_key ||
      !bytes_are_nonzero(private_key, MESH_MGMT_ED25519_PRIVATE_KEY_SIZE)) {
    return M3_GATEWAY_DATAPANE_INVALID_ARG;
  }
  if (m3_chunk_mesh_router_init_v1(&datapane->mesh_router, node) !=
      M3_CHUNK_MESH_OK) {
    return M3_GATEWAY_DATAPANE_INTERNAL;
  }
  datapane->mesh_node = node;
  memcpy(datapane->signer_private_key, private_key,
         sizeof(datapane->signer_private_key));
  if (mesh_mgmt_ed25519_public_from_private(private_key,
                                           datapane->signer_public_key) !=
      MESH_MGMT_CRYPTO_OK) {
    m3_chunk_mesh_router_destroy_v1(&datapane->mesh_router);
    memset(datapane, 0, sizeof(*datapane));
    return M3_GATEWAY_DATAPANE_INTERNAL;
  }
  datapane->mesh_attached = 1u;
  return M3_GATEWAY_DATAPANE_OK;
}

m3_gateway_datapane_result_t m3_gateway_datapane_register_mesh_store_v1(
    m3_gateway_datapane_v1_t *datapane,
    const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const char *host, int port) {
  m3_gateway_datapane_store_v1_t *slot;
  m3_chunk_mesh_result_t mesh_result;

  if (!datapane || !datapane->mesh_attached || !host || host[0] == '\0' ||
      port <= 0 || port > 65535 ||
      !bytes_are_nonzero(store_node_id, M3_CHUNK_CAPABILITY_NODE_ID_SIZE) ||
      !bytes_are_nonzero(public_key, MESH_MGMT_ED25519_PUBLIC_KEY_SIZE)) {
    return M3_GATEWAY_DATAPANE_INVALID_ARG;
  }
  for (size_t i = 0u; i < datapane->store_count; i++) {
    if (memcmp(datapane->stores[i].node_id, store_node_id,
               M3_CHUNK_CAPABILITY_NODE_ID_SIZE) == 0) {
      return M3_GATEWAY_DATAPANE_INVALID_ARG;
    }
  }
  if (datapane->store_count >= M3_GATEWAY_DATAPANE_MAX_STORES)
    return M3_GATEWAY_DATAPANE_RESOURCE_EXHAUSTED;
  slot = &datapane->stores[datapane->store_count];
  memset(slot, 0, sizeof(*slot));
  memcpy(slot->node_id, store_node_id, sizeof(slot->node_id));
  memcpy(slot->public_key, public_key, sizeof(slot->public_key));
  mesh_result = m3_chunk_mesh_client_connect_v1(
      &slot->mesh, datapane->mesh_node, store_node_id, public_key, host, port);
  if (mesh_result != M3_CHUNK_MESH_OK)
    return M3_GATEWAY_DATAPANE_NETWORK_FAILED;
  if (m3_chunk_mesh_router_add_client_v1(&datapane->mesh_router, &slot->mesh) !=
      M3_CHUNK_MESH_OK) {
    m3_chunk_mesh_client_destroy_v1(&slot->mesh);
    return M3_GATEWAY_DATAPANE_INTERNAL;
  }
  slot->transport = 1u;
  datapane->store_count++;
  return M3_GATEWAY_DATAPANE_OK;
}

m3_gateway_datapane_result_t m3_gateway_datapane_put_chunk_v1(
    m3_gateway_datapane_v1_t *datapane, size_t store_index,
    const m3_chunk_cid_v1_t *cid, const uint8_t *bytes, size_t size,
    uint64_t now_ms, m3_chunk_receipt_v1_t *out_receipt) {
  m3_gateway_datapane_store_v1_t *store;
  m3_chunk_capability_claims_v1_t claims;
  m3_chunk_access_request_v1_t request;
  m3_chunk_receipt_v1_t receipt;
  turbo_uuid_t request_id;
  m3_store_node_result_t store_result;

  if (out_receipt)
    memset(out_receipt, 0, sizeof(*out_receipt));
  if (!datapane || !cid || !out_receipt || (!bytes && size > 0u) ||
      store_index >= datapane->store_count)
    return M3_GATEWAY_DATAPANE_INVALID_ARG;
  store = &datapane->stores[store_index];
  next_request_id(datapane, 0u, store_index, &request_id);
  build_put_claims(datapane, store, cid, &request_id, now_ms, &claims);
  build_put_request(datapane, store, cid, &request_id, now_ms, &request);
  if (store->transport == 1u) {
    uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE];

    if (m3_chunk_mesh_claims_sign_v1(datapane->signer_private_key, &claims,
                                     signature) != M3_CHUNK_MESH_OK)
      return M3_GATEWAY_DATAPANE_NETWORK_FAILED;
    if (m3_chunk_mesh_client_put_v1(
            &store->mesh, &claims, signature, datapane->signer_public_key,
            bytes, size, M3_GATEWAY_DATAPANE_MESH_TIMEOUT_MS, &receipt) !=
        M3_CHUNK_MESH_OK) {
      return M3_GATEWAY_DATAPANE_NETWORK_FAILED;
    }
  } else {
    store_result = m3_store_node_put_chunk_v1(store->store, &claims, &request,
                                              bytes, size, &receipt);
    if (store_result != M3_STORE_NODE_OK)
      return M3_GATEWAY_DATAPANE_NOT_AVAILABLE;
  }
  if (m3_chunk_receipt_verify_v1(store->public_key, &receipt) !=
          M3_CHUNK_RECEIPT_OK ||
      m3_chunk_receipt_check_binding_v1(&receipt, store->node_id, cid,
                                        &request_id, now_ms,
                                        datapane->policy.max_ttl_ms) !=
          M3_CHUNK_RECEIPT_OK) {
    return M3_GATEWAY_DATAPANE_CORRUPT;
  }
  *out_receipt = receipt;
  return M3_GATEWAY_DATAPANE_OK;
}

static m3_gateway_datapane_result_t publish_chunk(
    m3_gateway_datapane_v1_t *datapane, size_t write_target, size_t chunk_index,
    const m3_chunk_cid_v1_t *cid, const uint8_t *bytes, uint64_t now_ms,
    m3_object_manifest_placement_v1_t *out_placements,
    size_t *out_placement_count) {
  size_t placement_count = 0u;

  for (size_t s = 0u; s < write_target; s++) {
    m3_gateway_datapane_store_v1_t *store = &datapane->stores[s];
    m3_chunk_receipt_v1_t receipt;

    if (m3_gateway_datapane_put_chunk_v1(
            datapane, s, cid, bytes, (size_t)cid->size, now_ms, &receipt) !=
        M3_GATEWAY_DATAPANE_OK) {
      continue;
    }
    if (m3_chunk_receipt_digest_v1(&receipt,
                                   out_placements[placement_count].receipt_digest) !=
        M3_CHUNK_RECEIPT_OK) {
      continue;
    }
    out_placements[placement_count].chunk_index = (uint32_t)chunk_index;
    memcpy(out_placements[placement_count].store_node_id, store->node_id,
           sizeof(out_placements[placement_count].store_node_id));
    placement_count++;
  }
  *out_placement_count = placement_count;
  return placement_count >= datapane->min_durable_replicas
             ? M3_GATEWAY_DATAPANE_OK
             : M3_GATEWAY_DATAPANE_INSUFFICIENT_REPLICAS;
}

m3_gateway_datapane_result_t m3_gateway_datapane_put_object_v1(
    m3_gateway_datapane_v1_t *datapane, const uint8_t *body, size_t body_len,
    uint64_t max_chunk_bytes, uint64_t now_ms, uint8_t **out_manifest_bytes,
    size_t *out_manifest_size, uint64_t *out_object_size) {
  m3_chunk_cid_v1_t *chunks = NULL;
  m3_object_manifest_placement_v1_t *placements = NULL;
  m3_object_manifest_v2_t manifest;
  turbo_crypto_sha256_ctx_t object_ctx;
  uint8_t object_digest[M3_CHUNK_CID_DIGEST_SIZE];
  size_t chunk_count;
  size_t write_target;
  size_t placement_count = 0u;
  size_t max_placements;
  uint64_t total = 0u;
  m3_gateway_datapane_result_t result;

  if (out_manifest_bytes)
    *out_manifest_bytes = NULL;
  if (out_manifest_size)
    *out_manifest_size = 0u;
  if (out_object_size)
    *out_object_size = 0u;
  if (!datapane || datapane->store_count == 0u || !out_manifest_bytes ||
      !out_manifest_size || !out_object_size || max_chunk_bytes == 0u ||
      (!body && body_len > 0u)) {
    return M3_GATEWAY_DATAPANE_INVALID_ARG;
  }
  chunk_count =
      body_len == 0u ? 0u : (body_len - 1u) / (size_t)max_chunk_bytes + 1u;
  write_target = datapane->target_replicas < datapane->store_count
                     ? datapane->target_replicas
                     : datapane->store_count;
  max_placements = chunk_count * write_target;
  if (chunk_count > M3_GATEWAY_DATAPANE_MAX_CHUNKS ||
      (max_placements > 0u &&
       (max_placements / write_target != chunk_count))) {
    return M3_GATEWAY_DATAPANE_RESOURCE_EXHAUSTED;
  }
  if (chunk_count > 0u) {
    chunks = (m3_chunk_cid_v1_t *)calloc(chunk_count, sizeof(*chunks));
    placements = (m3_object_manifest_placement_v1_t *)calloc(
        max_placements, sizeof(*placements));
    if (!chunks || !placements) {
      result = M3_GATEWAY_DATAPANE_RESOURCE_EXHAUSTED;
      goto cleanup;
    }
  }
  if (turbo_crypto_sha256_init(&object_ctx) != TURBO_CRYPTO_OK) {
    result = M3_GATEWAY_DATAPANE_CRYPTO_FAILED;
    goto cleanup;
  }
  for (size_t i = 0u; i < chunk_count; i++) {
    size_t offset = (size_t)i * (size_t)max_chunk_bytes;
    size_t take = body_len - offset;
    size_t chunk_placements = 0u;

    if (take > (size_t)max_chunk_bytes)
      take = (size_t)max_chunk_bytes;
    total += (uint64_t)take;
    if (m3_chunk_cid_calculate_v1(body + offset, take, &chunks[i]) !=
        M3_CHUNK_STORE_OK) {
      result = M3_GATEWAY_DATAPANE_CRYPTO_FAILED;
      goto cleanup;
    }
    result = publish_chunk(datapane, write_target, i, &chunks[i], body + offset,
                           now_ms, placements + placement_count,
                           &chunk_placements);
    if (result != M3_GATEWAY_DATAPANE_OK)
      goto cleanup;
    placement_count += chunk_placements;
    if (turbo_crypto_sha256_update(&object_ctx, chunks[i].digest,
                                   sizeof(chunks[i].digest)) !=
        TURBO_CRYPTO_OK) {
      result = M3_GATEWAY_DATAPANE_CRYPTO_FAILED;
      goto cleanup;
    }
  }
  if (turbo_crypto_sha256_final(&object_ctx, object_digest) != TURBO_CRYPTO_OK) {
    result = M3_GATEWAY_DATAPANE_CRYPTO_FAILED;
    goto cleanup;
  }

  memset(&manifest, 0, sizeof(manifest));
  manifest.version = M3_OBJECT_MANIFEST_VERSION_2;
  manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest.object_cid.size = total;
  memcpy(manifest.object_cid.digest, object_digest, sizeof(object_digest));
  manifest.chunks = chunks;
  manifest.chunk_count = chunk_count;
  manifest.placements = placements;
  manifest.placement_count = placement_count;
  if (m3_object_manifest_encode_v2(
          &manifest, M3_GATEWAY_DATAPANE_MAX_OBJECT_BYTES,
          M3_GATEWAY_DATAPANE_MAX_CHUNKS, max_placements, out_manifest_bytes,
          out_manifest_size) != M3_OBJECT_MANIFEST_OK) {
    result = M3_GATEWAY_DATAPANE_INTERNAL;
    goto cleanup;
  }
  *out_object_size = total;
  result = M3_GATEWAY_DATAPANE_OK;

cleanup:
  free(placements);
  free(chunks);
  if (result != M3_GATEWAY_DATAPANE_OK) {
    m3_object_manifest_bytes_free_v2(*out_manifest_bytes);
    if (out_manifest_bytes)
      *out_manifest_bytes = NULL;
    if (out_manifest_size)
      *out_manifest_size = 0u;
    if (out_object_size)
      *out_object_size = 0u;
  }
  return result;
}

static m3_gateway_datapane_store_v1_t *find_store(
    m3_gateway_datapane_v1_t *datapane,
    const uint8_t node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE]) {
  for (size_t i = 0u; i < datapane->store_count; i++) {
    if (memcmp(datapane->stores[i].node_id, node_id,
               M3_CHUNK_CAPABILITY_NODE_ID_SIZE) == 0) {
      return &datapane->stores[i];
    }
  }
  return NULL;
}

m3_gateway_datapane_result_t m3_gateway_datapane_read_chunk_v1(
    m3_gateway_datapane_v1_t *datapane, const m3_object_manifest_v2_t *manifest,
    size_t chunk_index, const m3_chunk_cid_v1_t *cid, uint64_t chunk_offset,
    size_t length, uint64_t now_ms, uint8_t *buffer, size_t *out_read) {
  m3_gateway_datapane_store_v1_t *replicas[M3_GATEWAY_DATAPANE_MAX_STORES];
  size_t replica_count = 0u;
  size_t i;

  if (out_read)
    *out_read = 0u;
  if (!datapane || !manifest || !cid || !buffer || !out_read ||
      chunk_index >= manifest->chunk_count || length == 0u ||
      chunk_offset > cid->size || (uint64_t)length > cid->size - chunk_offset) {
    return M3_GATEWAY_DATAPANE_INVALID_ARG;
  }
  for (i = 0u; i < manifest->placement_count; i++) {
    const m3_object_manifest_placement_v1_t *placement =
        &manifest->placements[i];

    if (placement->chunk_index != chunk_index)
      continue;
    if (replica_count >= M3_GATEWAY_DATAPANE_MAX_STORES)
      break;
    replicas[replica_count++] =
        find_store(datapane, placement->store_node_id);
  }
  for (i = 0u; i < replica_count; i++) {
    m3_gateway_datapane_store_v1_t *store = replicas[i];
    m3_chunk_capability_claims_v1_t claims;
    m3_chunk_access_request_v1_t request;
    m3_store_node_result_t store_result;
    turbo_uuid_t request_id;
    size_t read = 0u;

    if (!store)
      continue;
    next_request_id(datapane, chunk_index, i, &request_id);
    memset(&claims, 0, sizeof(claims));
    memcpy(claims.tenant_id, datapane->tenant_id, sizeof(claims.tenant_id));
    claims.cid = *cid;
    claims.operation = M3_CHUNK_OPERATION_READ;
    claims.range_offset = chunk_offset;
    claims.range_length = (uint64_t)length;
    memcpy(claims.audience_node_id, store->node_id,
           sizeof(claims.audience_node_id));
    claims.request_id = request_id;
    claims.issued_at_ms = now_ms;
    claims.expires_at_ms = now_ms + datapane->policy.max_ttl_ms;

    memset(&request, 0, sizeof(request));
    memcpy(request.tenant_id, datapane->tenant_id,
           sizeof(request.tenant_id));
    request.cid = *cid;
    request.operation = M3_CHUNK_OPERATION_READ;
    request.range_offset = chunk_offset;
    request.range_length = (uint64_t)length;
    memcpy(request.local_node_id, store->node_id,
           sizeof(request.local_node_id));
    request.request_id = request_id;
    request.now_ms = now_ms;

    if (store->transport == 1u) {
      uint8_t signature[M3_CHUNK_MESH_SIGNATURE_SIZE];

      if (m3_chunk_mesh_claims_sign_v1(datapane->signer_private_key, &claims,
                                       signature) != M3_CHUNK_MESH_OK)
        continue;
      if (m3_chunk_mesh_client_get_v1(&store->mesh, &claims, signature,
                                      datapane->signer_public_key, buffer,
                                      length, &read,
                                      M3_GATEWAY_DATAPANE_MESH_TIMEOUT_MS) ==
              M3_CHUNK_MESH_OK &&
          read == length) {
        *out_read = read;
        return M3_GATEWAY_DATAPANE_OK;
      }
    } else {
      store_result = m3_store_node_read_chunk_v1(store->store, &claims, &request,
                                                 buffer, length, &read);
      if (store_result == M3_STORE_NODE_OK && read == length) {
        *out_read = read;
        return M3_GATEWAY_DATAPANE_OK;
      }
    }
  }
  return M3_GATEWAY_DATAPANE_NOT_AVAILABLE;
}
