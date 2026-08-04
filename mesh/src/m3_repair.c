#include "m3_repair.h"

#include <stdlib.h>
#include <string.h>

static size_t chunk_receipt_count(const m3_object_manifest_v2_t *manifest,
                                  size_t chunk_index) {
  size_t count = 0u;

  for (size_t i = 0u; i < manifest->placement_count; i++) {
    if (manifest->placements[i].chunk_index == chunk_index)
      count++;
  }
  return count;
}

static int chunk_has_healthy_source(const m3_gateway_datapane_v1_t *dp,
                                    const m3_object_manifest_v2_t *manifest,
                                    size_t chunk_index) {
  for (size_t i = 0u; i < manifest->placement_count; i++) {
    const m3_object_manifest_placement_v1_t *p = &manifest->placements[i];

    if (p->chunk_index == chunk_index) {
      for (size_t s = 0u; s < dp->store_count; s++) {
        if (memcmp(dp->stores[s].node_id, p->store_node_id,
                   M3_CHUNK_CAPABILITY_NODE_ID_SIZE) == 0) {
          return 1;
        }
      }
    }
  }
  return 0;
}

m3_repair_result_t m3_repair_plan_v1(
    m3_gateway_datapane_v1_t *datapane, const m3_object_manifest_v2_t *manifest,
    size_t target_replicas, m3_repair_action_v1_t *out_actions,
    size_t action_capacity, size_t *out_action_count) {
  size_t action_count = 0u;

  if (out_action_count)
    *out_action_count = 0u;
  if (!datapane || datapane->store_count == 0u || !manifest ||
      target_replicas == 0u || !out_action_count ||
      (action_capacity > 0u && !out_actions)) {
    return M3_REPAIR_INVALID_ARG;
  }
  for (size_t chunk_index = 0u; chunk_index < manifest->chunk_count;
       chunk_index++) {
    size_t have = chunk_receipt_count(manifest, chunk_index);

    if (have >= target_replicas)
      continue;
    if (!chunk_has_healthy_source(datapane, manifest, chunk_index))
      return M3_REPAIR_NOT_AVAILABLE;
    for (size_t missing = 0u; have + missing < target_replicas; missing++) {
      size_t chosen = SIZE_MAX;

      for (size_t s = 0u; s < datapane->store_count; s++) {
        int already = 0;

        for (size_t i = 0u; i < manifest->placement_count; i++) {
          const m3_object_manifest_placement_v1_t *p = &manifest->placements[i];

          if (p->chunk_index == chunk_index &&
              memcmp(p->store_node_id, datapane->stores[s].node_id,
                     M3_CHUNK_CAPABILITY_NODE_ID_SIZE) == 0) {
            already = 1;
            break;
          }
        }
        if (!already) {
          chosen = s;
          break;
        }
      }
      if (chosen == SIZE_MAX)
        return M3_REPAIR_NOT_AVAILABLE;
      if (out_actions && action_count < action_capacity) {
        out_actions[action_count].chunk_index = chunk_index;
        out_actions[action_count].target_store_index = chosen;
      }
      action_count++;
    }
  }
  if (action_count > action_capacity)
    return M3_REPAIR_RESOURCE_EXHAUSTED;
  *out_action_count = action_count;
  return M3_REPAIR_OK;
}

m3_repair_result_t m3_repair_execute_v1(
    m3_gateway_datapane_v1_t *datapane, const m3_object_manifest_v2_t *manifest,
    size_t target_replicas, uint64_t now_ms,
    m3_object_manifest_owned_v2_t *out_updated) {
  m3_repair_action_v1_t actions[M3_GATEWAY_DATAPANE_MAX_STORES *
                                M3_GATEWAY_DATAPANE_MAX_STORES];
  m3_object_manifest_owned_v2_t updated = {0};
  m3_repair_result_t result;
  size_t action_count = 0u;
  size_t capacity;
  size_t added = 0u;

  if (!out_updated)
    return M3_REPAIR_INVALID_ARG;
  memset(out_updated, 0, sizeof(*out_updated));
  result = m3_repair_plan_v1(
      datapane, manifest, target_replicas, actions,
      M3_GATEWAY_DATAPANE_MAX_STORES * M3_GATEWAY_DATAPANE_MAX_STORES,
      &action_count);
  if (result != M3_REPAIR_OK)
    return result;

  updated.manifest.version = M3_OBJECT_MANIFEST_VERSION_2;
  updated.manifest.object_cid = manifest->object_cid;
  updated.manifest.chunk_count = manifest->chunk_count;
  if (manifest->chunk_count > 0u) {
    updated.owned_chunks = (m3_chunk_cid_v1_t *)malloc(
        manifest->chunk_count * sizeof(*updated.owned_chunks));
    if (!updated.owned_chunks)
      return M3_REPAIR_RESOURCE_EXHAUSTED;
    memcpy(updated.owned_chunks, manifest->chunks,
           manifest->chunk_count * sizeof(*updated.owned_chunks));
  }
  updated.manifest.chunks = updated.owned_chunks;

  capacity = manifest->placement_count + action_count;
  if (capacity > 0u) {
    updated.owned_placements = (m3_object_manifest_placement_v1_t *)malloc(
        capacity * sizeof(*updated.owned_placements));
    if (!updated.owned_placements) {
      m3_object_manifest_owned_destroy_v2(&updated);
      return M3_REPAIR_RESOURCE_EXHAUSTED;
    }
    if (manifest->placement_count > 0u) {
      memcpy(updated.owned_placements, manifest->placements,
             manifest->placement_count * sizeof(*updated.owned_placements));
    }
  }
  updated.manifest.placements = updated.owned_placements;
  updated.manifest.placement_count = manifest->placement_count;

  for (size_t a = 0u; a < action_count; a++) {
    const m3_chunk_cid_v1_t *cid = &manifest->chunks[actions[a].chunk_index];
    m3_gateway_datapane_store_v1_t *target =
        &datapane->stores[actions[a].target_store_index];
    m3_chunk_receipt_v1_t receipt;
    uint8_t *bytes;
    size_t read = 0u;
    m3_gateway_datapane_result_t dp_result;

    if (cid->size > SIZE_MAX)
      continue;
    bytes = (uint8_t *)malloc((size_t)cid->size);
    if (!bytes) {
      m3_object_manifest_owned_destroy_v2(&updated);
      return M3_REPAIR_RESOURCE_EXHAUSTED;
    }
    dp_result = m3_gateway_datapane_read_chunk_v1(
        datapane, manifest, actions[a].chunk_index, cid, 0u, (size_t)cid->size,
        now_ms, bytes, &read);
    if (dp_result != M3_GATEWAY_DATAPANE_OK || read != (size_t)cid->size) {
      free(bytes);
      m3_object_manifest_owned_destroy_v2(&updated);
      return M3_REPAIR_NOT_AVAILABLE;
    }
    dp_result = m3_gateway_datapane_put_chunk_v1(
        datapane, actions[a].target_store_index, cid, bytes, (size_t)cid->size,
        now_ms, &receipt);
    free(bytes);
    if (dp_result != M3_GATEWAY_DATAPANE_OK) {
      m3_object_manifest_owned_destroy_v2(&updated);
      return M3_REPAIR_NOT_AVAILABLE;
    }
    {
      m3_object_manifest_placement_v1_t *p =
          &updated.owned_placements[updated.manifest.placement_count + added];

      p->chunk_index = (uint32_t)actions[a].chunk_index;
      memcpy(p->store_node_id, target->node_id, sizeof(p->store_node_id));
      if (m3_chunk_receipt_digest_v1(&receipt, p->receipt_digest) !=
          M3_CHUNK_RECEIPT_OK) {
        m3_object_manifest_owned_destroy_v2(&updated);
        return M3_REPAIR_INTERNAL;
      }
      added++;
    }
  }
  updated.manifest.placement_count += added;
  *out_updated = updated;
  return M3_REPAIR_OK;
}
