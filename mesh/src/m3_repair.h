#ifndef M3_REPAIR_H
#define M3_REPAIR_H

#include "m3_gateway_datapane.h"
#include "m3_object_manifest.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_REPAIR_OK = 0,
  M3_REPAIR_INVALID_ARG = -1,
  M3_REPAIR_NOT_FOUND = -2,
  M3_REPAIR_RESOURCE_EXHAUSTED = -3,
  M3_REPAIR_NOT_AVAILABLE = -4,
  M3_REPAIR_INTERNAL = -5,
} m3_repair_result_t;

/** One backfill action: replicate chunk chunk_index onto target_store_index. */
typedef struct {
  size_t chunk_index;
  size_t target_store_index;
} m3_repair_action_v1_t;

/**
 * Plan backfill actions for a committed manifest: every chunk whose placement
 * count is below target_replicas receives one action per missing replica, with
 * a target store that does not already hold the chunk. Source replicas are the
 * manifest's existing placements. Returns NOT_AVAILABLE when no registered
 * store can serve as a new replica or when a chunk has no healthy source.
 */
m3_repair_result_t m3_repair_plan_v1(
    m3_gateway_datapane_v1_t *datapane, const m3_object_manifest_v2_t *manifest,
    size_t target_replicas, m3_repair_action_v1_t *out_actions,
    size_t action_capacity, size_t *out_action_count);

/**
 * Execute the backfill plan: read each under-replicated chunk from a healthy
 * replica and durably publish it to the target store, then produce an updated
 * owned manifest with the new placements (same object version). The caller
 * encodes and commits it via UPDATE_PLACEMENT. On success *out_updated is
 * owned and released with m3_object_manifest_owned_destroy_v2().
 */
m3_repair_result_t m3_repair_execute_v1(
    m3_gateway_datapane_v1_t *datapane, const m3_object_manifest_v2_t *manifest,
    size_t target_replicas, uint64_t now_ms,
    m3_object_manifest_owned_v2_t *out_updated);

#ifdef __cplusplus
}
#endif

#endif
