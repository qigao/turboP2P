#ifndef MESH_CONTROL_CHECKPOINT_H
#define MESH_CONTROL_CHECKPOINT_H

#include "mesh_control_owner.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_CHECKPOINT_VERSION_V1 1u
#define MESH_CONTROL_CHECKPOINT_VERSION_V2 2u
#define MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1 69107968u

typedef enum {
  MESH_CONTROL_CHECKPOINT_OK = 0,
  MESH_CONTROL_CHECKPOINT_INVALID_ARG = -1,
  MESH_CONTROL_CHECKPOINT_INVALID_STATE = -2,
  MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED = -3,
  MESH_CONTROL_CHECKPOINT_CORRUPT = -4,
  MESH_CONTROL_CHECKPOINT_BINDING_MISMATCH = -5
} mesh_control_checkpoint_result_t;

/**
 * Encodes the owner's authoritative state, replay window and committed WAL
 * index into one
 * canonical, SHA-256 protected checkpoint. The returned allocation is owned
 * by the caller and must be released with mesh_control_checkpoint_free_v1().
 * Only the owner thread may call this while state mutation is quiescent.
 */
mesh_control_checkpoint_result_t
mesh_control_checkpoint_encode_v1(const mesh_control_owner_v1_t *owner, uint8_t **out_bytes,
                                  size_t *out_size);

/**
 * Validates a canonical V2 checkpoint without mutating an owner and returns
 * the WAL index represented by that checkpoint. V1 checkpoints are rejected
 * because they do not carry a committed WAL index and therefore cannot be
 * used as a safe compaction boundary.
 */
mesh_control_checkpoint_result_t
mesh_control_checkpoint_committed_log_index_v1(const uint8_t *bytes, size_t size,
                                               uint64_t *out_index);

/**
 * Restores a checkpoint into a newly initialized, otherwise unused owner.
 * The inbound channel must be empty and owner diagnostic counters must still
 * be zero. Identity/session binding and all capacity limits must match the
 * current owner configuration. On failure the owner remains unchanged.
 *
 * Replay entries expired at now_ms are omitted while last_sequence remains
 * authoritative. Running operation recovery is deliberately a separate
 * reconciler policy; this codec preserves the committed fact source exactly.
 */
mesh_control_checkpoint_result_t mesh_control_checkpoint_restore_v1(mesh_control_owner_v1_t *owner,
                                                                    const uint8_t *bytes,
                                                                    size_t size, uint64_t now_ms);

void mesh_control_checkpoint_free_v1(uint8_t *bytes);

#ifdef __cplusplus
}
#endif

#endif
