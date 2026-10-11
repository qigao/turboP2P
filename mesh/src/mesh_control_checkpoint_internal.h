#ifndef MESH_CONTROL_CHECKPOINT_INTERNAL_H
#define MESH_CONTROL_CHECKPOINT_INTERNAL_H

#include "mesh_control_checkpoint.h"

/* Private transaction boundary: validation and allocation finish before this
 * synchronous callback; owner state changes only when it returns nonzero.
 * The callback must not access or mutate the owner. */
mesh_control_checkpoint_result_t mesh_control_checkpoint_restore_before_commit(
    mesh_control_owner_v1_t *owner, const uint8_t *bytes, size_t size,
    uint64_t now_ms, int (*before_commit)(void *), void *context);

#endif
