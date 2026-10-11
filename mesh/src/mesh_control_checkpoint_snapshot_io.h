#ifndef MESH_CONTROL_CHECKPOINT_SNAPSHOT_IO_H
#define MESH_CONTROL_CHECKPOINT_SNAPSHOT_IO_H

#include <cmeta_fs.h>

/* Private synchronous publication boundary. Both spans are borrowed; the
 * store owns authentication and the exclusive writer lock. */
int mesh_control_checkpoint_snapshot_write(
    const char *staging, const char *destination, const uint8_t *bytes,
    size_t size, const uint8_t *tag, size_t tag_size,
    cmeta_fs_replace_state_t *publication);

#endif
