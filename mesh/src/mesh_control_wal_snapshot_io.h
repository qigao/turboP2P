#ifndef MESH_CONTROL_WAL_SNAPSHOT_IO_H
#define MESH_CONTROL_WAL_SNAPSHOT_IO_H

#include <cmeta_fs.h>

/* Private synchronous filesystem boundary. Bytes are borrowed for the call;
 * WAL authentication and index state remain with the calling WAL owner. */
int mesh_control_wal_snapshot_write(
    const char *staging, const char *destination, const uint8_t *bytes,
    size_t size, cmeta_fs_replace_state_t *publication);

/* Republish the exact validated file with bounded scratch storage. The owner
 * holds the writer lock throughout validation, copy and publication. */
int mesh_control_wal_snapshot_republish(
    const char *staging, const char *destination, size_t validated_size,
    cmeta_fs_replace_state_t *publication);

#endif
