#ifndef MESH_MGMT_EXECUTION_SNAPSHOT_IO_H
#define MESH_MGMT_EXECUTION_SNAPSHOT_IO_H

#include <cmeta_fs.h>

/* Private filesystem boundary. The caller owns immutable encoded bytes for
 * this synchronous call. No journal state or signature policy lives here.
 * Publication is always reported, including when durability is uncertain. */
int mesh_mgmt_execution_snapshot_write(
    const char *staging_path, const char *destination_path,
    const uint8_t *bytes, size_t size, cmeta_fs_replace_state_t *publication);

#endif
