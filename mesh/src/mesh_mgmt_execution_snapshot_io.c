#include "mesh_mgmt_execution_snapshot_io.h"

#include <errno.h>
#include <limits.h>

int mesh_mgmt_execution_snapshot_write(
    const char *staging_path, const char *destination_path,
    const uint8_t *bytes, size_t size, cmeta_fs_replace_state_t *publication) {
  cmeta_file_t file;
  size_t written = 0u;
  int result = 0;
  if (!publication) return -EINVAL;
  *publication = SALTS_FS_REPLACE_NOT_PUBLISHED;
  if (!staging_path || !destination_path || !bytes || !size)
    return -EINVAL;
  file = cmeta_fs_open(staging_path,
      SALTS_FS_O_WRONLY | SALTS_FS_O_CREAT | SALTS_FS_O_TRUNC, 0600);
  if (file == SALTS_INVALID_FILE) return -EIO;
  while (written < size) {
    size_t chunk = size - written;
    if (chunk > INT_MAX) chunk = INT_MAX;
    int count = cmeta_fs_write(file, (const char *)bytes + written, chunk);
    if (count <= 0 || (size_t)count > chunk) {
      result = count < 0 ? count : -EIO;
      break;
    }
    written += (size_t)count;
  }
  /* Close exactly once even after write failure. The SDK reopens/flushed
   * staging and publishes the namespace using the platform durability step. */
  int close_result = cmeta_fs_close(file);
  if (!result) result = close_result;
  if (!result)
    result = cmeta_fs_replace_durable(staging_path, destination_path, publication);
  if (*publication == SALTS_FS_REPLACE_NOT_PUBLISHED)
    (void)cmeta_fs_unlink(staging_path);
  return result;
}
