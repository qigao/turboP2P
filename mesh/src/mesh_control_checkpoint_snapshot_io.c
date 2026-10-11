#include "mesh_control_checkpoint_snapshot_io.h"

#include <errno.h>
#include <limits.h>

static int write_all(cmeta_file_t file, const uint8_t *bytes, size_t size) {
  size_t offset = 0u;
  while (offset < size) {
    size_t chunk = size - offset;
    if (chunk > INT_MAX) chunk = INT_MAX;
    int count = cmeta_fs_write(file, (const char *)bytes + offset, chunk);
    if (count <= 0 || (size_t)count > chunk)
      return count < 0 ? count : -EIO;
    offset += (size_t)count;
  }
  return 0;
}

int mesh_control_checkpoint_snapshot_write(
    const char *staging, const char *destination, const uint8_t *bytes,
    size_t size, const uint8_t *tag, size_t tag_size,
    cmeta_fs_replace_state_t *publication) {
  if (!publication) return -EINVAL;
  *publication = SALTS_FS_REPLACE_NOT_PUBLISHED;
  if (!staging || !destination || !bytes || !size || (tag_size && !tag))
    return -EINVAL;
  cmeta_file_t file = cmeta_fs_open(staging,
      SALTS_FS_O_WRONLY | SALTS_FS_O_CREAT | SALTS_FS_O_TRUNC, 0600);
  if (file == SALTS_INVALID_FILE) return -EIO;
  int status = write_all(file, bytes, size);
  if (!status && tag_size) status = write_all(file, tag, tag_size);
  int close_status = cmeta_fs_close(file);
  if (!status) status = close_status;
  if (!status)
    status = cmeta_fs_replace_durable(staging, destination, publication);
  if (*publication == SALTS_FS_REPLACE_NOT_PUBLISHED)
    (void)cmeta_fs_unlink(staging);
  return status;
}
