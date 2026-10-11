#include "mesh_control_wal_snapshot_io.h"

#include <errno.h>
#include <limits.h>

enum { WAL_COPY_CHUNK_SIZE = 8192 };

static int write_all(cmeta_file_t file, const uint8_t *bytes, size_t size) {
  size_t offset = 0u;
  while (offset < size) {
    size_t chunk = size - offset;
    if (chunk > INT_MAX) chunk = INT_MAX;
    int written = cmeta_fs_write(file, (const char *)bytes + offset, chunk);
    if (written <= 0 || (size_t)written > chunk)
      return written < 0 ? written : -EIO;
    offset += (size_t)written;
  }
  return 0;
}

static int finish_staging(cmeta_file_t file, int status, const char *staging,
                          const char *destination,
                          cmeta_fs_replace_state_t *publication) {
  int close_status = cmeta_fs_close(file);
  if (!status) status = close_status;
  if (!status)
    status = cmeta_fs_replace_durable(staging, destination, publication);
  if (*publication == SALTS_FS_REPLACE_NOT_PUBLISHED)
    (void)cmeta_fs_unlink(staging);
  return status;
}

int mesh_control_wal_snapshot_write(
    const char *staging, const char *destination, const uint8_t *bytes,
    size_t size, cmeta_fs_replace_state_t *publication) {
  if (!publication) return -EINVAL;
  *publication = SALTS_FS_REPLACE_NOT_PUBLISHED;
  if (!staging || !destination || !bytes || !size) return -EINVAL;
  cmeta_file_t file = cmeta_fs_open(staging,
      SALTS_FS_O_WRONLY | SALTS_FS_O_CREAT | SALTS_FS_O_TRUNC, 0600);
  if (file == SALTS_INVALID_FILE) return -EIO;
  return finish_staging(file, write_all(file, bytes, size), staging,
                        destination, publication);
}

int mesh_control_wal_snapshot_republish(
    const char *staging, const char *destination, size_t validated_size,
    cmeta_fs_replace_state_t *publication) {
  uint8_t buffer[WAL_COPY_CHUNK_SIZE];
  size_t copied = 0u;
  int status = 0;
  if (!publication) return -EINVAL;
  *publication = SALTS_FS_REPLACE_NOT_PUBLISHED;
  if (!staging || !destination || !validated_size) return -EINVAL;
  cmeta_file_t source = cmeta_fs_open(destination, SALTS_FS_O_RDONLY, 0);
  if (source == SALTS_INVALID_FILE) return -EIO;
  cmeta_file_t output = cmeta_fs_open(staging,
      SALTS_FS_O_WRONLY | SALTS_FS_O_CREAT | SALTS_FS_O_TRUNC, 0600);
  if (output == SALTS_INVALID_FILE) {
    (void)cmeta_fs_close(source);
    return -EIO;
  }
  while (copied < validated_size) {
    size_t chunk = validated_size - copied;
    if (chunk > sizeof(buffer)) chunk = sizeof(buffer);
    int count = cmeta_fs_read(source, (char *)buffer, chunk);
    if (count <= 0 || (size_t)count > chunk) {
      status = count < 0 ? count : -EIO;
      break;
    }
    status = write_all(output, buffer, (size_t)count);
    if (status) break;
    copied += (size_t)count;
  }
  if (!status && cmeta_fs_read(source, (char *)buffer, 1u) != 0) status = -EIO;
  int close_status = cmeta_fs_close(source);
  if (!status) status = close_status;
  return finish_staging(output, status, staging, destination, publication);
}
