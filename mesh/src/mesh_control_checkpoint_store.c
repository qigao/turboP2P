#include "mesh_control_checkpoint_store.h"

#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECKPOINT_STORE_MODE 0600
#define CHECKPOINT_STORE_MIN_FILE_SIZE 256u

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int
checkpoint_authenticate(const uint8_t key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1],
                        const uint8_t *bytes, size_t size,
                        uint8_t output[MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1]) {
  unsigned int output_size = 0u;
  if (!key || !bytes || !output || size > INT_MAX)
    return 0;
  return HMAC(EVP_sha256(), key, MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1, bytes, size,
              output, &output_size) != NULL &&
         output_size == MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1;
}

static int path_is_absolute(const char *path) {
  if (!path || path[0] == '\0')
    return 0;
  if (path[0] == '/')
    return 1;
  return (path[0] == '\\' && path[1] == '\\') ||
         (isalpha((unsigned char)path[0]) && path[1] == ':' && (path[2] == '/' || path[2] == '\\'));
}

static mesh_control_checkpoint_store_result_t
map_checkpoint_result(mesh_control_checkpoint_result_t result) {
  switch (result) {
  case MESH_CONTROL_CHECKPOINT_OK:
    return MESH_CONTROL_CHECKPOINT_STORE_OK;
  case MESH_CONTROL_CHECKPOINT_RESOURCE_EXHAUSTED:
    return MESH_CONTROL_CHECKPOINT_STORE_RESOURCE_EXHAUSTED;
  case MESH_CONTROL_CHECKPOINT_CORRUPT:
    return MESH_CONTROL_CHECKPOINT_STORE_CORRUPT;
  case MESH_CONTROL_CHECKPOINT_BINDING_MISMATCH:
    return MESH_CONTROL_CHECKPOINT_STORE_BINDING_MISMATCH;
  case MESH_CONTROL_CHECKPOINT_INVALID_STATE:
    return MESH_CONTROL_CHECKPOINT_STORE_INVALID_STATE;
  default:
    return MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;
  }
}

static mesh_control_checkpoint_store_result_t write_all(turbo_file_t file, const uint8_t *bytes,
                                                        size_t size) {
  size_t offset = 0u;
  while (offset < size) {
    int written = turbo_fs_write(file, (const char *)bytes + offset, size - offset);
    if (written <= 0)
      return MESH_CONTROL_CHECKPOINT_STORE_IO;
    offset += (size_t)written;
  }
  return MESH_CONTROL_CHECKPOINT_STORE_OK;
}

static mesh_control_checkpoint_store_result_t
read_exact_file(const char *path, size_t max_size, uint8_t **out_bytes, size_t *out_size) {
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t *bytes = NULL;
  uint8_t trailing;
  size_t offset = 0u;
  int read_size;

  if (!path || !out_bytes || !out_size || turbo_fs_stat(path, &stat) != 0 || !stat.is_file ||
      stat.size < CHECKPOINT_STORE_MIN_FILE_SIZE || stat.size > max_size || stat.size > SIZE_MAX) {
    return MESH_CONTROL_CHECKPOINT_STORE_CORRUPT;
  }
  bytes = (uint8_t *)malloc((size_t)stat.size);
  if (!bytes)
    return MESH_CONTROL_CHECKPOINT_STORE_RESOURCE_EXHAUSTED;
  file = turbo_fs_open(path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    goto io_failed;
  while (offset < (size_t)stat.size) {
    read_size = turbo_fs_read(file, (char *)bytes + offset, (size_t)stat.size - offset);
    if (read_size <= 0)
      goto io_failed;
    offset += (size_t)read_size;
  }
  read_size = turbo_fs_read(file, (char *)&trailing, 1u);
  if (read_size != 0 || turbo_fs_close(file) != 0)
    goto io_failed_closed;
  *out_bytes = bytes;
  *out_size = offset;
  return MESH_CONTROL_CHECKPOINT_STORE_OK;

io_failed:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
io_failed_closed:
  free(bytes);
  return MESH_CONTROL_CHECKPOINT_STORE_IO;
}

static mesh_control_checkpoint_store_result_t checkpoint_store_open(
    mesh_control_checkpoint_store_v1_t *store, const char *path,
    const uint8_t authentication_key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1]) {
  int length;
  mesh_control_checkpoint_store_result_t result = MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;

  if (!store || !path || !path_is_absolute(path) || strlen(path) >= TURBO_FS_MAX_PATH)
    return result;
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
  memcpy(store->path, path, strlen(path) + 1u);
  length = snprintf(store->temp_path, sizeof(store->temp_path), "%s.tmp", path);
  if (length < 0 || (size_t)length >= sizeof(store->temp_path))
    goto failed;
  length = snprintf(store->lock_path, sizeof(store->lock_path), "%s.lock", path);
  if (length < 0 || (size_t)length >= sizeof(store->lock_path))
    goto failed;
  store->lock_file =
      turbo_fs_open(store->lock_path, TURBO_FS_O_RDWR | TURBO_FS_O_CREAT, CHECKPOINT_STORE_MODE);
  if (store->lock_file == TURBO_INVALID_FILE) {
    result = MESH_CONTROL_CHECKPOINT_STORE_IO;
    goto failed;
  }
  if (turbo_fs_lock(store->lock_file, TURBO_FS_LOCK_EXCLUSIVE | TURBO_FS_LOCK_NONBLOCK, 0, 1u) !=
      0) {
    result = MESH_CONTROL_CHECKPOINT_STORE_LOCKED;
    goto failed;
  }
  store->open = 1u;
  if (authentication_key) {
    memcpy(store->authentication_key, authentication_key, sizeof(store->authentication_key));
    store->authenticated = 1u;
  }
  return MESH_CONTROL_CHECKPOINT_STORE_OK;

failed:
  mesh_control_checkpoint_store_close_v1(store);
  return result;
}

mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_open_v1(mesh_control_checkpoint_store_v1_t *store, const char *path) {
  return checkpoint_store_open(store, path, NULL);
}

mesh_control_checkpoint_store_result_t mesh_control_checkpoint_store_open_authenticated_v1(
    mesh_control_checkpoint_store_v1_t *store, const char *path,
    const uint8_t authentication_key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1]) {
  if (bytes_zero(authentication_key, MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1))
    return MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;
  return checkpoint_store_open(store, path, authentication_key);
}

mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_load_v1(const mesh_control_checkpoint_store_v1_t *store,
                                      mesh_control_owner_v1_t *owner, uint64_t now_ms,
                                      uint8_t *out_found) {
  uint8_t *bytes = NULL;
  size_t payload_size;
  size_t size = 0u;
  mesh_control_checkpoint_store_result_t result;

  if (!store || store->open == 0u || !owner || !out_found)
    return MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;
  *out_found = 0u;
  if (turbo_fs_access(store->path, TURBO_FS_ACCESS_EXISTS) != 0)
    return MESH_CONTROL_CHECKPOINT_STORE_OK;
  result = read_exact_file(
      store->path,
      MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1 +
          (store->authenticated ? MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1 : 0u),
      &bytes, &size);
  if (result != MESH_CONTROL_CHECKPOINT_STORE_OK)
    return result;
  payload_size = size;
  if (store->authenticated) {
    uint8_t expected[MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1];
    if (size < CHECKPOINT_STORE_MIN_FILE_SIZE + MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1) {
      result = MESH_CONTROL_CHECKPOINT_STORE_CORRUPT;
      goto cleanup;
    }
    payload_size = size - MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1;
    if (!checkpoint_authenticate(store->authentication_key, bytes, payload_size, expected) ||
        CRYPTO_memcmp(expected, bytes + payload_size, sizeof(expected)) != 0) {
      OPENSSL_cleanse(expected, sizeof(expected));
      result = MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED;
      goto cleanup;
    }
    OPENSSL_cleanse(expected, sizeof(expected));
  }
  result =
      map_checkpoint_result(mesh_control_checkpoint_restore_v1(owner, bytes, payload_size, now_ms));
cleanup:
  OPENSSL_cleanse(bytes, size);
  free(bytes);
  if (result == MESH_CONTROL_CHECKPOINT_STORE_OK)
    *out_found = 1u;
  return result;
}

mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_save_bytes_v1(const mesh_control_checkpoint_store_v1_t *store,
                                            const uint8_t *bytes, size_t size) {
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t authenticator[MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1];
  mesh_control_checkpoint_store_result_t result = MESH_CONTROL_CHECKPOINT_STORE_IO;
  int close_result;
  int fsync_result;

  if (!store || store->open == 0u || !bytes || size == 0u ||
      size > MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1)
    return MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;
  file = turbo_fs_open(store->temp_path, TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       CHECKPOINT_STORE_MODE);
  if (file == TURBO_INVALID_FILE) {
    result = MESH_CONTROL_CHECKPOINT_STORE_IO;
    goto cleanup;
  }
  result = write_all(file, bytes, size);
  if (result != MESH_CONTROL_CHECKPOINT_STORE_OK)
    goto cleanup;
  if (store->authenticated) {
    if (!checkpoint_authenticate(store->authentication_key, bytes, size, authenticator)) {
      result = MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED;
      goto cleanup;
    }
    result = write_all(file, authenticator, sizeof(authenticator));
    if (result != MESH_CONTROL_CHECKPOINT_STORE_OK)
      goto cleanup;
  }
  fsync_result = turbo_fs_fsync(file);
  close_result = turbo_fs_close(file);
  file = TURBO_INVALID_FILE;
  if (fsync_result != 0 || close_result != 0) {
    result = MESH_CONTROL_CHECKPOINT_STORE_IO;
    goto cleanup;
  }
  if (turbo_fs_rename(store->temp_path, store->path) != 0) {
    result = MESH_CONTROL_CHECKPOINT_STORE_IO;
    goto cleanup;
  }
  result = MESH_CONTROL_CHECKPOINT_STORE_OK;

cleanup:
  OPENSSL_cleanse(authenticator, sizeof(authenticator));
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  if (result != MESH_CONTROL_CHECKPOINT_STORE_OK &&
      turbo_fs_access(store->temp_path, TURBO_FS_ACCESS_EXISTS) == 0) {
    (void)turbo_fs_unlink(store->temp_path);
  }
  return result;
}

mesh_control_checkpoint_store_result_t
mesh_control_checkpoint_store_save_v1(const mesh_control_checkpoint_store_v1_t *store,
                                      const mesh_control_owner_v1_t *owner) {
  uint8_t *bytes = NULL;
  size_t size = 0u;
  mesh_control_checkpoint_store_result_t result;

  if (!store || store->open == 0u || !owner)
    return MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;
  result = map_checkpoint_result(mesh_control_checkpoint_encode_v1(owner, &bytes, &size));
  if (result == MESH_CONTROL_CHECKPOINT_STORE_OK)
    result = mesh_control_checkpoint_store_save_bytes_v1(store, bytes, size);
  mesh_control_checkpoint_free_v1(bytes);
  return result;
}

void mesh_control_checkpoint_store_close_v1(mesh_control_checkpoint_store_v1_t *store) {
  if (!store)
    return;
  if (store->lock_file != TURBO_INVALID_FILE) {
    if (store->open != 0u)
      (void)turbo_fs_unlock(store->lock_file, 0, 1u);
    (void)turbo_fs_close(store->lock_file);
  }
  OPENSSL_cleanse(store, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
}
