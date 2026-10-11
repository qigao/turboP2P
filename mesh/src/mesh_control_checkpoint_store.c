#include "mesh_control_checkpoint_store.h"
#include "mesh_control_checkpoint_internal.h"
#include "mesh_control_checkpoint_snapshot_io.h"
#include <fmt.h>
#include <errno.h>
#include <limits.h>

#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
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

static mesh_control_checkpoint_store_result_t
read_exact_file(const char *path, size_t max_size, uint8_t **out_bytes, size_t *out_size) {
  cmeta_fs_stat_t stat;
  cmeta_file_t file = SALTS_INVALID_FILE;
  uint8_t *bytes = NULL;
  uint8_t trailing;
  size_t offset = 0u;
  int read_size;

  if (cmeta_fs_lstat(path, &stat) != 0)
    return MESH_CONTROL_CHECKPOINT_STORE_IO;
  if (!stat.is_file || stat.is_symlink || stat.size < CHECKPOINT_STORE_MIN_FILE_SIZE ||
      stat.size > max_size || stat.size > SIZE_MAX) {
    return MESH_CONTROL_CHECKPOINT_STORE_CORRUPT;
  }
  bytes = (uint8_t *)malloc((size_t)stat.size);
  if (!bytes)
    return MESH_CONTROL_CHECKPOINT_STORE_RESOURCE_EXHAUSTED;
  file = cmeta_fs_open(path, SALTS_FS_O_RDONLY, 0);
  if (file == SALTS_INVALID_FILE)
    goto io_failed;
  while (offset < (size_t)stat.size) {
    read_size = cmeta_fs_read(file, (char *)bytes + offset, (size_t)stat.size - offset);
    if (read_size <= 0 || (size_t)read_size > (size_t)stat.size - offset)
      goto io_failed;
    offset += (size_t)read_size;
  }
  read_size = cmeta_fs_read(file, (char *)&trailing, 1u);
  int close_result = cmeta_fs_close(file);
  file = SALTS_INVALID_FILE;
  if (read_size != 0 || close_result != 0)
    goto io_failed_closed;
  *out_bytes = bytes;
  *out_size = offset;
  return MESH_CONTROL_CHECKPOINT_STORE_OK;

io_failed:
  if (file != SALTS_INVALID_FILE)
    (void)cmeta_fs_close(file);
io_failed_closed:
  OPENSSL_cleanse(bytes, (size_t)stat.size);
  free(bytes);
  return MESH_CONTROL_CHECKPOINT_STORE_IO;
}

static mesh_control_checkpoint_store_result_t checkpoint_store_open(
    mesh_control_checkpoint_store_v1_t *store, const char *path,
    const uint8_t authentication_key[MESH_CONTROL_CHECKPOINT_STORE_AUTH_KEY_SIZE_V1]) {
  tstr suffix = NULL;
  mesh_control_checkpoint_store_result_t result = MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;

  if (!store || !path || !path_is_absolute(path) || strlen(path) >= SALTS_FS_MAX_PATH)
    return result;
  memset(store, 0, sizeof(*store));
  store->lock_file = SALTS_INVALID_FILE;
  memcpy(store->path, path, strlen(path) + 1u);
  suffix = tstr_format("{}.tmp", path);
  if (!suffix) {
    result = MESH_CONTROL_CHECKPOINT_STORE_RESOURCE_EXHAUSTED;
    goto failed;
  }
  memcpy(store->temp_path, suffix, tstr_len(suffix) + 1u);
  tstr_free(suffix);
  suffix = tstr_format("{}.lock", path);
  if (!suffix) {
    result = MESH_CONTROL_CHECKPOINT_STORE_RESOURCE_EXHAUSTED;
    goto failed;
  }
  memcpy(store->lock_path, suffix, tstr_len(suffix) + 1u);
  tstr_free(suffix);
  cmeta_fs_stat_t lock_stat;
  int lookup = cmeta_fs_lstat(store->lock_path, &lock_stat);
  if (lookup != 0 && lookup != -ENOENT) {
    result = MESH_CONTROL_CHECKPOINT_STORE_IO;
    goto failed;
  }
  if (!lookup && (!lock_stat.is_file || lock_stat.is_symlink)) {
    result = MESH_CONTROL_CHECKPOINT_STORE_IO;
    goto failed;
  }
  store->lock_file = cmeta_fs_open(store->lock_path,
      SALTS_FS_O_RDWR | (lookup == -ENOENT ? SALTS_FS_O_CREAT : 0), CHECKPOINT_STORE_MODE);
  if (store->lock_file == SALTS_INVALID_FILE) {
    result = MESH_CONTROL_CHECKPOINT_STORE_IO;
    goto failed;
  }
  if (cmeta_fs_lock(store->lock_file, SALTS_FS_LOCK_EXCLUSIVE | SALTS_FS_LOCK_NONBLOCK, 0, 1u) !=
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

typedef struct {
  const mesh_control_checkpoint_store_v1_t *store;
  const uint8_t *bytes;
  size_t size;
  uint8_t failed;
} checkpoint_publication;

static int republish_before_restore(void *argument) {
  checkpoint_publication *pending = (checkpoint_publication *)argument;
  cmeta_fs_replace_state_t publication = SALTS_FS_REPLACE_NOT_PUBLISHED;
  int status = mesh_control_checkpoint_snapshot_write(pending->store->temp_path,
      pending->store->path, pending->bytes, pending->size, NULL, 0u, &publication);
  pending->failed = status != 0 || publication != SALTS_FS_REPLACE_PUBLISHED_DURABLE;
  return !pending->failed;
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
  cmeta_fs_stat_t stat;
  int lookup = cmeta_fs_lstat(store->path, &stat);
  if (lookup == -ENOENT)
    return MESH_CONTROL_CHECKPOINT_STORE_OK;
  if (lookup != 0)
    return MESH_CONTROL_CHECKPOINT_STORE_IO;
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
  checkpoint_publication pending = {store, bytes, size, 0u};
  result = map_checkpoint_result(mesh_control_checkpoint_restore_before_commit(
      owner, bytes, payload_size, now_ms, republish_before_restore, &pending));
  if (pending.failed) result = MESH_CONTROL_CHECKPOINT_STORE_IO;
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
  uint8_t authenticator[MESH_CONTROL_CHECKPOINT_STORE_AUTH_TAG_SIZE_V1] = {0};
  size_t tag_size = 0u;
  cmeta_fs_replace_state_t publication = SALTS_FS_REPLACE_NOT_PUBLISHED;

  if (!store || store->open == 0u || !bytes || size == 0u ||
      size > MESH_CONTROL_CHECKPOINT_MAX_SIZE_V1)
    return MESH_CONTROL_CHECKPOINT_STORE_INVALID_ARG;
  if (store->authenticated) {
    if (!checkpoint_authenticate(store->authentication_key, bytes, size, authenticator)) {
      OPENSSL_cleanse(authenticator, sizeof(authenticator));
      return MESH_CONTROL_CHECKPOINT_STORE_AUTH_FAILED;
    }
    tag_size = sizeof(authenticator);
  }
  int status = mesh_control_checkpoint_snapshot_write(store->temp_path, store->path,
      bytes, size, authenticator, tag_size, &publication);
  OPENSSL_cleanse(authenticator, sizeof(authenticator));
  return !status && publication == SALTS_FS_REPLACE_PUBLISHED_DURABLE
      ? MESH_CONTROL_CHECKPOINT_STORE_OK : MESH_CONTROL_CHECKPOINT_STORE_IO;
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
  if (store->lock_file != SALTS_INVALID_FILE) {
    if (store->open != 0u)
      (void)cmeta_fs_unlock(store->lock_file, 0, 1u);
    (void)cmeta_fs_close(store->lock_file);
  }
  OPENSSL_cleanse(store, sizeof(*store));
  store->lock_file = SALTS_INVALID_FILE;
}
