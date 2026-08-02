#include "m3_chunk_store.h"

#include <openssl/evp.h>
#include <platform.h>

#include <stdio.h>
#include <string.h>

enum {
  M3_CHUNK_STORE_IO_BLOCK = 32 * 1024,
  M3_CHUNK_STORE_DIRECTORY_MODE = 0700,
  M3_CHUNK_STORE_FILE_MODE = 0600,
  M3_CHUNK_STORE_TEMP_RANDOM_SIZE = 16,
};

static const char M3_CHUNK_STORE_LAYOUT[] = "v1";
static const char M3_CHUNK_STORE_CHUNKS[] = "chunks";
static const char M3_CHUNK_STORE_TEMP[] = "tmp";
static const char M3_CHUNK_STORE_LOCK[] = ".store.lock";

static int cid_is_valid(const m3_chunk_cid_v1_t *cid) {
  return cid &&
         cid->hash_algorithm == M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
}

static int cid_equal(const m3_chunk_cid_v1_t *left,
                     const m3_chunk_cid_v1_t *right) {
  return cid_is_valid(left) && cid_is_valid(right) &&
         left->hash_algorithm == right->hash_algorithm &&
         left->size == right->size &&
         memcmp(left->digest, right->digest, sizeof(left->digest)) == 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t size, char *output) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0; i < size; i++) {
    output[i * 2u] = digits[bytes[i] >> 4u];
    output[i * 2u + 1u] = digits[bytes[i] & 0x0fu];
  }
  output[size * 2u] = '\0';
}

static m3_chunk_store_result_t ensure_directory(const char *path) {
  turbo_fs_stat_t stat;

  if (!path)
    return M3_CHUNK_STORE_INVALID_ARG;
  if (turbo_fs_lstat(path, &stat) == 0) {
    return stat.is_directory && !stat.is_symlink ? M3_CHUNK_STORE_OK
                                                  : M3_CHUNK_STORE_CORRUPT;
  }
  if (turbo_fs_mkdir(path, M3_CHUNK_STORE_DIRECTORY_MODE) == 0)
    return M3_CHUNK_STORE_OK;

  /* A concurrent creator is acceptable only when it published a real dir. */
  if (turbo_fs_lstat(path, &stat) == 0 && stat.is_directory &&
      !stat.is_symlink)
    return M3_CHUNK_STORE_OK;
  return M3_CHUNK_STORE_IO;
}

static m3_chunk_store_result_t join_path(char output[TURBO_FS_MAX_PATH],
                                         const char *base,
                                         const char *component) {
  if (!output || !base || !component ||
      turbo_fs_path_join(output, TURBO_FS_MAX_PATH, base, component) != 0)
    return M3_CHUNK_STORE_INVALID_ARG;
  return M3_CHUNK_STORE_OK;
}

static m3_chunk_store_result_t build_chunk_path(
    const m3_chunk_store_v1_t *store, const m3_chunk_cid_v1_t *cid,
    char shard_path[TURBO_FS_MAX_PATH],
    char chunk_path[TURBO_FS_MAX_PATH]) {
  char digest_hex[M3_CHUNK_CID_DIGEST_SIZE * 2u + 1u];
  char shard[3];
  char filename[M3_CHUNK_CID_DIGEST_SIZE * 2u + 7u];

  if (!store || !store->open || !cid_is_valid(cid) || !shard_path ||
      !chunk_path)
    return M3_CHUNK_STORE_INVALID_ARG;

  bytes_to_hex(cid->digest, sizeof(cid->digest), digest_hex);
  shard[0] = digest_hex[0];
  shard[1] = digest_hex[1];
  shard[2] = '\0';
  if (snprintf(filename, sizeof(filename), "%s.chunk", digest_hex + 2) < 0)
    return M3_CHUNK_STORE_INVALID_ARG;
  if (join_path(shard_path, store->chunks_path, shard) !=
          M3_CHUNK_STORE_OK ||
      join_path(chunk_path, shard_path, filename) != M3_CHUNK_STORE_OK)
    return M3_CHUNK_STORE_INVALID_ARG;
  return M3_CHUNK_STORE_OK;
}

static m3_chunk_store_result_t write_all(turbo_file_t file,
                                          const uint8_t *bytes, size_t size) {
  size_t written = 0u;

  while (written < size) {
    int result =
        turbo_fs_write(file, (const char *)bytes + written, size - written);
    if (result <= 0)
      return M3_CHUNK_STORE_IO;
    written += (size_t)result;
  }
  return M3_CHUNK_STORE_OK;
}

static m3_chunk_store_result_t hash_bytes(
    const uint8_t *bytes, size_t size,
    uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE]) {
  static const uint8_t empty = 0u;
  unsigned int digest_size = 0u;

  if ((!bytes && size > 0u) || !digest)
    return M3_CHUNK_STORE_INVALID_ARG;
  if (EVP_Digest(size > 0u ? bytes : &empty, size, digest, &digest_size,
                 EVP_sha256(), NULL) != 1 ||
      digest_size != M3_CHUNK_CID_DIGEST_SIZE)
    return M3_CHUNK_STORE_RESOURCE_EXHAUSTED;
  return M3_CHUNK_STORE_OK;
}

static m3_chunk_store_result_t read_verify_range(
    const char *path, const m3_chunk_cid_v1_t *cid, uint64_t offset,
    size_t length, uint8_t *buffer, size_t *out_read) {
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  EVP_MD_CTX *hash = NULL;
  uint8_t block[M3_CHUNK_STORE_IO_BLOCK];
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
  uint64_t position = 0u;
  size_t copied = 0u;
  unsigned int digest_size = 0u;
  int read_size = 0;
  m3_chunk_store_result_t result = M3_CHUNK_STORE_IO;

  if (!path || !cid_is_valid(cid) || (!buffer && length > 0u) || !out_read)
    return M3_CHUNK_STORE_INVALID_ARG;
  *out_read = 0u;

  if (turbo_fs_lstat(path, &stat) != 0)
    return M3_CHUNK_STORE_NOT_FOUND;
  if (!stat.is_file || stat.is_symlink || stat.size != cid->size)
    return M3_CHUNK_STORE_CORRUPT;

  file = turbo_fs_open(path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    return M3_CHUNK_STORE_IO;
  hash = EVP_MD_CTX_new();
  if (!hash) {
    result = M3_CHUNK_STORE_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
    result = M3_CHUNK_STORE_RESOURCE_EXHAUSTED;
    goto cleanup;
  }

  while ((read_size = turbo_fs_read(file, (char *)block, sizeof(block))) > 0) {
    uint64_t block_end = position + (uint64_t)read_size;
    uint64_t range_end = offset + (uint64_t)length;

    if (block_end < position ||
        EVP_DigestUpdate(hash, block, (size_t)read_size) != 1) {
      result = M3_CHUNK_STORE_CORRUPT;
      goto cleanup;
    }
    if (length > 0u && block_end > offset && position < range_end) {
      uint64_t copy_start = position > offset ? position : offset;
      uint64_t copy_end = block_end < range_end ? block_end : range_end;
      size_t copy_size = (size_t)(copy_end - copy_start);
      size_t block_offset = (size_t)(copy_start - position);
      memcpy(buffer + copied, block + block_offset, copy_size);
      copied += copy_size;
    }
    position = block_end;
  }
  if (read_size < 0 || position != cid->size || copied != length) {
    result = M3_CHUNK_STORE_CORRUPT;
    goto cleanup;
  }
  if (EVP_DigestFinal_ex(hash, digest, &digest_size) != 1 ||
      digest_size != sizeof(digest)) {
    result = M3_CHUNK_STORE_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  if (memcmp(digest, cid->digest, sizeof(digest)) != 0) {
    result = M3_CHUNK_STORE_CORRUPT;
    goto cleanup;
  }
  result = M3_CHUNK_STORE_OK;
  *out_read = copied;

cleanup:
  EVP_MD_CTX_free(hash);
  if (file != TURBO_INVALID_FILE && turbo_fs_close(file) != 0 &&
      result == M3_CHUNK_STORE_OK) {
    *out_read = 0u;
    result = M3_CHUNK_STORE_IO;
  }
  return result;
}

m3_chunk_store_result_t m3_chunk_cid_calculate_v1(
    const uint8_t *bytes, size_t size, m3_chunk_cid_v1_t *out_cid) {
  m3_chunk_store_result_t result;

  if ((!bytes && size > 0u) || !out_cid)
    return M3_CHUNK_STORE_INVALID_ARG;
  memset(out_cid, 0, sizeof(*out_cid));
  result = hash_bytes(bytes, size, out_cid->digest);
  if (result != M3_CHUNK_STORE_OK) {
    memset(out_cid, 0, sizeof(*out_cid));
    return result;
  }
  out_cid->hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  out_cid->size = (uint64_t)size;
  return M3_CHUNK_STORE_OK;
}

m3_chunk_store_result_t m3_chunk_store_open_v1(
    m3_chunk_store_v1_t *store, const char *root, uint64_t max_chunk_bytes) {
  char layout_path[TURBO_FS_MAX_PATH];
  m3_chunk_store_result_t result;

  if (!store || !root || root[0] == '\0' || max_chunk_bytes == 0u ||
      !turbo_fs_path_is_absolute(root) || strlen(root) >= sizeof(store->root))
    return M3_CHUNK_STORE_INVALID_ARG;

  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
  memcpy(store->root, root, strlen(root) + 1u);
  store->max_chunk_bytes = max_chunk_bytes;

  result = ensure_directory(store->root);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;
  result = join_path(layout_path, store->root, M3_CHUNK_STORE_LAYOUT);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;
  result = ensure_directory(layout_path);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;
  result = join_path(store->chunks_path, layout_path, M3_CHUNK_STORE_CHUNKS);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;
  result = ensure_directory(store->chunks_path);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;
  result = join_path(store->temp_path, layout_path, M3_CHUNK_STORE_TEMP);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;
  result = ensure_directory(store->temp_path);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;
  result = join_path(store->lock_path, layout_path, M3_CHUNK_STORE_LOCK);
  if (result != M3_CHUNK_STORE_OK)
    goto failed;

  store->lock_file =
      turbo_fs_open(store->lock_path, TURBO_FS_O_RDWR | TURBO_FS_O_CREAT,
                    M3_CHUNK_STORE_FILE_MODE);
  if (store->lock_file == TURBO_INVALID_FILE) {
    result = M3_CHUNK_STORE_IO;
    goto failed;
  }
  if (turbo_fs_lock(store->lock_file,
                    TURBO_FS_LOCK_EXCLUSIVE | TURBO_FS_LOCK_NONBLOCK, 0, 1u) !=
      0) {
    result = M3_CHUNK_STORE_LOCKED;
    goto failed;
  }

  store->open = 1u;
  return M3_CHUNK_STORE_OK;

failed:
  if (store->lock_file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(store->lock_file);
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
  return result;
}

void m3_chunk_store_close_v1(m3_chunk_store_v1_t *store) {
  if (!store)
    return;
  if (store->open && store->lock_file != TURBO_INVALID_FILE) {
    (void)turbo_fs_unlock(store->lock_file, 0, 1u);
    (void)turbo_fs_close(store->lock_file);
  }
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
}

m3_chunk_store_result_t m3_chunk_store_put_bytes_v1(
    m3_chunk_store_v1_t *store, const m3_chunk_cid_v1_t *expected_cid,
    const uint8_t *bytes, size_t size, uint8_t *out_created) {
  m3_chunk_cid_v1_t actual_cid;
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t random_bytes[M3_CHUNK_STORE_TEMP_RANDOM_SIZE];
  char random_hex[M3_CHUNK_STORE_TEMP_RANDOM_SIZE * 2u + 1u];
  char digest_hex[M3_CHUNK_CID_DIGEST_SIZE * 2u + 1u];
  char shard_path[TURBO_FS_MAX_PATH];
  char chunk_path[TURBO_FS_MAX_PATH];
  char temp_name[M3_CHUNK_CID_DIGEST_SIZE * 2u +
                 M3_CHUNK_STORE_TEMP_RANDOM_SIZE * 2u + 7u];
  char temp_path[TURBO_FS_MAX_PATH];
  size_t verified = 0u;
  m3_chunk_store_result_t result;

  if (out_created)
    *out_created = 0u;
  if (!store || !store->open || !cid_is_valid(expected_cid) ||
      (!bytes && size > 0u) || expected_cid->size != (uint64_t)size)
    return M3_CHUNK_STORE_INVALID_ARG;
  if ((uint64_t)size > store->max_chunk_bytes)
    return M3_CHUNK_STORE_RESOURCE_EXHAUSTED;

  result = m3_chunk_cid_calculate_v1(bytes, size, &actual_cid);
  if (result != M3_CHUNK_STORE_OK)
    return result;
  if (!cid_equal(&actual_cid, expected_cid))
    return M3_CHUNK_STORE_DIGEST_MISMATCH;

  result = build_chunk_path(store, expected_cid, shard_path, chunk_path);
  if (result != M3_CHUNK_STORE_OK)
    return result;
  if (turbo_fs_lstat(chunk_path, &stat) == 0) {
    return read_verify_range(chunk_path, expected_cid, 0u, 0u, NULL,
                             &verified);
  }
  result = ensure_directory(shard_path);
  if (result != M3_CHUNK_STORE_OK)
    return result;
  if (turbo_secure_random(random_bytes, sizeof(random_bytes)) != 0)
    return M3_CHUNK_STORE_CSPRNG_FAILED;

  bytes_to_hex(random_bytes, sizeof(random_bytes), random_hex);
  bytes_to_hex(expected_cid->digest, sizeof(expected_cid->digest), digest_hex);
  if (snprintf(temp_name, sizeof(temp_name), "%s-%s.tmp", digest_hex,
               random_hex) < 0 ||
      join_path(temp_path, store->temp_path, temp_name) != M3_CHUNK_STORE_OK)
    return M3_CHUNK_STORE_INVALID_ARG;

  file = turbo_fs_open(temp_path,
                       TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       M3_CHUNK_STORE_FILE_MODE);
  if (file == TURBO_INVALID_FILE)
    return M3_CHUNK_STORE_IO;
  result = write_all(file, bytes, size);
  if (result != M3_CHUNK_STORE_OK)
    goto cleanup;
  if (turbo_fs_fsync(file) != 0 || turbo_fs_close(file) != 0) {
    file = TURBO_INVALID_FILE;
    result = M3_CHUNK_STORE_IO;
    goto cleanup;
  }
  file = TURBO_INVALID_FILE;

  if (turbo_fs_rename(temp_path, chunk_path) != 0) {
    result = read_verify_range(chunk_path, expected_cid, 0u, 0u, NULL,
                               &verified);
    if (result == M3_CHUNK_STORE_OK)
      goto existing;
    result = M3_CHUNK_STORE_IO;
    goto cleanup;
  }
  result =
      read_verify_range(chunk_path, expected_cid, 0u, 0u, NULL, &verified);
  if (result != M3_CHUNK_STORE_OK)
    goto cleanup;
  if (out_created)
    *out_created = 1u;
  return M3_CHUNK_STORE_OK;

existing:
  (void)turbo_fs_unlink(temp_path);
  return M3_CHUNK_STORE_OK;

cleanup:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  (void)turbo_fs_unlink(temp_path);
  return result;
}

m3_chunk_store_result_t m3_chunk_store_read_range_v1(
    const m3_chunk_store_v1_t *store, const m3_chunk_cid_v1_t *cid,
    uint64_t offset, size_t length, uint8_t *buffer, size_t *out_read) {
  char shard_path[TURBO_FS_MAX_PATH];
  char chunk_path[TURBO_FS_MAX_PATH];
  m3_chunk_store_result_t result;

  if (out_read)
    *out_read = 0u;
  if (!store || !store->open || !cid_is_valid(cid) || !out_read ||
      (!buffer && length > 0u) || cid->size > store->max_chunk_bytes ||
      offset > cid->size || (uint64_t)length > cid->size - offset)
    return M3_CHUNK_STORE_INVALID_ARG;

  result = build_chunk_path(store, cid, shard_path, chunk_path);
  if (result != M3_CHUNK_STORE_OK)
    return result;
  return read_verify_range(chunk_path, cid, offset, length, buffer, out_read);
}
