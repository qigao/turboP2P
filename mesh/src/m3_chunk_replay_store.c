#include "m3_chunk_replay_store.h"

#include "platform.h"

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TURBO_WIN32
#include <errno.h>
#include <fcntl.h>
#endif

#define REPLAY_STORE_VERSION 1u
#define REPLAY_STORE_HEADER_SIZE 80u
#define REPLAY_STORE_RECORD_SIZE 72u
#define REPLAY_STORE_FILE_MODE 0600

#define HEADER_MAGIC_OFFSET 0u
#define HEADER_VERSION_OFFSET 8u
#define HEADER_SIZE_OFFSET 12u
#define HEADER_RECORD_SIZE_OFFSET 16u
#define HEADER_CAPACITY_OFFSET 20u
#define HEADER_MAX_TTL_OFFSET 24u
#define HEADER_GENERATION_OFFSET 32u
#define HEADER_DIGEST_OFFSET 40u
#define HEADER_RESERVED_OFFSET 72u

#define RECORD_STATE_OFFSET 0u
#define RECORD_RESERVED0_OFFSET 1u
#define RECORD_REQUEST_ID_OFFSET 4u
#define RECORD_ACCESS_DIGEST_OFFSET 20u
#define RECORD_EXPIRES_OFFSET 52u
#define RECORD_RESULT_OFFSET 60u
#define RECORD_RESERVED1_OFFSET 64u

static const uint8_t REPLAY_STORE_MAGIC[8] = {
    'M', '3', 'R', 'P', 'L', 'Y', '1', 0,
};

/*
 * The snapshot file is fsynced before this boundary. Windows provides a
 * write-through replace operation; POSIX remains rename-only until the project
 * has a directory-sync adapter, so mutation callers must not claim strict
 * power-loss durability there.
 */
typedef enum {
  REPLACE_SNAPSHOT_FAILED = -1,
  REPLACE_SNAPSHOT_DURABLE = 0,
  REPLACE_SNAPSHOT_COMMIT_UNCERTAIN = 1
} replace_snapshot_result_t;

static replace_snapshot_result_t replace_snapshot(const char *old_path,
                                                  const char *new_path) {
#ifdef TURBO_WIN32
  return MoveFileExA(old_path, new_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
             ? REPLACE_SNAPSHOT_DURABLE
             : REPLACE_SNAPSHOT_FAILED;
#else
  char directory[TURBO_FS_MAX_PATH];
  int directory_file;
  int open_flags = O_RDONLY;
  int sync_result;

  if (turbo_fs_rename(old_path, new_path) != 0)
    return REPLACE_SNAPSHOT_FAILED;
  if (turbo_fs_path_dirname(new_path, directory, sizeof(directory)) != 0)
    return REPLACE_SNAPSHOT_COMMIT_UNCERTAIN;
#ifdef O_DIRECTORY
  open_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
  open_flags |= O_CLOEXEC;
#endif
  directory_file = open(directory, open_flags);
  if (directory_file < 0)
    return REPLACE_SNAPSHOT_COMMIT_UNCERTAIN;
  do {
    sync_result = fsync(directory_file);
  } while (sync_result != 0 && errno == EINTR);
  (void)close(directory_file);
  return sync_result == 0 ? REPLACE_SNAPSHOT_DURABLE
                          : REPLACE_SNAPSHOT_COMMIT_UNCERTAIN;
#endif
}

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < size; i++)
    aggregate |= bytes[i];
  return aggregate == 0u;
}

static void write_u32(uint8_t output[4], uint32_t value) {
  output[0] = (uint8_t)(value >> 24u);
  output[1] = (uint8_t)(value >> 16u);
  output[2] = (uint8_t)(value >> 8u);
  output[3] = (uint8_t)value;
}

static uint32_t read_u32(const uint8_t input[4]) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) |
         ((uint32_t)input[2] << 8u) | (uint32_t)input[3];
}

static void write_u64(uint8_t output[8], uint64_t value) {
  for (size_t i = 0; i < 8u; i++)
    output[i] = (uint8_t)(value >> (56u - i * 8u));
}

static uint64_t read_u64(const uint8_t input[8]) {
  uint64_t value = 0u;

  for (size_t i = 0; i < 8u; i++)
    value = (value << 8u) | input[i];
  return value;
}

static size_t snapshot_size(size_t capacity) {
  if (capacity > (SIZE_MAX - REPLAY_STORE_HEADER_SIZE) /
                     REPLAY_STORE_RECORD_SIZE) {
    return 0u;
  }
  return REPLAY_STORE_HEADER_SIZE + capacity * REPLAY_STORE_RECORD_SIZE;
}

static m3_chunk_replay_store_result_t calculate_digest(
    uint8_t *bytes, size_t size,
    uint8_t output[M3_CHUNK_REPLAY_DIGEST_SIZE]) {
  uint8_t saved[M3_CHUNK_REPLAY_DIGEST_SIZE];
  unsigned int digest_size = 0u;

  if (!bytes || size < REPLAY_STORE_HEADER_SIZE || !output)
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  memcpy(saved, bytes + HEADER_DIGEST_OFFSET, sizeof(saved));
  memset(bytes + HEADER_DIGEST_OFFSET, 0, sizeof(saved));
  if (EVP_Digest(bytes, size, output, &digest_size, EVP_sha256(), NULL) != 1 ||
      digest_size != M3_CHUNK_REPLAY_DIGEST_SIZE) {
    memcpy(bytes + HEADER_DIGEST_OFFSET, saved, sizeof(saved));
    memset(output, 0, M3_CHUNK_REPLAY_DIGEST_SIZE);
    return M3_CHUNK_REPLAY_STORE_CRYPTO_FAILED;
  }
  memcpy(bytes + HEADER_DIGEST_OFFSET, saved, sizeof(saved));
  return M3_CHUNK_REPLAY_STORE_OK;
}

static m3_chunk_replay_store_result_t write_all(turbo_file_t file,
                                                 const uint8_t *bytes,
                                                 size_t size) {
  size_t offset = 0u;

  while (offset < size) {
    int written =
        turbo_fs_write(file, (const char *)bytes + offset, size - offset);
    if (written <= 0)
      return M3_CHUNK_REPLAY_STORE_IO;
    offset += (size_t)written;
  }
  return M3_CHUNK_REPLAY_STORE_OK;
}

static m3_chunk_replay_store_result_t encode_snapshot(
    const m3_chunk_replay_store_v1_t *store, uint64_t generation,
    uint8_t **out_bytes, size_t *out_size) {
  uint8_t *bytes = NULL;
  uint8_t digest[M3_CHUNK_REPLAY_DIGEST_SIZE];
  size_t size;
  m3_chunk_replay_store_result_t result;

  if (!store || !store->journal.entries || !out_bytes || !out_size ||
      store->journal.capacity > UINT32_MAX || generation == 0u) {
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  }
  *out_bytes = NULL;
  *out_size = 0u;
  size = snapshot_size(store->journal.capacity);
  if (size == 0u)
    return M3_CHUNK_REPLAY_STORE_RESOURCE_EXHAUSTED;
  bytes = (uint8_t *)calloc(1, size);
  if (!bytes)
    return M3_CHUNK_REPLAY_STORE_RESOURCE_EXHAUSTED;

  memcpy(bytes + HEADER_MAGIC_OFFSET, REPLAY_STORE_MAGIC,
         sizeof(REPLAY_STORE_MAGIC));
  write_u32(bytes + HEADER_VERSION_OFFSET, REPLAY_STORE_VERSION);
  write_u32(bytes + HEADER_SIZE_OFFSET, REPLAY_STORE_HEADER_SIZE);
  write_u32(bytes + HEADER_RECORD_SIZE_OFFSET, REPLAY_STORE_RECORD_SIZE);
  write_u32(bytes + HEADER_CAPACITY_OFFSET,
            (uint32_t)store->journal.capacity);
  write_u64(bytes + HEADER_MAX_TTL_OFFSET, store->journal.max_ttl_ms);
  write_u64(bytes + HEADER_GENERATION_OFFSET, generation);

  for (size_t i = 0; i < store->journal.capacity; i++) {
    const m3_chunk_replay_entry_v1_t *entry = &store->journal.entries[i];
    uint8_t *record =
        bytes + REPLAY_STORE_HEADER_SIZE + i * REPLAY_STORE_RECORD_SIZE;

    if (entry->state == M3_CHUNK_REPLAY_ENTRY_FREE)
      continue;
    if (entry->state != M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS &&
        entry->state != M3_CHUNK_REPLAY_ENTRY_COMPLETED) {
      free(bytes);
      return M3_CHUNK_REPLAY_STORE_CORRUPT;
    }
    record[RECORD_STATE_OFFSET] = (uint8_t)entry->state;
    memcpy(record + RECORD_REQUEST_ID_OFFSET, entry->request_id.bytes,
           sizeof(entry->request_id.bytes));
    memcpy(record + RECORD_ACCESS_DIGEST_OFFSET, entry->access_digest,
           sizeof(entry->access_digest));
    write_u64(record + RECORD_EXPIRES_OFFSET, entry->expires_at_ms);
    write_u32(record + RECORD_RESULT_OFFSET, (uint32_t)entry->result_code);
  }

  result = calculate_digest(bytes, size, digest);
  if (result != M3_CHUNK_REPLAY_STORE_OK) {
    free(bytes);
    return result;
  }
  memcpy(bytes + HEADER_DIGEST_OFFSET, digest, sizeof(digest));
  *out_bytes = bytes;
  *out_size = size;
  return M3_CHUNK_REPLAY_STORE_OK;
}

static m3_chunk_replay_store_result_t persist_snapshot(
    m3_chunk_replay_store_v1_t *store, int *out_commit_uncertain) {
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t *bytes = NULL;
  size_t size = 0u;
  uint64_t next_generation;
  replace_snapshot_result_t replace_result;
  m3_chunk_replay_store_result_t result;

  if (out_commit_uncertain)
    *out_commit_uncertain = 0;
  if (!store || !store->open || store->generation == UINT64_MAX)
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  next_generation = store->generation + 1u;
  result = encode_snapshot(store, next_generation, &bytes, &size);
  if (result != M3_CHUNK_REPLAY_STORE_OK)
    return result;

  file = turbo_fs_open(store->temp_path,
                       TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       REPLAY_STORE_FILE_MODE);
  if (file == TURBO_INVALID_FILE) {
    result = M3_CHUNK_REPLAY_STORE_IO;
    goto cleanup;
  }
  result = write_all(file, bytes, size);
  if (result != M3_CHUNK_REPLAY_STORE_OK)
    goto cleanup;
  if (turbo_fs_fsync(file) != 0) {
    result = M3_CHUNK_REPLAY_STORE_IO;
    goto cleanup;
  }
  if (turbo_fs_close(file) != 0) {
    file = TURBO_INVALID_FILE;
    result = M3_CHUNK_REPLAY_STORE_IO;
    goto cleanup;
  }
  file = TURBO_INVALID_FILE;
  replace_result = replace_snapshot(store->temp_path, store->path);
  if (replace_result == REPLACE_SNAPSHOT_FAILED) {
    result = M3_CHUNK_REPLAY_STORE_IO;
    goto cleanup;
  }
  store->generation = next_generation;
  if (replace_result == REPLACE_SNAPSHOT_COMMIT_UNCERTAIN) {
    if (out_commit_uncertain)
      *out_commit_uncertain = 1;
    result = M3_CHUNK_REPLAY_STORE_IO;
    goto cleanup;
  }
  result = M3_CHUNK_REPLAY_STORE_OK;

cleanup:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  if (result != M3_CHUNK_REPLAY_STORE_OK)
    (void)turbo_fs_unlink(store->temp_path);
  free(bytes);
  return result;
}

static m3_chunk_replay_store_result_t read_exact_file(
    const char *path, size_t expected_size, uint8_t **out_bytes) {
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t *bytes = NULL;
  size_t offset = 0u;

  if (!path || expected_size == 0u || !out_bytes)
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  *out_bytes = NULL;
  if (turbo_fs_lstat(path, &stat) != 0)
    return M3_CHUNK_REPLAY_STORE_NOT_FOUND;
  if (!stat.is_file || stat.is_symlink || stat.size != expected_size)
    return M3_CHUNK_REPLAY_STORE_CORRUPT;
  bytes = (uint8_t *)malloc(expected_size);
  if (!bytes)
    return M3_CHUNK_REPLAY_STORE_RESOURCE_EXHAUSTED;
  file = turbo_fs_open(path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    goto failed;
  while (offset < expected_size) {
    int read_size =
        turbo_fs_read(file, (char *)bytes + offset, expected_size - offset);
    if (read_size <= 0)
      goto failed;
    offset += (size_t)read_size;
  }
  {
    uint8_t trailing;
    if (turbo_fs_read(file, (char *)&trailing, 1u) != 0)
      goto failed;
    if (turbo_fs_close(file) != 0) {
      file = TURBO_INVALID_FILE;
      goto failed;
    }
    file = TURBO_INVALID_FILE;
  }
  *out_bytes = bytes;
  return M3_CHUNK_REPLAY_STORE_OK;

failed:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  free(bytes);
  return M3_CHUNK_REPLAY_STORE_IO;
}

static int record_reserved_is_zero(const uint8_t *record) {
  return bytes_are_zero(record + RECORD_RESERVED0_OFFSET, 3u) &&
         bytes_are_zero(record + RECORD_RESERVED1_OFFSET, 8u);
}

static m3_chunk_replay_store_result_t decode_snapshot(
    m3_chunk_replay_store_v1_t *store, uint8_t *bytes, size_t size,
    uint64_t now_ms, size_t *out_recovered_in_progress,
    size_t *out_expired) {
  uint8_t stored_digest[M3_CHUNK_REPLAY_DIGEST_SIZE];
  uint8_t actual_digest[M3_CHUNK_REPLAY_DIGEST_SIZE];
  size_t recovered = 0u;
  size_t expired = 0u;
  m3_chunk_replay_store_result_t result;

  if (!store || !bytes || size != snapshot_size(store->journal.capacity))
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  if (memcmp(bytes + HEADER_MAGIC_OFFSET, REPLAY_STORE_MAGIC,
             sizeof(REPLAY_STORE_MAGIC)) != 0 ||
      read_u32(bytes + HEADER_VERSION_OFFSET) != REPLAY_STORE_VERSION ||
      read_u32(bytes + HEADER_SIZE_OFFSET) != REPLAY_STORE_HEADER_SIZE ||
      read_u32(bytes + HEADER_RECORD_SIZE_OFFSET) !=
          REPLAY_STORE_RECORD_SIZE ||
      read_u32(bytes + HEADER_CAPACITY_OFFSET) != store->journal.capacity ||
      read_u64(bytes + HEADER_MAX_TTL_OFFSET) != store->journal.max_ttl_ms ||
      !bytes_are_zero(bytes + HEADER_RESERVED_OFFSET, 8u)) {
    return M3_CHUNK_REPLAY_STORE_CORRUPT;
  }
  store->generation = read_u64(bytes + HEADER_GENERATION_OFFSET);
  if (store->generation == 0u)
    return M3_CHUNK_REPLAY_STORE_CORRUPT;
  memcpy(stored_digest, bytes + HEADER_DIGEST_OFFSET, sizeof(stored_digest));
  result = calculate_digest(bytes, size, actual_digest);
  if (result != M3_CHUNK_REPLAY_STORE_OK)
    return result;
  if (memcmp(stored_digest, actual_digest, sizeof(stored_digest)) != 0)
    return M3_CHUNK_REPLAY_STORE_CORRUPT;

  for (size_t i = 0; i < store->journal.capacity; i++) {
    const uint8_t *record =
        bytes + REPLAY_STORE_HEADER_SIZE + i * REPLAY_STORE_RECORD_SIZE;
    m3_chunk_replay_entry_v1_t *entry = &store->journal.entries[i];
    uint8_t state = record[RECORD_STATE_OFFSET];

    if (state == M3_CHUNK_REPLAY_ENTRY_FREE) {
      if (!bytes_are_zero(record, REPLAY_STORE_RECORD_SIZE))
        return M3_CHUNK_REPLAY_STORE_CORRUPT;
      continue;
    }
    if ((state != M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS &&
         state != M3_CHUNK_REPLAY_ENTRY_COMPLETED) ||
        !record_reserved_is_zero(record) ||
        bytes_are_zero(record + RECORD_REQUEST_ID_OFFSET,
                       sizeof(entry->request_id.bytes)) ||
        bytes_are_zero(record + RECORD_ACCESS_DIGEST_OFFSET,
                       sizeof(entry->access_digest))) {
      return M3_CHUNK_REPLAY_STORE_CORRUPT;
    }
    entry->expires_at_ms = read_u64(record + RECORD_EXPIRES_OFFSET);
    entry->result_code =
        (int32_t)read_u32(record + RECORD_RESULT_OFFSET);
    if (entry->expires_at_ms == 0u ||
        (state == M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS &&
         entry->result_code != 0)) {
      return M3_CHUNK_REPLAY_STORE_CORRUPT;
    }
    if (now_ms >= entry->expires_at_ms) {
      memset(entry, 0, sizeof(*entry));
      expired++;
      continue;
    }
    memcpy(entry->request_id.bytes, record + RECORD_REQUEST_ID_OFFSET,
           sizeof(entry->request_id.bytes));
    memcpy(entry->access_digest, record + RECORD_ACCESS_DIGEST_OFFSET,
           sizeof(entry->access_digest));
    entry->state = (m3_chunk_replay_entry_state_t)state;
    if (entry->state == M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS)
      recovered++;
    for (size_t previous = 0; previous < i; previous++) {
      const m3_chunk_replay_entry_v1_t *other =
          &store->journal.entries[previous];
      if (other->state != M3_CHUNK_REPLAY_ENTRY_FREE &&
          turbo_uuid_equal(&other->request_id, &entry->request_id)) {
        return M3_CHUNK_REPLAY_STORE_CORRUPT;
      }
    }
  }
  if (out_recovered_in_progress)
    *out_recovered_in_progress = recovered;
  if (out_expired)
    *out_expired = expired;
  return M3_CHUNK_REPLAY_STORE_OK;
}

static m3_chunk_replay_store_result_t map_replay_result(
    m3_chunk_replay_result_t result) {
  switch (result) {
  case M3_CHUNK_REPLAY_OK:
    return M3_CHUNK_REPLAY_STORE_OK;
  case M3_CHUNK_REPLAY_CONFLICT:
    return M3_CHUNK_REPLAY_STORE_CONFLICT;
  case M3_CHUNK_REPLAY_EXPIRED:
    return M3_CHUNK_REPLAY_STORE_EXPIRED;
  case M3_CHUNK_REPLAY_NOT_FOUND:
    return M3_CHUNK_REPLAY_STORE_NOT_FOUND;
  case M3_CHUNK_REPLAY_RESOURCE_EXHAUSTED:
    return M3_CHUNK_REPLAY_STORE_RESOURCE_EXHAUSTED;
  case M3_CHUNK_REPLAY_CRYPTO_FAILED:
    return M3_CHUNK_REPLAY_STORE_CRYPTO_FAILED;
  case M3_CHUNK_REPLAY_INVALID_ARG:
  case M3_CHUNK_REPLAY_INVALID_ACCESS:
  default:
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  }
}

static m3_chunk_replay_entry_v1_t *find_entry(
    m3_chunk_replay_store_v1_t *store, const turbo_uuid_t *request_id) {
  if (!store || !store->journal.entries || !request_id)
    return NULL;
  for (size_t i = 0; i < store->journal.capacity; i++) {
    m3_chunk_replay_entry_v1_t *entry = &store->journal.entries[i];
    if (entry->state != M3_CHUNK_REPLAY_ENTRY_FREE &&
        turbo_uuid_equal(&entry->request_id, request_id)) {
      return entry;
    }
  }
  return NULL;
}

m3_chunk_replay_store_result_t m3_chunk_replay_store_open_v1(
    m3_chunk_replay_store_v1_t *store, const char *path, size_t capacity,
    uint64_t max_ttl_ms, uint64_t now_ms,
    size_t *out_recovered_in_progress) {
  turbo_fs_stat_t stat;
  uint8_t *bytes = NULL;
  size_t expired = 0u;
  size_t expected_size;
  int path_length;
  m3_chunk_replay_store_result_t result;

  if (out_recovered_in_progress)
    *out_recovered_in_progress = 0u;
  if (!store || store->open || !path || !turbo_fs_path_is_absolute(path) ||
      capacity == 0u || capacity > M3_CHUNK_REPLAY_MAX_ENTRIES ||
      max_ttl_ms == 0u || strlen(path) >= TURBO_FS_MAX_PATH) {
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  }
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
  result = map_replay_result(m3_chunk_replay_journal_init_v1(
      &store->journal, capacity, max_ttl_ms));
  if (result != M3_CHUNK_REPLAY_STORE_OK)
    goto failed;
  memcpy(store->path, path, strlen(path) + 1u);
  path_length =
      snprintf(store->temp_path, sizeof(store->temp_path), "%s.tmp", path);
  if (path_length < 0 ||
      (size_t)path_length >= sizeof(store->temp_path)) {
    result = M3_CHUNK_REPLAY_STORE_INVALID_ARG;
    goto failed;
  }
  path_length =
      snprintf(store->lock_path, sizeof(store->lock_path), "%s.lock", path);
  if (path_length < 0 ||
      (size_t)path_length >= sizeof(store->lock_path)) {
    result = M3_CHUNK_REPLAY_STORE_INVALID_ARG;
    goto failed;
  }
  store->lock_file =
      turbo_fs_open(store->lock_path, TURBO_FS_O_RDWR | TURBO_FS_O_CREAT,
                    REPLAY_STORE_FILE_MODE);
  if (store->lock_file == TURBO_INVALID_FILE) {
    result = M3_CHUNK_REPLAY_STORE_IO;
    goto failed;
  }
  if (turbo_fs_lock(store->lock_file,
                    TURBO_FS_LOCK_EXCLUSIVE | TURBO_FS_LOCK_NONBLOCK, 0, 1u) !=
      0) {
    result = M3_CHUNK_REPLAY_STORE_LOCKED;
    goto failed;
  }
  store->open = 1u;
  expected_size = snapshot_size(capacity);
  if (turbo_fs_lstat(store->path, &stat) == 0) {
    result = read_exact_file(store->path, expected_size, &bytes);
    if (result != M3_CHUNK_REPLAY_STORE_OK)
      goto failed;
    result = decode_snapshot(store, bytes, expected_size, now_ms,
                             out_recovered_in_progress, &expired);
    free(bytes);
    bytes = NULL;
    if (result != M3_CHUNK_REPLAY_STORE_OK)
      goto failed;
    if (expired > 0u) {
      result = persist_snapshot(store, NULL);
      if (result != M3_CHUNK_REPLAY_STORE_OK)
        goto failed;
    }
    return M3_CHUNK_REPLAY_STORE_OK;
  }

  store->generation = 0u;
  result = persist_snapshot(store, NULL);
  if (result != M3_CHUNK_REPLAY_STORE_OK)
    goto failed;
  return M3_CHUNK_REPLAY_STORE_OK;

failed:
  free(bytes);
  if (store->lock_file != TURBO_INVALID_FILE) {
    if (store->open)
      (void)turbo_fs_unlock(store->lock_file, 0, 1u);
    (void)turbo_fs_close(store->lock_file);
  }
  m3_chunk_replay_journal_destroy_v1(&store->journal);
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
  return result;
}

void m3_chunk_replay_store_close_v1(
    m3_chunk_replay_store_v1_t *store) {
  if (!store)
    return;
  if (store->open && store->lock_file != TURBO_INVALID_FILE) {
    (void)turbo_fs_unlock(store->lock_file, 0, 1u);
    (void)turbo_fs_close(store->lock_file);
  }
  m3_chunk_replay_journal_destroy_v1(&store->journal);
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
}

m3_chunk_replay_store_result_t m3_chunk_replay_store_begin_v1(
    m3_chunk_replay_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    m3_chunk_replay_begin_v1_t *out_begin) {
  m3_chunk_replay_entry_v1_t *entry;
  m3_chunk_replay_result_t replay_result;
  m3_chunk_replay_store_result_t result;
  int commit_uncertain = 0;

  if (!store || !store->open || !access || !out_begin)
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  replay_result = m3_chunk_replay_begin_request_v1(
      &store->journal, access, now_ms, out_begin);
  result = map_replay_result(replay_result);
  if (result != M3_CHUNK_REPLAY_STORE_OK)
    return result;
  if (out_begin->kind != M3_CHUNK_REPLAY_BEGIN_NEW)
    return M3_CHUNK_REPLAY_STORE_OK;

  result = persist_snapshot(store, &commit_uncertain);
  if (result == M3_CHUNK_REPLAY_STORE_OK)
    return result;
  if (!commit_uncertain) {
    entry = find_entry(store, &access->request_id);
    if (entry && entry->state == M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS)
      memset(entry, 0, sizeof(*entry));
  }
  memset(out_begin, 0, sizeof(*out_begin));
  return result;
}

m3_chunk_replay_store_result_t m3_chunk_replay_store_complete_v1(
    m3_chunk_replay_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, int32_t result_code) {
  m3_chunk_replay_entry_v1_t *entry;
  int was_completed;
  m3_chunk_replay_result_t replay_result;
  m3_chunk_replay_store_result_t result;

  if (!store || !store->open || !access)
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  entry = find_entry(store, &access->request_id);
  was_completed =
      entry && entry->state == M3_CHUNK_REPLAY_ENTRY_COMPLETED;
  replay_result = m3_chunk_replay_complete_request_v1(
      &store->journal, access, result_code);
  result = map_replay_result(replay_result);
  if (result != M3_CHUNK_REPLAY_STORE_OK || was_completed)
    return result;
  return persist_snapshot(store, NULL);
}

m3_chunk_replay_store_result_t m3_chunk_replay_store_sweep_v1(
    m3_chunk_replay_store_v1_t *store, uint64_t now_ms,
    size_t *out_removed) {
  size_t removed;

  if (out_removed)
    *out_removed = 0u;
  if (!store || !store->open || !out_removed)
    return M3_CHUNK_REPLAY_STORE_INVALID_ARG;
  removed =
      m3_chunk_replay_journal_sweep_v1(&store->journal, now_ms);
  *out_removed = removed;
  if (removed == 0u)
    return M3_CHUNK_REPLAY_STORE_OK;
  return persist_snapshot(store, NULL);
}
