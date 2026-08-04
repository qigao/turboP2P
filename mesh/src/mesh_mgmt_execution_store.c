#include "mesh_mgmt_execution_store.h"

#include <ctype.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXECUTION_STORE_HEADER_SIZE 64u
#define EXECUTION_STORE_RECORD_SIZE_V1 64u
#define EXECUTION_STORE_RECORD_SIZE_V2 576u
#define EXECUTION_STORE_RESULT_FLAG_OFFSET 64u
#define EXECUTION_STORE_RESULT_CANONICAL_OFFSET 72u
#define EXECUTION_STORE_RESULT_SIGNATURE_OFFSET 511u
#define EXECUTION_STORE_DIGEST_OFFSET 32u
#define EXECUTION_STORE_DIGEST_SIZE 32u
#define EXECUTION_STORE_MODE 0600

static const uint8_t execution_store_magic[8] = {
    'T', 'M', 'E', 'X', 'J', 'N', 'L', '1'};

static int path_is_absolute(const char *path) {
  if (!path || path[0] == '\0')
    return 0;
  if (path[0] == '/')
    return 1;
  if ((path[0] == '\\' && path[1] == '\\') ||
      (isalpha((unsigned char)path[0]) && path[1] == ':' &&
       (path[2] == '/' || path[2] == '\\')))
    return 1;
  return 0;
}

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24u);
  output[1] = (uint8_t)(value >> 16u);
  output[2] = (uint8_t)(value >> 8u);
  output[3] = (uint8_t)value;
}

static void write_u64(uint8_t *output, uint64_t value) {
  write_u32(output, (uint32_t)(value >> 32u));
  write_u32(output + 4u, (uint32_t)value);
}

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24u) | ((uint32_t)input[1] << 16u) |
         ((uint32_t)input[2] << 8u) | (uint32_t)input[3];
}

static uint64_t read_u64(const uint8_t *input) {
  return ((uint64_t)read_u32(input) << 32u) |
         (uint64_t)read_u32(input + 4u);
}

static int32_t read_i32(const uint8_t *input) {
  uint32_t encoded = read_u32(input);
  int64_t signed_value = encoded <= INT32_MAX
                             ? (int64_t)encoded
                             : (int64_t)encoded - 4294967296LL;
  return (int32_t)signed_value;
}

static mesh_mgmt_execution_store_result_t map_journal_result(
    mesh_mgmt_execution_result_t result) {
  switch (result) {
  case MESH_MGMT_EXECUTION_OK:
    return MESH_MGMT_EXECUTION_STORE_OK;
  case MESH_MGMT_EXECUTION_CONFLICT:
    return MESH_MGMT_EXECUTION_STORE_CONFLICT;
  case MESH_MGMT_EXECUTION_NOT_FOUND:
    return MESH_MGMT_EXECUTION_STORE_NOT_FOUND;
  case MESH_MGMT_EXECUTION_INVALID_STATE:
    return MESH_MGMT_EXECUTION_STORE_INVALID_STATE;
  case MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED:
    return MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
  default:
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  }
}

static int calculate_snapshot_digest(
    const uint8_t *bytes, size_t size,
    uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]) {
  EVP_MD_CTX *context;
  unsigned int digest_size = 0u;
  int result = -1;

  if (!bytes || size < EXECUTION_STORE_HEADER_SIZE || !digest)
    return -1;
  context = EVP_MD_CTX_new();
  if (!context)
    return -1;
  if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
      EVP_DigestUpdate(context, bytes, EXECUTION_STORE_DIGEST_OFFSET) == 1 &&
      EVP_DigestUpdate(
          context, bytes + EXECUTION_STORE_HEADER_SIZE,
          size - EXECUTION_STORE_HEADER_SIZE) == 1 &&
      EVP_DigestFinal_ex(context, digest, &digest_size) == 1 &&
      digest_size == MESH_MGMT_EXECUTION_DIGEST_SIZE)
    result = 0;
  EVP_MD_CTX_free(context);
  return result;
}

static mesh_mgmt_execution_store_result_t write_all(
    turbo_file_t file, const uint8_t *bytes, size_t size) {
  size_t written = 0u;

  while (written < size) {
    int result =
        turbo_fs_write(file, (const char *)bytes + written, size - written);
    if (result <= 0)
      return MESH_MGMT_EXECUTION_STORE_IO;
    written += (size_t)result;
  }
  return MESH_MGMT_EXECUTION_STORE_OK;
}

static mesh_mgmt_execution_store_result_t read_exact_file(
    const char *path, uint8_t **out_bytes, size_t *out_size) {
  const uint64_t max_size =
      EXECUTION_STORE_HEADER_SIZE +
      (uint64_t)MESH_MGMT_EXECUTION_JOURNAL_MAX *
          EXECUTION_STORE_RECORD_SIZE_V2;
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t *bytes = NULL;
  size_t offset = 0u;
  int read_size;
  uint8_t trailing;

  if (turbo_fs_stat(path, &stat) != 0 || !stat.is_file ||
      stat.size < EXECUTION_STORE_HEADER_SIZE || stat.size > max_size ||
      stat.size > SIZE_MAX)
    return MESH_MGMT_EXECUTION_STORE_CORRUPT;
  bytes = (uint8_t *)malloc((size_t)stat.size);
  if (!bytes)
    return MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
  file = turbo_fs_open(path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    goto failed;
  while (offset < (size_t)stat.size) {
    read_size = turbo_fs_read(file, (char *)bytes + offset,
                              (size_t)stat.size - offset);
    if (read_size <= 0)
      goto failed;
    offset += (size_t)read_size;
  }
  read_size = turbo_fs_read(file, (char *)&trailing, 1u);
  if (read_size != 0 || turbo_fs_close(file) != 0)
    goto failed_closed;
  *out_bytes = bytes;
  *out_size = offset;
  return MESH_MGMT_EXECUTION_STORE_OK;

failed:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
failed_closed:
  free(bytes);
  return MESH_MGMT_EXECUTION_STORE_IO;
}

static mesh_mgmt_execution_store_result_t persist_snapshot(
    const mesh_mgmt_execution_store_v1_t *store) {
  uint8_t *bytes = NULL;
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  turbo_file_t file = TURBO_INVALID_FILE;
  size_t count = 0u;
  size_t size;
  size_t index;
  mesh_mgmt_execution_store_result_t result =
      MESH_MGMT_EXECUTION_STORE_IO;

  if (store->journal.count > UINT32_MAX)
    return MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
  count = store->journal.count;
  size =
      EXECUTION_STORE_HEADER_SIZE + count * EXECUTION_STORE_RECORD_SIZE_V2;
  bytes = (uint8_t *)calloc(1u, size);
  if (!bytes) {
    result = MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  memcpy(bytes, execution_store_magic, sizeof(execution_store_magic));
  write_u32(bytes + 8u, MESH_MGMT_EXECUTION_STORE_VERSION);
  write_u32(bytes + 12u, EXECUTION_STORE_RECORD_SIZE_V2);
  write_u32(bytes + 16u, (uint32_t)count);
  write_u64(bytes + 24u, store->journal.generation);
  count = 0u;
  for (index = 0u; index < store->journal.capacity; ++index) {
    const mesh_mgmt_execution_journal_entry_v1_t *entry =
        &store->journal.entries[index];
    const mesh_mgmt_execution_stored_result_v1_t *stored_result =
        &store->results[index];
    uint8_t *record =
        bytes + EXECUTION_STORE_HEADER_SIZE +
        count * EXECUTION_STORE_RECORD_SIZE_V2;
    size_t canonical_size = 0u;

    if (!entry->occupied)
      continue;
    memcpy(record, entry->command_id, MESH_MGMT_EXECUTION_ID_SIZE);
    memcpy(record + 16u, entry->request_digest,
           MESH_MGMT_EXECUTION_DIGEST_SIZE);
    write_u32(record + 48u, (uint32_t)entry->state);
    write_u32(record + 52u, (uint32_t)entry->result_code);
    write_u64(record + 56u, entry->generation);
    if (stored_result->occupied) {
      record[EXECUTION_STORE_RESULT_FLAG_OFFSET] = 1u;
      if (mesh_mgmt_execution_result_encode_canonical_v1(
              &stored_result->result,
              record + EXECUTION_STORE_RESULT_CANONICAL_OFFSET,
              MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1,
              &canonical_size) != MESH_MGMT_EXECUTION_RESULT_OK ||
          canonical_size != MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1) {
        result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
        goto cleanup;
      }
      memcpy(record + EXECUTION_STORE_RESULT_SIGNATURE_OFFSET,
             stored_result->result.signature,
             MESH_MGMT_EXECUTION_SIGNATURE_SIZE);
    }
    count++;
  }
  if (calculate_snapshot_digest(bytes, size, digest) != 0) {
    result = MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  memcpy(bytes + EXECUTION_STORE_DIGEST_OFFSET, digest, sizeof(digest));

  file = turbo_fs_open(store->temp_path,
                       TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT |
                           TURBO_FS_O_TRUNC,
                       EXECUTION_STORE_MODE);
  if (file == TURBO_INVALID_FILE)
    goto cleanup;
  result = write_all(file, bytes, size);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    goto cleanup;
  if (turbo_fs_fsync(file) != 0 || turbo_fs_close(file) != 0) {
    file = TURBO_INVALID_FILE;
    result = MESH_MGMT_EXECUTION_STORE_IO;
    goto cleanup;
  }
  file = TURBO_INVALID_FILE;
  if (turbo_fs_rename(store->temp_path, store->path) != 0) {
    result = MESH_MGMT_EXECUTION_STORE_IO;
    goto cleanup;
  }
  result = MESH_MGMT_EXECUTION_STORE_OK;

cleanup:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    (void)turbo_fs_unlink(store->temp_path);
  free(bytes);
  return result;
}

static mesh_mgmt_execution_store_result_t load_snapshot(
    mesh_mgmt_execution_store_v1_t *store) {
  mesh_mgmt_execution_journal_entry_v1_t *entries = NULL;
  uint8_t *bytes = NULL;
  uint8_t digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint32_t count;
  uint32_t version;
  uint32_t record_size;
  uint64_t generation;
  size_t expected_size;
  size_t size = 0u;
  size_t index;
  mesh_mgmt_execution_store_result_t result;

  result = read_exact_file(store->path, &bytes, &size);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    return result;
  if (memcmp(bytes, execution_store_magic, sizeof(execution_store_magic)) !=
          0 ||
      read_u32(bytes + 20u) != 0u) {
    result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
    goto cleanup;
  }
  version = read_u32(bytes + 8u);
  record_size = read_u32(bytes + 12u);
  if (!((version == 1u && record_size == EXECUTION_STORE_RECORD_SIZE_V1) ||
        (version == MESH_MGMT_EXECUTION_STORE_VERSION &&
         record_size == EXECUTION_STORE_RECORD_SIZE_V2))) {
    result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
    goto cleanup;
  }
  count = read_u32(bytes + 16u);
  generation = read_u64(bytes + 24u);
  if (count > store->journal.capacity ||
      (size_t)count >
          (SIZE_MAX - EXECUTION_STORE_HEADER_SIZE) /
              record_size) {
    result = MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  expected_size =
      EXECUTION_STORE_HEADER_SIZE + (size_t)count * record_size;
  if (size != expected_size ||
      calculate_snapshot_digest(bytes, size, digest) != 0 ||
      memcmp(digest, bytes + EXECUTION_STORE_DIGEST_OFFSET,
             EXECUTION_STORE_DIGEST_SIZE) != 0) {
    result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
    goto cleanup;
  }
  if (count > 0u) {
    entries = (mesh_mgmt_execution_journal_entry_v1_t *)calloc(
        count, sizeof(*entries));
    if (!entries) {
      result = MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
      goto cleanup;
    }
  }
  for (index = 0u; index < count; ++index) {
    const uint8_t *record =
        bytes + EXECUTION_STORE_HEADER_SIZE +
        index * record_size;
    memcpy(entries[index].command_id, record, MESH_MGMT_EXECUTION_ID_SIZE);
    memcpy(entries[index].request_digest, record + 16u,
           MESH_MGMT_EXECUTION_DIGEST_SIZE);
    entries[index].state =
        (mesh_mgmt_execution_state_t)read_u32(record + 48u);
    entries[index].result_code = read_i32(record + 52u);
    entries[index].generation = read_u64(record + 56u);
    entries[index].occupied = 1u;
    if (version == MESH_MGMT_EXECUTION_STORE_VERSION) {
      uint8_t has_result = record[EXECUTION_STORE_RESULT_FLAG_OFFSET];
      size_t reserved_index;

      if (has_result > 1u) {
        result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
        goto cleanup;
      }
      for (reserved_index = 65u; reserved_index < 72u; ++reserved_index) {
        if (record[reserved_index] != 0u) {
          result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
          goto cleanup;
        }
      }
      if (record[EXECUTION_STORE_RECORD_SIZE_V2 - 1u] != 0u) {
        result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
        goto cleanup;
      }
      if (has_result) {
        mesh_mgmt_execution_result_v1_t *stored =
            &store->results[index].result;
        if (mesh_mgmt_execution_result_decode_canonical_v1(
                record + EXECUTION_STORE_RESULT_CANONICAL_OFFSET,
                MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1,
                stored) != MESH_MGMT_EXECUTION_RESULT_OK) {
          result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
          goto cleanup;
        }
        memcpy(stored->signature,
               record + EXECUTION_STORE_RESULT_SIGNATURE_OFFSET,
               MESH_MGMT_EXECUTION_SIGNATURE_SIZE);
        if (mesh_mgmt_execution_result_verify_v1(
                stored, stored->signer_public_key) !=
                MESH_MGMT_EXECUTION_RESULT_OK ||
            memcmp(stored->command_id, entries[index].command_id,
                   MESH_MGMT_EXECUTION_ID_SIZE) != 0 ||
            memcmp(stored->request_digest, entries[index].request_digest,
                   MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0 ||
            stored->state != entries[index].state ||
            !mesh_mgmt_execution_state_is_terminal_v1(
                entries[index].state)) {
          result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
          goto cleanup;
        }
        store->results[index].occupied = 1u;
      } else {
        for (reserved_index = EXECUTION_STORE_RESULT_CANONICAL_OFFSET;
             reserved_index < EXECUTION_STORE_RECORD_SIZE_V2;
             ++reserved_index) {
          if (record[reserved_index] != 0u) {
            result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
            goto cleanup;
          }
        }
      }
    }
  }
  if (mesh_mgmt_execution_journal_import_v1(&store->journal, entries,
                                             count) !=
          MESH_MGMT_EXECUTION_OK ||
      store->journal.generation != generation) {
    result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
    goto cleanup;
  }
  result = MESH_MGMT_EXECUTION_STORE_OK;

cleanup:
  free(entries);
  free(bytes);
  return result;
}

static void save_rollback(mesh_mgmt_execution_store_v1_t *store,
                          size_t *out_count, uint64_t *out_generation) {
  memcpy(store->rollback_entries, store->journal.entries,
         store->journal.capacity * sizeof(*store->journal.entries));
  memcpy(store->rollback_results, store->results,
         store->journal.capacity * sizeof(*store->results));
  *out_count = store->journal.count;
  *out_generation = store->journal.generation;
}

static void restore_rollback(mesh_mgmt_execution_store_v1_t *store,
                             size_t count, uint64_t generation) {
  memcpy(store->journal.entries, store->rollback_entries,
         store->journal.capacity * sizeof(*store->journal.entries));
  memcpy(store->results, store->rollback_results,
         store->journal.capacity * sizeof(*store->results));
  store->journal.count = count;
  store->journal.generation = generation;
}

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_open_v1(
    mesh_mgmt_execution_store_v1_t *store, const char *path,
    size_t capacity, size_t *out_recovered) {
  turbo_fs_stat_t stat;
  size_t recovered = 0u;
  int path_length;
  mesh_mgmt_execution_store_result_t result;

  if (!store || !path || !path_is_absolute(path) ||
      strlen(path) >= TURBO_FS_MAX_PATH)
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
  if (mesh_mgmt_execution_journal_init_v1(&store->journal, capacity) !=
      MESH_MGMT_EXECUTION_OK)
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  store->rollback_entries =
      (mesh_mgmt_execution_journal_entry_v1_t *)calloc(
          capacity, sizeof(*store->rollback_entries));
  if (!store->rollback_entries) {
    result = MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
    goto failed;
  }
  store->results = (mesh_mgmt_execution_stored_result_v1_t *)calloc(
      capacity, sizeof(*store->results));
  store->rollback_results =
      (mesh_mgmt_execution_stored_result_v1_t *)calloc(
          capacity, sizeof(*store->rollback_results));
  if (!store->results || !store->rollback_results) {
    result = MESH_MGMT_EXECUTION_STORE_RESOURCE_EXHAUSTED;
    goto failed;
  }
  memcpy(store->path, path, strlen(path) + 1u);
  path_length =
      snprintf(store->temp_path, sizeof(store->temp_path), "%s.tmp", path);
  if (path_length < 0 || (size_t)path_length >= sizeof(store->temp_path)) {
    result = MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
    goto failed;
  }
  path_length =
      snprintf(store->lock_path, sizeof(store->lock_path), "%s.lock", path);
  if (path_length < 0 || (size_t)path_length >= sizeof(store->lock_path)) {
    result = MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
    goto failed;
  }
  store->lock_file = turbo_fs_open(
      store->lock_path, TURBO_FS_O_RDWR | TURBO_FS_O_CREAT,
      EXECUTION_STORE_MODE);
  if (store->lock_file == TURBO_INVALID_FILE) {
    result = MESH_MGMT_EXECUTION_STORE_IO;
    goto failed;
  }
  if (turbo_fs_lock(store->lock_file,
                    TURBO_FS_LOCK_EXCLUSIVE | TURBO_FS_LOCK_NONBLOCK,
                    0, 1u) != 0) {
    result = MESH_MGMT_EXECUTION_STORE_LOCKED;
    goto failed;
  }

  store->open = 1u;
  /* First open has no journal yet; access() avoids ERROR logs for a missing file. */
  if (turbo_fs_access(store->path, TURBO_FS_ACCESS_EXISTS) == 0 &&
      turbo_fs_stat(store->path, &stat) == 0) {
    result = load_snapshot(store);
    if (result != MESH_MGMT_EXECUTION_STORE_OK)
      goto failed;
    if (mesh_mgmt_execution_journal_recover_v1(&store->journal,
                                                &recovered) !=
        MESH_MGMT_EXECUTION_OK) {
      result = MESH_MGMT_EXECUTION_STORE_CORRUPT;
      goto failed;
    }
    if (recovered > 0u) {
      result = persist_snapshot(store);
      if (result != MESH_MGMT_EXECUTION_STORE_OK)
        goto failed;
    }
  } else {
    result = persist_snapshot(store);
    if (result != MESH_MGMT_EXECUTION_STORE_OK)
      goto failed;
  }
  if (out_recovered)
    *out_recovered = recovered;
  return MESH_MGMT_EXECUTION_STORE_OK;

failed:
  mesh_mgmt_execution_store_close_v1(store);
  return result;
}

void mesh_mgmt_execution_store_close_v1(
    mesh_mgmt_execution_store_v1_t *store) {
  if (!store)
    return;
  if (store->lock_file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(store->lock_file);
  free(store->rollback_entries);
  free(store->results);
  free(store->rollback_results);
  mesh_mgmt_execution_journal_destroy_v1(&store->journal);
  memset(store, 0, sizeof(*store));
  store->lock_file = TURBO_INVALID_FILE;
}

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_submit_v1(
    mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry) {
  size_t saved_count;
  uint64_t saved_generation;
  mesh_mgmt_execution_result_t journal_result;
  mesh_mgmt_execution_store_result_t result;

  if (!store || !store->open)
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  save_rollback(store, &saved_count, &saved_generation);
  journal_result = mesh_mgmt_execution_journal_submit_v1(
      &store->journal, command_id, request_digest, out_entry);
  result = map_journal_result(journal_result);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    return result;
  if (store->journal.generation == saved_generation)
    return MESH_MGMT_EXECUTION_STORE_OK;
  result = persist_snapshot(store);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    restore_rollback(store, saved_count, saved_generation);
  return result;
}

static size_t find_entry_index(
    const mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE]) {
  size_t index;

  for (index = 0u; index < store->journal.capacity; ++index) {
    if (store->journal.entries[index].occupied &&
        memcmp(store->journal.entries[index].command_id, command_id,
               MESH_MGMT_EXECUTION_ID_SIZE) == 0)
      return index;
  }
  return store->journal.capacity;
}

static int result_is_equal(const mesh_mgmt_execution_result_v1_t *lhs,
                           const mesh_mgmt_execution_result_v1_t *rhs) {
  uint8_t lhs_canonical[MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1];
  uint8_t rhs_canonical[MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1];
  size_t lhs_size = 0u;
  size_t rhs_size = 0u;

  return mesh_mgmt_execution_result_encode_canonical_v1(
             lhs, lhs_canonical, sizeof(lhs_canonical), &lhs_size) ==
             MESH_MGMT_EXECUTION_RESULT_OK &&
         mesh_mgmt_execution_result_encode_canonical_v1(
             rhs, rhs_canonical, sizeof(rhs_canonical), &rhs_size) ==
             MESH_MGMT_EXECUTION_RESULT_OK &&
         lhs_size == rhs_size &&
         memcmp(lhs_canonical, rhs_canonical, lhs_size) == 0 &&
         memcmp(lhs->signature, rhs->signature,
                MESH_MGMT_EXECUTION_SIGNATURE_SIZE) == 0;
}

mesh_mgmt_execution_store_result_t
mesh_mgmt_execution_store_commit_result_v1(
    mesh_mgmt_execution_store_v1_t *store,
    const mesh_mgmt_execution_result_v1_t *result,
    mesh_mgmt_execution_journal_entry_v1_t *out_entry) {
  mesh_mgmt_execution_journal_entry_v1_t *entry;
  size_t index;
  size_t saved_count;
  uint64_t saved_generation;
  int32_t terminal_code;
  mesh_mgmt_execution_result_t journal_result;
  mesh_mgmt_execution_store_result_t store_result;

  if (!store || !store->open || !result ||
      mesh_mgmt_execution_result_verify_v1(
          result, result->signer_public_key) !=
          MESH_MGMT_EXECUTION_RESULT_OK)
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  index = find_entry_index(store, result->command_id);
  if (index == store->journal.capacity)
    return MESH_MGMT_EXECUTION_STORE_NOT_FOUND;
  entry = &store->journal.entries[index];
  if (memcmp(entry->request_digest, result->request_digest,
             MESH_MGMT_EXECUTION_DIGEST_SIZE) != 0)
    return MESH_MGMT_EXECUTION_STORE_CONFLICT;
  if (mesh_mgmt_execution_state_is_terminal_v1(entry->state)) {
    if (!store->results[index].occupied)
      return MESH_MGMT_EXECUTION_STORE_INVALID_STATE;
    if (!result_is_equal(&store->results[index].result, result))
      return MESH_MGMT_EXECUTION_STORE_CONFLICT;
    if (out_entry)
      *out_entry = *entry;
    return MESH_MGMT_EXECUTION_STORE_OK;
  }
  if (entry->state != MESH_MGMT_EXECUTION_STATE_RUNNING)
    return MESH_MGMT_EXECUTION_STORE_INVALID_STATE;
  terminal_code = result->runtime_code != 0 ? result->runtime_code
                                            : result->guest_exit_code;
  save_rollback(store, &saved_count, &saved_generation);
  journal_result = mesh_mgmt_execution_journal_transition_v1(
      &store->journal, result->command_id, result->state, terminal_code,
      out_entry);
  store_result = map_journal_result(journal_result);
  if (store_result != MESH_MGMT_EXECUTION_STORE_OK)
    return store_result;
  store->results[index].result = *result;
  store->results[index].occupied = 1u;
  store_result = persist_snapshot(store);
  if (store_result != MESH_MGMT_EXECUTION_STORE_OK)
    restore_rollback(store, saved_count, saved_generation);
  return store_result;
}

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_get_result_v1(
    const mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_result_v1_t *out_result) {
  size_t index;

  if (!store || !store->open || !command_id || !out_result)
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  index = find_entry_index(store, command_id);
  if (index == store->journal.capacity || !store->results[index].occupied)
    return MESH_MGMT_EXECUTION_STORE_NOT_FOUND;
  *out_result = store->results[index].result;
  return MESH_MGMT_EXECUTION_STORE_OK;
}

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_get_v1(
    const mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry) {
  if (!store || !store->open)
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  return map_journal_result(mesh_mgmt_execution_journal_get_v1(
      &store->journal, command_id, out_entry));
}

mesh_mgmt_execution_store_result_t mesh_mgmt_execution_store_transition_v1(
    mesh_mgmt_execution_store_v1_t *store,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_state_t next_state, int32_t result_code,
    mesh_mgmt_execution_journal_entry_v1_t *out_entry) {
  size_t saved_count;
  uint64_t saved_generation;
  mesh_mgmt_execution_result_t journal_result;
  mesh_mgmt_execution_store_result_t result;

  if (!store || !store->open)
    return MESH_MGMT_EXECUTION_STORE_INVALID_ARG;
  if (mesh_mgmt_execution_state_is_terminal_v1(next_state))
    return MESH_MGMT_EXECUTION_STORE_INVALID_STATE;
  save_rollback(store, &saved_count, &saved_generation);
  journal_result = mesh_mgmt_execution_journal_transition_v1(
      &store->journal, command_id, next_state, result_code, out_entry);
  result = map_journal_result(journal_result);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    return result;
  result = persist_snapshot(store);
  if (result != MESH_MGMT_EXECUTION_STORE_OK)
    restore_rollback(store, saved_count, saved_generation);
  return result;
}
