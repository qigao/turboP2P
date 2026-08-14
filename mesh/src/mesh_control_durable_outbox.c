#include "mesh_control_durable_outbox.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DURABLE_OUTBOX_FILE_MODE 0600
#define DURABLE_OUTBOX_HEADER_SIZE 64u
#define DURABLE_OUTBOX_RECORD_SIZE 176u
#define DURABLE_OUTBOX_SESSION_RECORD_SIZE 80u
#define DURABLE_OUTBOX_AUTH_SIZE 32u

static const uint8_t durable_outbox_magic[8] = {'T', 'M', 'C', 'O', 'B', 'X', '0', '1'};

struct mesh_control_durable_outbox_entry_v1 {
  uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t payload_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t claimed_session_id[MESH_CONTROL_ID_SIZE];
  uint64_t sequence;
  uint64_t created_at_ms;
  uint64_t lease_generation;
  uint64_t claimed_session_generation;
  uint64_t lease_expires_at_ms;
  uint64_t acked_at_ms;
  uint32_t delivery_attempts;
  uint32_t state;
  uint8_t *payload;
  size_t payload_size;
  uint8_t occupied;
};

struct mesh_control_durable_outbox_session_v1 {
  uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  uint64_t generation;
  uint64_t connected_at_ms;
  uint8_t active;
  uint8_t occupied;
};

static int bytes_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;
  size_t index;
  if (!bytes)
    return 1;
  for (index = 0u; index < size; ++index)
    aggregate |= bytes[index];
  return aggregate == 0u;
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
  return ((uint64_t)read_u32(input) << 32u) | read_u32(input + 4u);
}

static int calculate_sha256(const uint8_t *bytes, size_t size,
                            uint8_t output[MESH_CONTROL_DIGEST_SIZE]) {
  unsigned int output_size = 0u;
  return bytes && output &&
         EVP_Digest(bytes, size, output, &output_size, EVP_sha256(), NULL) == 1 &&
         output_size == MESH_CONTROL_DIGEST_SIZE;
}

static int calculate_hmac(
    const uint8_t key[MESH_CONTROL_DURABLE_OUTBOX_AUTH_KEY_SIZE_V1],
    const uint8_t *bytes, size_t size,
    uint8_t output[MESH_CONTROL_DURABLE_OUTBOX_AUTH_KEY_SIZE_V1]) {
  unsigned int output_size = 0u;
  return key && bytes && output && size <= INT_MAX &&
         HMAC(EVP_sha256(), key, MESH_CONTROL_DURABLE_OUTBOX_AUTH_KEY_SIZE_V1,
              bytes, size, output, &output_size) != NULL &&
         output_size == MESH_CONTROL_DURABLE_OUTBOX_AUTH_KEY_SIZE_V1;
}

static int config_valid(const mesh_control_durable_outbox_config_v1_t *config) {
  return config && config->path && turbo_fs_path_is_absolute(config->path) &&
         strlen(config->path) < TURBO_FS_MAX_PATH - 6u &&
         config->entry_capacity > 0u &&
         config->entry_capacity <= MESH_CONTROL_DURABLE_OUTBOX_MAX_ENTRIES_V1 &&
         config->session_capacity > 0u &&
         config->session_capacity <= MESH_CONTROL_DURABLE_OUTBOX_MAX_ENTRIES_V1 &&
         config->byte_capacity > 0u &&
         config->byte_capacity <= MESH_CONTROL_DURABLE_OUTBOX_MAX_BYTES_V1 &&
         config->max_payload_size > 0u &&
         config->max_payload_size <= MESH_CONTROL_MAX_FRAME_SIZE_V1 &&
         config->max_payload_size <= config->byte_capacity &&
         config->max_claim_lease_ms > 0u && config->ack_retention_ms > 0u &&
         !bytes_zero(config->authentication_key,
                     sizeof(config->authentication_key));
}

static int entry_state_valid(uint32_t state) {
  return state == MESH_CONTROL_DURABLE_OUTBOX_PENDING ||
         state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED ||
         state == MESH_CONTROL_DURABLE_OUTBOX_ACKED;
}

static void view_from_entry(const mesh_control_durable_outbox_entry_v1_t *entry,
                            mesh_control_durable_outbox_view_v1_t *out_view) {
  memset(out_view, 0, sizeof(*out_view));
  memcpy(out_view->target_node_id, entry->target_node_id,
         sizeof(out_view->target_node_id));
  memcpy(out_view->message_id, entry->message_id, sizeof(out_view->message_id));
  memcpy(out_view->request_id, entry->request_id, sizeof(out_view->request_id));
  memcpy(out_view->payload_digest, entry->payload_digest,
         sizeof(out_view->payload_digest));
  memcpy(out_view->claimed_session_id, entry->claimed_session_id,
         sizeof(out_view->claimed_session_id));
  out_view->sequence = entry->sequence;
  out_view->created_at_ms = entry->created_at_ms;
  out_view->lease_generation = entry->lease_generation;
  out_view->claimed_session_generation = entry->claimed_session_generation;
  out_view->lease_expires_at_ms = entry->lease_expires_at_ms;
  out_view->acked_at_ms = entry->acked_at_ms;
  out_view->delivery_attempts = entry->delivery_attempts;
  out_view->state = (mesh_control_durable_outbox_state_v1_t)entry->state;
  out_view->payload = entry->state == MESH_CONTROL_DURABLE_OUTBOX_ACKED
                          ? NULL
                          : entry->payload;
  out_view->payload_size = entry->state == MESH_CONTROL_DURABLE_OUTBOX_ACKED
                               ? 0u
                               : entry->payload_size;
}

static mesh_control_durable_outbox_entry_v1_t *find_entry(
    const mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t message_id[MESH_CONTROL_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    if (outbox->entries[index].occupied &&
        memcmp(outbox->entries[index].message_id, message_id,
               MESH_CONTROL_ID_SIZE) == 0)
      return &outbox->entries[index];
  }
  return NULL;
}

static mesh_control_durable_outbox_session_v1_t *find_session(
    const mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE]) {
  size_t index;
  for (index = 0u; index < outbox->config.session_capacity; ++index) {
    if (outbox->sessions[index].occupied &&
        memcmp(outbox->sessions[index].target_node_id, target_node_id,
               MESH_CONTROL_NODE_ID_SIZE) == 0)
      return &outbox->sessions[index];
  }
  return NULL;
}

static int session_matches(
    const mesh_control_durable_outbox_session_v1_t *session,
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t generation) {
  return session && session->active && session->generation == generation &&
         memcmp(session->session_id, session_id, MESH_CONTROL_ID_SIZE) == 0;
}

static mesh_control_durable_outbox_result_t write_all(turbo_file_t file,
                                                       const uint8_t *bytes,
                                                       size_t size) {
  size_t offset = 0u;
  while (offset < size) {
    int written = turbo_fs_write(file, (const char *)bytes + offset, size - offset);
    if (written <= 0)
      return MESH_CONTROL_DURABLE_OUTBOX_IO;
    offset += (size_t)written;
  }
  return MESH_CONTROL_DURABLE_OUTBOX_OK;
}

static mesh_control_durable_outbox_result_t persist_snapshot(
    mesh_control_durable_outbox_v1_t *outbox) {
  uint8_t authenticator[DURABLE_OUTBOX_AUTH_SIZE];
  uint8_t *bytes = NULL;
  uint8_t *cursor;
  turbo_file_t file = TURBO_INVALID_FILE;
  size_t payload_bytes = 0u;
  size_t record_count = 0u;
  size_t session_count = 0u;
  size_t size;
  size_t index;
  mesh_control_durable_outbox_result_t result = MESH_CONTROL_DURABLE_OUTBOX_IO;

  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    const mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
    if (!entry->occupied)
      continue;
    record_count++;
    if (entry->state != MESH_CONTROL_DURABLE_OUTBOX_ACKED) {
      if (payload_bytes > SIZE_MAX - entry->payload_size)
        return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
      payload_bytes += entry->payload_size;
    }
  }
  for (index = 0u; index < outbox->config.session_capacity; ++index) {
    if (outbox->sessions[index].occupied)
      session_count++;
  }
  if (record_count > (SIZE_MAX - DURABLE_OUTBOX_HEADER_SIZE - DURABLE_OUTBOX_AUTH_SIZE) /
                         DURABLE_OUTBOX_RECORD_SIZE ||
      session_count >
          (SIZE_MAX - DURABLE_OUTBOX_HEADER_SIZE - DURABLE_OUTBOX_AUTH_SIZE -
           record_count * DURABLE_OUTBOX_RECORD_SIZE) /
              DURABLE_OUTBOX_SESSION_RECORD_SIZE ||
      payload_bytes > SIZE_MAX - DURABLE_OUTBOX_HEADER_SIZE - DURABLE_OUTBOX_AUTH_SIZE -
                          record_count * DURABLE_OUTBOX_RECORD_SIZE -
                          session_count * DURABLE_OUTBOX_SESSION_RECORD_SIZE)
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  size = DURABLE_OUTBOX_HEADER_SIZE + record_count * DURABLE_OUTBOX_RECORD_SIZE +
         payload_bytes + session_count * DURABLE_OUTBOX_SESSION_RECORD_SIZE +
         DURABLE_OUTBOX_AUTH_SIZE;
  bytes = (uint8_t *)calloc(1u, size);
  if (!bytes)
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  memcpy(bytes, durable_outbox_magic, sizeof(durable_outbox_magic));
  write_u32(bytes + 8u, MESH_CONTROL_DURABLE_OUTBOX_VERSION_V1);
  write_u32(bytes + 12u, DURABLE_OUTBOX_HEADER_SIZE);
  write_u32(bytes + 16u, DURABLE_OUTBOX_RECORD_SIZE);
  write_u32(bytes + 20u, (uint32_t)record_count);
  write_u64(bytes + 24u, outbox->generation);
  write_u64(bytes + 32u, payload_bytes);
  write_u32(bytes + 40u, (uint32_t)session_count);
  write_u32(bytes + 44u, DURABLE_OUTBOX_SESSION_RECORD_SIZE);
  cursor = bytes + DURABLE_OUTBOX_HEADER_SIZE;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    const mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
    uint32_t encoded_payload_size;
    if (!entry->occupied)
      continue;
    encoded_payload_size = entry->state == MESH_CONTROL_DURABLE_OUTBOX_ACKED
                               ? 0u
                               : (uint32_t)entry->payload_size;
    memcpy(cursor, entry->target_node_id, MESH_CONTROL_NODE_ID_SIZE);
    memcpy(cursor + 32u, entry->message_id, MESH_CONTROL_ID_SIZE);
    memcpy(cursor + 48u, entry->request_id, MESH_CONTROL_ID_SIZE);
    memcpy(cursor + 64u, entry->payload_digest, MESH_CONTROL_DIGEST_SIZE);
    memcpy(cursor + 96u, entry->claimed_session_id, MESH_CONTROL_ID_SIZE);
    write_u64(cursor + 112u, entry->sequence);
    write_u64(cursor + 120u, entry->created_at_ms);
    write_u64(cursor + 128u, entry->lease_generation);
    write_u64(cursor + 136u, entry->lease_expires_at_ms);
    write_u64(cursor + 144u, entry->acked_at_ms);
    write_u32(cursor + 152u, entry->state);
    write_u32(cursor + 156u, entry->delivery_attempts);
    write_u32(cursor + 160u, encoded_payload_size);
    write_u64(cursor + 164u, entry->claimed_session_generation);
    cursor += DURABLE_OUTBOX_RECORD_SIZE;
    if (encoded_payload_size > 0u) {
      memcpy(cursor, entry->payload, encoded_payload_size);
      cursor += encoded_payload_size;
    }
  }
  for (index = 0u; index < outbox->config.session_capacity; ++index) {
    const mesh_control_durable_outbox_session_v1_t *session =
        &outbox->sessions[index];
    if (!session->occupied)
      continue;
    memcpy(cursor, session->target_node_id, MESH_CONTROL_NODE_ID_SIZE);
    memcpy(cursor + 32u, session->session_id, MESH_CONTROL_ID_SIZE);
    write_u64(cursor + 48u, session->generation);
    write_u64(cursor + 56u, session->connected_at_ms);
    cursor[64u] = session->active;
    cursor += DURABLE_OUTBOX_SESSION_RECORD_SIZE;
  }
  if (!calculate_hmac(outbox->config.authentication_key, bytes,
                      size - DURABLE_OUTBOX_AUTH_SIZE, authenticator)) {
    result = MESH_CONTROL_DURABLE_OUTBOX_AUTH_FAILED;
    goto cleanup;
  }
  memcpy(bytes + size - DURABLE_OUTBOX_AUTH_SIZE, authenticator,
         DURABLE_OUTBOX_AUTH_SIZE);
  file = turbo_fs_open(outbox->temp_path,
                       TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       DURABLE_OUTBOX_FILE_MODE);
  if (file == TURBO_INVALID_FILE)
    goto cleanup;
  result = write_all(file, bytes, size);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK)
    goto cleanup;
  if (turbo_fs_fsync(file) != 0 || turbo_fs_close(file) != 0) {
    file = TURBO_INVALID_FILE;
    result = MESH_CONTROL_DURABLE_OUTBOX_IO;
    goto cleanup;
  }
  file = TURBO_INVALID_FILE;
  if (turbo_fs_rename(outbox->temp_path, outbox->path) != 0) {
    result = MESH_CONTROL_DURABLE_OUTBOX_IO;
    goto cleanup;
  }
  result = MESH_CONTROL_DURABLE_OUTBOX_OK;

cleanup:
  OPENSSL_cleanse(authenticator, sizeof(authenticator));
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    (void)turbo_fs_unlink(outbox->temp_path);
    outbox->faulted = 1u;
  }
  if (bytes) {
    OPENSSL_cleanse(bytes, size);
    free(bytes);
  }
  return result;
}

static mesh_control_durable_outbox_result_t read_file(const char *path,
                                                       size_t max_size,
                                                       uint8_t **out_bytes,
                                                       size_t *out_size) {
  turbo_fs_stat_t stat;
  turbo_file_t file = TURBO_INVALID_FILE;
  uint8_t *bytes = NULL;
  size_t offset = 0u;
  if (turbo_fs_stat(path, &stat) != 0 || !stat.is_file ||
      stat.size < DURABLE_OUTBOX_HEADER_SIZE + DURABLE_OUTBOX_AUTH_SIZE ||
      stat.size > max_size || stat.size > SIZE_MAX)
    return MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
  bytes = (uint8_t *)malloc((size_t)stat.size);
  if (!bytes)
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  file = turbo_fs_open(path, TURBO_FS_O_RDONLY, 0);
  if (file == TURBO_INVALID_FILE)
    goto io_failed;
  while (offset < (size_t)stat.size) {
    int amount = turbo_fs_read(file, (char *)bytes + offset,
                               (size_t)stat.size - offset);
    if (amount <= 0)
      goto io_failed;
    offset += (size_t)amount;
  }
  if (turbo_fs_close(file) != 0)
    goto io_failed_closed;
  *out_bytes = bytes;
  *out_size = offset;
  return MESH_CONTROL_DURABLE_OUTBOX_OK;

io_failed:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
io_failed_closed:
  free(bytes);
  return MESH_CONTROL_DURABLE_OUTBOX_IO;
}

static void free_entries(mesh_control_durable_outbox_v1_t *outbox) {
  size_t index;
  if (!outbox->entries)
    return;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    if (outbox->entries[index].payload) {
      OPENSSL_cleanse(outbox->entries[index].payload,
                      outbox->entries[index].payload_size);
      free(outbox->entries[index].payload);
    }
  }
  free(outbox->entries);
  outbox->entries = NULL;
  free(outbox->sessions);
  outbox->sessions = NULL;
}

static mesh_control_durable_outbox_result_t load_snapshot(
    mesh_control_durable_outbox_v1_t *outbox) {
  uint8_t expected[DURABLE_OUTBOX_AUTH_SIZE];
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t *bytes = NULL;
  const uint8_t *cursor;
  const uint8_t *payload_end;
  uint32_t record_count;
  uint32_t session_count;
  uint64_t retained;
  size_t size = 0u;
  size_t index;
  mesh_control_durable_outbox_result_t result;

  result = read_file(outbox->path,
                     DURABLE_OUTBOX_HEADER_SIZE +
                         outbox->config.entry_capacity * DURABLE_OUTBOX_RECORD_SIZE +
                         outbox->config.session_capacity *
                             DURABLE_OUTBOX_SESSION_RECORD_SIZE +
                         outbox->config.byte_capacity + DURABLE_OUTBOX_AUTH_SIZE,
                     &bytes, &size);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK)
    return result;
  if (!calculate_hmac(outbox->config.authentication_key, bytes,
                      size - DURABLE_OUTBOX_AUTH_SIZE, expected) ||
      CRYPTO_memcmp(expected, bytes + size - DURABLE_OUTBOX_AUTH_SIZE,
                    DURABLE_OUTBOX_AUTH_SIZE) != 0) {
    result = MESH_CONTROL_DURABLE_OUTBOX_AUTH_FAILED;
    goto cleanup;
  }
  if (memcmp(bytes, durable_outbox_magic, sizeof(durable_outbox_magic)) != 0 ||
      read_u32(bytes + 8u) != MESH_CONTROL_DURABLE_OUTBOX_VERSION_V1 ||
      read_u32(bytes + 12u) != DURABLE_OUTBOX_HEADER_SIZE ||
      read_u32(bytes + 16u) != DURABLE_OUTBOX_RECORD_SIZE) {
    result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
    goto cleanup;
  }
  record_count = read_u32(bytes + 20u);
  retained = read_u64(bytes + 32u);
  session_count = read_u32(bytes + 40u);
  if (record_count > outbox->config.entry_capacity ||
      session_count > outbox->config.session_capacity ||
      retained > outbox->config.byte_capacity ||
      read_u32(bytes + 44u) != DURABLE_OUTBOX_SESSION_RECORD_SIZE ||
      read_u64(bytes + 48u) != 0u || read_u64(bytes + 56u) != 0u) {
    result = MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
    goto cleanup;
  }
  if ((size_t)record_count >
      (size - DURABLE_OUTBOX_HEADER_SIZE - DURABLE_OUTBOX_AUTH_SIZE) /
          DURABLE_OUTBOX_RECORD_SIZE) {
    result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
    goto cleanup;
  }
  cursor = bytes + DURABLE_OUTBOX_HEADER_SIZE;
  payload_end = bytes + size - DURABLE_OUTBOX_AUTH_SIZE;
  outbox->generation = read_u64(bytes + 24u);
  for (index = 0u; index < record_count; ++index) {
    mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
    uint32_t payload_size;
    size_t reserved_index;
    if ((size_t)(payload_end - cursor) < DURABLE_OUTBOX_RECORD_SIZE) {
      result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
      goto cleanup;
    }
    memcpy(entry->target_node_id, cursor, MESH_CONTROL_NODE_ID_SIZE);
    memcpy(entry->message_id, cursor + 32u, MESH_CONTROL_ID_SIZE);
    memcpy(entry->request_id, cursor + 48u, MESH_CONTROL_ID_SIZE);
    memcpy(entry->payload_digest, cursor + 64u, MESH_CONTROL_DIGEST_SIZE);
    memcpy(entry->claimed_session_id, cursor + 96u, MESH_CONTROL_ID_SIZE);
    entry->sequence = read_u64(cursor + 112u);
    entry->created_at_ms = read_u64(cursor + 120u);
    entry->lease_generation = read_u64(cursor + 128u);
    entry->lease_expires_at_ms = read_u64(cursor + 136u);
    entry->acked_at_ms = read_u64(cursor + 144u);
    entry->state = read_u32(cursor + 152u);
    entry->delivery_attempts = read_u32(cursor + 156u);
    payload_size = read_u32(cursor + 160u);
    entry->claimed_session_generation = read_u64(cursor + 164u);
    for (reserved_index = 172u; reserved_index < DURABLE_OUTBOX_RECORD_SIZE;
         ++reserved_index) {
      if (cursor[reserved_index] != 0u) {
        result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
        goto cleanup;
      }
    }
    cursor += DURABLE_OUTBOX_RECORD_SIZE;
    if (bytes_zero(entry->target_node_id, sizeof(entry->target_node_id)) ||
        bytes_zero(entry->message_id, sizeof(entry->message_id)) ||
        bytes_zero(entry->request_id, sizeof(entry->request_id)) ||
        bytes_zero(entry->payload_digest, sizeof(entry->payload_digest)) ||
        entry->sequence == 0u || entry->created_at_ms == 0u ||
        !entry_state_valid(entry->state) || payload_size > outbox->config.max_payload_size ||
        (size_t)(payload_end - cursor) < payload_size ||
        (entry->state == MESH_CONTROL_DURABLE_OUTBOX_ACKED
             ? payload_size != 0u || entry->acked_at_ms == 0u
             : payload_size == 0u || entry->acked_at_ms != 0u) ||
        (entry->state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED
             ? bytes_zero(entry->claimed_session_id,
                          sizeof(entry->claimed_session_id)) ||
                   entry->claimed_session_generation == 0u ||
                   entry->lease_generation == 0u ||
                   entry->lease_expires_at_ms == 0u
             : entry->lease_expires_at_ms != 0u ||
                   (entry->state == MESH_CONTROL_DURABLE_OUTBOX_PENDING &&
                    entry->claimed_session_generation != 0u))) {
      result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
      goto cleanup;
    }
    if (payload_size > 0u) {
      entry->payload = (uint8_t *)malloc(payload_size);
      if (!entry->payload) {
        result = MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
        goto cleanup;
      }
      memcpy(entry->payload, cursor, payload_size);
      entry->payload_size = payload_size;
      if (!calculate_sha256(entry->payload, entry->payload_size, digest) ||
          CRYPTO_memcmp(digest, entry->payload_digest, sizeof(digest)) != 0) {
        result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
        goto cleanup;
      }
      cursor += payload_size;
      outbox->retained_payload_bytes += payload_size;
    }
    entry->occupied = 1u;
    outbox->count++;
  }
  for (index = 0u; index < session_count; ++index) {
    mesh_control_durable_outbox_session_v1_t *session = &outbox->sessions[index];
    size_t reserved_index;
    if ((size_t)(payload_end - cursor) < DURABLE_OUTBOX_SESSION_RECORD_SIZE) {
      result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
      goto cleanup;
    }
    memcpy(session->target_node_id, cursor, MESH_CONTROL_NODE_ID_SIZE);
    memcpy(session->session_id, cursor + 32u, MESH_CONTROL_ID_SIZE);
    session->generation = read_u64(cursor + 48u);
    session->connected_at_ms = read_u64(cursor + 56u);
    session->active = cursor[64u];
    for (reserved_index = 65u;
         reserved_index < DURABLE_OUTBOX_SESSION_RECORD_SIZE;
         ++reserved_index) {
      if (cursor[reserved_index] != 0u) {
        result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
        goto cleanup;
      }
    }
    if (bytes_zero(session->target_node_id, sizeof(session->target_node_id)) ||
        bytes_zero(session->session_id, sizeof(session->session_id)) ||
        session->generation == 0u || session->connected_at_ms == 0u ||
        session->active > 1u || find_session(outbox, session->target_node_id)) {
      result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
      goto cleanup;
    }
    session->occupied = 1u;
    cursor += DURABLE_OUTBOX_SESSION_RECORD_SIZE;
  }
  if (cursor != payload_end || outbox->retained_payload_bytes != retained) {
    result = MESH_CONTROL_DURABLE_OUTBOX_CORRUPT;
    goto cleanup;
  }
  result = MESH_CONTROL_DURABLE_OUTBOX_OK;

cleanup:
  OPENSSL_cleanse(expected, sizeof(expected));
  OPENSSL_cleanse(digest, sizeof(digest));
  if (bytes) {
    OPENSSL_cleanse(bytes, size);
    free(bytes);
  }
  return result;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_open_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const mesh_control_durable_outbox_config_v1_t *config,
    size_t *out_recovered_claims) {
  size_t recovered = 0u;
  size_t recovered_sessions = 0u;
  size_t index;
  int length;
  mesh_control_durable_outbox_result_t result = MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  if (!outbox || !config_valid(config))
    return result;
  memset(outbox, 0, sizeof(*outbox));
  outbox->lock_file = TURBO_INVALID_FILE;
  outbox->config = *config;
  memcpy(outbox->path, config->path, strlen(config->path) + 1u);
  outbox->config.path = outbox->path;
  length = snprintf(outbox->temp_path, sizeof(outbox->temp_path), "%s.tmp", outbox->path);
  if (length < 0 || (size_t)length >= sizeof(outbox->temp_path))
    goto failed;
  length = snprintf(outbox->lock_path, sizeof(outbox->lock_path), "%s.lock", outbox->path);
  if (length < 0 || (size_t)length >= sizeof(outbox->lock_path))
    goto failed;
  outbox->entries = (mesh_control_durable_outbox_entry_v1_t *)calloc(
      config->entry_capacity, sizeof(*outbox->entries));
  outbox->sessions = (mesh_control_durable_outbox_session_v1_t *)calloc(
      config->session_capacity, sizeof(*outbox->sessions));
  if (!outbox->entries || !outbox->sessions) {
    result = MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
    goto failed;
  }
  outbox->lock_file = turbo_fs_open(outbox->lock_path,
                                    TURBO_FS_O_RDWR | TURBO_FS_O_CREAT,
                                    DURABLE_OUTBOX_FILE_MODE);
  if (outbox->lock_file == TURBO_INVALID_FILE) {
    result = MESH_CONTROL_DURABLE_OUTBOX_IO;
    goto failed;
  }
  if (turbo_fs_lock(outbox->lock_file,
                    TURBO_FS_LOCK_EXCLUSIVE | TURBO_FS_LOCK_NONBLOCK,
                    0u, 1u) != 0) {
    result = MESH_CONTROL_DURABLE_OUTBOX_LOCKED;
    goto failed;
  }
  outbox->open = 1u;
  if (turbo_fs_access(outbox->path, TURBO_FS_ACCESS_EXISTS) == 0) {
    result = load_snapshot(outbox);
    if (result != MESH_CONTROL_DURABLE_OUTBOX_OK)
      goto failed;
    for (index = 0u; index < outbox->config.entry_capacity; ++index) {
      mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
      if (entry->occupied && entry->state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED) {
        entry->state = MESH_CONTROL_DURABLE_OUTBOX_PENDING;
        memset(entry->claimed_session_id, 0, sizeof(entry->claimed_session_id));
        entry->claimed_session_generation = 0u;
        entry->lease_expires_at_ms = 0u;
        recovered++;
      }
    }
    for (index = 0u; index < outbox->config.session_capacity; ++index) {
      if (outbox->sessions[index].occupied && outbox->sessions[index].active) {
        outbox->sessions[index].active = 0u;
        recovered_sessions++;
      }
    }
    if (recovered > 0u || recovered_sessions > 0u) {
      outbox->generation++;
      result = persist_snapshot(outbox);
      if (result != MESH_CONTROL_DURABLE_OUTBOX_OK)
        goto failed;
      outbox->counters.reclaimed = recovered;
      outbox->counters.recovered_sessions = recovered_sessions;
    }
  } else {
    outbox->generation = 1u;
    result = persist_snapshot(outbox);
    if (result != MESH_CONTROL_DURABLE_OUTBOX_OK)
      goto failed;
  }
  if (out_recovered_claims)
    *out_recovered_claims = recovered;
  return MESH_CONTROL_DURABLE_OUTBOX_OK;

failed:
  mesh_control_durable_outbox_close_v1(outbox);
  return result;
}

void mesh_control_durable_outbox_close_v1(mesh_control_durable_outbox_v1_t *outbox) {
  if (!outbox)
    return;
  if (outbox->lock_file != TURBO_INVALID_FILE) {
    if (outbox->open)
      (void)turbo_fs_unlock(outbox->lock_file, 0u, 1u);
    (void)turbo_fs_close(outbox->lock_file);
  }
  free_entries(outbox);
  OPENSSL_cleanse(outbox, sizeof(*outbox));
  outbox->lock_file = TURBO_INVALID_FILE;
}

static int message_equal(const mesh_control_durable_outbox_entry_v1_t *entry,
                         const mesh_control_durable_outbox_message_v1_t *message,
                         const uint8_t digest[MESH_CONTROL_DIGEST_SIZE]) {
  return memcmp(entry->target_node_id, message->target_node_id,
                MESH_CONTROL_NODE_ID_SIZE) == 0 &&
         memcmp(entry->request_id, message->request_id, MESH_CONTROL_ID_SIZE) == 0 &&
         memcmp(entry->payload_digest, digest, MESH_CONTROL_DIGEST_SIZE) == 0 &&
         entry->sequence == message->sequence &&
         entry->created_at_ms == message->created_at_ms;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_submit_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const mesh_control_durable_outbox_message_v1_t *message,
    mesh_control_durable_outbox_view_v1_t *out_view) {
  uint8_t digest[MESH_CONTROL_DIGEST_SIZE];
  mesh_control_durable_outbox_entry_v1_t *entry = NULL;
  size_t index;
  uint64_t saved_generation;
  mesh_control_durable_outbox_result_t result;
  if (!outbox || !outbox->open || outbox->faulted || !message ||
      bytes_zero(message->target_node_id, sizeof(message->target_node_id)) ||
      bytes_zero(message->message_id, sizeof(message->message_id)) ||
      bytes_zero(message->request_id, sizeof(message->request_id)) ||
      message->sequence == 0u || message->created_at_ms == 0u || !message->payload ||
      message->payload_size == 0u ||
      message->payload_size > outbox->config.max_payload_size ||
      !calculate_sha256(message->payload, message->payload_size, digest))
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  entry = find_entry(outbox, message->message_id);
  if (entry) {
    result = message_equal(entry, message, digest)
                 ? MESH_CONTROL_DURABLE_OUTBOX_OK
                 : MESH_CONTROL_DURABLE_OUTBOX_CONFLICT;
    if (result == MESH_CONTROL_DURABLE_OUTBOX_OK && out_view)
      view_from_entry(entry, out_view);
    OPENSSL_cleanse(digest, sizeof(digest));
    return result;
  }
  if (outbox->count >= outbox->config.entry_capacity ||
      message->payload_size >
          outbox->config.byte_capacity - outbox->retained_payload_bytes) {
    OPENSSL_cleanse(digest, sizeof(digest));
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    if (!outbox->entries[index].occupied) {
      entry = &outbox->entries[index];
      break;
    }
  }
  if (!entry) {
    OPENSSL_cleanse(digest, sizeof(digest));
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  entry->payload = (uint8_t *)malloc(message->payload_size);
  if (!entry->payload) {
    OPENSSL_cleanse(digest, sizeof(digest));
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  memcpy(entry->payload, message->payload, message->payload_size);
  memcpy(entry->target_node_id, message->target_node_id, sizeof(entry->target_node_id));
  memcpy(entry->message_id, message->message_id, sizeof(entry->message_id));
  memcpy(entry->request_id, message->request_id, sizeof(entry->request_id));
  memcpy(entry->payload_digest, digest, sizeof(entry->payload_digest));
  entry->sequence = message->sequence;
  entry->created_at_ms = message->created_at_ms;
  entry->payload_size = message->payload_size;
  entry->state = MESH_CONTROL_DURABLE_OUTBOX_PENDING;
  entry->occupied = 1u;
  outbox->count++;
  outbox->retained_payload_bytes += entry->payload_size;
  saved_generation = outbox->generation++;
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    outbox->generation = saved_generation;
    outbox->count--;
    outbox->retained_payload_bytes -= entry->payload_size;
    OPENSSL_cleanse(entry->payload, entry->payload_size);
    free(entry->payload);
    memset(entry, 0, sizeof(*entry));
  } else {
    outbox->counters.submitted++;
    if (out_view)
      view_from_entry(entry, out_view);
  }
  OPENSSL_cleanse(digest, sizeof(digest));
  return result;
}

mesh_control_durable_outbox_result_t
mesh_control_durable_outbox_activate_session_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t connected_at_ms,
    uint64_t *out_session_generation, size_t *out_released_claims) {
  mesh_control_durable_outbox_session_v1_t *session;
  mesh_control_durable_outbox_session_v1_t saved_session;
  mesh_control_durable_outbox_entry_v1_t *saved_entries = NULL;
  size_t *indices = NULL;
  size_t released = 0u;
  size_t index;
  uint64_t saved_generation;
  int new_slot = 0;
  mesh_control_durable_outbox_result_t result;
  if (out_session_generation)
    *out_session_generation = 0u;
  if (out_released_claims)
    *out_released_claims = 0u;
  if (!outbox || !outbox->open || outbox->faulted ||
      bytes_zero(target_node_id, MESH_CONTROL_NODE_ID_SIZE) ||
      bytes_zero(session_id, MESH_CONTROL_ID_SIZE) || connected_at_ms == 0u ||
      !out_session_generation)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  session = find_session(outbox, target_node_id);
  if (session && session_matches(session, session_id, session->generation)) {
    *out_session_generation = session->generation;
    return MESH_CONTROL_DURABLE_OUTBOX_OK;
  }
  if (!session) {
    for (index = 0u; index < outbox->config.session_capacity; ++index) {
      if (!outbox->sessions[index].occupied) {
        session = &outbox->sessions[index];
        new_slot = 1;
        break;
      }
    }
    if (!session)
      return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  } else if (session->generation == UINT64_MAX) {
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  indices = (size_t *)malloc(outbox->config.entry_capacity * sizeof(*indices));
  saved_entries = (mesh_control_durable_outbox_entry_v1_t *)malloc(
      outbox->config.entry_capacity * sizeof(*saved_entries));
  if (!indices || !saved_entries) {
    free(indices);
    free(saved_entries);
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  saved_session = *session;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
    if (entry->occupied && entry->state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED &&
        memcmp(entry->target_node_id, target_node_id,
               MESH_CONTROL_NODE_ID_SIZE) == 0) {
      indices[released] = index;
      saved_entries[released++] = *entry;
      entry->state = MESH_CONTROL_DURABLE_OUTBOX_PENDING;
      entry->lease_expires_at_ms = 0u;
      entry->claimed_session_generation = 0u;
      memset(entry->claimed_session_id, 0, sizeof(entry->claimed_session_id));
    }
  }
  if (new_slot) {
    memset(session, 0, sizeof(*session));
    memcpy(session->target_node_id, target_node_id, MESH_CONTROL_NODE_ID_SIZE);
    session->generation = 1u;
    session->occupied = 1u;
  } else {
    session->generation++;
  }
  memcpy(session->session_id, session_id, MESH_CONTROL_ID_SIZE);
  session->connected_at_ms = connected_at_ms;
  session->active = 1u;
  saved_generation = outbox->generation++;
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    *session = saved_session;
    for (index = 0u; index < released; ++index)
      outbox->entries[indices[index]] = saved_entries[index];
    outbox->generation = saved_generation;
  } else {
    *out_session_generation = session->generation;
    if (out_released_claims)
      *out_released_claims = released;
    outbox->counters.fenced_sessions += released;
  }
  free(indices);
  free(saved_entries);
  return result;
}

mesh_control_durable_outbox_result_t
mesh_control_durable_outbox_deactivate_session_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation) {
  mesh_control_durable_outbox_session_v1_t *session;
  mesh_control_durable_outbox_session_v1_t saved_session;
  mesh_control_durable_outbox_entry_v1_t *saved_entries = NULL;
  size_t *indices = NULL;
  size_t released = 0u;
  size_t index;
  uint64_t saved_generation;
  mesh_control_durable_outbox_result_t result;
  if (!outbox || !outbox->open || outbox->faulted ||
      bytes_zero(target_node_id, MESH_CONTROL_NODE_ID_SIZE) ||
      bytes_zero(session_id, MESH_CONTROL_ID_SIZE) || session_generation == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  session = find_session(outbox, target_node_id);
  if (!session)
    return MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND;
  if (!session_matches(session, session_id, session_generation))
    return MESH_CONTROL_DURABLE_OUTBOX_FENCED;
  indices = (size_t *)malloc(outbox->config.entry_capacity * sizeof(*indices));
  saved_entries = (mesh_control_durable_outbox_entry_v1_t *)malloc(
      outbox->config.entry_capacity * sizeof(*saved_entries));
  if (!indices || !saved_entries) {
    free(indices);
    free(saved_entries);
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  saved_session = *session;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
    if (entry->occupied && entry->state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED &&
        entry->claimed_session_generation == session_generation &&
        memcmp(entry->target_node_id, target_node_id,
               MESH_CONTROL_NODE_ID_SIZE) == 0 &&
        memcmp(entry->claimed_session_id, session_id,
               MESH_CONTROL_ID_SIZE) == 0) {
      indices[released] = index;
      saved_entries[released++] = *entry;
      entry->state = MESH_CONTROL_DURABLE_OUTBOX_PENDING;
      entry->lease_expires_at_ms = 0u;
      entry->claimed_session_generation = 0u;
      memset(entry->claimed_session_id, 0, sizeof(entry->claimed_session_id));
    }
  }
  session->active = 0u;
  saved_generation = outbox->generation++;
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    *session = saved_session;
    for (index = 0u; index < released; ++index)
      outbox->entries[indices[index]] = saved_entries[index];
    outbox->generation = saved_generation;
  } else {
    outbox->counters.fenced_sessions += released;
  }
  free(indices);
  free(saved_entries);
  return result;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_claim_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation, uint64_t now_ms, uint64_t lease_ms,
    mesh_control_durable_outbox_view_v1_t *out_view) {
  mesh_control_durable_outbox_entry_v1_t *entry = NULL;
  mesh_control_durable_outbox_entry_v1_t saved;
  size_t index;
  uint64_t saved_generation;
  int reclaimed = 0;
  mesh_control_durable_outbox_result_t result;
  mesh_control_durable_outbox_session_v1_t *session;
  if (!outbox || !outbox->open || outbox->faulted || !out_view ||
      bytes_zero(target_node_id, MESH_CONTROL_NODE_ID_SIZE) ||
      bytes_zero(session_id, MESH_CONTROL_ID_SIZE) || now_ms == 0u || lease_ms == 0u ||
      session_generation == 0u ||
      lease_ms > outbox->config.max_claim_lease_ms || now_ms > UINT64_MAX - lease_ms)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  session = find_session(outbox, target_node_id);
  if (!session_matches(session, session_id, session_generation))
    return MESH_CONTROL_DURABLE_OUTBOX_FENCED;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    mesh_control_durable_outbox_entry_v1_t *candidate = &outbox->entries[index];
    int eligible;
    if (!candidate->occupied ||
        memcmp(candidate->target_node_id, target_node_id,
               MESH_CONTROL_NODE_ID_SIZE) != 0)
      continue;
    eligible = candidate->state == MESH_CONTROL_DURABLE_OUTBOX_PENDING ||
               (candidate->state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED &&
                candidate->lease_expires_at_ms <= now_ms);
    if (!eligible)
      continue;
    if (!entry || candidate->created_at_ms < entry->created_at_ms ||
        (candidate->created_at_ms == entry->created_at_ms &&
         candidate->sequence < entry->sequence))
      entry = candidate;
  }
  if (!entry)
    return MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND;
  saved = *entry;
  saved_generation = outbox->generation++;
  reclaimed = entry->state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED;
  if (entry->lease_generation == UINT64_MAX || entry->delivery_attempts == UINT32_MAX) {
    outbox->generation = saved_generation;
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  entry->state = MESH_CONTROL_DURABLE_OUTBOX_CLAIMED;
  entry->lease_generation++;
  entry->delivery_attempts++;
  entry->lease_expires_at_ms = now_ms + lease_ms;
  entry->claimed_session_generation = session_generation;
  memcpy(entry->claimed_session_id, session_id, MESH_CONTROL_ID_SIZE);
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    *entry = saved;
    outbox->generation = saved_generation;
    return result;
  }
  outbox->counters.claimed_total++;
  if (reclaimed)
    outbox->counters.reclaimed++;
  view_from_entry(entry, out_view);
  return MESH_CONTROL_DURABLE_OUTBOX_OK;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_ack_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation, uint64_t lease_generation,
    uint64_t acked_at_ms) {
  mesh_control_durable_outbox_entry_v1_t *entry;
  mesh_control_durable_outbox_entry_v1_t saved;
  size_t saved_retained;
  uint64_t saved_generation;
  mesh_control_durable_outbox_result_t result;
  mesh_control_durable_outbox_session_v1_t *session;
  if (!outbox || !outbox->open || outbox->faulted ||
      bytes_zero(target_node_id, MESH_CONTROL_NODE_ID_SIZE) ||
      bytes_zero(message_id, MESH_CONTROL_ID_SIZE) ||
      bytes_zero(session_id, MESH_CONTROL_ID_SIZE) || lease_generation == 0u ||
      session_generation == 0u ||
      acked_at_ms == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  session = find_session(outbox, target_node_id);
  if (!session_matches(session, session_id, session_generation))
    return MESH_CONTROL_DURABLE_OUTBOX_FENCED;
  entry = find_entry(outbox, message_id);
  if (!entry || memcmp(entry->target_node_id, target_node_id,
                       MESH_CONTROL_NODE_ID_SIZE) != 0)
    return MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND;
  if (entry->state == MESH_CONTROL_DURABLE_OUTBOX_ACKED) {
    return entry->lease_generation == lease_generation &&
                   entry->claimed_session_generation == session_generation &&
                   memcmp(entry->claimed_session_id, session_id,
                          MESH_CONTROL_ID_SIZE) == 0
               ? MESH_CONTROL_DURABLE_OUTBOX_OK
               : MESH_CONTROL_DURABLE_OUTBOX_FENCED;
  }
  if (entry->state != MESH_CONTROL_DURABLE_OUTBOX_CLAIMED ||
      entry->lease_generation != lease_generation ||
      entry->claimed_session_generation != session_generation ||
      memcmp(entry->claimed_session_id, session_id, MESH_CONTROL_ID_SIZE) != 0)
    return MESH_CONTROL_DURABLE_OUTBOX_FENCED;
  saved = *entry;
  saved_retained = outbox->retained_payload_bytes;
  saved_generation = outbox->generation++;
  entry->state = MESH_CONTROL_DURABLE_OUTBOX_ACKED;
  entry->lease_expires_at_ms = 0u;
  entry->acked_at_ms = acked_at_ms;
  outbox->retained_payload_bytes -= entry->payload_size;
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    *entry = saved;
    outbox->retained_payload_bytes = saved_retained;
    outbox->generation = saved_generation;
    return result;
  }
  OPENSSL_cleanse(entry->payload, entry->payload_size);
  free(entry->payload);
  entry->payload = NULL;
  entry->payload_size = 0u;
  outbox->counters.acknowledged++;
  return MESH_CONTROL_DURABLE_OUTBOX_OK;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_release_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation, uint64_t lease_generation) {
  mesh_control_durable_outbox_entry_v1_t *entry;
  mesh_control_durable_outbox_entry_v1_t saved;
  uint64_t saved_generation;
  mesh_control_durable_outbox_result_t result;
  mesh_control_durable_outbox_session_v1_t *session;
  if (!outbox || !outbox->open || outbox->faulted ||
      bytes_zero(target_node_id, MESH_CONTROL_NODE_ID_SIZE) ||
      bytes_zero(message_id, MESH_CONTROL_ID_SIZE) ||
      bytes_zero(session_id, MESH_CONTROL_ID_SIZE) ||
      session_generation == 0u || lease_generation == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  session = find_session(outbox, target_node_id);
  if (!session_matches(session, session_id, session_generation))
    return MESH_CONTROL_DURABLE_OUTBOX_FENCED;
  entry = find_entry(outbox, message_id);
  if (!entry || memcmp(entry->target_node_id, target_node_id,
                       MESH_CONTROL_NODE_ID_SIZE) != 0)
    return MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND;
  if (entry->state != MESH_CONTROL_DURABLE_OUTBOX_CLAIMED ||
      entry->lease_generation != lease_generation ||
      entry->claimed_session_generation != session_generation ||
      memcmp(entry->claimed_session_id, session_id, MESH_CONTROL_ID_SIZE) != 0)
    return MESH_CONTROL_DURABLE_OUTBOX_FENCED;
  saved = *entry;
  saved_generation = outbox->generation++;
  entry->state = MESH_CONTROL_DURABLE_OUTBOX_PENDING;
  entry->lease_expires_at_ms = 0u;
  entry->claimed_session_generation = 0u;
  memset(entry->claimed_session_id, 0, sizeof(entry->claimed_session_id));
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    *entry = saved;
    outbox->generation = saved_generation;
  }
  return result;
}

mesh_control_durable_outbox_result_t
mesh_control_durable_outbox_fence_target_session_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t new_session_id[MESH_CONTROL_ID_SIZE], size_t *out_released) {
  size_t *indices = NULL;
  mesh_control_durable_outbox_entry_v1_t *saved_entries = NULL;
  size_t count = 0u;
  size_t index;
  uint64_t saved_generation;
  mesh_control_durable_outbox_result_t result;
  if (out_released)
    *out_released = 0u;
  if (!outbox || !outbox->open || outbox->faulted ||
      bytes_zero(target_node_id, MESH_CONTROL_NODE_ID_SIZE) ||
      bytes_zero(new_session_id, MESH_CONTROL_ID_SIZE))
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  indices = (size_t *)malloc(outbox->config.entry_capacity * sizeof(*indices));
  saved_entries = (mesh_control_durable_outbox_entry_v1_t *)malloc(
      outbox->config.entry_capacity * sizeof(*saved_entries));
  if (!indices || !saved_entries) {
    free(indices);
    free(saved_entries);
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  }
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
    if (entry->occupied && entry->state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED &&
        memcmp(entry->target_node_id, target_node_id, MESH_CONTROL_NODE_ID_SIZE) == 0 &&
        memcmp(entry->claimed_session_id, new_session_id, MESH_CONTROL_ID_SIZE) != 0) {
      indices[count++] = index;
      saved_entries[count - 1u] = *entry;
      entry->state = MESH_CONTROL_DURABLE_OUTBOX_PENDING;
      entry->lease_expires_at_ms = 0u;
      entry->claimed_session_generation = 0u;
      memset(entry->claimed_session_id, 0, sizeof(entry->claimed_session_id));
    }
  }
  if (count == 0u) {
    free(indices);
    free(saved_entries);
    return MESH_CONTROL_DURABLE_OUTBOX_OK;
  }
  saved_generation = outbox->generation++;
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    for (index = 0u; index < count; ++index)
      outbox->entries[indices[index]] = saved_entries[index];
    outbox->generation = saved_generation;
  } else {
    outbox->counters.fenced_sessions += count;
    if (out_released)
      *out_released = count;
  }
  free(indices);
  free(saved_entries);
  return result;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_compact_v1(
    mesh_control_durable_outbox_v1_t *outbox, uint64_t now_ms,
    size_t *out_removed) {
  size_t *indices = NULL;
  size_t count = 0u;
  size_t index;
  uint64_t saved_generation;
  mesh_control_durable_outbox_result_t result;
  if (out_removed)
    *out_removed = 0u;
  if (!outbox || !outbox->open || outbox->faulted || now_ms == 0u)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  indices = (size_t *)malloc(outbox->config.entry_capacity * sizeof(*indices));
  if (!indices)
    return MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    mesh_control_durable_outbox_entry_v1_t *entry = &outbox->entries[index];
    if (entry->occupied && entry->state == MESH_CONTROL_DURABLE_OUTBOX_ACKED &&
        entry->acked_at_ms <= now_ms &&
        now_ms - entry->acked_at_ms >= outbox->config.ack_retention_ms) {
      indices[count++] = index;
      entry->occupied = 0u;
      outbox->count--;
    }
  }
  if (count == 0u) {
    free(indices);
    return MESH_CONTROL_DURABLE_OUTBOX_OK;
  }
  saved_generation = outbox->generation++;
  result = persist_snapshot(outbox);
  if (result != MESH_CONTROL_DURABLE_OUTBOX_OK) {
    for (index = 0u; index < count; ++index)
      outbox->entries[indices[index]].occupied = 1u;
    outbox->count += count;
    outbox->generation = saved_generation;
  } else {
    for (index = 0u; index < count; ++index)
      memset(&outbox->entries[indices[index]], 0, sizeof(*outbox->entries));
    outbox->counters.compacted += count;
    if (out_removed)
      *out_removed = count;
  }
  free(indices);
  return result;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_get_v1(
    const mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    mesh_control_durable_outbox_view_v1_t *out_view) {
  mesh_control_durable_outbox_entry_v1_t *entry;
  if (!outbox || !outbox->open || !message_id || !out_view)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  entry = find_entry(outbox, message_id);
  if (!entry)
    return MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND;
  view_from_entry(entry, out_view);
  return MESH_CONTROL_DURABLE_OUTBOX_OK;
}

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_get_stats_v1(
    const mesh_control_durable_outbox_v1_t *outbox,
    mesh_control_durable_outbox_stats_v1_t *out_stats) {
  size_t index;
  if (!outbox || !outbox->open || !out_stats)
    return MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG;
  *out_stats = outbox->counters;
  out_stats->generation = outbox->generation;
  out_stats->entries = outbox->count;
  out_stats->retained_payload_bytes = outbox->retained_payload_bytes;
  for (index = 0u; index < outbox->config.entry_capacity; ++index) {
    if (!outbox->entries[index].occupied)
      continue;
    if (outbox->entries[index].state == MESH_CONTROL_DURABLE_OUTBOX_PENDING)
      out_stats->pending++;
    else if (outbox->entries[index].state == MESH_CONTROL_DURABLE_OUTBOX_CLAIMED)
      out_stats->claimed++;
    else if (outbox->entries[index].state == MESH_CONTROL_DURABLE_OUTBOX_ACKED)
      out_stats->acked++;
  }
  for (index = 0u; index < outbox->config.session_capacity; ++index) {
    if (!outbox->sessions[index].occupied)
      continue;
    out_stats->retained_sessions++;
    if (outbox->sessions[index].active)
      out_stats->active_sessions++;
  }
  return MESH_CONTROL_DURABLE_OUTBOX_OK;
}
