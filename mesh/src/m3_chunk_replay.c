#include "m3_chunk_replay.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

static const uint8_t M3_CHUNK_REPLAY_DOMAIN[] =
    "TurboNet-M3-Chunk-Authorized-Access-v1";

static int bytes_are_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < length; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static int access_is_valid(const m3_chunk_authorized_access_v1_t *access) {
  if (!access ||
      access->cid.hash_algorithm != M3_CHUNK_STORE_HASH_ALGORITHM_SHA256 ||
      !bytes_are_nonzero(access->cid.digest, sizeof(access->cid.digest)) ||
      !bytes_are_nonzero(access->tenant_id, sizeof(access->tenant_id)) ||
      !bytes_are_nonzero(access->audience_node_id,
                         sizeof(access->audience_node_id)) ||
      !bytes_are_nonzero(access->request_id.bytes,
                         sizeof(access->request_id.bytes)) ||
      access->expires_at_ms == 0u || access->range_offset > access->cid.size ||
      access->range_length > access->cid.size - access->range_offset ||
      (access->operation != M3_CHUNK_OPERATION_READ &&
       access->operation != M3_CHUNK_OPERATION_PUT)) {
    return 0;
  }
  return access->operation != M3_CHUNK_OPERATION_PUT ||
         (access->range_offset == 0u &&
          access->range_length == access->cid.size);
}

static void write_u32_be(uint8_t output[4], uint32_t value) {
  output[0] = (uint8_t)(value >> 24u);
  output[1] = (uint8_t)(value >> 16u);
  output[2] = (uint8_t)(value >> 8u);
  output[3] = (uint8_t)value;
}

static void write_u64_be(uint8_t output[8], uint64_t value) {
  for (size_t i = 0; i < 8u; i++)
    output[i] = (uint8_t)(value >> (56u - i * 8u));
}

static m3_chunk_replay_result_t hash_access(
    const m3_chunk_authorized_access_v1_t *access,
    uint8_t output[M3_CHUNK_REPLAY_DIGEST_SIZE]) {
  EVP_MD_CTX *hash = NULL;
  uint8_t encoded_integer[8];
  unsigned int digest_size = 0u;
  m3_chunk_replay_result_t result = M3_CHUNK_REPLAY_CRYPTO_FAILED;

  if (!access_is_valid(access) || !output)
    return M3_CHUNK_REPLAY_INVALID_ACCESS;
  hash = EVP_MD_CTX_new();
  if (!hash)
    return M3_CHUNK_REPLAY_RESOURCE_EXHAUSTED;
  if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(hash, M3_CHUNK_REPLAY_DOMAIN,
                       sizeof(M3_CHUNK_REPLAY_DOMAIN) - 1u) != 1 ||
      EVP_DigestUpdate(hash, access->tenant_id,
                       sizeof(access->tenant_id)) != 1 ||
      EVP_DigestUpdate(hash, &access->cid.hash_algorithm,
                       sizeof(access->cid.hash_algorithm)) != 1) {
    goto cleanup;
  }
  write_u64_be(encoded_integer, access->cid.size);
  if (EVP_DigestUpdate(hash, encoded_integer, sizeof(encoded_integer)) != 1 ||
      EVP_DigestUpdate(hash, access->cid.digest,
                       sizeof(access->cid.digest)) != 1) {
    goto cleanup;
  }
  write_u32_be(encoded_integer, (uint32_t)access->operation);
  if (EVP_DigestUpdate(hash, encoded_integer, 4u) != 1)
    goto cleanup;
  write_u64_be(encoded_integer, access->range_offset);
  if (EVP_DigestUpdate(hash, encoded_integer, sizeof(encoded_integer)) != 1)
    goto cleanup;
  write_u64_be(encoded_integer, access->range_length);
  if (EVP_DigestUpdate(hash, encoded_integer, sizeof(encoded_integer)) != 1 ||
      EVP_DigestUpdate(hash, access->audience_node_id,
                       sizeof(access->audience_node_id)) != 1 ||
      EVP_DigestUpdate(hash, access->request_id.bytes,
                       sizeof(access->request_id.bytes)) != 1) {
    goto cleanup;
  }
  write_u64_be(encoded_integer, access->expires_at_ms);
  if (EVP_DigestUpdate(hash, encoded_integer, sizeof(encoded_integer)) != 1 ||
      EVP_DigestFinal_ex(hash, output, &digest_size) != 1 ||
      digest_size != M3_CHUNK_REPLAY_DIGEST_SIZE) {
    goto cleanup;
  }
  result = M3_CHUNK_REPLAY_OK;

cleanup:
  EVP_MD_CTX_free(hash);
  if (result != M3_CHUNK_REPLAY_OK)
    memset(output, 0, M3_CHUNK_REPLAY_DIGEST_SIZE);
  return result;
}

static m3_chunk_replay_entry_v1_t *find_entry(
    m3_chunk_replay_journal_v1_t *journal, const turbo_uuid_t *request_id) {
  if (!journal || !journal->entries || !request_id)
    return NULL;
  for (size_t i = 0; i < journal->capacity; i++) {
    m3_chunk_replay_entry_v1_t *entry = &journal->entries[i];
    if (entry->state != M3_CHUNK_REPLAY_ENTRY_FREE &&
        turbo_uuid_equal(&entry->request_id, request_id)) {
      return entry;
    }
  }
  return NULL;
}

m3_chunk_replay_result_t m3_chunk_replay_journal_init_v1(
    m3_chunk_replay_journal_v1_t *journal, size_t capacity,
    uint64_t max_ttl_ms) {
  m3_chunk_replay_entry_v1_t *entries;

  if (!journal || journal->entries || journal->capacity != 0u ||
      capacity == 0u || capacity > M3_CHUNK_REPLAY_MAX_ENTRIES ||
      max_ttl_ms == 0u) {
    return M3_CHUNK_REPLAY_INVALID_ARG;
  }
  entries =
      (m3_chunk_replay_entry_v1_t *)calloc(capacity, sizeof(*entries));
  if (!entries)
    return M3_CHUNK_REPLAY_RESOURCE_EXHAUSTED;
  journal->entries = entries;
  journal->capacity = capacity;
  journal->max_ttl_ms = max_ttl_ms;
  return M3_CHUNK_REPLAY_OK;
}

void m3_chunk_replay_journal_destroy_v1(
    m3_chunk_replay_journal_v1_t *journal) {
  if (!journal)
    return;
  free(journal->entries);
  memset(journal, 0, sizeof(*journal));
}

size_t m3_chunk_replay_journal_sweep_v1(
    m3_chunk_replay_journal_v1_t *journal, uint64_t now_ms) {
  size_t removed = 0u;

  if (!journal || !journal->entries)
    return 0u;
  for (size_t i = 0; i < journal->capacity; i++) {
    m3_chunk_replay_entry_v1_t *entry = &journal->entries[i];
    if (entry->state != M3_CHUNK_REPLAY_ENTRY_FREE &&
        now_ms >= entry->expires_at_ms) {
      memset(entry, 0, sizeof(*entry));
      removed++;
    }
  }
  return removed;
}

m3_chunk_replay_result_t m3_chunk_replay_begin_request_v1(
    m3_chunk_replay_journal_v1_t *journal,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    m3_chunk_replay_begin_v1_t *out_begin) {
  m3_chunk_replay_entry_v1_t *entry = NULL;
  m3_chunk_replay_entry_v1_t *free_entry = NULL;
  uint8_t digest[M3_CHUNK_REPLAY_DIGEST_SIZE];
  m3_chunk_replay_result_t result;

  if (out_begin)
    memset(out_begin, 0, sizeof(*out_begin));
  if (!journal || !journal->entries || !access || !out_begin)
    return M3_CHUNK_REPLAY_INVALID_ARG;
  if (!access_is_valid(access))
    return M3_CHUNK_REPLAY_INVALID_ACCESS;
  if (now_ms >= access->expires_at_ms)
    return M3_CHUNK_REPLAY_EXPIRED;
  if (access->expires_at_ms - now_ms > journal->max_ttl_ms)
    return M3_CHUNK_REPLAY_INVALID_ACCESS;

  result = hash_access(access, digest);
  if (result != M3_CHUNK_REPLAY_OK)
    return result;
  (void)m3_chunk_replay_journal_sweep_v1(journal, now_ms);
  entry = find_entry(journal, &access->request_id);
  if (entry) {
    if (memcmp(entry->access_digest, digest, sizeof(digest)) != 0)
      return M3_CHUNK_REPLAY_CONFLICT;
    out_begin->kind =
        entry->state == M3_CHUNK_REPLAY_ENTRY_COMPLETED
            ? M3_CHUNK_REPLAY_BEGIN_COMPLETED
            : M3_CHUNK_REPLAY_BEGIN_IN_PROGRESS;
    out_begin->result_code = entry->result_code;
    return M3_CHUNK_REPLAY_OK;
  }

  for (size_t i = 0; i < journal->capacity; i++) {
    if (journal->entries[i].state == M3_CHUNK_REPLAY_ENTRY_FREE) {
      free_entry = &journal->entries[i];
      break;
    }
  }
  if (!free_entry)
    return M3_CHUNK_REPLAY_RESOURCE_EXHAUSTED;

  free_entry->request_id = access->request_id;
  memcpy(free_entry->access_digest, digest, sizeof(digest));
  free_entry->expires_at_ms = access->expires_at_ms;
  free_entry->state = M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS;
  out_begin->kind = M3_CHUNK_REPLAY_BEGIN_NEW;
  return M3_CHUNK_REPLAY_OK;
}

m3_chunk_replay_result_t m3_chunk_replay_complete_request_v1(
    m3_chunk_replay_journal_v1_t *journal,
    const m3_chunk_authorized_access_v1_t *access, int32_t result_code) {
  m3_chunk_replay_entry_v1_t *entry;
  uint8_t digest[M3_CHUNK_REPLAY_DIGEST_SIZE];
  m3_chunk_replay_result_t result;

  if (!journal || !journal->entries || !access)
    return M3_CHUNK_REPLAY_INVALID_ARG;
  result = hash_access(access, digest);
  if (result != M3_CHUNK_REPLAY_OK)
    return result;
  entry = find_entry(journal, &access->request_id);
  if (!entry)
    return M3_CHUNK_REPLAY_NOT_FOUND;
  if (memcmp(entry->access_digest, digest, sizeof(digest)) != 0)
    return M3_CHUNK_REPLAY_CONFLICT;
  if (entry->state == M3_CHUNK_REPLAY_ENTRY_COMPLETED)
    return entry->result_code == result_code ? M3_CHUNK_REPLAY_OK
                                             : M3_CHUNK_REPLAY_CONFLICT;
  if (entry->state != M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS)
    return M3_CHUNK_REPLAY_NOT_FOUND;

  entry->result_code = result_code;
  entry->state = M3_CHUNK_REPLAY_ENTRY_COMPLETED;
  return M3_CHUNK_REPLAY_OK;
}
