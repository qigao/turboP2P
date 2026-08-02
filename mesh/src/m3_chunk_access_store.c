#include "m3_chunk_access_store.h"

#include <string.h>

static int bytes_are_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < length; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static int cid_is_valid(const m3_chunk_cid_v1_t *cid) {
  return cid &&
         cid->hash_algorithm == M3_CHUNK_STORE_HASH_ALGORITHM_SHA256 &&
         bytes_are_nonzero(cid->digest, sizeof(cid->digest));
}

static int access_is_valid(const m3_chunk_authorized_access_v1_t *access) {
  if (!access || !cid_is_valid(&access->cid) ||
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
  if (access->operation == M3_CHUNK_OPERATION_PUT &&
      (access->range_offset != 0u ||
       access->range_length != access->cid.size)) {
    return 0;
  }
  return 1;
}

static m3_chunk_access_store_result_t
map_store_result(m3_chunk_store_result_t result) {
  switch (result) {
  case M3_CHUNK_STORE_OK:
    return M3_CHUNK_ACCESS_STORE_OK;
  case M3_CHUNK_STORE_INVALID_ARG:
    return M3_CHUNK_ACCESS_STORE_INVALID_ARG;
  case M3_CHUNK_STORE_NOT_FOUND:
    return M3_CHUNK_ACCESS_STORE_NOT_FOUND;
  case M3_CHUNK_STORE_CORRUPT:
    return M3_CHUNK_ACCESS_STORE_CORRUPT;
  case M3_CHUNK_STORE_DIGEST_MISMATCH:
    return M3_CHUNK_ACCESS_STORE_DIGEST_MISMATCH;
  case M3_CHUNK_STORE_RESOURCE_EXHAUSTED:
    return M3_CHUNK_ACCESS_STORE_RESOURCE_EXHAUSTED;
  case M3_CHUNK_STORE_LOCKED:
    return M3_CHUNK_ACCESS_STORE_LOCKED;
  case M3_CHUNK_STORE_CSPRNG_FAILED:
    return M3_CHUNK_ACCESS_STORE_CSPRNG_FAILED;
  case M3_CHUNK_STORE_IO:
  default:
    return M3_CHUNK_ACCESS_STORE_IO;
  }
}

m3_chunk_access_store_result_t m3_chunk_access_store_put_v1(
    m3_chunk_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    const uint8_t *bytes, size_t size, uint8_t *out_created) {
  if (out_created)
    *out_created = 0u;
  if (!store || !access || !out_created || (!bytes && size > 0u))
    return M3_CHUNK_ACCESS_STORE_INVALID_ARG;
  if (!access_is_valid(access) ||
      access->operation != M3_CHUNK_OPERATION_PUT) {
    return M3_CHUNK_ACCESS_STORE_INVALID_ACCESS;
  }
  if (now_ms >= access->expires_at_ms)
    return M3_CHUNK_ACCESS_STORE_EXPIRED;
  if (access->range_length > SIZE_MAX ||
      access->range_length != (uint64_t)size) {
    return M3_CHUNK_ACCESS_STORE_RESOURCE_EXHAUSTED;
  }
  return map_store_result(m3_chunk_store_put_bytes_v1(
      store, &access->cid, bytes, size, out_created));
}

m3_chunk_access_store_result_t m3_chunk_access_store_read_v1(
    const m3_chunk_store_v1_t *store,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    uint8_t *buffer, size_t buffer_size, size_t *out_read) {
  if (out_read)
    *out_read = 0u;
  if (!store || !access || !out_read)
    return M3_CHUNK_ACCESS_STORE_INVALID_ARG;
  if (!access_is_valid(access) ||
      access->operation != M3_CHUNK_OPERATION_READ) {
    return M3_CHUNK_ACCESS_STORE_INVALID_ACCESS;
  }
  if (now_ms >= access->expires_at_ms)
    return M3_CHUNK_ACCESS_STORE_EXPIRED;
  if (access->range_length > SIZE_MAX ||
      buffer_size < (size_t)access->range_length ||
      (!buffer && access->range_length > 0u)) {
    return M3_CHUNK_ACCESS_STORE_RESOURCE_EXHAUSTED;
  }
  return map_store_result(m3_chunk_store_read_range_v1(
      store, &access->cid, access->range_offset,
      (size_t)access->range_length, buffer, out_read));
}
