#include "m3_object_manifest.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

#define MANIFEST_HEADER_SIZE 104u
#define MANIFEST_RECORD_SIZE 48u

#define HEADER_MAGIC_OFFSET 0u
#define HEADER_VERSION_OFFSET 8u
#define HEADER_SIZE_OFFSET 12u
#define HEADER_RECORD_SIZE_OFFSET 16u
#define HEADER_CHUNK_COUNT_OFFSET 20u
#define HEADER_OBJECT_ALGORITHM_OFFSET 24u
#define HEADER_RESERVED_OFFSET 25u
#define HEADER_OBJECT_SIZE_OFFSET 32u
#define HEADER_OBJECT_DIGEST_OFFSET 40u
#define HEADER_ENVELOPE_DIGEST_OFFSET 72u

#define RECORD_ALGORITHM_OFFSET 0u
#define RECORD_RESERVED_OFFSET 1u
#define RECORD_SIZE_OFFSET 8u
#define RECORD_DIGEST_OFFSET 16u

static const uint8_t MANIFEST_MAGIC[8] = {
    'M', '3', 'M', 'N', 'F', '1', 0, 0,
};

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

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < size; i++)
    aggregate |= bytes[i];
  return aggregate == 0u;
}

static int bytes_are_nonzero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < size; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static int cid_is_valid(const m3_chunk_cid_v1_t *cid) {
  return cid &&
         cid->hash_algorithm == M3_CHUNK_STORE_HASH_ALGORITHM_SHA256 &&
         !bytes_are_zero(cid->digest, sizeof(cid->digest));
}

static size_t encoded_size(size_t chunk_count) {
  if (chunk_count >
      (SIZE_MAX - MANIFEST_HEADER_SIZE) / MANIFEST_RECORD_SIZE) {
    return 0u;
  }
  return MANIFEST_HEADER_SIZE + chunk_count * MANIFEST_RECORD_SIZE;
}

m3_object_manifest_result_t m3_object_manifest_validate_v1(
    const m3_object_manifest_v1_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks) {
  uint64_t total = 0u;

  if (!manifest || manifest->version != M3_OBJECT_MANIFEST_VERSION ||
      !cid_is_valid(&manifest->object_cid) || max_object_bytes == 0u ||
      manifest->object_cid.size > max_object_bytes || max_chunks == 0u ||
      manifest->chunk_count > max_chunks ||
      manifest->chunk_count > UINT32_MAX ||
      (manifest->chunk_count > 0u && !manifest->chunks)) {
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  }
  for (size_t i = 0; i < manifest->chunk_count; i++) {
    if (!cid_is_valid(&manifest->chunks[i]) ||
        manifest->chunks[i].size > UINT64_MAX - total) {
      return M3_OBJECT_MANIFEST_INVALID_ARG;
    }
    total += manifest->chunks[i].size;
  }
  return total == manifest->object_cid.size
             ? M3_OBJECT_MANIFEST_OK
             : M3_OBJECT_MANIFEST_INVALID_ARG;
}

static m3_object_manifest_result_t calculate_envelope_digest_at(
    const uint8_t *bytes, size_t size, size_t digest_offset,
    uint8_t output[M3_CHUNK_CID_DIGEST_SIZE]) {
  static const uint8_t zeros[M3_CHUNK_CID_DIGEST_SIZE] = {0};
  EVP_MD_CTX *hash = NULL;
  unsigned int digest_size = 0u;
  m3_object_manifest_result_t result = M3_OBJECT_MANIFEST_CRYPTO_FAILED;

  if (!bytes || size < digest_offset + M3_CHUNK_CID_DIGEST_SIZE || !output)
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  hash = EVP_MD_CTX_new();
  if (!hash)
    return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
  if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(hash, bytes, digest_offset) != 1 ||
      EVP_DigestUpdate(hash, zeros, sizeof(zeros)) != 1 ||
      EVP_DigestUpdate(hash, bytes + digest_offset + sizeof(zeros),
                       size - digest_offset - sizeof(zeros)) != 1 ||
      EVP_DigestFinal_ex(hash, output, &digest_size) != 1 ||
      digest_size != M3_CHUNK_CID_DIGEST_SIZE) {
    goto cleanup;
  }
  result = M3_OBJECT_MANIFEST_OK;

cleanup:
  EVP_MD_CTX_free(hash);
  if (result != M3_OBJECT_MANIFEST_OK)
    memset(output, 0, M3_CHUNK_CID_DIGEST_SIZE);
  return result;
}

static m3_object_manifest_result_t calculate_envelope_digest(
    const uint8_t *bytes, size_t size,
    uint8_t output[M3_CHUNK_CID_DIGEST_SIZE]) {
  return calculate_envelope_digest_at(bytes, size,
                                      HEADER_ENVELOPE_DIGEST_OFFSET, output);
}

m3_object_manifest_result_t m3_object_manifest_encode_v1(
    const m3_object_manifest_v1_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks, uint8_t **out_bytes, size_t *out_size) {
  uint8_t *bytes;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
  size_t size;
  m3_object_manifest_result_t result;

  if (!out_bytes || !out_size)
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  *out_bytes = NULL;
  *out_size = 0u;
  result = m3_object_manifest_validate_v1(
      manifest, max_object_bytes, max_chunks);
  if (result != M3_OBJECT_MANIFEST_OK)
    return result;
  size = encoded_size(manifest->chunk_count);
  if (size == 0u)
    return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
  bytes = (uint8_t *)calloc(1, size);
  if (!bytes)
    return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;

  memcpy(bytes + HEADER_MAGIC_OFFSET, MANIFEST_MAGIC, sizeof(MANIFEST_MAGIC));
  write_u32(bytes + HEADER_VERSION_OFFSET, M3_OBJECT_MANIFEST_VERSION);
  write_u32(bytes + HEADER_SIZE_OFFSET, MANIFEST_HEADER_SIZE);
  write_u32(bytes + HEADER_RECORD_SIZE_OFFSET, MANIFEST_RECORD_SIZE);
  write_u32(bytes + HEADER_CHUNK_COUNT_OFFSET,
            (uint32_t)manifest->chunk_count);
  bytes[HEADER_OBJECT_ALGORITHM_OFFSET] =
      manifest->object_cid.hash_algorithm;
  write_u64(bytes + HEADER_OBJECT_SIZE_OFFSET, manifest->object_cid.size);
  memcpy(bytes + HEADER_OBJECT_DIGEST_OFFSET, manifest->object_cid.digest,
         sizeof(manifest->object_cid.digest));
  for (size_t i = 0; i < manifest->chunk_count; i++) {
    const m3_chunk_cid_v1_t *cid = &manifest->chunks[i];
    uint8_t *record =
        bytes + MANIFEST_HEADER_SIZE + i * MANIFEST_RECORD_SIZE;

    record[RECORD_ALGORITHM_OFFSET] = cid->hash_algorithm;
    write_u64(record + RECORD_SIZE_OFFSET, cid->size);
    memcpy(record + RECORD_DIGEST_OFFSET, cid->digest,
           sizeof(cid->digest));
  }
  result = calculate_envelope_digest(bytes, size, digest);
  if (result != M3_OBJECT_MANIFEST_OK) {
    free(bytes);
    return result;
  }
  memcpy(bytes + HEADER_ENVELOPE_DIGEST_OFFSET, digest, sizeof(digest));
  *out_bytes = bytes;
  *out_size = size;
  return M3_OBJECT_MANIFEST_OK;
}

m3_object_manifest_result_t m3_object_manifest_decode_v1(
    const uint8_t *bytes, size_t size, uint64_t max_object_bytes,
    size_t max_chunks, m3_object_manifest_owned_v1_t *out_manifest) {
  m3_object_manifest_owned_v1_t decoded = {0};
  uint8_t actual_digest[M3_CHUNK_CID_DIGEST_SIZE];
  uint32_t chunk_count;
  size_t expected_size;
  m3_object_manifest_result_t result;

  if (!bytes || !out_manifest || size < MANIFEST_HEADER_SIZE ||
      max_object_bytes == 0u || max_chunks == 0u) {
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  }
  memset(out_manifest, 0, sizeof(*out_manifest));
  if (memcmp(bytes + HEADER_MAGIC_OFFSET, MANIFEST_MAGIC,
             sizeof(MANIFEST_MAGIC)) != 0 ||
      read_u32(bytes + HEADER_VERSION_OFFSET) !=
          M3_OBJECT_MANIFEST_VERSION ||
      read_u32(bytes + HEADER_SIZE_OFFSET) != MANIFEST_HEADER_SIZE ||
      read_u32(bytes + HEADER_RECORD_SIZE_OFFSET) != MANIFEST_RECORD_SIZE ||
      !bytes_are_zero(bytes + HEADER_RESERVED_OFFSET, 7u)) {
    return M3_OBJECT_MANIFEST_CORRUPT;
  }
  chunk_count = read_u32(bytes + HEADER_CHUNK_COUNT_OFFSET);
  expected_size = encoded_size(chunk_count);
  if (chunk_count > max_chunks || expected_size == 0u ||
      size != expected_size) {
    return M3_OBJECT_MANIFEST_CORRUPT;
  }
  result = calculate_envelope_digest(bytes, size, actual_digest);
  if (result != M3_OBJECT_MANIFEST_OK)
    return result;
  if (memcmp(actual_digest, bytes + HEADER_ENVELOPE_DIGEST_OFFSET,
             sizeof(actual_digest)) != 0) {
    return M3_OBJECT_MANIFEST_INTEGRITY;
  }

  decoded.manifest.version = M3_OBJECT_MANIFEST_VERSION;
  decoded.manifest.object_cid.hash_algorithm =
      bytes[HEADER_OBJECT_ALGORITHM_OFFSET];
  decoded.manifest.object_cid.size =
      read_u64(bytes + HEADER_OBJECT_SIZE_OFFSET);
  memcpy(decoded.manifest.object_cid.digest,
         bytes + HEADER_OBJECT_DIGEST_OFFSET,
         sizeof(decoded.manifest.object_cid.digest));
  decoded.manifest.chunk_count = chunk_count;
  if (chunk_count > 0u) {
    decoded.owned_chunks = (m3_chunk_cid_v1_t *)calloc(
        chunk_count, sizeof(*decoded.owned_chunks));
    if (!decoded.owned_chunks)
      return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
  }
  decoded.manifest.chunks = decoded.owned_chunks;
  for (size_t i = 0; i < chunk_count; i++) {
    const uint8_t *record =
        bytes + MANIFEST_HEADER_SIZE + i * MANIFEST_RECORD_SIZE;
    m3_chunk_cid_v1_t *cid = &decoded.owned_chunks[i];

    if (!bytes_are_zero(record + RECORD_RESERVED_OFFSET, 7u)) {
      result = M3_OBJECT_MANIFEST_CORRUPT;
      goto failed;
    }
    cid->hash_algorithm = record[RECORD_ALGORITHM_OFFSET];
    cid->size = read_u64(record + RECORD_SIZE_OFFSET);
    memcpy(cid->digest, record + RECORD_DIGEST_OFFSET, sizeof(cid->digest));
  }
  result = m3_object_manifest_validate_v1(
      &decoded.manifest, max_object_bytes, max_chunks);
  if (result != M3_OBJECT_MANIFEST_OK) {
    result = M3_OBJECT_MANIFEST_CORRUPT;
    goto failed;
  }
  *out_manifest = decoded;
  return M3_OBJECT_MANIFEST_OK;

failed:
  free(decoded.owned_chunks);
  return result;
}

void m3_object_manifest_owned_destroy_v1(
    m3_object_manifest_owned_v1_t *manifest) {
  if (!manifest)
    return;
  free(manifest->owned_chunks);
  memset(manifest, 0, sizeof(*manifest));
}

void m3_object_manifest_bytes_free_v1(uint8_t *bytes) {
  free(bytes);
}

/* ------------------------------------------------------------------------ */
/* V2: placement segment                                                    */
/* ------------------------------------------------------------------------ */

#define V2_HEADER_SIZE 128u
#define V2_PLACEMENT_RECORD_SIZE 80u

#define V2_HEADER_VERSION_OFFSET 8u
#define V2_HEADER_HEADER_SIZE_OFFSET 12u
#define V2_HEADER_CHUNK_RECORD_SIZE_OFFSET 16u
#define V2_HEADER_CHUNK_COUNT_OFFSET 20u
#define V2_HEADER_PLACEMENT_RECORD_SIZE_OFFSET 24u
#define V2_HEADER_PLACEMENT_COUNT_OFFSET 28u
#define V2_HEADER_OBJECT_ALGORITHM_OFFSET 32u
#define V2_HEADER_OBJECT_RESERVED_OFFSET 33u
#define V2_HEADER_OBJECT_SIZE_OFFSET 40u
#define V2_HEADER_OBJECT_DIGEST_OFFSET 48u
#define V2_HEADER_ENVELOPE_DIGEST_OFFSET 80u
#define V2_HEADER_RESERVED_OFFSET 112u

#define V2_PLACEMENT_CHUNK_INDEX_OFFSET 0u
#define V2_PLACEMENT_RESERVED_OFFSET 4u
#define V2_PLACEMENT_STORE_NODE_ID_OFFSET 8u
#define V2_PLACEMENT_RECEIPT_DIGEST_OFFSET 40u
#define V2_PLACEMENT_RESERVED_TAIL_OFFSET 72u

static const uint8_t MANIFEST_MAGIC_V2[8] = {
    'M', '3', 'M', 'N', 'F', '2', 0, 0,
};

static int placement_compare(const void *left, const void *right) {
  const m3_object_manifest_placement_v1_t *a =
      (const m3_object_manifest_placement_v1_t *)left;
  const m3_object_manifest_placement_v1_t *b =
      (const m3_object_manifest_placement_v1_t *)right;
  int order;

  if (a->chunk_index != b->chunk_index)
    return a->chunk_index < b->chunk_index ? -1 : 1;
  order = memcmp(a->store_node_id, b->store_node_id,
                 sizeof(a->store_node_id));
  return order < 0 ? -1 : (order > 0 ? 1 : 0);
}

static size_t encoded_size_v2(size_t chunk_count, size_t placement_count) {
  size_t total;

  if (chunk_count > (SIZE_MAX - V2_HEADER_SIZE) / MANIFEST_RECORD_SIZE)
    return 0u;
  total = V2_HEADER_SIZE + chunk_count * MANIFEST_RECORD_SIZE;
  if (placement_count >
      (SIZE_MAX - total) / V2_PLACEMENT_RECORD_SIZE) {
    return 0u;
  }
  return total + placement_count * V2_PLACEMENT_RECORD_SIZE;
}

m3_object_manifest_result_t m3_object_manifest_validate_v2(
    const m3_object_manifest_v2_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_placements) {
  uint64_t total = 0u;

  if (!manifest || manifest->version != M3_OBJECT_MANIFEST_VERSION_2 ||
      !cid_is_valid(&manifest->object_cid) || max_object_bytes == 0u ||
      manifest->object_cid.size > max_object_bytes || max_chunks == 0u ||
      manifest->chunk_count > max_chunks ||
      manifest->chunk_count > UINT32_MAX ||
      (manifest->chunk_count > 0u && !manifest->chunks) ||
      manifest->placement_count > max_placements ||
      (manifest->placement_count > 0u && !manifest->placements)) {
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  }
  for (size_t i = 0; i < manifest->chunk_count; i++) {
    if (!cid_is_valid(&manifest->chunks[i]) ||
        manifest->chunks[i].size > UINT64_MAX - total) {
      return M3_OBJECT_MANIFEST_INVALID_ARG;
    }
    total += manifest->chunks[i].size;
  }
  if (total != manifest->object_cid.size)
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  for (size_t i = 0; i < manifest->placement_count; i++) {
    const m3_object_manifest_placement_v1_t *placement =
        &manifest->placements[i];

    if (placement->chunk_index >= manifest->chunk_count ||
        !bytes_are_nonzero(placement->store_node_id,
                           sizeof(placement->store_node_id)) ||
        !bytes_are_nonzero(placement->receipt_digest,
                           sizeof(placement->receipt_digest))) {
      return M3_OBJECT_MANIFEST_INVALID_ARG;
    }
    for (size_t j = 0; j < i; j++) {
      const m3_object_manifest_placement_v1_t *other =
          &manifest->placements[j];

      if (placement->chunk_index == other->chunk_index &&
          memcmp(placement->store_node_id, other->store_node_id,
                 sizeof(placement->store_node_id)) == 0) {
        return M3_OBJECT_MANIFEST_INVALID_ARG;
      }
    }
  }
  return M3_OBJECT_MANIFEST_OK;
}

m3_object_manifest_result_t m3_object_manifest_encode_v2(
    const m3_object_manifest_v2_t *manifest, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_placements, uint8_t **out_bytes,
    size_t *out_size) {
  m3_object_manifest_placement_v1_t *sorted = NULL;
  uint8_t *bytes = NULL;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
  size_t size;
  m3_object_manifest_result_t result;

  if (!out_bytes || !out_size)
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  *out_bytes = NULL;
  *out_size = 0u;
  result = m3_object_manifest_validate_v2(
      manifest, max_object_bytes, max_chunks, max_placements);
  if (result != M3_OBJECT_MANIFEST_OK)
    return result;
  if (manifest->placement_count > 0u) {
    sorted = (m3_object_manifest_placement_v1_t *)malloc(
        manifest->placement_count * sizeof(*sorted));
    if (!sorted)
      return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
    memcpy(sorted, manifest->placements,
           manifest->placement_count * sizeof(*sorted));
    qsort(sorted, manifest->placement_count, sizeof(*sorted),
          placement_compare);
  }
  size = encoded_size_v2(manifest->chunk_count, manifest->placement_count);
  if (size == 0u) {
    free(sorted);
    return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
  }
  bytes = (uint8_t *)calloc(1, size);
  if (!bytes) {
    free(sorted);
    return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
  }

  memcpy(bytes, MANIFEST_MAGIC_V2, sizeof(MANIFEST_MAGIC_V2));
  write_u32(bytes + V2_HEADER_VERSION_OFFSET, M3_OBJECT_MANIFEST_VERSION_2);
  write_u32(bytes + V2_HEADER_HEADER_SIZE_OFFSET, V2_HEADER_SIZE);
  write_u32(bytes + V2_HEADER_CHUNK_RECORD_SIZE_OFFSET, MANIFEST_RECORD_SIZE);
  write_u32(bytes + V2_HEADER_CHUNK_COUNT_OFFSET,
            (uint32_t)manifest->chunk_count);
  write_u32(bytes + V2_HEADER_PLACEMENT_RECORD_SIZE_OFFSET,
            V2_PLACEMENT_RECORD_SIZE);
  write_u32(bytes + V2_HEADER_PLACEMENT_COUNT_OFFSET,
            (uint32_t)manifest->placement_count);
  bytes[V2_HEADER_OBJECT_ALGORITHM_OFFSET] =
      manifest->object_cid.hash_algorithm;
  write_u64(bytes + V2_HEADER_OBJECT_SIZE_OFFSET, manifest->object_cid.size);
  memcpy(bytes + V2_HEADER_OBJECT_DIGEST_OFFSET,
         manifest->object_cid.digest, sizeof(manifest->object_cid.digest));
  for (size_t i = 0; i < manifest->chunk_count; i++) {
    const m3_chunk_cid_v1_t *cid = &manifest->chunks[i];
    uint8_t *record = bytes + V2_HEADER_SIZE + i * MANIFEST_RECORD_SIZE;

    record[RECORD_ALGORITHM_OFFSET] = cid->hash_algorithm;
    write_u64(record + RECORD_SIZE_OFFSET, cid->size);
    memcpy(record + RECORD_DIGEST_OFFSET, cid->digest,
           sizeof(cid->digest));
  }
  for (size_t i = 0; i < manifest->placement_count; i++) {
    const m3_object_manifest_placement_v1_t *placement =
        sorted ? &sorted[i] : &manifest->placements[i];
    uint8_t *record =
        bytes + V2_HEADER_SIZE +
        manifest->chunk_count * MANIFEST_RECORD_SIZE +
        i * V2_PLACEMENT_RECORD_SIZE;

    write_u32(record + V2_PLACEMENT_CHUNK_INDEX_OFFSET,
              placement->chunk_index);
    memcpy(record + V2_PLACEMENT_STORE_NODE_ID_OFFSET,
           placement->store_node_id, sizeof(placement->store_node_id));
    memcpy(record + V2_PLACEMENT_RECEIPT_DIGEST_OFFSET,
           placement->receipt_digest, sizeof(placement->receipt_digest));
  }
  result = calculate_envelope_digest_at(bytes, size,
                                        V2_HEADER_ENVELOPE_DIGEST_OFFSET,
                                        digest);
  if (result != M3_OBJECT_MANIFEST_OK) {
    free(bytes);
    free(sorted);
    return result;
  }
  memcpy(bytes + V2_HEADER_ENVELOPE_DIGEST_OFFSET, digest, sizeof(digest));
  *out_bytes = bytes;
  *out_size = size;
  free(sorted);
  return M3_OBJECT_MANIFEST_OK;
}

m3_object_manifest_result_t m3_object_manifest_decode_v2(
    const uint8_t *bytes, size_t size, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_placements,
    m3_object_manifest_owned_v2_t *out_manifest) {
  m3_object_manifest_owned_v2_t decoded = {0};
  uint8_t actual_digest[M3_CHUNK_CID_DIGEST_SIZE];
  uint32_t chunk_count;
  uint32_t placement_count;
  size_t expected_size;
  m3_object_manifest_result_t result;

  if (!bytes || !out_manifest || size < MANIFEST_HEADER_SIZE ||
      max_object_bytes == 0u || max_chunks == 0u) {
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  }
  memset(out_manifest, 0, sizeof(*out_manifest));
  if (read_u32(bytes + HEADER_VERSION_OFFSET) == M3_OBJECT_MANIFEST_VERSION) {
    m3_object_manifest_owned_v1_t v1 = {0};

    result = m3_object_manifest_decode_v1(
        bytes, size, max_object_bytes, max_chunks, &v1);
    if (result != M3_OBJECT_MANIFEST_OK)
      return result;
    decoded.manifest.version = M3_OBJECT_MANIFEST_VERSION_2;
    decoded.manifest.object_cid = v1.manifest.object_cid;
    decoded.manifest.chunk_count = v1.manifest.chunk_count;
    decoded.owned_chunks = v1.owned_chunks;
    decoded.manifest.chunks = decoded.owned_chunks;
    v1.owned_chunks = NULL;
    memset(&v1, 0, sizeof(v1));
    *out_manifest = decoded;
    return M3_OBJECT_MANIFEST_OK;
  }

  if (size < V2_HEADER_SIZE ||
      memcmp(bytes, MANIFEST_MAGIC_V2, sizeof(MANIFEST_MAGIC_V2)) != 0 ||
      read_u32(bytes + V2_HEADER_VERSION_OFFSET) !=
          M3_OBJECT_MANIFEST_VERSION_2 ||
      read_u32(bytes + V2_HEADER_HEADER_SIZE_OFFSET) != V2_HEADER_SIZE ||
      read_u32(bytes + V2_HEADER_CHUNK_RECORD_SIZE_OFFSET) !=
          MANIFEST_RECORD_SIZE ||
      read_u32(bytes + V2_HEADER_PLACEMENT_RECORD_SIZE_OFFSET) !=
          V2_PLACEMENT_RECORD_SIZE ||
      !bytes_are_zero(bytes + V2_HEADER_OBJECT_RESERVED_OFFSET, 7u) ||
      !bytes_are_zero(bytes + V2_HEADER_RESERVED_OFFSET,
                      V2_HEADER_SIZE - V2_HEADER_RESERVED_OFFSET)) {
    return M3_OBJECT_MANIFEST_CORRUPT;
  }
  chunk_count = read_u32(bytes + V2_HEADER_CHUNK_COUNT_OFFSET);
  placement_count = read_u32(bytes + V2_HEADER_PLACEMENT_COUNT_OFFSET);
  expected_size = encoded_size_v2(chunk_count, placement_count);
  if (chunk_count > max_chunks || placement_count > max_placements ||
      expected_size == 0u || size != expected_size) {
    return M3_OBJECT_MANIFEST_CORRUPT;
  }
  result = calculate_envelope_digest_at(bytes, size,
                                        V2_HEADER_ENVELOPE_DIGEST_OFFSET,
                                        actual_digest);
  if (result != M3_OBJECT_MANIFEST_OK)
    return result;
  if (memcmp(actual_digest, bytes + V2_HEADER_ENVELOPE_DIGEST_OFFSET,
             sizeof(actual_digest)) != 0) {
    return M3_OBJECT_MANIFEST_INTEGRITY;
  }

  decoded.manifest.version = M3_OBJECT_MANIFEST_VERSION_2;
  decoded.manifest.object_cid.hash_algorithm =
      bytes[V2_HEADER_OBJECT_ALGORITHM_OFFSET];
  decoded.manifest.object_cid.size =
      read_u64(bytes + V2_HEADER_OBJECT_SIZE_OFFSET);
  memcpy(decoded.manifest.object_cid.digest,
         bytes + V2_HEADER_OBJECT_DIGEST_OFFSET,
         sizeof(decoded.manifest.object_cid.digest));
  decoded.manifest.chunk_count = chunk_count;
  if (chunk_count > 0u) {
    decoded.owned_chunks = (m3_chunk_cid_v1_t *)calloc(
        chunk_count, sizeof(*decoded.owned_chunks));
    if (!decoded.owned_chunks)
      return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
  }
  decoded.manifest.chunks = decoded.owned_chunks;
  for (size_t i = 0; i < chunk_count; i++) {
    const uint8_t *record =
        bytes + V2_HEADER_SIZE + i * MANIFEST_RECORD_SIZE;
    m3_chunk_cid_v1_t *cid = &decoded.owned_chunks[i];

    if (!bytes_are_zero(record + RECORD_RESERVED_OFFSET, 7u)) {
      result = M3_OBJECT_MANIFEST_CORRUPT;
      goto failed;
    }
    cid->hash_algorithm = record[RECORD_ALGORITHM_OFFSET];
    cid->size = read_u64(record + RECORD_SIZE_OFFSET);
    memcpy(cid->digest, record + RECORD_DIGEST_OFFSET, sizeof(cid->digest));
  }

  decoded.manifest.placement_count = placement_count;
  if (placement_count > 0u) {
    decoded.owned_placements = (m3_object_manifest_placement_v1_t *)calloc(
        placement_count, sizeof(*decoded.owned_placements));
    if (!decoded.owned_placements) {
      result = M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
      goto failed;
    }
  }
  decoded.manifest.placements = decoded.owned_placements;
  for (size_t i = 0; i < placement_count; i++) {
    const uint8_t *record =
        bytes + V2_HEADER_SIZE + chunk_count * MANIFEST_RECORD_SIZE +
        i * V2_PLACEMENT_RECORD_SIZE;
    m3_object_manifest_placement_v1_t *placement =
        &decoded.owned_placements[i];

    if (!bytes_are_zero(record + V2_PLACEMENT_RESERVED_OFFSET, 4u) ||
        !bytes_are_zero(record + V2_PLACEMENT_RESERVED_TAIL_OFFSET, 8u)) {
      result = M3_OBJECT_MANIFEST_CORRUPT;
      goto failed;
    }
    placement->chunk_index = read_u32(record + V2_PLACEMENT_CHUNK_INDEX_OFFSET);
    memcpy(placement->store_node_id,
           record + V2_PLACEMENT_STORE_NODE_ID_OFFSET,
           sizeof(placement->store_node_id));
    memcpy(placement->receipt_digest,
           record + V2_PLACEMENT_RECEIPT_DIGEST_OFFSET,
           sizeof(placement->receipt_digest));
    if (i > 0u &&
        placement_compare(&decoded.owned_placements[i - 1], placement) >= 0) {
      result = M3_OBJECT_MANIFEST_CORRUPT;
      goto failed;
    }
  }
  result = m3_object_manifest_validate_v2(
      &decoded.manifest, max_object_bytes, max_chunks, max_placements);
  if (result != M3_OBJECT_MANIFEST_OK) {
    result = M3_OBJECT_MANIFEST_CORRUPT;
    goto failed;
  }
  *out_manifest = decoded;
  return M3_OBJECT_MANIFEST_OK;

failed:
  free(decoded.owned_chunks);
  free(decoded.owned_placements);
  return result;
}

void m3_object_manifest_owned_destroy_v2(
    m3_object_manifest_owned_v2_t *manifest) {
  if (!manifest)
    return;
  free(manifest->owned_chunks);
  free(manifest->owned_placements);
  memset(manifest, 0, sizeof(*manifest));
}

void m3_object_manifest_bytes_free_v2(uint8_t *bytes) {
  free(bytes);
}

m3_object_manifest_result_t m3_object_manifest_placement_policy_v2(
    const m3_object_manifest_v2_t *manifest, size_t min_durable_replicas,
    size_t target_replicas, m3_object_manifest_placement_debt_v1_t *out_debt,
    size_t debt_capacity, size_t *out_debt_count) {
  m3_object_manifest_result_t result;
  size_t debt_count = 0u;

  if (out_debt_count)
    *out_debt_count = 0u;
  if (!manifest || min_durable_replicas == 0u || target_replicas == 0u ||
      target_replicas < min_durable_replicas ||
      target_replicas > UINT32_MAX) {
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  }
  result = m3_object_manifest_validate_v2(
      manifest, manifest->object_cid.size, manifest->chunk_count,
      manifest->placement_count);
  if (result != M3_OBJECT_MANIFEST_OK)
    return result;
  for (size_t chunk_index = 0u; chunk_index < manifest->chunk_count;
       chunk_index++) {
    size_t receipt_count = 0u;

    for (size_t i = 0u; i < manifest->placement_count; i++) {
      if (manifest->placements[i].chunk_index == chunk_index)
        receipt_count++;
    }
    if (receipt_count > target_replicas)
      return M3_OBJECT_MANIFEST_INVALID_ARG;
    if (receipt_count < target_replicas) {
      if (out_debt && debt_count < debt_capacity) {
        out_debt[debt_count].chunk_index = chunk_index;
        out_debt[debt_count].receipt_count = receipt_count;
        out_debt[debt_count].missing = target_replicas - receipt_count;
      }
      debt_count++;
    }
  }
  if (out_debt_count)
    *out_debt_count = debt_count;
  return M3_OBJECT_MANIFEST_OK;
}
