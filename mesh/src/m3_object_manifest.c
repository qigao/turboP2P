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

static m3_object_manifest_result_t calculate_envelope_digest(
    const uint8_t *bytes, size_t size,
    uint8_t output[M3_CHUNK_CID_DIGEST_SIZE]) {
  static const uint8_t zeros[M3_CHUNK_CID_DIGEST_SIZE] = {0};
  EVP_MD_CTX *hash = NULL;
  unsigned int digest_size = 0u;
  m3_object_manifest_result_t result = M3_OBJECT_MANIFEST_CRYPTO_FAILED;

  if (!bytes || size < MANIFEST_HEADER_SIZE || !output)
    return M3_OBJECT_MANIFEST_INVALID_ARG;
  hash = EVP_MD_CTX_new();
  if (!hash)
    return M3_OBJECT_MANIFEST_RESOURCE_EXHAUSTED;
  if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(hash, bytes, HEADER_ENVELOPE_DIGEST_OFFSET) != 1 ||
      EVP_DigestUpdate(hash, zeros, sizeof(zeros)) != 1 ||
      EVP_DigestUpdate(
          hash,
          bytes + HEADER_ENVELOPE_DIGEST_OFFSET + sizeof(zeros),
          size - HEADER_ENVELOPE_DIGEST_OFFSET - sizeof(zeros)) != 1 ||
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
