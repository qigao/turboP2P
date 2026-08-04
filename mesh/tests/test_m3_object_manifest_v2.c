#include <tinytest.h>

#include "m3_object_manifest.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

#define TEST_CHUNK_COUNT 3u
#define TEST_PLACEMENT_COUNT 6u
#define V2_HEADER_SIZE 128u
#define V2_CHUNK_RECORD_SIZE 48u
#define V2_PLACEMENT_RECORD_SIZE 80u
#define V2_ENVELOPE_DIGEST_OFFSET 80u
#define V2_HEADER_RESERVED_OFFSET 112u

static void fill_bytes(uint8_t *bytes, size_t size, uint8_t seed) {
  for (size_t i = 0u; i < size; i++)
    bytes[i] = (uint8_t)(seed + i);
}

static void make_manifest(m3_object_manifest_v2_t *manifest,
                          m3_chunk_cid_v1_t *chunks,
                          m3_object_manifest_placement_v1_t *placements) {
  static const uint64_t sizes[TEST_CHUNK_COUNT] = {100u, 200u, 300u};
  static const uint8_t store_seed[3] = {0xa0u, 0xb0u, 0xc0u};
  static const uint8_t chunk_indexes[TEST_PLACEMENT_COUNT] = {1u, 0u, 1u, 0u, 2u, 2u};
  static const uint8_t store_of[TEST_PLACEMENT_COUNT] = {2u, 1u, 1u, 0u, 2u, 0u};

  memset(manifest, 0, sizeof(*manifest));
  memset(chunks, 0, sizeof(*chunks) * TEST_CHUNK_COUNT);
  memset(placements, 0, sizeof(*placements) * TEST_PLACEMENT_COUNT);
  manifest->version = M3_OBJECT_MANIFEST_VERSION_2;
  manifest->object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest->object_cid.size = 600u;
  fill_bytes(manifest->object_cid.digest, sizeof(manifest->object_cid.digest),
             0x01u);
  manifest->chunks = chunks;
  manifest->chunk_count = TEST_CHUNK_COUNT;
  for (size_t i = 0u; i < TEST_CHUNK_COUNT; i++) {
    chunks[i].hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
    chunks[i].size = sizes[i];
    fill_bytes(chunks[i].digest, sizeof(chunks[i].digest),
               (uint8_t)(0x20u + i * 16u));
  }
  manifest->placements = placements;
  manifest->placement_count = TEST_PLACEMENT_COUNT;
  for (size_t i = 0u; i < TEST_PLACEMENT_COUNT; i++) {
    placements[i].chunk_index = chunk_indexes[i];
    fill_bytes(placements[i].store_node_id,
               sizeof(placements[i].store_node_id), store_seed[store_of[i]]);
    fill_bytes(placements[i].receipt_digest,
               sizeof(placements[i].receipt_digest), (uint8_t)(0x50u + i * 8u));
  }
}

static void rewrite_envelope_digest(uint8_t *bytes, size_t size) {
  static const uint8_t zeros[M3_CHUNK_CID_DIGEST_SIZE] = {0};
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
  unsigned int digest_size = 0u;

  check_true(context != NULL);
  check_int_eq(EVP_DigestInit_ex(context, EVP_sha256(), NULL), 1);
  check_int_eq(EVP_DigestUpdate(context, bytes, V2_ENVELOPE_DIGEST_OFFSET), 1);
  check_int_eq(EVP_DigestUpdate(context, zeros, sizeof(zeros)), 1);
  check_int_eq(EVP_DigestUpdate(context, bytes + V2_HEADER_RESERVED_OFFSET,
                                size - V2_HEADER_RESERVED_OFFSET), 1);
  check_int_eq(EVP_DigestFinal_ex(context, digest, &digest_size), 1);
  check_size_eq(digest_size, sizeof(digest));
  memcpy(bytes + V2_ENVELOPE_DIGEST_OFFSET, digest, sizeof(digest));
  EVP_MD_CTX_free(context);
}

static void test_manifest_v2_round_trip_and_canonical_order(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_CHUNK_COUNT];
  m3_object_manifest_placement_v1_t placements[TEST_PLACEMENT_COUNT];
  m3_object_manifest_owned_v2_t decoded = {0};
  uint8_t *encoded = NULL;
  size_t encoded_size = 0u;

  make_manifest(&manifest, chunks, placements);
  check_int_eq(m3_object_manifest_encode_v2(
                   &manifest, 4096u, 64u, 64u, &encoded, &encoded_size),
               M3_OBJECT_MANIFEST_OK);
  check_int_eq(m3_object_manifest_decode_v2(
                   encoded, encoded_size, 4096u, 64u, 64u, &decoded),
               M3_OBJECT_MANIFEST_OK);
  check_uint_eq(decoded.manifest.version, M3_OBJECT_MANIFEST_VERSION_2);
  check_uint_eq(decoded.manifest.chunk_count, TEST_CHUNK_COUNT);
  check_uint_eq(decoded.manifest.placement_count, TEST_PLACEMENT_COUNT);
  check_mem_eq(&decoded.manifest.object_cid, &manifest.object_cid,
               sizeof(manifest.object_cid));
  check_mem_eq(decoded.manifest.chunks, chunks,
               sizeof(chunks));
  /* Encode canonicalizes: chunk_index then store_node_id. */
  for (size_t i = 1u; i < TEST_PLACEMENT_COUNT; i++) {
    const m3_object_manifest_placement_v1_t *prev =
        &decoded.manifest.placements[i - 1u];
    const m3_object_manifest_placement_v1_t *cur =
        &decoded.manifest.placements[i];

    check_true(prev->chunk_index < cur->chunk_index ||
               (prev->chunk_index == cur->chunk_index &&
                memcmp(prev->store_node_id, cur->store_node_id,
                       sizeof(prev->store_node_id)) < 0));
  }
  check_uint_eq(decoded.manifest.placements[0].chunk_index, 0u);
  check_uint_eq(decoded.manifest.placements[0].store_node_id[0], 0xa0u);
  m3_object_manifest_owned_destroy_v2(&decoded);
  m3_object_manifest_bytes_free_v2(encoded);
}

static void test_manifest_v2_decodes_v1(void) {
  m3_object_manifest_v1_t v1;
  m3_chunk_cid_v1_t chunks[TEST_CHUNK_COUNT];
  m3_object_manifest_owned_v2_t decoded = {0};
  uint8_t *encoded = NULL;
  size_t encoded_size = 0u;

  memset(&v1, 0, sizeof(v1));
  memset(chunks, 0, sizeof(chunks));
  v1.version = M3_OBJECT_MANIFEST_VERSION;
  v1.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  v1.object_cid.size = 600u;
  fill_bytes(v1.object_cid.digest, sizeof(v1.object_cid.digest), 0x01u);
  v1.chunks = chunks;
  v1.chunk_count = TEST_CHUNK_COUNT;
  {
    static const uint64_t sizes[TEST_CHUNK_COUNT] = {100u, 200u, 300u};
    for (size_t i = 0u; i < TEST_CHUNK_COUNT; i++) {
      chunks[i].hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
      chunks[i].size = sizes[i];
      fill_bytes(chunks[i].digest, sizeof(chunks[i].digest),
                 (uint8_t)(0x20u + i * 16u));
    }
  }
  check_int_eq(m3_object_manifest_encode_v1(&v1, 4096u, 64u, &encoded,
                                            &encoded_size),
               M3_OBJECT_MANIFEST_OK);
  check_int_eq(m3_object_manifest_decode_v2(encoded, encoded_size, 4096u, 64u,
                                            64u, &decoded),
               M3_OBJECT_MANIFEST_OK);
  check_uint_eq(decoded.manifest.version, M3_OBJECT_MANIFEST_VERSION_2);
  check_uint_eq(decoded.manifest.chunk_count, TEST_CHUNK_COUNT);
  check_uint_eq(decoded.manifest.placement_count, 0u);
  check_mem_eq(decoded.manifest.chunks, chunks, sizeof(chunks));
  m3_object_manifest_owned_destroy_v2(&decoded);
  m3_object_manifest_bytes_free_v2(encoded);
}

static void test_manifest_v2_rejects_tampering_and_bad_order(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_CHUNK_COUNT];
  m3_object_manifest_placement_v1_t placements[TEST_PLACEMENT_COUNT];
  m3_object_manifest_owned_v2_t decoded = {0};
  uint8_t *encoded = NULL;
  size_t encoded_size = 0u;
  size_t placements_offset;

  make_manifest(&manifest, chunks, placements);
  check_int_eq(m3_object_manifest_encode_v2(
                   &manifest, 4096u, 64u, 64u, &encoded, &encoded_size),
               M3_OBJECT_MANIFEST_OK);

  encoded[V2_HEADER_SIZE + 1u] ^= 0x01u;
  check_int_eq(m3_object_manifest_decode_v2(
                   encoded, encoded_size, 4096u, 64u, 64u, &decoded),
               M3_OBJECT_MANIFEST_INTEGRITY);
  encoded[V2_HEADER_SIZE + 1u] ^= 0x01u;

  placements_offset =
      V2_HEADER_SIZE + TEST_CHUNK_COUNT * V2_CHUNK_RECORD_SIZE;
  encoded[placements_offset + V2_PLACEMENT_RECORD_SIZE + 8u] ^= 0x40u;
  check_int_eq(m3_object_manifest_decode_v2(
                   encoded, encoded_size, 4096u, 64u, 64u, &decoded),
               M3_OBJECT_MANIFEST_INTEGRITY);
  encoded[placements_offset + V2_PLACEMENT_RECORD_SIZE + 8u] ^= 0x40u;

  /* Swap the first two placement records and re-sign the envelope. The
   * canonical-order invariant must reject the non-canonical wire form. */
  {
    uint8_t tmp[V2_PLACEMENT_RECORD_SIZE];
    uint8_t *first = encoded + placements_offset;
    uint8_t *second = first + V2_PLACEMENT_RECORD_SIZE;

    memcpy(tmp, first, sizeof(tmp));
    memcpy(first, second, sizeof(tmp));
    memcpy(second, tmp, sizeof(tmp));
    rewrite_envelope_digest(encoded, encoded_size);
  }
  check_int_eq(m3_object_manifest_decode_v2(
                   encoded, encoded_size, 4096u, 64u, 64u, &decoded),
               M3_OBJECT_MANIFEST_CORRUPT);
  m3_object_manifest_owned_destroy_v2(&decoded);
  m3_object_manifest_bytes_free_v2(encoded);
}

static void test_manifest_v2_structural_validation(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_CHUNK_COUNT];
  m3_object_manifest_placement_v1_t placements[TEST_PLACEMENT_COUNT];
  m3_chunk_cid_v1_t bad_chunks[TEST_CHUNK_COUNT];
  m3_object_manifest_placement_v1_t bad_placements[TEST_PLACEMENT_COUNT];
  m3_object_manifest_v2_t bad;

  make_manifest(&manifest, chunks, placements);
  check_int_eq(m3_object_manifest_validate_v2(&manifest, 4096u, 64u, 64u),
               M3_OBJECT_MANIFEST_OK);
  check_int_eq(m3_object_manifest_validate_v2(NULL, 4096u, 64u, 64u),
               M3_OBJECT_MANIFEST_INVALID_ARG);

  memcpy(bad_chunks, chunks, sizeof(chunks));
  memcpy(bad_placements, placements, sizeof(placements));
  bad = manifest;
  bad.chunks = bad_chunks;
  bad.placements = bad_placements;

  bad_placements[0].chunk_index = TEST_CHUNK_COUNT;
  check_int_eq(m3_object_manifest_validate_v2(&bad, 4096u, 64u, 64u),
               M3_OBJECT_MANIFEST_INVALID_ARG);
  bad_placements[0] = placements[0];

  memset(bad_placements[1].store_node_id, 0,
         sizeof(bad_placements[1].store_node_id));
  check_int_eq(m3_object_manifest_validate_v2(&bad, 4096u, 64u, 64u),
               M3_OBJECT_MANIFEST_INVALID_ARG);
  bad_placements[1] = placements[1];

  memset(bad_placements[2].receipt_digest, 0,
         sizeof(bad_placements[2].receipt_digest));
  check_int_eq(m3_object_manifest_validate_v2(&bad, 4096u, 64u, 64u),
               M3_OBJECT_MANIFEST_INVALID_ARG);
  bad_placements[2] = placements[2];

  bad_placements[3] = bad_placements[0];
  check_int_eq(m3_object_manifest_validate_v2(&bad, 4096u, 64u, 64u),
               M3_OBJECT_MANIFEST_INVALID_ARG);
  bad_placements[3] = placements[3];

  bad_chunks[1].size = 999u;
  check_int_eq(m3_object_manifest_validate_v2(&bad, 4096u, 64u, 64u),
               M3_OBJECT_MANIFEST_INVALID_ARG);
}

static void test_manifest_v2_placement_policy(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_CHUNK_COUNT];
  m3_object_manifest_placement_v1_t placements[TEST_PLACEMENT_COUNT];
  m3_object_manifest_placement_debt_v1_t debt[TEST_CHUNK_COUNT];
  size_t debt_count = 0u;

  make_manifest(&manifest, chunks, placements);
  /* Each chunk has exactly 2 receipts: min=2,target=3 leaves debt 1/chunk. */
  check_int_eq(m3_object_manifest_placement_policy_v2(
                   &manifest, 2u, 3u, debt, TEST_CHUNK_COUNT, &debt_count),
               M3_OBJECT_MANIFEST_OK);
  check_size_eq(debt_count, TEST_CHUNK_COUNT);
  for (size_t i = 0u; i < debt_count; i++) {
    check_size_eq(debt[i].receipt_count, 2u);
    check_size_eq(debt[i].missing, 1u);
  }

  /* min=2,target=2 is fully satisfied: no debt. */
  check_int_eq(m3_object_manifest_placement_policy_v2(
                   &manifest, 2u, 2u, NULL, 0u, &debt_count),
               M3_OBJECT_MANIFEST_OK);
  check_size_eq(debt_count, 0u);

  /* Over-replication is a structural anomaly. */
  check_int_eq(m3_object_manifest_placement_policy_v2(
                   &manifest, 1u, 1u, NULL, 0u, &debt_count),
               M3_OBJECT_MANIFEST_INVALID_ARG);

  /* Invalid policy bounds. */
  check_int_eq(m3_object_manifest_placement_policy_v2(
                   &manifest, 0u, 3u, NULL, 0u, &debt_count),
               M3_OBJECT_MANIFEST_INVALID_ARG);
  check_int_eq(m3_object_manifest_placement_policy_v2(
                   &manifest, 4u, 3u, NULL, 0u, &debt_count),
               M3_OBJECT_MANIFEST_INVALID_ARG);
}

spec("m3 object manifest v2") {
    describe("placement segment") {
        it("round-trips and canonicalizes placement order") {
            test_manifest_v2_round_trip_and_canonical_order();
        }
        it("decodes V1 manifests as V2 with no placements") {
            test_manifest_v2_decodes_v1();
        }
        it("rejects tampered bytes and non-canonical order") {
            test_manifest_v2_rejects_tampering_and_bad_order();
        }
        it("validates placement structure and bounds") {
            test_manifest_v2_structural_validation();
        }
        it("computes replica debt against the placement policy") {
            test_manifest_v2_placement_policy();
        }
    }
}



