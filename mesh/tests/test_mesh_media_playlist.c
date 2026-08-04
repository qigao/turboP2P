#include <tinytest.h>

#include "mesh_media_playlist.h"

#include <turbo_crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* P12: HLS-style playlists over the media index. The media playlist lists
 * each segment with an EXTINF duration and EXT-X-BYTERANGE (offset@len) that a
 * player feeds straight into mesh_stream_media_pull; the master playlist
 * lists the ABR ladder for rendition selection. */

#define TEST_BLOCK 1024u
#define TEST_BLOCKS 8u
#define TEST_OBJECT_SIZE (TEST_BLOCK * TEST_BLOCKS)

static uint8_t g_data[TEST_OBJECT_SIZE];

static void fill_data(void) {
  for (size_t i = 0u; i < TEST_OBJECT_SIZE; i++)
    g_data[i] = (uint8_t)(i * 7u + (i >> 4u) + 1u);
}

static void build_manifest(m3_object_manifest_v2_t *manifest,
                           m3_chunk_cid_v1_t *chunks) {
  turbo_crypto_sha256_ctx_t ctx;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];

  (void)turbo_crypto_sha256_init(&ctx);
  memset(manifest, 0, sizeof(*manifest));
  memset(chunks, 0, TEST_BLOCKS * sizeof(*chunks));
  for (size_t i = 0u; i < TEST_BLOCKS; i++) {
    (void)turbo_crypto_sha256(g_data + i * TEST_BLOCK, TEST_BLOCK, chunks[i].digest);
    (void)turbo_crypto_sha256_update(&ctx, chunks[i].digest,
                                     sizeof(chunks[i].digest));
    chunks[i].hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
    chunks[i].size = TEST_BLOCK;
  }
  (void)turbo_crypto_sha256_final(&ctx, digest);
  manifest->version = M3_OBJECT_MANIFEST_VERSION_2;
  manifest->object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  manifest->object_cid.size = TEST_OBJECT_SIZE;
  memcpy(manifest->object_cid.digest, digest, sizeof(digest));
  manifest->chunks = chunks;
  manifest->chunk_count = TEST_BLOCKS;
}

static void build_index(mesh_media_index_v1_t *index,
                        const m3_object_manifest_v2_t *manifest) {
  memset(index, 0, sizeof(*index));
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_index_build_v1(index, manifest, 3u * TEST_BLOCK));
  check_size_eq(index->segment_count, 3u);
}

/* Extract the (index, offset, len) tuples from a media playlist. */
static size_t parse_media_playlist(const char *text, size_t *offsets,
                                   size_t *lens) {
  const char *cursor = text;
  size_t count = 0u;

  while ((cursor = strstr(cursor, "#EXT-X-BYTERANGE:")) != NULL) {
    unsigned long long offset = 0u;
    unsigned long long len = 0u;

    if (sscanf(cursor + 17, "%llu@%llu", &len, &offset) == 2) {
      if (count < 64u) {
        offsets[count] = (size_t)offset;
        lens[count] = (size_t)len;
      }
      count++;
    }
    cursor += 1;
  }
  return count;
}

static void test_media_playlist(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  mesh_media_index_v1_t index;
  char playlist[4096];
  size_t playlist_len = 0u;
  size_t offsets[64];
  size_t lens[64];
  size_t count = 0u;
  char uri[32];

  fill_data();
  build_manifest(&manifest, chunks);
  build_index(&index, &manifest);

  check_int_eq(MESH_MEDIA_PLAYLIST_OK,
               mesh_media_playlist_media_v1(&manifest, &index, 3000u, playlist,
                                            sizeof(playlist), &playlist_len));
  check_true(playlist_len > 0u);
  check_str_eq(playlist, "#EXTM3U\n"
                         "#EXT-X-VERSION:3\n"
                         "#EXT-X-TARGETDURATION:3\n"
                         "#EXT-X-MEDIA-SEQUENCE:0\n"
                         "#EXTINF:3.000,\n"
                         "#EXT-X-BYTERANGE:3072@0\n"
                         "seg-0\n"
                         "#EXTINF:3.000,\n"
                         "#EXT-X-BYTERANGE:3072@3072\n"
                         "seg-1\n"
                         "#EXTINF:3.000,\n"
                         "#EXT-X-BYTERANGE:2048@6144\n"
                         "seg-2\n");

  /* Round-trip: the byteranges match the index segments exactly. */
  count = parse_media_playlist(playlist, offsets, lens);
  check_size_eq(count, index.segment_count);
  for (size_t s = 0u; s < count; s++) {
    check_uint_eq(offsets[s], index.segments[s].byte_offset);
    check_uint_eq(lens[s], index.segments[s].byte_len);
  }

  check_int_eq(MESH_MEDIA_PLAYLIST_OK,
               mesh_media_playlist_segment_uri_v1(0u, uri, sizeof(uri)));
  check_str_eq(uri, "seg-0");
  check_int_eq(MESH_MEDIA_PLAYLIST_OK,
               mesh_media_playlist_segment_uri_v1(2u, uri, sizeof(uri)));
  check_str_eq(uri, "seg-2");

  mesh_media_index_destroy_v1(&index);
}

static void test_master_playlist(void) {
  mesh_media_abr_rendition_v1_t ladder[4];
  char playlist[1024];
  size_t playlist_len = 0u;
  size_t picked = SIZE_MAX;

  memset(ladder, 0, sizeof(ladder));
  snprintf(ladder[0].id, sizeof(ladder[0].id), "p240");
  ladder[0].bandwidth_bps = 300000u;
  snprintf(ladder[1].id, sizeof(ladder[1].id), "p480");
  ladder[1].bandwidth_bps = 1000000u;
  snprintf(ladder[2].id, sizeof(ladder[2].id), "p720");
  ladder[2].bandwidth_bps = 2500000u;
  snprintf(ladder[3].id, sizeof(ladder[3].id), "p1080");
  ladder[3].bandwidth_bps = 5000000u;

  check_int_eq(MESH_MEDIA_PLAYLIST_OK,
               mesh_media_playlist_master_v1(ladder, 4u, playlist,
                                             sizeof(playlist), &playlist_len));
  check_true(strstr(playlist, "#EXTM3U\n") != NULL);
  check_true(strstr(playlist, "#EXT-X-STREAM-INF:BANDWIDTH=300000\nrend-p240.m3u8\n") != NULL);
  check_true(strstr(playlist, "#EXT-X-STREAM-INF:BANDWIDTH=5000000\nrend-p1080.m3u8\n") != NULL);

  /* ABR picks a rendition that the master playlist lists. */
  check_int_eq(MESH_MEDIA_INDEX_OK,
               mesh_media_abr_select_v1(ladder, 4u, 3000000u, &picked));
  check_size_eq(picked, 2u);
  {
    char expected[64];

    snprintf(expected, sizeof(expected), "rend-%s.m3u8\n", ladder[picked].id);
    check_true(strstr(playlist, expected) != NULL);
  }

  /* An empty rendition id is rejected. */
  {
    mesh_media_abr_rendition_v1_t bad[1] = {{0}};

    check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
                 mesh_media_playlist_master_v1(bad, 1u, playlist,
                                               sizeof(playlist), &playlist_len));
  }
}

static void test_invalid_args(void) {
  m3_object_manifest_v2_t manifest;
  m3_chunk_cid_v1_t chunks[TEST_BLOCKS];
  mesh_media_index_v1_t index;
  mesh_media_abr_rendition_v1_t ladder[1] = {{0}};
  char out[512];
  size_t out_len = 0u;

  fill_data();
  build_manifest(&manifest, chunks);
  build_index(&index, &manifest);
  snprintf(ladder[0].id, sizeof(ladder[0].id), "p1");
  ladder[0].bandwidth_bps = 1000000u;

  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_media_v1(NULL, &index, 3000u, out,
                                            sizeof(out), &out_len));
  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_media_v1(&manifest, NULL, 3000u, out,
                                            sizeof(out), &out_len));
  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_media_v1(&manifest, &index, 0u, out,
                                            sizeof(out), &out_len));
  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_media_v1(&manifest, &index, 3000u, NULL,
                                            sizeof(out), &out_len));
  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_media_v1(&manifest, &index, 3000u, out,
                                            sizeof(out), NULL));

  /* A too-small buffer fails fast. */
  check_int_eq(MESH_MEDIA_PLAYLIST_RESOURCE_EXHAUSTED,
               mesh_media_playlist_media_v1(&manifest, &index, 3000u, out, 16u,
                                            &out_len));
  check_int_eq(MESH_MEDIA_PLAYLIST_RESOURCE_EXHAUSTED,
               mesh_media_playlist_master_v1(ladder, 1u, out, 4u, &out_len));

  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_master_v1(NULL, 1u, out, sizeof(out), &out_len));
  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_master_v1(ladder, 0u, out, sizeof(out), &out_len));
  check_int_eq(MESH_MEDIA_PLAYLIST_INVALID_ARG,
               mesh_media_playlist_segment_uri_v1(0u, NULL, 8u));
  check_int_eq(MESH_MEDIA_PLAYLIST_RESOURCE_EXHAUSTED,
               mesh_media_playlist_segment_uri_v1(0u, out, 3u));

  mesh_media_index_destroy_v1(&index);
}

spec("mesh media playlist") {
    describe("HLS-style media + master playlists") {
        it("generates a media playlist with segment byteranges") {
            test_media_playlist();
        }
        it("generates a master playlist from the ABR ladder") {
            test_master_playlist();
        }
        it("rejects invalid arguments") {
            test_invalid_args();
        }
    }
}