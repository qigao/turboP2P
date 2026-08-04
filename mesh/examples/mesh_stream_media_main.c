/* mesh_stream_media_main.c - media pipeline executable.
 *
 * Runs one command per process over the media data plane:
 *   publish <file> [--block <bytes>] [--segment <bytes>] [--dur-ms <ms>]
 *     Chunk the file into an M3 V2 manifest (SHA-256 per chunk + object
 *     digest), print the canonical manifest hex, then generate the HLS-style
 *     media playlist (per-segment EXT-X-BYTERANGE) and a single-rendition
 *     master playlist.
 *   pull <file> <manifest-hex> <start> <len>
 *     Decode the manifest, build the media index, resolve the byte range and
 *     pull exactly the covering chunks from the file (verified against their
 *     CIDs), then print the assembled window as hex.
 *
 * Usage:
 *   mesh_stream_media_main publish <file> [--block 65536] [--segment 1048576] [--dur-ms 4000]
 *   mesh_stream_media_main pull <file> <manifest-hex> <start> <len>
 *   mesh_stream_media_main release pack <name> <version> <file> <key>...
 *     [--paths <name> <version> <file> <path> <key>...]
 *   mesh_stream_media_main release publish <name> <version> <file> <key>...
 *     [--paths ...] [--sign-key <ed25519-secret-hex>] --gateway <host:port>
 *   mesh_stream_media_main release pull <release-hex|name> <dir> --gateway <host:port>
 *     [--pubkey <ed25519-public-hex>]
 *   mesh_stream_media_main release mirror <name> --from <backbone:port> --to <local:port>
 */

#include "m3_gateway_sigv4.h"
#include "m3_object_manifest.h"
#include "mesh_mgmt_crypto.h"
#include "mesh_media_index.h"
#include "mesh_media_playlist.h"
#include "mesh_release.h"

#include <CoroNet.h>
#include <http/http_client.h>

#include <time.h>
#include "mesh_stream_media_pull.h"

#include <turbo_crypto.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#ifdef _WIN32
#define fseeko _fseeki64
#endif

#define DEFAULT_BLOCK_BYTES (64u * 1024u)
#define DEFAULT_SEGMENT_BYTES (1024u * 1024u)
#define DEFAULT_DURATION_MS 4000u

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int hex_to_bytes(const char *text, uint8_t *out, size_t out_size) {
  size_t length = strlen(text);

  if (length != out_size * 2u)
    return -1;
  for (size_t i = 0u; i < out_size; i++) {
    int hi = hex_value(text[i * 2u]);
    int lo = hex_value(text[i * 2u + 1u]);

    if (hi < 0 || lo < 0)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t size, char *output) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0u; i < size; i++) {
    output[i * 2u] = digits[bytes[i] >> 4u];
    output[i * 2u + 1u] = digits[bytes[i] & 0x0fu];
  }
  output[size * 2u] = '\0';
}

static const char *bytes_to_hex_short(const uint8_t *bytes) {
  static char buf[65];

  bytes_to_hex(bytes, 32u, buf);
  return buf;
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
  FILE *file = fopen(path, "rb");
  long size;

  if (!file)
    return -1;
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return -1;
  }
  size = ftell(file);
  if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return -1;
  }
  *out = (uint8_t *)malloc((size_t)size + 1u);
  if (!*out) {
    fclose(file);
    return -1;
  }
  if (size > 0 && fread(*out, 1u, (size_t)size, file) != (size_t)size) {
    free(*out);
    fclose(file);
    return -1;
  }
  fclose(file);
  (*out)[size] = '\0';
  *out_len = (size_t)size;
  return 0;
}

static int build_manifest(const uint8_t *data, size_t len, uint64_t block_size,
                          m3_chunk_cid_v1_t **out_chunks,
                          m3_object_manifest_v2_t *out_manifest) {
  size_t chunk_count = (len + (size_t)block_size - 1u) / (size_t)block_size;
  m3_chunk_cid_v1_t *chunks;
  turbo_crypto_sha256_ctx_t ctx;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];

  if (chunk_count == 0u)
    return -1;
  chunks = (m3_chunk_cid_v1_t *)calloc(chunk_count, sizeof(*chunks));
  if (!chunks)
    return -1;
  if (turbo_crypto_sha256_init(&ctx) != TURBO_CRYPTO_OK) {
    free(chunks);
    return -1;
  }
  for (size_t i = 0u; i < chunk_count; i++) {
    size_t offset = i * (size_t)block_size;
    size_t take = len - offset;

    if (take > (size_t)block_size)
      take = (size_t)block_size;
    if (turbo_crypto_sha256(data + offset, take, chunks[i].digest) !=
            TURBO_CRYPTO_OK ||
        turbo_crypto_sha256_update(&ctx, chunks[i].digest,
                                   sizeof(chunks[i].digest)) != TURBO_CRYPTO_OK) {
      free(chunks);
      return -1;
    }
    chunks[i].hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
    chunks[i].size = take;
  }
  if (turbo_crypto_sha256_final(&ctx, digest) != TURBO_CRYPTO_OK) {
    free(chunks);
    return -1;
  }
  memset(out_manifest, 0, sizeof(*out_manifest));
  out_manifest->version = M3_OBJECT_MANIFEST_VERSION_2;
  out_manifest->object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
  out_manifest->object_cid.size = len;
  memcpy(out_manifest->object_cid.digest, digest, sizeof(digest));
  out_manifest->chunks = chunks;
  out_manifest->chunk_count = chunk_count;
  *out_chunks = chunks;
  return 0;
}

static int cmd_publish(int argc, char **argv, int start) {
  const char *path = NULL;
  uint64_t block = DEFAULT_BLOCK_BYTES;
  uint64_t segment = DEFAULT_SEGMENT_BYTES;
  uint64_t duration_ms = DEFAULT_DURATION_MS;
  uint8_t *data = NULL;
  size_t data_len = 0u;
  m3_chunk_cid_v1_t *chunks = NULL;
  m3_object_manifest_v2_t manifest;
  uint8_t *manifest_bytes = NULL;
  size_t manifest_size = 0u;
  mesh_media_index_v1_t index;
  mesh_media_abr_rendition_v1_t ladder[1];
  char playlist[8192];
  char master[512];
  size_t playlist_len = 0u;
  size_t master_len = 0u;
  char *hex = NULL;

  if (start >= argc)
    return 1;
  path = argv[start];
  for (int i = start + 1; i < argc; i++) {
    if (strcmp(argv[i], "--block") == 0 && i + 1 < argc)
      block = strtoull(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--segment") == 0 && i + 1 < argc)
      segment = strtoull(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--dur-ms") == 0 && i + 1 < argc)
      duration_ms = strtoull(argv[++i], NULL, 10);
    else {
      fprintf(stderr, "unknown publish arg: %s\n", argv[i]);
      return 1;
    }
  }
  if (block == 0u || segment == 0u || duration_ms == 0u)
    return 1;
  if (read_file(path, &data, &data_len) != 0 || data_len == 0u) {
    fprintf(stderr, "cannot read file: %s\n", path);
    return 1;
  }
  if (build_manifest(data, data_len, block, &chunks, &manifest) != 0)
    return 1;
  if (m3_object_manifest_encode_v2(&manifest, UINT64_C(1) << 40, 1u << 20,
                                   1u << 20, &manifest_bytes,
                                   &manifest_size) != M3_OBJECT_MANIFEST_OK) {
    fprintf(stderr, "manifest encode failed\n");
    return 1;
  }
  hex = (char *)malloc(manifest_size * 2u + 1u);
  if (!hex)
    return 1;
  bytes_to_hex(manifest_bytes, manifest_size, hex);
  printf("PUBLISH OK file=%s size=%zu chunks=%zu\n", path, data_len,
         manifest.chunk_count);
  printf("MANIFEST %s\n", hex);

  memset(&index, 0, sizeof(index));
  if (mesh_media_index_build_v1(&index, &manifest, segment) !=
      MESH_MEDIA_INDEX_OK) {
    fprintf(stderr, "media index build failed\n");
    return 1;
  }
  if (mesh_media_playlist_media_v1(&manifest, &index, duration_ms, playlist,
                                   sizeof(playlist), &playlist_len) !=
      MESH_MEDIA_PLAYLIST_OK) {
    fprintf(stderr, "media playlist failed\n");
    return 1;
  }
  memset(&ladder[0], 0, sizeof(ladder[0]));
  snprintf(ladder[0].id, sizeof(ladder[0].id), "src");
  ladder[0].bandwidth_bps =
      (uint64_t)((double)data_len * 8.0 * 1000.0 / (double)duration_ms);
  ladder[0].object_size = data_len;
  if (mesh_media_playlist_master_v1(ladder, 1u, master, sizeof(master),
                                    &master_len) != MESH_MEDIA_PLAYLIST_OK) {
    fprintf(stderr, "master playlist failed\n");
    return 1;
  }
  printf("PLAYLIST BEGIN\n%sPLAYLIST END\n", playlist);
  printf("MASTER BEGIN\n%sMASTER END\n", master);
  printf("SEGMENTS %zu\n", index.segment_count);

  m3_object_manifest_bytes_free_v2(manifest_bytes);
  mesh_media_index_destroy_v1(&index);
  free(chunks);
  free(data);
  free(hex);
  return 0;
}

typedef struct {
  const char *path;
  uint64_t block_size;
} pull_source_t;

static int file_fetch_chunk(void *context, size_t chunk_index, uint8_t *out,
                            size_t cap, size_t *out_len) {
  pull_source_t *source = (pull_source_t *)context;
  FILE *file = fopen(source->path, "rb");
  long long offset = (long long)chunk_index * (long long)source->block_size;
  size_t got = 0u;

  *out_len = 0u;
  if (!file)
    return -1;
  if (fseeko(file, offset, SEEK_SET) != 0) {
    fclose(file);
    return -1;
  }
  got = fread(out, 1u, cap, file);
  fclose(file);
  *out_len = got;
  return got > 0u ? 0 : -1;
}

static int cmd_pull(int argc, char **argv, int start) {
  const char *path;
  const char *manifest_hex;
  unsigned long long byte_start = 0u;
  unsigned long long byte_len = 0u;
  uint8_t *data = NULL;
  size_t data_len = 0u;
  m3_object_manifest_owned_v2_t owned;
  mesh_media_index_v1_t index;
  mesh_stream_media_pull_v1_t pull;
  mesh_stream_media_pull_config_v1_t config;
  pull_source_t source;
  uint8_t *window = NULL;
  size_t window_len = 0u;
  char *window_hex = NULL;

  if (start + 3 >= argc)
    return 1;
  path = argv[start];
  manifest_hex = argv[start + 1];
  byte_start = strtoull(argv[start + 2], NULL, 10);
  byte_len = strtoull(argv[start + 3], NULL, 10);
  if (read_file(path, &data, &data_len) != 0 || data_len == 0u) {
    fprintf(stderr, "cannot read file: %s\n", path);
    return 1;
  }
  {
    size_t manifest_cap = strlen(manifest_hex) / 2u;
    uint8_t *manifest_bytes = (uint8_t *)malloc(manifest_cap);

    if (!manifest_bytes ||
        hex_to_bytes(manifest_hex, manifest_bytes, manifest_cap) != 0 ||
        m3_object_manifest_decode_v2(manifest_bytes, manifest_cap,
                                     UINT64_C(1) << 40, 1u << 20, 1u << 20,
                                     &owned) != M3_OBJECT_MANIFEST_OK) {
      fprintf(stderr, "manifest decode failed\n");
      return 1;
    }
    free(manifest_bytes);
  }
  memset(&index, 0, sizeof(index));
  if (mesh_media_index_build_v1(&index, &owned.manifest,
                                DEFAULT_SEGMENT_BYTES) != MESH_MEDIA_INDEX_OK) {
    fprintf(stderr, "media index build failed\n");
    return 1;
  }
  source.path = path;
  source.block_size = DEFAULT_BLOCK_BYTES;
  memset(&config, 0, sizeof(config));
  config.io.fetch_chunk = file_fetch_chunk;
  config.io.context = &source;
  config.max_chunk_bytes = DEFAULT_BLOCK_BYTES;
  config.target_segment_bytes = DEFAULT_SEGMENT_BYTES;
  memset(&pull, 0, sizeof(pull));
  if (mesh_stream_media_pull_init_v1(&pull, &owned.manifest, &config) !=
      MESH_STREAM_MEDIA_PULL_OK) {
    fprintf(stderr, "media pull init failed\n");
    return 1;
  }
  if (mesh_stream_media_pull_start_v1(&pull, byte_start, byte_len) !=
      MESH_STREAM_MEDIA_PULL_OK) {
    fprintf(stderr, "media pull start failed (range out of bounds?)\n");
    return 1;
  }
  window_len = (size_t)mesh_stream_media_pull_window_len(&pull);
  window = (uint8_t *)malloc(window_len + 1u);
  if (!window)
    return 1;
  while (!mesh_stream_media_pull_complete(&pull)) {
    size_t got = 0u;
    mesh_stream_media_pull_result_t rc =
        mesh_stream_media_pull_pump_v1(&pull, window, window_len, &got);

    if (rc == MESH_STREAM_MEDIA_PULL_AGAIN)
      continue;
    if (rc != MESH_STREAM_MEDIA_PULL_OK) {
      fprintf(stderr, "media pull failed\n");
      return 1;
    }
  }
  window_hex = (char *)malloc(window_len * 2u + 1u);
  if (!window_hex)
    return 1;
  bytes_to_hex(window, window_len, window_hex);
  printf("PULL OK start=%llu len=%llu window=%zu\n", byte_start, byte_len,
         window_len);
  printf("WINDOW %s\n", window_hex);

  mesh_stream_media_pull_destroy_v1(&pull);
  mesh_media_index_destroy_v1(&index);
  m3_object_manifest_owned_destroy_v2(&owned);
  free(window_hex);
  free(window);
  free(data);
  return 0;
}

static const char *base_name(const char *path) {
  const char *last = path;

  for (const char *p = path; *p != '\0'; p++) {
    if (*p == '/' || *p == '\\')
      last = p + 1;
  }
  return *last != '\0' ? last : path;
}

/* Create every missing directory component above a file path so release
 * pull can write into nested release paths. Returns 0 on success. */
static int ensure_parent_dirs(const char *path) {
  char buf[4096];
  size_t len = strlen(path);
  size_t i;

  if (len == 0u || len >= sizeof(buf))
    return -1;
  memcpy(buf, path, len + 1u);
  for (i = 1u; i < len; i++) {
    if (buf[i] == '/' || buf[i] == '\\') {
      buf[i] = '\0';
      if (buf[i - 1u] != ':') { /* skip drive roots like "C:" */
#ifdef _WIN32
        if (_mkdir(buf) != 0 && errno != EEXIST)
#else
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
#endif
          return -1;
      }
      buf[i] = '/';
    }
  }
  return 0;
}

/* Read one release file, build its M3 object manifest and fill the release
 * entry (path = release_path if given, else the file basename; object key,
 * size, digest). When out_m3_manifest is set, the encoded per-file M3
 * manifest is returned (caller releases with m3_object_manifest_bytes_free_v2).
 * Returns 0 on success. */
static int release_file_prepare(const char *file_path, const char *release_path,
                                const char *object_key,
                                mesh_release_entry_v1_t *entry,
                                uint8_t **out_m3_manifest,
                                size_t *out_m3_size) {
  uint8_t *data = NULL;
  size_t data_len = 0u;
  m3_chunk_cid_v1_t *chunks = NULL;
  m3_object_manifest_v2_t manifest;
  int rc = -1;

  if (!file_path || !object_key || !entry ||
      read_file(file_path, &data, &data_len) != 0 || data_len == 0u)
    return -1;
  if (build_manifest(data, data_len, DEFAULT_BLOCK_BYTES, &chunks, &manifest) != 0)
    goto out;
  memset(entry, 0, sizeof(*entry));
  snprintf(entry->path, sizeof(entry->path), "%s",
           release_path ? release_path : base_name(file_path));
  snprintf(entry->object_key, sizeof(entry->object_key), "%s", object_key);
  entry->size = data_len;
  memcpy(entry->object_cid, manifest.object_cid.digest,
         sizeof(entry->object_cid));
  if (out_m3_manifest && out_m3_size) {
    *out_m3_manifest = NULL;
    *out_m3_size = 0u;
    if (m3_object_manifest_encode_v2(&manifest, UINT64_C(1) << 40, 1u << 20,
                                     1u << 20, out_m3_manifest,
                                     out_m3_size) != M3_OBJECT_MANIFEST_OK)
      goto out;
  }
  rc = 0;

out:
  free(chunks);
  free(data);
  return rc;
}

/* Publisher anchoring (P32): the release manifest digest is signed with
 * the publisher's Ed25519 key and stored as a sidecar object rel/<name>.sig
 * so a consumer can verify the manifest was not tampered with even by a
 * compromised gateway. Blob layout: magic(4) | version(1) | reserved(3) |
 * digest(32) | signature(64). */
#define RELEASE_SIG_MAGIC "M3RS"
#define RELEASE_SIG_VERSION 1u
#define RELEASE_SIG_HEADER 8u
#define RELEASE_SIG_BLOB_SIZE (RELEASE_SIG_HEADER + 32u + 64u)

/* Build the canonical release signature blob over the manifest digest. */
static int release_sign_blob(const uint8_t private_key[32],
                             const uint8_t digest[32],
                             uint8_t blob[RELEASE_SIG_BLOB_SIZE]) {
  memcpy(blob, RELEASE_SIG_MAGIC, 4);
  blob[4] = RELEASE_SIG_VERSION;
  memset(blob + 5, 0, 3);
  memcpy(blob + RELEASE_SIG_HEADER, digest, 32);
  if (mesh_mgmt_ed25519_sign(private_key, digest, 32,
                              blob + RELEASE_SIG_HEADER + 32) !=
      MESH_MGMT_CRYPTO_OK)
    return -1;
  return 0;
}

/* Verify a release signature blob against the manifest digest and the
 * publisher public key. Returns 0 on success, -1 otherwise. */
static int release_verify_blob(const uint8_t *blob, size_t blob_len,
                               const uint8_t public_key[32],
                               const uint8_t digest[32]) {
  if (!blob || blob_len != RELEASE_SIG_BLOB_SIZE || !public_key || !digest)
    return -1;
  if (memcmp(blob, RELEASE_SIG_MAGIC, 4) != 0 ||
      blob[4] != RELEASE_SIG_VERSION)
    return -1;
  if (memcmp(blob + RELEASE_SIG_HEADER, digest, 32) != 0)
    return -1;
  return mesh_mgmt_ed25519_verify(public_key, digest, 32,
                                  blob + RELEASE_SIG_HEADER + 32) ==
                 MESH_MGMT_CRYPTO_OK
             ? 0
             : -1;
}

/* Verify downloaded bytes match the release entry's object digest (the
 * same SHA-256-over-chunk-digests computation used at pack time). Returns
 * 0 when the bytes are exactly the packed file. */
static int release_verify_object(const uint8_t *data, size_t len,
                                 const mesh_release_entry_v1_t *entry) {
  m3_chunk_cid_v1_t *chunks = NULL;
  m3_object_manifest_v2_t manifest;
  int rc = -1;

  if (!data || !entry || len != (size_t)entry->size)
    return -1;
  if (build_manifest(data, len, DEFAULT_BLOCK_BYTES, &chunks, &manifest) != 0)
    return -1;
  if (memcmp(manifest.object_cid.digest, entry->object_cid,
             sizeof(entry->object_cid)) == 0)
    rc = 0;
  free(chunks);
  return rc;
}

static void sha256_hex(const uint8_t *data, size_t len, char out[65]) {
  uint8_t digest[32];

  turbo_crypto_sha256(data, len, digest);
  bytes_to_hex(digest, sizeof(digest), out);
}

/* release pack <name> <version> <file> <object-key> [<file> <object-key>...]
 * release pack --paths <name> <version> <file> <release-path> <object-key>...
 * Builds a multi-file software release: each file becomes an M3 object
 * (chunked manifest) referenced by release path + gateway object key +
 * digest. --paths assigns an explicit in-release path (may contain '/'). */
static int cmd_release_pack(int argc, char **argv, int start) {
  const char *name = NULL;
  unsigned long long version = 0u;
  mesh_release_v1_t release;
  char hex[MESH_RELEASE_MAX_ENTRIES * 512u + 4096u];
  uint8_t *release_bytes = NULL;
  size_t release_len = 0u;

  int paths_mode = 0;
  int data_start;

  if (start + 2 >= argc)
    return 1;
  if (strcmp(argv[start], "--paths") == 0) {
    paths_mode = 1;
    start++;
  }
  name = argv[start];
  version = strtoull(argv[start + 1], NULL, 10);
  if (mesh_release_init_v1(&release, name, version) != MESH_RELEASE_OK) {
    fprintf(stderr, "invalid release name\n");
    return 1;
  }
  data_start = start + 2;
  if ((paths_mode && (argc - data_start) % 3 != 0) ||
      (!paths_mode && (argc - data_start) % 2 != 0)) {
    fprintf(stderr, "release pack: malformed file list (pairs, or "
                    "--paths triples <file> <path> <object-key>)\n");
    return 1;
  }
  for (int i = data_start; i < argc;) {
    const char *file_path;
    const char *release_path = NULL;
    const char *object_key;
    uint8_t *manifest_bytes = NULL;
    size_t manifest_size = 0u;
    mesh_release_entry_v1_t entry;
    char *manifest_hex = NULL;

    if (paths_mode) {
      file_path = argv[i];
      release_path = argv[i + 1];
      object_key = argv[i + 2];
      i += 3;
    } else {
      file_path = argv[i];
      object_key = argv[i + 1];
      i += 2;
    }
    if (release_file_prepare(file_path, release_path, object_key, &entry,
                             &manifest_bytes, &manifest_size) != 0) {
      fprintf(stderr, "cannot prepare file: %s\n", file_path);
      return 1;
    }
    {
      mesh_release_result_t rc = mesh_release_add_v1(&release, &entry);

      if (rc != MESH_RELEASE_OK) {
        fprintf(stderr, "release add failed (%d)\n", (int)rc);
        m3_object_manifest_bytes_free_v2(manifest_bytes);
        return 1;
      }
    }
    manifest_hex = (char *)malloc(manifest_size * 2u + 1u);
    if (!manifest_hex) {
      m3_object_manifest_bytes_free_v2(manifest_bytes);
      return 1;
    }
    bytes_to_hex(manifest_bytes, manifest_size, manifest_hex);
    printf("FILE %s key=%s size=%zu cid=%s\n", entry.path, entry.object_key,
           entry.size, bytes_to_hex_short(entry.object_cid));
    printf("FILE MANIFEST %s\n", manifest_hex);
    m3_object_manifest_bytes_free_v2(manifest_bytes);
    free(manifest_hex);
  }
  release_bytes = (uint8_t *)malloc(sizeof(hex));
  if (!release_bytes)
    return 1;
  if (mesh_release_encode_v1(&release, release_bytes, sizeof(hex) - 1u,
                             &release_len) != MESH_RELEASE_OK) {
    fprintf(stderr, "release encode failed\n");
    return 1;
  }
  bytes_to_hex(release_bytes, release_len, hex);
  printf("RELEASE %s version=%llu files=%zu\n", release.name,
         (unsigned long long)release.version, release.count);
  printf("RELEASE MANIFEST %s\n", hex);
  {
    uint8_t digest[32];
    char digest_hex[65];

    if (mesh_release_digest_v1(&release, digest) == MESH_RELEASE_OK) {
      bytes_to_hex(digest, sizeof(digest), digest_hex);
      printf("RELEASE DIGEST %s\n", digest_hex);
    }
  }
  free(release_bytes);
  return 0;
}

#define S3_EMPTY_PAYLOAD_HASH "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define S3_DEMO_ACCESS_KEY "AKIDEXAMPLE"
#define S3_DEMO_REGION "us-east-1"
#define S3_DEMO_SERVICE "s3"

static const uint8_t S3_DEMO_SECRET[32] = {
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34};

static void amzdate_now(char out[32]) {
  time_t now = time(NULL);
  struct tm tmv;

#ifdef _WIN32
  gmtime_s(&tmv, &now);
#else
  gmtime_r(&now, &tmv);
#endif
  strftime(out, 32, "%Y%m%dT%H%M%SZ", &tmv);
}

typedef struct {
  http_client_t *client;
  const char *host;                /* host:port used in signed headers */
  const char *const *source_paths; /* argv source paths, parallel to entries */
  uint8_t *release_bytes;          /* canonical release manifest bytes */
  size_t release_len;
  char manifest_key[MESH_RELEASE_KEY_MAX]; /* rel/<name> */
  uint8_t *sig_blob; /* publisher signature sidecar (rel/<name>.sig) */
  size_t sig_len;
  char sig_uri[MESH_RELEASE_KEY_MAX + 8u];
  mesh_release_v1_t release;
  int ok;
  int done;
  size_t uploaded;
  coro_context_t *ctx;
} release_publish_state_t;

/* One signed PUT through a gateway; returns 0 on HTTP 200. */
static int signed_put(http_client_t *client, const char *host,
                      const char *uri, const uint8_t *body,
                      size_t body_len) {
  char payload_hex[65];
  char amzdate[32];
  char auth[512];
  const char *headers[3];
  char header_buf[3][256];
  http_response_t *response;

  sha256_hex(body, body_len, payload_hex);
  amzdate_now(amzdate);
  if (m3_sigv4_sign_request_v1(
          "PUT", uri, NULL, payload_hex, S3_DEMO_SECRET, S3_DEMO_ACCESS_KEY,
          S3_DEMO_REGION, S3_DEMO_SERVICE, host, amzdate, auth,
          sizeof(auth)) != M3_SIGV4_OK)
    return -1;
  snprintf(header_buf[0], sizeof(header_buf[0]), "Authorization: %s", auth);
  snprintf(header_buf[1], sizeof(header_buf[1]), "x-amz-content-sha256: %s",
           payload_hex);
  snprintf(header_buf[2], sizeof(header_buf[2]), "x-amz-date: %s", amzdate);
  headers[0] = header_buf[0];
  headers[1] = header_buf[1];
  headers[2] = header_buf[2];
  response = http_request(client, HTTP_PUT, uri, headers, 3,
                          (const char *)body, body_len);
  if (!response || response->status_code != 200) {
    if (response)
      http_response_free(response);
    return -1;
  }
  http_response_free(response);
  return 0;
}

static void release_publish_coroutine(coro_t *co, void *arg) {
  release_publish_state_t *state = (release_publish_state_t *)arg;

  (void)co;
  for (size_t i = 0u; i < state->release.count; i++) {
    const mesh_release_entry_v1_t *entry = &state->release.entries[i];
    uint8_t *data = NULL;
    size_t data_len = 0u;
    char uri[MESH_RELEASE_KEY_MAX + 2u];

    snprintf(uri, sizeof(uri), "/%s", entry->object_key);
    if (read_file(state->source_paths[i], &data, &data_len) != 0) {
      state->ok = 0;
      break;
    }
    if (signed_put(state->client, state->host, uri, data, data_len) != 0) {
      free(data);
      state->ok = 0;
      break;
    }
    free(data);
    state->uploaded++;
    printf("PUT %s size=%zu OK\n", entry->object_key,
           (size_t)entry->size);
  }
  if (state->ok) {
    char manifest_uri[MESH_RELEASE_KEY_MAX + 2u];

    snprintf(manifest_uri, sizeof(manifest_uri), "/%s",
             state->manifest_key);
    if (signed_put(state->client, state->host, manifest_uri,
                   state->release_bytes, state->release_len) != 0) {
      state->ok = 0;
    } else {
      printf("PUT %s size=%zu OK\n", state->manifest_key,
             state->release_len);
    }
  }
  if (state->ok && state->sig_blob && state->sig_len > 0u) {
    char sig_uri[MESH_RELEASE_KEY_MAX + 8u];

    snprintf(sig_uri, sizeof(sig_uri), "/%s", state->sig_uri);
    if (signed_put(state->client, state->host, sig_uri, state->sig_blob,
                   state->sig_len) != 0) {
      state->ok = 0;
    } else {
      printf("PUT %s size=%zu OK\n", state->sig_uri, state->sig_len);
    }
  }
  state->done = 1;
  coro_context_stop(state->ctx);
}

/* release publish <name> <version> <file> <object-key> [<file> <object-key>...]
 * release publish --paths <name> <version> <file> <release-path> <object-key>...
 * --gateway <host:port> — pack the release and upload every file plus the
 * release manifest to a backbone gateway with signed PUTs. --paths assigns
 * explicit in-release paths (may contain '/'). Prints the release manifest
 * hex (for consumers) and a publish summary. */
static int cmd_release_publish(int argc, char **argv, int start) {
  const char *name = NULL;
  const char *gateway = NULL;
  unsigned long long version = 0u;
  int paths_mode = 0;
  int data_start;
  int data_end;
  size_t file_count = 0u;
  const char *source_paths[MESH_RELEASE_MAX_ENTRIES];
  mesh_release_v1_t release;
  uint8_t *release_bytes = NULL;
  size_t release_len = 0u;
  const char *sign_key_hex = NULL;
  release_publish_state_t state;
  coro_context_t *ctx = NULL;
  char base_url[128];
  char hex[MESH_RELEASE_MAX_ENTRIES * 512u + 4096u];
  uint8_t sig_blob[RELEASE_SIG_BLOB_SIZE];
  char sig_pubkey_hex[65];
  char sig_blob_hex[2u * RELEASE_SIG_BLOB_SIZE + 1u];
  int drain = 500;

  if (start + 2 >= argc)
    return 1;
  if (strcmp(argv[start], "--paths") == 0) {
    paths_mode = 1;
    start++;
  }
  name = argv[start];
  version = strtoull(argv[start + 1], NULL, 10);
  data_start = start + 2;
  data_end = argc;
  for (int i = data_start; i < argc; i++) {
    if (strcmp(argv[i], "--gateway") == 0) {
      if (i + 1 >= argc || i + 2 != argc) {
        fprintf(stderr, "--gateway must be the final argument\n");
        return 1;
      }
      gateway = argv[i + 1];
      data_end = i;
      break;
    }
  }
  if (data_end - 2 >= data_start &&
      strcmp(argv[data_end - 2], "--sign-key") == 0) {
    sign_key_hex = argv[data_end - 1];
    data_end -= 2;
  }
  if (!gateway) {
    fprintf(stderr, "release publish needs --gateway <host:port>\n");
    return 1;
  }
  if ((paths_mode && (data_end - data_start) % 3 != 0) ||
      (!paths_mode && (data_end - data_start) % 2 != 0)) {
    fprintf(stderr, "release publish: malformed file list (pairs, or "
                    "--paths triples <file> <path> <object-key>)\n");
    return 1;
  }
  file_count = (size_t)(paths_mode ? (data_end - data_start) / 3
                                    : (data_end - data_start) / 2);
  if (file_count == 0u || file_count > MESH_RELEASE_MAX_ENTRIES) {
    fprintf(stderr, "release publish needs 1..%d files\n",
            (int)MESH_RELEASE_MAX_ENTRIES);
    return 1;
  }
  if (strchr(name, '/') != NULL) {
    fprintf(stderr, "release name must not contain '/\n");
    return 1;
  }
  if (mesh_release_init_v1(&release, name, version) != MESH_RELEASE_OK) {
    fprintf(stderr, "invalid release name\n");
    return 1;
  }
  for (size_t i = 0u; i < file_count; i++) {
    const char *file_path;
    const char *release_path = NULL;
    const char *object_key;
    int base = data_start + (int)(paths_mode ? i * 3u : i * 2u);
    mesh_release_entry_v1_t entry;

    if (paths_mode) {
      file_path = argv[base];
      release_path = argv[base + 1];
      object_key = argv[base + 2];
    } else {
      file_path = argv[base];
      object_key = argv[base + 1];
    }
    if (release_file_prepare(file_path, release_path, object_key, &entry,
                             NULL, NULL) != 0) {
      fprintf(stderr, "cannot prepare file: %s\n", file_path);
      return 1;
    }
    if (mesh_release_add_v1(&release, &entry) != MESH_RELEASE_OK) {
      fprintf(stderr, "release add failed\n");
      return 1;
    }
  }
  /* Entries are stored in canonical path order; map each entry to its
   * argv source path by object key so the upload loop sends the right
   * bytes to the right key. */
  for (size_t i = 0u; i < release.count; i++) {
    const char *match = NULL;

    for (size_t j = 0u; j < file_count; j++) {
      int base = data_start + (int)(paths_mode ? j * 3u : j * 2u);
      const char *key = paths_mode ? argv[base + 2] : argv[base + 1];

      if (strcmp(key, release.entries[i].object_key) == 0) {
        match = argv[base];
        break;
      }
    }
    if (!match) {
      fprintf(stderr, "release source not found for key %s\n",
              release.entries[i].object_key);
      return 1;
    }
    source_paths[i] = match;
  }
  release_bytes = (uint8_t *)malloc(sizeof(hex));
  if (!release_bytes)
    return 1;
  if (mesh_release_encode_v1(&release, release_bytes, sizeof(hex) - 1u,
                             &release_len) != MESH_RELEASE_OK) {
    fprintf(stderr, "release encode failed\n");
    free(release_bytes);
    return 1;
  }
  bytes_to_hex(release_bytes, release_len, hex);
  printf("RELEASE %s version=%llu files=%zu\n", release.name,
         (unsigned long long)release.version, release.count);
  printf("RELEASE MANIFEST %s\n", hex);
  {
    uint8_t digest[32];
    char digest_hex[65];

    if (mesh_release_digest_v1(&release, digest) != MESH_RELEASE_OK) {
      fprintf(stderr, "release digest failed\n");
      free(release_bytes);
      return 1;
    }
    bytes_to_hex(digest, sizeof(digest), digest_hex);
    printf("RELEASE DIGEST %s\n", digest_hex);
    if (sign_key_hex) {
      uint8_t private_key[32];
      uint8_t pubkey[32];

      if (strlen(sign_key_hex) != 64u ||
          hex_to_bytes(sign_key_hex, private_key, 32) != 0 ||
          mesh_mgmt_ed25519_public_from_private(private_key, pubkey) !=
              MESH_MGMT_CRYPTO_OK ||
          release_sign_blob(private_key, digest, sig_blob) != 0) {
        fprintf(stderr, "release signing failed (bad --sign-key?)\n");
        free(release_bytes);
        return 1;
      }
      bytes_to_hex(pubkey, sizeof(pubkey), sig_pubkey_hex);
      bytes_to_hex(sig_blob, sizeof(sig_blob), sig_blob_hex);
      printf("RELEASE PUBKEY %s\n", sig_pubkey_hex);
      printf("RELEASE SIG %s\n", sig_blob_hex);
    }
  }

  memset(&state, 0, sizeof(state));
  state.host = gateway;
  state.source_paths = source_paths;
  state.release_bytes = release_bytes;
  state.release_len = release_len;
  state.release = release;
  state.ok = 1;
  snprintf(state.manifest_key, sizeof(state.manifest_key), "rel/%s", name);
  if (sign_key_hex) {
    state.sig_blob = sig_blob;
    state.sig_len = sizeof(sig_blob);
    snprintf(state.sig_uri, sizeof(state.sig_uri), "rel/%s.sig", name);
  }
  snprintf(base_url, sizeof(base_url), "http://%s", gateway);
  ctx = coro_context_create(NULL);
  if (!ctx) {
    free(release_bytes);
    return 1;
  }
  state.ctx = ctx;
  state.client = http_client_create(base_url);
  if (!state.client) {
    coro_context_destroy(ctx);
    free(release_bytes);
    return 1;
  }
  http_client_set_timeout(state.client, 10000);
  if (coro_context_spawn(ctx, release_publish_coroutine, &state) != 0) {
    http_client_destroy(state.client);
    coro_context_destroy(ctx);
    free(release_bytes);
    return 1;
  }
  coro_context_run(ctx, TURBO_RUN_DEFAULT);
  while (drain-- > 0 && coro_context_alive(ctx))
    coro_context_run(ctx, TURBO_RUN_NOWAIT);
  coro_context_destroy(ctx);
  http_client_destroy(state.client);
  free(release_bytes);
  if (!state.ok || state.uploaded != release.count) {
    fprintf(stderr, "release publish failed (%zu/%zu files)\n",
            state.uploaded, release.count);
    return 1;
  }
  printf("RELEASE PUBLISH OK files=%zu manifest=%s\n", state.uploaded,
         state.manifest_key);
  return 0;
}

typedef struct {
  http_client_t *client;
  const char *host; /* host:port used in the signed headers */
  const char *dir;
  const char *name; /* non-NULL: fetch rel/<name> manifest from the gateway */
  const uint8_t *pubkey; /* non-NULL: verify publisher signature sidecar */
  mesh_release_v1_t release;
  int ok;
  int done;
  size_t downloaded;
  coro_context_t *ctx;
} release_pull_state_t;

/* One signed GET through a gateway; returns 0 and owns *out_response on
 * HTTP 200. The request goes to request_uri while the signature covers
 * sign_uri: the gateway canonicalizes to bucket/object and ignores query
 * parameters, so derived views (?listing=1) are signed over the object. */
static int signed_get_path(http_client_t *client, const char *host,
                           const char *sign_uri, const char *request_uri,
                           http_response_t **out_response) {
  char amzdate[32];
  char auth[512];
  const char *headers[3];
  char header_buf[3][256];
  http_response_t *response;

  amzdate_now(amzdate);
  if (m3_sigv4_sign_request_v1(
          "GET", sign_uri, NULL, S3_EMPTY_PAYLOAD_HASH, S3_DEMO_SECRET,
          S3_DEMO_ACCESS_KEY, S3_DEMO_REGION, S3_DEMO_SERVICE, host,
          amzdate, auth, sizeof(auth)) != M3_SIGV4_OK)
    return -1;
  snprintf(header_buf[0], sizeof(header_buf[0]), "Authorization: %s", auth);
  snprintf(header_buf[1], sizeof(header_buf[1]), "x-amz-content-sha256: %s",
           S3_EMPTY_PAYLOAD_HASH);
  snprintf(header_buf[2], sizeof(header_buf[2]), "x-amz-date: %s", amzdate);
  headers[0] = header_buf[0];
  headers[1] = header_buf[1];
  headers[2] = header_buf[2];
  response = http_request(client, HTTP_GET, request_uri, headers, 3, NULL, 0);
  if (!response || response->status_code != 200) {
    if (response)
      http_response_free(response);
    return -1;
  }
  *out_response = response;
  return 0;
}

static int signed_get(http_client_t *client, const char *host,
                      const char *uri, http_response_t **out_response) {
  return signed_get_path(client, host, uri, uri, out_response);
}

/* Parse digest=<64-hex> from a release listing body (the first line of
 * mesh_release_format_v1 output). Returns 0 and fills out on success. */
static int release_parse_digest(const char *listing, uint8_t out[32]) {
  const char *p;
  char hex[65];
  size_t i;

  if (!listing)
    return -1;
  p = strstr(listing, "digest=");
  if (!p)
    return -1;
  p += 7u;
  for (i = 0u; i < 64u && p[i] != '\0' && hex_value(p[i]) >= 0; i++)
    hex[i] = p[i];
  if (i != 64u)
    return -1;
  hex[64] = '\0';
  return hex_to_bytes(hex, out, 32);
}

static void release_pull_coroutine(coro_t *co, void *arg) {
  release_pull_state_t *state = (release_pull_state_t *)arg;

  (void)co;
  if (state->name) {
    /* Release-name pull: fetch the canonical manifest from the gateway
     * (GET /rel/<name>), decode it, then download every file. */
    char manifest_uri[MESH_RELEASE_KEY_MAX + 2u];
    http_response_t *response = NULL;

    snprintf(manifest_uri, sizeof(manifest_uri), "/rel/%s", state->name);
    if (signed_get(state->client, state->host, manifest_uri, &response) != 0) {
      state->ok = 0;
      state->done = 1;
      coro_context_stop(state->ctx);
      return;
    }
    memset(&state->release, 0, sizeof(state->release));
    if (mesh_release_decode_v1((const uint8_t *)response->body,
                               response->body_len,
                               &state->release) != MESH_RELEASE_OK) {
      http_response_free(response);
      state->ok = 0;
      state->done = 1;
      coro_context_stop(state->ctx);
      return;
    }
    http_response_free(response);
    /* Cross-check the manifest-level digest against the gateway's
     * ?listing view (the listing carries digest=<hex> for the same
     * canonical manifest). */
    {
      char listing_uri[MESH_RELEASE_KEY_MAX + 32u];
      char sign_uri[MESH_RELEASE_KEY_MAX + 2u];
      http_response_t *listing = NULL;
      uint8_t expected[32];
      uint8_t actual[32];

      snprintf(listing_uri, sizeof(listing_uri), "/rel/%s?listing=1",
               state->name);
      snprintf(sign_uri, sizeof(sign_uri), "/rel/%s", state->name);
      if (signed_get_path(state->client, state->host, sign_uri,
                          listing_uri, &listing) != 0 ||
          release_parse_digest(listing->body, expected) != 0) {
        if (listing)
          http_response_free(listing);
        state->ok = 0;
        state->done = 1;
        coro_context_stop(state->ctx);
        return;
      }
      http_response_free(listing);
      if (mesh_release_digest_v1(&state->release, actual) !=
              MESH_RELEASE_OK ||
          memcmp(expected, actual, sizeof(actual)) != 0) {
        fprintf(stderr, "release listing digest mismatch\n");
        state->ok = 0;
        state->done = 1;
        coro_context_stop(state->ctx);
        return;
      }
    }
    if (state->pubkey) {
      char sig_uri[MESH_RELEASE_KEY_MAX + 8u];
      http_response_t *sig = NULL;
      uint8_t digest[32];

      snprintf(sig_uri, sizeof(sig_uri), "/rel/%s.sig", state->name);
      if (mesh_release_digest_v1(&state->release, digest) !=
              MESH_RELEASE_OK ||
          signed_get(state->client, state->host, sig_uri, &sig) != 0 ||
          release_verify_blob((const uint8_t *)sig->body, sig->body_len,
                              state->pubkey, digest) != 0) {
        if (sig)
          http_response_free(sig);
        fprintf(stderr, "release signature verification failed\n");
        state->ok = 0;
        state->done = 1;
        coro_context_stop(state->ctx);
        return;
      }
      http_response_free(sig);
      printf("RELEASE SIG OK\n");
    }
    printf("RELEASE %s version=%llu files=%zu\n", state->release.name,
           (unsigned long long)state->release.version,
           state->release.count);
  }
  for (size_t i = 0u; i < state->release.count; i++) {
    const mesh_release_entry_v1_t *entry = &state->release.entries[i];
    char uri[MESH_RELEASE_KEY_MAX + 2u];
    http_response_t *response = NULL;

    snprintf(uri, sizeof(uri), "/%s", entry->object_key);
    if (signed_get(state->client, state->host, uri, &response) != 0 ||
        response->body_len != (size_t)entry->size) {
      state->ok = 0;
      if (response)
        http_response_free(response);
      break;
    }
    if (release_verify_object((const uint8_t *)response->body,
                              response->body_len, entry) != 0) {
      fprintf(stderr, "PULL %s integrity mismatch (object digest)\n",
              entry->object_key);
      http_response_free(response);
      state->ok = 0;
      break;
    }
    {
      char out_path[MESH_RELEASE_PATH_MAX + 256u];

      snprintf(out_path, sizeof(out_path), "%s/%s", state->dir, entry->path);
      if (ensure_parent_dirs(out_path) != 0) {
        http_response_free(response);
        state->ok = 0;
        break;
      }
      FILE *file = fopen(out_path, "wb");

      if (!file || fwrite(response->body, 1u, response->body_len, file) !=
                       response->body_len) {
        if (file)
          fclose(file);
        http_response_free(response);
        state->ok = 0;
        break;
      }
      fclose(file);
    }
    http_response_free(response);
    state->downloaded++;
    printf("PULL %s -> %s/%s (%llu bytes)\n", entry->object_key, state->dir,
           entry->path, (unsigned long long)entry->size);
  }
  state->done = 1;
  coro_context_stop(state->ctx);
}

/* Returns 1 when the argument is a canonical release manifest hex that
 * decodes successfully (backward-compatible pull-by-hex). */
static int is_hex_release(const char *arg, mesh_release_v1_t *out) {
  size_t cap = strlen(arg) / 2u;
  uint8_t *bytes;
  int ok = 0;

  if (cap == 0u || strlen(arg) != cap * 2u)
    return 0;
  bytes = (uint8_t *)malloc(cap);
  if (!bytes)
    return 0;
  if (hex_to_bytes(arg, bytes, cap) == 0 &&
      mesh_release_decode_v1(bytes, cap, out) == MESH_RELEASE_OK)
    ok = 1;
  free(bytes);
  return ok;
}

/* release pull <release-hex|name> <dir> --gateway <host:port>
 * The first argument is either a canonical release manifest hex (decoded
 * locally) or a release name (the manifest is fetched from the gateway
 * as rel/<name> first). Either way every file is downloaded with signed
 * GETs and written byte-identical under <dir>. */
static int cmd_release_pull(int argc, char **argv, int start) {
  const char *release_arg;
  const char *dir;
  const char *gateway = NULL;
  const char *pubkey_hex = NULL;
  uint8_t pubkey[32];
  mesh_release_v1_t release;
  release_pull_state_t state;
  coro_context_t *ctx;
  char base_url[128];
  int drain = 500;

  if (start + 2 >= argc)
    return 1;
  release_arg = argv[start];
  dir = argv[start + 1];
  for (int i = start + 2; i < argc; i++) {
    if (strcmp(argv[i], "--gateway") == 0 && i + 1 < argc)
      gateway = argv[++i];
    else if (strcmp(argv[i], "--pubkey") == 0 && i + 1 < argc)
      pubkey_hex = argv[++i];
    else {
      fprintf(stderr, "unknown pull arg: %s\n", argv[i]);
      return 1;
    }
  }
  if (!gateway)
    return 1;
  if (pubkey_hex) {
    if (strlen(pubkey_hex) != 64u ||
        hex_to_bytes(pubkey_hex, pubkey, 32) != 0) {
      fprintf(stderr, "invalid --pubkey (need 64 hex chars)\n");
      return 1;
    }
  }
  memset(&state, 0, sizeof(state));
  state.host = gateway;
  state.dir = dir;
  state.ok = 1;
  if (pubkey_hex)
    state.pubkey = pubkey;
  if (is_hex_release(release_arg, &release)) {
    state.release = release;
  } else {
    if (strchr(release_arg, '/') != NULL) {
      fprintf(stderr, "release name must not contain '/\n");
      return 1;
    }
    state.name = release_arg;
  }
  snprintf(base_url, sizeof(base_url), "http://%s", gateway);
  ctx = coro_context_create(NULL);
  if (!ctx)
    return 1;
  state.ctx = ctx;
  state.client = http_client_create(base_url);
  if (!state.client) {
    coro_context_destroy(ctx);
    return 1;
  }
  http_client_set_timeout(state.client, 10000);
  if (coro_context_spawn(ctx, release_pull_coroutine, &state) != 0) {
    http_client_destroy(state.client);
    coro_context_destroy(ctx);
    return 1;
  }
  coro_context_run(ctx, TURBO_RUN_DEFAULT);
  while (drain-- > 0 && coro_context_alive(ctx))
    coro_context_run(ctx, TURBO_RUN_NOWAIT);
  coro_context_destroy(ctx);
  http_client_destroy(state.client);
  if (!state.ok || state.downloaded != state.release.count) {
    fprintf(stderr, "release pull failed (%zu/%zu files)\n",
            state.downloaded, state.release.count);
    return 1;
  }
  printf("RELEASE PULL OK files=%zu\n", state.downloaded);
  return 0;
}

typedef struct {
  http_client_t *from_client; /* backbone gateway */
  http_client_t *to_client;   /* local edge gateway */
  const char *from_host;      /* backbone host:port for signed headers */
  const char *to_host;        /* local host:port for signed headers */
  const char *name;           /* release name */
  mesh_release_v1_t release;
  int ok;
  int done;
  size_t mirrored;
  coro_context_t *ctx;
} release_mirror_state_t;

static void release_mirror_coroutine(coro_t *co, void *arg) {
  release_mirror_state_t *state = (release_mirror_state_t *)arg;
  char manifest_uri[MESH_RELEASE_KEY_MAX + 2u];
  http_response_t *response = NULL;
  uint8_t *release_bytes = NULL;
  size_t release_len = 0u;

  (void)co;
  /* Fetch the release manifest from the backbone. */
  snprintf(manifest_uri, sizeof(manifest_uri), "/rel/%s", state->name);
  if (signed_get(state->from_client, state->from_host, manifest_uri,
                 &response) != 0) {
    state->ok = 0;
    state->done = 1;
    coro_context_stop(state->ctx);
    return;
  }
  memset(&state->release, 0, sizeof(state->release));
  if (mesh_release_decode_v1((const uint8_t *)response->body,
                             response->body_len,
                             &state->release) != MESH_RELEASE_OK) {
    http_response_free(response);
    state->ok = 0;
    state->done = 1;
    coro_context_stop(state->ctx);
    return;
  }
  release_bytes = (uint8_t *)malloc(response->body_len);
  if (!release_bytes) {
    http_response_free(response);
    state->ok = 0;
    state->done = 1;
    coro_context_stop(state->ctx);
    return;
  }
  memcpy(release_bytes, response->body, response->body_len);
  release_len = response->body_len;
  http_response_free(response);
  printf("RELEASE %s version=%llu files=%zu\n", state->release.name,
         (unsigned long long)state->release.version,
         state->release.count);

  /* Copy every object from the backbone to the local edge gateway. */
  for (size_t i = 0u; i < state->release.count; i++) {
    const mesh_release_entry_v1_t *entry = &state->release.entries[i];
    char uri[MESH_RELEASE_KEY_MAX + 2u];
    http_response_t *obj = NULL;

    snprintf(uri, sizeof(uri), "/%s", entry->object_key);
    if (signed_get(state->from_client, state->from_host, uri, &obj) != 0 ||
        obj->body_len != (size_t)entry->size) {
      state->ok = 0;
      if (obj)
        http_response_free(obj);
      break;
    }
    if (release_verify_object((const uint8_t *)obj->body, obj->body_len,
                              entry) != 0) {
      fprintf(stderr, "MIRROR %s integrity mismatch (object digest)\n",
              entry->object_key);
      http_response_free(obj);
      state->ok = 0;
      break;
    }
    if (signed_put(state->to_client, state->to_host, uri,
                   (const uint8_t *)obj->body, obj->body_len) != 0) {
      http_response_free(obj);
      state->ok = 0;
      break;
    }
    http_response_free(obj);
    state->mirrored++;
    printf("MIRROR %s size=%llu OK\n", entry->object_key,
           (unsigned long long)entry->size);
  }

  /* Copy the release manifest itself. */
  if (state->ok &&
      signed_put(state->to_client, state->to_host, manifest_uri,
                 release_bytes, release_len) != 0) {
    state->ok = 0;
  } else if (state->ok) {
    printf("MIRROR %s size=%zu OK\n", manifest_uri, release_len);
  }
  /* Best-effort copy of the publisher signature sidecar (rel/<name>.sig)
   * when the backbone has one; an unsigned release (404) is not an error. */
  if (state->ok) {
    char sig_uri[MESH_RELEASE_KEY_MAX + 8u];
    http_response_t *sig = NULL;

    snprintf(sig_uri, sizeof(sig_uri), "/rel/%s.sig", state->name);
    if (signed_get(state->from_client, state->from_host, sig_uri, &sig) ==
        0) {
      if (signed_put(state->to_client, state->to_host, sig_uri,
                     (const uint8_t *)sig->body, sig->body_len) != 0) {
        http_response_free(sig);
        state->ok = 0;
      } else {
        printf("MIRROR %s size=%zu OK\n", sig_uri, sig->body_len);
        http_response_free(sig);
      }
    } else if (sig) {
      http_response_free(sig);
    }
  }
  free(release_bytes);
  state->done = 1;
  coro_context_stop(state->ctx);
}

/* release mirror <name> --from <backbone:port> --to <local:port>
 * Copies a published release from a backbone gateway to a local edge
 * gateway (CDN-style edge cache): the manifest and every object are
 * fetched from --from with signed GETs and written to --to with signed
 * PUTs. */
static int cmd_release_mirror(int argc, char **argv, int start) {
  const char *name = NULL;
  const char *from = NULL;
  const char *to = NULL;
  release_mirror_state_t state;
  coro_context_t *ctx = NULL;
  char from_url[128];
  char to_url[128];
  int drain = 500;

  if (start >= argc)
    return 1;
  name = argv[start];
  for (int i = start + 1; i < argc; i++) {
    if (strcmp(argv[i], "--from") == 0 && i + 1 < argc)
      from = argv[++i];
    else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc)
      to = argv[++i];
    else {
      fprintf(stderr, "unknown mirror arg: %s\n", argv[i]);
      return 1;
    }
  }
  if (!from || !to || strchr(name, '/') != NULL) {
    fprintf(stderr,
            "release mirror <name> --from <host:port> --to <host:port>\n");
    return 1;
  }
  memset(&state, 0, sizeof(state));
  state.from_host = from;
  state.to_host = to;
  state.name = name;
  state.ok = 1;
  snprintf(from_url, sizeof(from_url), "http://%s", from);
  snprintf(to_url, sizeof(to_url), "http://%s", to);
  ctx = coro_context_create(NULL);
  if (!ctx)
    return 1;
  state.ctx = ctx;
  state.from_client = http_client_create(from_url);
  if (!state.from_client) {
    coro_context_destroy(ctx);
    return 1;
  }
  state.to_client = http_client_create(to_url);
  if (!state.to_client) {
    http_client_destroy(state.from_client);
    coro_context_destroy(ctx);
    return 1;
  }
  http_client_set_timeout(state.from_client, 10000);
  http_client_set_timeout(state.to_client, 10000);
  if (coro_context_spawn(ctx, release_mirror_coroutine, &state) != 0) {
    http_client_destroy(state.to_client);
    http_client_destroy(state.from_client);
    coro_context_destroy(ctx);
    return 1;
  }
  coro_context_run(ctx, TURBO_RUN_DEFAULT);
  while (drain-- > 0 && coro_context_alive(ctx))
    coro_context_run(ctx, TURBO_RUN_NOWAIT);
  coro_context_destroy(ctx);
  http_client_destroy(state.to_client);
  http_client_destroy(state.from_client);
  if (!state.ok || state.mirrored != state.release.count) {
    fprintf(stderr, "release mirror failed (%zu/%zu files)\n",
            state.mirrored, state.release.count);
    return 1;
  }
  printf("RELEASE MIRROR OK files=%zu name=%s\n", state.mirrored,
         state.name);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr,
            "usage: mesh_stream_media_main <publish|pull> ...\n");
    return 1;
  }
  if (strcmp(argv[1], "publish") == 0)
    return cmd_publish(argc, argv, 2);
  if (strcmp(argv[1], "pull") == 0)
    return cmd_pull(argc, argv, 2);
  if (strcmp(argv[1], "release") == 0) {
    if (argc >= 3 && strcmp(argv[2], "pack") == 0)
      return cmd_release_pack(argc, argv, 3);
    if (argc >= 3 && strcmp(argv[2], "publish") == 0)
      return cmd_release_publish(argc, argv, 3);
    if (argc >= 3 && strcmp(argv[2], "pull") == 0)
      return cmd_release_pull(argc, argv, 3);
    if (argc >= 3 && strcmp(argv[2], "mirror") == 0)
      return cmd_release_mirror(argc, argv, 3);
    fprintf(stderr, "release needs <pack|publish|pull|mirror>\n");
    return 1;
  }
  fprintf(stderr, "unknown command: %s\n", argv[1]);
  return 1;
}
