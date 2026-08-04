#include "mesh_sync_engine.h"

#include <turbo_crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATE_HEADER_SIZE 45u /* 8 magic + 32 version + 4 count + 1 committed */
#define STATE_PREV_HEADER 4u  /* prev_count u32 before the prev chunk list */
#define STATE_CHUNK_RECORD 40u /* size u64 + digest[32] */
#define STATE_FILE_MODE 0600

static const uint8_t STATE_MAGIC[8] = {
    'M', '3', 'S', 'Y', 'N', 'C', '1', 0,
};

struct mesh_sync_prev_chunk_s {
  uint64_t size;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
};

static void write_u32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)(value >> 24u);
  out[1] = (uint8_t)(value >> 16u);
  out[2] = (uint8_t)(value >> 8u);
  out[3] = (uint8_t)value;
}

static uint32_t read_u32(const uint8_t in[4]) {
  return ((uint32_t)in[0] << 24u) | ((uint32_t)in[1] << 16u) |
         ((uint32_t)in[2] << 8u) | (uint32_t)in[3];
}

static void write_u64(uint8_t out[8], uint64_t value) {
  for (size_t i = 0u; i < 8u; i++)
    out[i] = (uint8_t)(value >> (56u - i * 8u));
}

static uint64_t read_u64(const uint8_t in[8]) {
  uint64_t value = 0u;

  for (size_t i = 0u; i < 8u; i++)
    value = (value << 8u) | in[i];
  return value;
}

static size_t state_bitmap_bytes(size_t chunk_count) {
  return (chunk_count + 7u) / 8u;
}

static int write_all(turbo_file_t file, const uint8_t *bytes, size_t size) {
  size_t written = 0u;

  while (written < size) {
    int result = turbo_fs_write(file, (const char *)bytes + written, size - written);

    if (result <= 0)
      return -1;
    written += (size_t)result;
  }
  return 0;
}

static int write_state(mesh_sync_engine_v1_t *engine) {
  size_t bitmap_bytes = state_bitmap_bytes(engine->source.manifest.chunk_count);
  size_t size = STATE_HEADER_SIZE + bitmap_bytes + STATE_PREV_HEADER +
                engine->prev_count * STATE_CHUNK_RECORD;
  uint8_t *buffer;
  turbo_file_t file;
  int result = -1;

  buffer = (uint8_t *)calloc(1, size);
  if (!buffer)
    return -1;
  memcpy(buffer, STATE_MAGIC, sizeof(STATE_MAGIC));
  memcpy(buffer + 8u, engine->source.manifest.object_cid.digest,
         sizeof(engine->source.manifest.object_cid.digest));
  write_u32(buffer + 40u, (uint32_t)engine->source.manifest.chunk_count);
  buffer[44u] = engine->complete ? 1u : 0u;
  for (size_t i = 0u; i < engine->source.manifest.chunk_count; i++) {
    if (engine->present[i])
      buffer[45u + i / 8u] |= (uint8_t)(1u << (i % 8u));
  }
  {
    size_t cursor = STATE_HEADER_SIZE + bitmap_bytes;

    write_u32(buffer + cursor, (uint32_t)engine->prev_count);
    cursor += STATE_PREV_HEADER;
    for (size_t i = 0u; i < engine->prev_count; i++) {
      write_u64(buffer + cursor, engine->prev_chunks[i].size);
      memcpy(buffer + cursor + 8u, engine->prev_chunks[i].digest,
             M3_CHUNK_CID_DIGEST_SIZE);
      cursor += STATE_CHUNK_RECORD;
    }
  }
  file = turbo_fs_open(engine->config.state_path,
                       TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
                       STATE_FILE_MODE);
  if (file == TURBO_INVALID_FILE)
    goto cleanup;
  if (write_all(file, buffer, size) != 0)
    goto cleanup;
  result = 0;

cleanup:
  if (file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(file);
  free(buffer);
  return result;
}

/* Returns 0 resume (version matches), 1 version differs, -1 none/corrupt. */
static int load_state(mesh_sync_engine_v1_t *engine) {
  turbo_fs_buf_t file = {0};
  size_t bitmap_bytes;
  int result = -1;

  if (turbo_fs_read_file(engine->config.state_path, &file) != 0)
    return -1;
  if (file.len < STATE_HEADER_SIZE ||
      memcmp(file.base, STATE_MAGIC, sizeof(STATE_MAGIC)) != 0)
    goto cleanup;
  {
    uint32_t stored_count = read_u32((const uint8_t *)file.base + 40u);

    if (stored_count != engine->source.manifest.chunk_count)
      goto cleanup;
  }
  bitmap_bytes = state_bitmap_bytes(engine->source.manifest.chunk_count);
  if (file.len < STATE_HEADER_SIZE + bitmap_bytes + STATE_PREV_HEADER)
    goto cleanup;
  {
    size_t cursor = STATE_HEADER_SIZE + bitmap_bytes;
    uint32_t prev_count = read_u32((const uint8_t *)file.base + cursor);

    if (prev_count > engine->config.max_chunks ||
        file.len <
            STATE_HEADER_SIZE + bitmap_bytes + STATE_PREV_HEADER +
                (size_t)prev_count * STATE_CHUNK_RECORD) {
      goto cleanup;
    }
    engine->prev_count = prev_count;
    if (prev_count > 0u) {
      engine->prev_chunks = (mesh_sync_prev_chunk_v1_t *)malloc(
          prev_count * sizeof(*engine->prev_chunks));
      if (!engine->prev_chunks)
        goto cleanup;
      cursor += STATE_PREV_HEADER;
      for (uint32_t i = 0u; i < prev_count; i++) {
        engine->prev_chunks[i].size =
            read_u64((const uint8_t *)file.base + cursor);
        memcpy(engine->prev_chunks[i].digest, file.base + cursor + 8u,
               M3_CHUNK_CID_DIGEST_SIZE);
        cursor += STATE_CHUNK_RECORD;
      }
    }
  }
  if (memcmp(file.base + 8u, engine->source.manifest.object_cid.digest,
             sizeof(engine->source.manifest.object_cid.digest)) != 0) {
    result = 1;
    goto cleanup;
  }
  engine->present_count = 0u;
  for (size_t i = 0u; i < engine->source.manifest.chunk_count; i++) {
    if (file.base[45u + i / 8u] & (uint8_t)(1u << (i % 8u))) {
      engine->present[i] = 1u;
      engine->present_count++;
    }
  }
  if (file.base[44u] == 1u && engine->present_count == engine->source.manifest.chunk_count)
    engine->complete = 1u;
  result = 0;

cleanup:
  turbo_fs_buf_free(&file);
  return result;
}

static void bytes_to_hex(const uint8_t *bytes, size_t size, char *output) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0u; i < size; i++) {
    output[i * 2u] = digits[bytes[i] >> 4u];
    output[i * 2u + 1u] = digits[bytes[i] & 0x0fu];
  }
  output[size * 2u] = '\0';
}

/* Compute per-source-chunk local offsets: a source chunk whose digest exists
 * in the previous version can be copied from the old committed output. */
static void compute_local_offsets(mesh_sync_engine_v1_t *engine) {
  for (size_t i = 0u; i < engine->source.manifest.chunk_count; i++)
    engine->local_offsets[i] = SIZE_MAX;
  for (size_t p = 0u; p < engine->prev_count; p++) {
    uint64_t offset = 0u;

    for (size_t q = 0u; q < p; q++)
      offset += engine->prev_chunks[q].size;
    for (size_t i = 0u; i < engine->source.manifest.chunk_count; i++) {
      const m3_chunk_cid_v1_t *cid = &engine->source.manifest.chunks[i];

      if (cid->size == engine->prev_chunks[p].size &&
          memcmp(cid->digest, engine->prev_chunks[p].digest,
                 M3_CHUNK_CID_DIGEST_SIZE) == 0) {
        engine->local_offsets[i] = offset;
        break;
      }
    }
  }
}

mesh_sync_result_t mesh_sync_engine_init_v1(
    mesh_sync_engine_v1_t *engine, const mesh_sync_config_v1_t *config,
    const uint8_t *manifest_bytes, size_t manifest_size) {
  turbo_fs_stat_t stat;
  int state;
  int has_local_use = 0;

  if (!engine || engine->open || !config || !config->io.fetch_chunk ||
      config->state_path[0] == '\0' || config->output_path[0] == '\0' ||
      config->max_object_bytes == 0u || config->max_chunks == 0u ||
      config->max_chunk_bytes == 0u ||
      (config->conflict_policy != MESH_SYNC_CONFLICT_LAST_WRITER_WINS &&
       config->conflict_policy != MESH_SYNC_CONFLICT_KEEP_BOTH) ||
      !manifest_bytes || manifest_size == 0u) {
    return MESH_SYNC_INVALID_ARG;
  }
  memset(engine, 0, sizeof(*engine));
  engine->temp_file = TURBO_INVALID_FILE;
  engine->local_file = TURBO_INVALID_FILE;
  engine->config = *config;
  if (m3_object_manifest_decode_v2(
          manifest_bytes, manifest_size, config->max_object_bytes,
          config->max_chunks, config->max_chunks * 8u,
          &engine->source) != M3_OBJECT_MANIFEST_OK) {
    return MESH_SYNC_INVALID_ARG;
  }
  engine->scratch = (uint8_t *)malloc((size_t)config->max_chunk_bytes);
  engine->present =
      (uint8_t *)calloc(engine->source.manifest.chunk_count, 1u);
  engine->local_offsets = (uint64_t *)malloc(
      engine->source.manifest.chunk_count * sizeof(*engine->local_offsets));
  if (!engine->scratch || !engine->present || !engine->local_offsets) {
    mesh_sync_engine_destroy_v1(engine);
    return MESH_SYNC_RESOURCE_EXHAUSTED;
  }
  snprintf(engine->temp_path, sizeof(engine->temp_path), "%s.tmp",
           config->output_path);

  state = load_state(engine);
  if (state == 1) {
    /* A different committed version occupies the output: conflict policy. */
    if (turbo_fs_lstat(config->output_path, &stat) == 0 && stat.is_file &&
        !stat.is_symlink) {
      if (config->conflict_policy == MESH_SYNC_CONFLICT_KEEP_BOTH) {
        char hex[sizeof(engine->source.manifest.object_cid.digest) * 2u + 1u];

        bytes_to_hex(engine->source.manifest.object_cid.digest,
                     sizeof(engine->source.manifest.object_cid.digest), hex);
        snprintf(engine->conflict_path, sizeof(engine->conflict_path),
                 "%s.conflict-%.16s", config->output_path, hex);
        if (turbo_fs_rename(config->output_path, engine->conflict_path) != 0) {
          mesh_sync_engine_destroy_v1(engine);
          return MESH_SYNC_IO;
        }
        snprintf(engine->local_read_path, sizeof(engine->local_read_path),
                 "%s", engine->conflict_path);
      } else {
        /* LWW: keep the old output for local chunk reuse; it is removed at
         * finalize just before the temp is renamed into place. */
        snprintf(engine->local_read_path, sizeof(engine->local_read_path),
                 "%s", config->output_path);
      }
      engine->conflict = 1u;
    }
  }
  /* Always (re)derive the local copy map: with no state the previous
   * chunk list is empty and every offset stays SIZE_MAX (no reuse). */
  compute_local_offsets(engine);
  for (size_t i = 0u; i < engine->source.manifest.chunk_count; i++) {
    if (!engine->present[i] && engine->local_offsets[i] != SIZE_MAX)
      has_local_use = 1;
  }
  if (has_local_use && engine->local_read_path[0] != '\0') {
    /* Open the previous committed output to copy reused chunks from it. */
    engine->local_file =
        turbo_fs_open(engine->local_read_path, TURBO_FS_O_RDONLY, 0);
    if (engine->local_file == TURBO_INVALID_FILE) {
      mesh_sync_engine_destroy_v1(engine);
      return MESH_SYNC_IO;
    }
  }
  if (engine->complete) {
    engine->open = 1u;
    return MESH_SYNC_OK;
  }
  engine->temp_file = turbo_fs_open(
      engine->temp_path, TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT |
                             (engine->present_count > 0u ? 0u : TURBO_FS_O_TRUNC),
      STATE_FILE_MODE);
  if (engine->temp_file == TURBO_INVALID_FILE) {
    mesh_sync_engine_destroy_v1(engine);
    return MESH_SYNC_IO;
  }
  engine->temp_open = 1u;
  engine->write_offset = 0u;
  for (size_t i = 0u; i < engine->source.manifest.chunk_count; i++) {
    if (engine->present[i])
      engine->write_offset += engine->source.manifest.chunks[i].size;
  }
  engine->open = 1u;
  return MESH_SYNC_OK;
}

void mesh_sync_engine_destroy_v1(mesh_sync_engine_v1_t *engine) {
  if (!engine)
    return;
  if (engine->temp_open && engine->temp_file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(engine->temp_file);
  if (engine->local_file != TURBO_INVALID_FILE)
    (void)turbo_fs_close(engine->local_file);
  m3_object_manifest_owned_destroy_v2(&engine->source);
  free(engine->present);
  free(engine->scratch);
  free(engine->local_offsets);
  free(engine->prev_chunks);
  memset(engine, 0, sizeof(*engine));
}

static mesh_sync_result_t finalize(mesh_sync_engine_v1_t *engine) {
  turbo_fs_stat_t stat;
  size_t i;

  if (engine->temp_open && engine->temp_file != TURBO_INVALID_FILE) {
    if (turbo_fs_fsync(engine->temp_file) != 0 ||
        turbo_fs_close(engine->temp_file) != 0) {
      engine->temp_open = 0u;
      return MESH_SYNC_IO;
    }
  }
  engine->temp_open = 0u;
  if (engine->local_file != TURBO_INVALID_FILE) {
    (void)turbo_fs_close(engine->local_file);
    engine->local_file = TURBO_INVALID_FILE;
  }
  if (turbo_fs_lstat(engine->config.output_path, &stat) == 0)
    (void)turbo_fs_unlink(engine->config.output_path);
  if (turbo_fs_rename(engine->temp_path, engine->config.output_path) != 0)
    return MESH_SYNC_IO;
  /* The committed source becomes the previous version for the next diff. */
  free(engine->prev_chunks);
  engine->prev_chunks = NULL;
  engine->prev_count = engine->source.manifest.chunk_count;
  if (engine->prev_count > 0u) {
    engine->prev_chunks = (mesh_sync_prev_chunk_v1_t *)malloc(
        engine->prev_count * sizeof(*engine->prev_chunks));
    if (!engine->prev_chunks)
      return MESH_SYNC_RESOURCE_EXHAUSTED;
    for (i = 0u; i < engine->prev_count; i++) {
      engine->prev_chunks[i].size = engine->source.manifest.chunks[i].size;
      memcpy(engine->prev_chunks[i].digest,
             engine->source.manifest.chunks[i].digest,
             M3_CHUNK_CID_DIGEST_SIZE);
    }
  }
  engine->complete = 1u;
  if (write_state(engine) != 0)
    return MESH_SYNC_IO;
  return MESH_SYNC_END;
}

mesh_sync_result_t mesh_sync_engine_pump_v1(mesh_sync_engine_v1_t *engine) {
  size_t missing = SIZE_MAX;
  size_t len = 0u;
  int fetch_result;

  if (!engine || !engine->open)
    return MESH_SYNC_INVALID_ARG;
  if (engine->complete)
    return MESH_SYNC_END;
  for (size_t i = 0u; i < engine->source.manifest.chunk_count; i++) {
    if (!engine->present[i]) {
      missing = i;
      break;
    }
  }
  if (missing == SIZE_MAX)
    return finalize(engine);

  {
    const m3_chunk_cid_v1_t *cid = &engine->source.manifest.chunks[missing];
    uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];

    if (engine->local_offsets[missing] != SIZE_MAX &&
        engine->local_file != TURBO_INVALID_FILE) {
      /* Reuse a chunk already present in the previous committed output. */
      if (turbo_fs_pread(engine->local_file, (char *)engine->scratch, cid->size,
                         (int64_t)engine->local_offsets[missing]) != (int)cid->size) {
        return MESH_SYNC_IO;
      }
      len = (size_t)cid->size;
    } else {
      fetch_result = engine->config.io.fetch_chunk(
          engine->config.io.context, missing, engine->scratch,
          (size_t)engine->config.max_chunk_bytes, &len);
      if (fetch_result < 0)
        return MESH_SYNC_IO;
      if (fetch_result > 0)
        return MESH_SYNC_AGAIN;
    }
    if (len != cid->size)
      return MESH_SYNC_INTEGRITY;
    if (turbo_crypto_sha256(engine->scratch, len, digest) != TURBO_CRYPTO_OK)
      return MESH_SYNC_INTEGRITY;
    if (memcmp(digest, cid->digest, sizeof(digest)) != 0)
      return MESH_SYNC_INTEGRITY;
  }
  if (turbo_fs_pwrite(engine->temp_file, (const char *)engine->scratch, len,
                      (int64_t)engine->write_offset) != (int)len) {
    return MESH_SYNC_IO;
  }
  engine->write_offset += len;
  engine->present[missing] = 1u;
  engine->present_count++;
  if (write_state(engine) != 0)
    return MESH_SYNC_IO;
  return MESH_SYNC_OK;
}

int mesh_sync_engine_complete(const mesh_sync_engine_v1_t *engine) {
  return engine && engine->complete;
}

uint8_t mesh_sync_engine_conflict(const mesh_sync_engine_v1_t *engine) {
  return engine ? engine->conflict : 0u;
}

const char *mesh_sync_engine_conflict_path(const mesh_sync_engine_v1_t *engine) {
  return engine && engine->conflict_path[0] != '\0' ? engine->conflict_path
                                                     : NULL;
}
