#include "mesh_release.h"

#include <turbo_crypto.h>

#include <stdio.h>
#include <string.h>

/* P17: release manifest. Canonical wire format (big-endian):
 *   magic "M3REL1" (6) | version u64 | name_len u16 | name
 *   | count u16
 *   | per entry: path_len u16 | path | key_len u16 | object_key
 *     | size u64 | object_cid[32]
 * Entries are kept sorted by path so the encoding is canonical and the digest
 * is reproducible. */

static void bytes_to_hex_short(const uint8_t *bytes, char *out) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0u; i < 32u; i++) {
    out[i * 2u] = digits[bytes[i] >> 4u];
    out[i * 2u + 1u] = digits[bytes[i] & 0x0fu];
  }
  out[64u] = '\0';
}

#define RELEASE_MAGIC "M3REL1"
#define RELEASE_MAGIC_SIZE 6u
#define RELEASE_MAX_NAME_BYTES (MESH_RELEASE_NAME_MAX - 1u)
#define RELEASE_MAX_PATH_BYTES (MESH_RELEASE_PATH_MAX - 1u)
#define RELEASE_MAX_KEY_BYTES (MESH_RELEASE_KEY_MAX - 1u)

static void write_u16(uint8_t out[2], uint16_t value) {
  out[0] = (uint8_t)(value >> 8u);
  out[1] = (uint8_t)value;
}

static uint16_t read_u16(const uint8_t in[2]) {
  return (uint16_t)(((uint16_t)in[0] << 8u) | in[1]);
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

static size_t encoded_size(const mesh_release_v1_t *release) {
  size_t size = RELEASE_MAGIC_SIZE + 8u + 2u + 1u + strlen(release->name) +
                2u; /* count */

  for (size_t i = 0u; i < release->count; i++) {
    const mesh_release_entry_v1_t *e = &release->entries[i];

    size += 2u + strlen(e->path) + 2u + strlen(e->object_key) + 8u +
            M3_CHUNK_CID_DIGEST_SIZE;
  }
  return size;
}

mesh_release_result_t mesh_release_init_v1(mesh_release_v1_t *release,
                                           const char *name, uint64_t version) {
  size_t name_len;

  if (!release || !name)
    return MESH_RELEASE_INVALID_ARG;
  name_len = strlen(name);
  if (name_len == 0u || name_len > RELEASE_MAX_NAME_BYTES)
    return MESH_RELEASE_INVALID_ARG;
  memset(release, 0, sizeof(*release));
  memcpy(release->name, name, name_len);
  release->version = version;
  return MESH_RELEASE_OK;
}

mesh_release_result_t mesh_release_add_v1(mesh_release_v1_t *release,
                                          const mesh_release_entry_v1_t *entry) {
  size_t insert_at;

  if (!release || !entry)
    return MESH_RELEASE_INVALID_ARG;
  if (entry->path[0] == '\0' || entry->object_key[0] == '\0' ||
      entry->size == 0u)
    return MESH_RELEASE_INVALID_ARG;
  if (release->count >= MESH_RELEASE_MAX_ENTRIES)
    return MESH_RELEASE_RESOURCE_EXHAUSTED;
  for (size_t i = 0u; i < release->count; i++) {
    int cmp = strcmp(entry->path, release->entries[i].path);

    if (cmp == 0)
      return MESH_RELEASE_DUPLICATE;
    if (cmp < 0) {
      insert_at = i;
      goto insert;
    }
  }
  insert_at = release->count;
insert:
  if (insert_at < release->count) {
    memmove(&release->entries[insert_at + 1u], &release->entries[insert_at],
            (release->count - insert_at) * sizeof(release->entries[0]));
  }
  release->entries[insert_at] = *entry;
  release->count++;
  return MESH_RELEASE_OK;
}

mesh_release_result_t mesh_release_lookup_v1(const mesh_release_v1_t *release,
                                             const char *path,
                                             mesh_release_entry_v1_t *out_entry) {
  size_t lo;
  size_t hi;

  if (!release || !path || !out_entry)
    return MESH_RELEASE_INVALID_ARG;
  lo = 0u;
  hi = release->count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2u;
    int cmp = strcmp(path, release->entries[mid].path);

    if (cmp == 0) {
      *out_entry = release->entries[mid];
      return MESH_RELEASE_OK;
    }
    if (cmp < 0)
      hi = mid;
    else
      lo = mid + 1u;
  }
  return MESH_RELEASE_NOT_FOUND;
}

mesh_release_result_t mesh_release_encode_v1(const mesh_release_v1_t *release,
                                             uint8_t *out, size_t cap,
                                             size_t *out_len) {
  size_t size;
  size_t cursor = 0u;
  size_t name_len;
  size_t path_len;
  size_t key_len;

  if (!release || !out || !out_len)
    return MESH_RELEASE_INVALID_ARG;
  size = encoded_size(release);
  if (size > cap)
    return MESH_RELEASE_RESOURCE_EXHAUSTED;
  name_len = strlen(release->name);
  memcpy(out + cursor, RELEASE_MAGIC, RELEASE_MAGIC_SIZE);
  cursor += RELEASE_MAGIC_SIZE;
  write_u64(out + cursor, release->version);
  cursor += 8u;
  write_u16(out + cursor, (uint16_t)name_len);
  cursor += 2u;
  memcpy(out + cursor, release->name, name_len);
  cursor += name_len;
  write_u16(out + cursor, (uint16_t)release->count);
  cursor += 2u;
  for (size_t i = 0u; i < release->count; i++) {
    const mesh_release_entry_v1_t *e = &release->entries[i];

    path_len = strlen(e->path);
    key_len = strlen(e->object_key);
    write_u16(out + cursor, (uint16_t)path_len);
    cursor += 2u;
    memcpy(out + cursor, e->path, path_len);
    cursor += path_len;
    write_u16(out + cursor, (uint16_t)key_len);
    cursor += 2u;
    memcpy(out + cursor, e->object_key, key_len);
    cursor += key_len;
    write_u64(out + cursor, e->size);
    cursor += 8u;
    memcpy(out + cursor, e->object_cid, M3_CHUNK_CID_DIGEST_SIZE);
    cursor += M3_CHUNK_CID_DIGEST_SIZE;
  }
  *out_len = cursor;
  return MESH_RELEASE_OK;
}

mesh_release_result_t mesh_release_decode_v1(const uint8_t *bytes, size_t len,
                                             mesh_release_v1_t *out_release) {
  size_t cursor = 0u;
  uint64_t version;
  uint16_t name_len;
  uint16_t count;

  if (!bytes || !out_release)
    return MESH_RELEASE_INVALID_ARG;
  memset(out_release, 0, sizeof(*out_release));
  if (len < RELEASE_MAGIC_SIZE + 8u + 2u + 1u + 2u ||
      memcmp(bytes, RELEASE_MAGIC, RELEASE_MAGIC_SIZE) != 0) {
    return MESH_RELEASE_INTEGRITY;
  }
  cursor = RELEASE_MAGIC_SIZE;
  version = read_u64(bytes + cursor);
  cursor += 8u;
  name_len = read_u16(bytes + cursor);
  cursor += 2u;
  if (name_len == 0u || name_len > RELEASE_MAX_NAME_BYTES ||
      cursor + name_len > len) {
    return MESH_RELEASE_INTEGRITY;
  }
  memcpy(out_release->name, bytes + cursor, name_len);
  out_release->name[name_len] = '\0';
  cursor += name_len;
  count = read_u16(bytes + cursor);
  cursor += 2u;
  if (count > MESH_RELEASE_MAX_ENTRIES)
    return MESH_RELEASE_INTEGRITY;
  out_release->version = version;
  out_release->count = count;
  for (size_t i = 0u; i < count; i++) {
    mesh_release_entry_v1_t *e = &out_release->entries[i];
    uint16_t path_len;
    uint16_t key_len;

    if (cursor + 2u > len)
      return MESH_RELEASE_INTEGRITY;
    path_len = read_u16(bytes + cursor);
    cursor += 2u;
    if (path_len == 0u || path_len > RELEASE_MAX_PATH_BYTES ||
        cursor + path_len > len) {
      return MESH_RELEASE_INTEGRITY;
    }
    memcpy(e->path, bytes + cursor, path_len);
    e->path[path_len] = '\0';
    cursor += path_len;
    if (cursor + 2u > len)
      return MESH_RELEASE_INTEGRITY;
    key_len = read_u16(bytes + cursor);
    cursor += 2u;
    if (key_len == 0u || key_len > RELEASE_MAX_KEY_BYTES ||
        cursor + key_len > len) {
      return MESH_RELEASE_INTEGRITY;
    }
    memcpy(e->object_key, bytes + cursor, key_len);
    e->object_key[key_len] = '\0';
    cursor += key_len;
    if (cursor + 8u + M3_CHUNK_CID_DIGEST_SIZE > len)
      return MESH_RELEASE_INTEGRITY;
    e->size = read_u64(bytes + cursor);
    cursor += 8u;
    memcpy(e->object_cid, bytes + cursor, M3_CHUNK_CID_DIGEST_SIZE);
    cursor += M3_CHUNK_CID_DIGEST_SIZE;
    if (i > 0u && strcmp(e->path, out_release->entries[i - 1u].path) <= 0)
      return MESH_RELEASE_INTEGRITY; /* must be strictly sorted */
  }
  if (cursor != len)
    return MESH_RELEASE_INTEGRITY;
  return MESH_RELEASE_OK;
}

mesh_release_result_t mesh_release_digest_v1(const mesh_release_v1_t *release,
                                             uint8_t out_digest[32]) {
  uint8_t *buffer;
  size_t size;
  size_t len = 0u;
  mesh_release_result_t rc;

  if (!release || !out_digest)
    return MESH_RELEASE_INVALID_ARG;
  size = encoded_size(release);
  buffer = (uint8_t *)malloc(size);
  if (!buffer)
    return MESH_RELEASE_RESOURCE_EXHAUSTED;
  rc = mesh_release_encode_v1(release, buffer, size, &len);
  if (rc == MESH_RELEASE_OK) {
    if (turbo_crypto_sha256(buffer, len, out_digest) != TURBO_CRYPTO_OK)
      rc = MESH_RELEASE_INTEGRITY;
  }
  free(buffer);
  return rc;
}

mesh_release_result_t mesh_release_format_v1(const mesh_release_v1_t *release,
                                             char *out, size_t cap,
                                             size_t *out_len) {
  size_t used = 0u;
  int written;
  uint8_t digest[32];
  char digest_hex[65];

  if (!release || !out || !out_len)
    return MESH_RELEASE_INVALID_ARG;
  *out_len = 0u;
  if (mesh_release_digest_v1(release, digest) != MESH_RELEASE_OK)
    return MESH_RELEASE_INTEGRITY;
  bytes_to_hex_short(digest, digest_hex);
#define FORMAT_APPEND(...)                                                     \
  do {                                                                         \
    written = snprintf(out + used, cap > used ? cap - used : 0u, __VA_ARGS__); \
    if (written < 0 || (size_t)written >= (cap > used ? cap - used : 0u))      \
      return MESH_RELEASE_RESOURCE_EXHAUSTED;                                  \
    used += (size_t)written;                                                   \
  } while (0)

  FORMAT_APPEND("RELEASE %s version=%llu files=%zu digest=%s\n", release->name,
                (unsigned long long)release->version, release->count, digest_hex);
  for (size_t i = 0u; i < release->count; i++) {
    const mesh_release_entry_v1_t *e = &release->entries[i];

    bytes_to_hex_short(e->object_cid, digest_hex);
    FORMAT_APPEND("%s %s %llu %s\n", e->path, e->object_key,
                  (unsigned long long)e->size, digest_hex);
  }
#undef FORMAT_APPEND
  *out_len = used;
  return MESH_RELEASE_OK;
}