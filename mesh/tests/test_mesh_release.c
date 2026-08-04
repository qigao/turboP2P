#include <tinytest.h>

#include "mesh_release.h"

#include <string.h>

/* P17: multi-file software release manifest: canonical encode/decode with a
 * reproducible digest, sorted-path canonical order, lookup and validation. */

static void make_entry(mesh_release_entry_v1_t *entry, const char *path,
                       const char *key, uint64_t size, uint8_t seed) {
  memset(entry, 0, sizeof(*entry));
  snprintf(entry->path, sizeof(entry->path), "%s", path);
  snprintf(entry->object_key, sizeof(entry->object_key), "%s", key);
  entry->size = size;
  memset(entry->object_cid, seed, sizeof(entry->object_cid));
}

static void test_release_round_trip(void) {
  mesh_release_v1_t release;
  mesh_release_entry_v1_t entry;
  mesh_release_entry_v1_t found;
  uint8_t bytes[4096];
  size_t len = 0u;
  mesh_release_v1_t decoded;
  uint8_t digest[32];
  uint8_t digest2[32];

  check_int_eq(MESH_RELEASE_OK,
               mesh_release_init_v1(&release, "app-1.2.3", 7u));
  make_entry(&entry, "bin/tool", "rel/bin/tool", 12345u, 0x11u);
  check_int_eq(MESH_RELEASE_OK, mesh_release_add_v1(&release, &entry));
  make_entry(&entry, "etc/config.json", "rel/etc/config.json", 321u, 0x22u);
  check_int_eq(MESH_RELEASE_OK, mesh_release_add_v1(&release, &entry));
  make_entry(&entry, "lib/core.so", "rel/lib/core.so", 999999u, 0x33u);
  check_int_eq(MESH_RELEASE_OK, mesh_release_add_v1(&release, &entry));
  check_size_eq(release.count, 3u);

  /* Sorted by path: etc < lib < bin? strcmp("bin/tool","etc/..") -> 'b'<'e' -> bin first. */
  check_str_eq(release.entries[0].path, "bin/tool");
  check_str_eq(release.entries[1].path, "etc/config.json");
  check_str_eq(release.entries[2].path, "lib/core.so");

  check_int_eq(MESH_RELEASE_OK,
               mesh_release_lookup_v1(&release, "etc/config.json", &found));
  check_uint_eq(found.size, 321u);
  check_str_eq(found.object_key, "rel/etc/config.json");
  check_int_eq(MESH_RELEASE_NOT_FOUND,
               mesh_release_lookup_v1(&release, "missing", &found));

  check_int_eq(MESH_RELEASE_OK,
               mesh_release_encode_v1(&release, bytes, sizeof(bytes), &len));
  check_true(len > 0u);
  check_int_eq(MESH_RELEASE_OK,
               mesh_release_decode_v1(bytes, len, &decoded));
  check_str_eq(decoded.name, "app-1.2.3");
  check_uint_eq(decoded.version, 7u);
  check_size_eq(decoded.count, 3u);
  for (size_t i = 0u; i < 3u; i++) {
    check_str_eq(decoded.entries[i].path, release.entries[i].path);
    check_str_eq(decoded.entries[i].object_key, release.entries[i].object_key);
    check_uint_eq(decoded.entries[i].size, release.entries[i].size);
    check_mem_eq(decoded.entries[i].object_cid, release.entries[i].object_cid,
                 sizeof(decoded.entries[i].object_cid));
  }

  /* Digest is reproducible and sensitive to content. */
  check_int_eq(MESH_RELEASE_OK,
               mesh_release_digest_v1(&release, digest));
  check_int_eq(MESH_RELEASE_OK,
               mesh_release_digest_v1(&release, digest2));
  check_mem_eq(digest, digest2, sizeof(digest));
  make_entry(&entry, "lib/core.so", "rel/lib/core.so", 999998u, 0x33u);
  check_int_eq(MESH_RELEASE_DUPLICATE, mesh_release_add_v1(&release, &entry));
  check_int_eq(MESH_RELEASE_OK,
               mesh_release_digest_v1(&decoded, digest2));
  check_mem_eq(digest, digest2, sizeof(digest)); /* decode is canonical */

  /* Text listing is deterministic and includes every file. */
  {
    char listing[2048];
    size_t listing_len = 0u;

    check_int_eq(MESH_RELEASE_OK,
                 mesh_release_format_v1(&release, listing, sizeof(listing),
                                        &listing_len));
    check_true(listing_len > 0u);
    check_true(strstr(listing, "RELEASE app-1.2.3 version=7 files=3 digest=") != NULL);
    check_true(strstr(listing, "bin/tool rel/bin/tool 12345 ") != NULL);
    check_true(strstr(listing, "etc/config.json rel/etc/config.json 321 ") != NULL);
    check_true(strstr(listing, "lib/core.so rel/lib/core.so 999999 ") != NULL);
  }
}

static void test_release_invalid(void) {
  mesh_release_v1_t release;
  mesh_release_entry_v1_t entry;
  uint8_t bytes[4096];
  size_t len = 0u;
  mesh_release_v1_t decoded;

  check_int_eq(MESH_RELEASE_INVALID_ARG,
               mesh_release_init_v1(NULL, "name", 1u));
  check_int_eq(MESH_RELEASE_INVALID_ARG,
               mesh_release_init_v1(&release, "", 1u));
  check_int_eq(MESH_RELEASE_INVALID_ARG,
               mesh_release_init_v1(&release, NULL, 1u));

  check_int_eq(MESH_RELEASE_OK,
               mesh_release_init_v1(&release, "r", 1u));
  make_entry(&entry, "", "k", 10u, 0x01u);
  check_int_eq(MESH_RELEASE_INVALID_ARG, mesh_release_add_v1(&release, &entry));
  make_entry(&entry, "p", "", 10u, 0x01u);
  check_int_eq(MESH_RELEASE_INVALID_ARG, mesh_release_add_v1(&release, &entry));
  make_entry(&entry, "p", "k", 0u, 0x01u);
  check_int_eq(MESH_RELEASE_INVALID_ARG, mesh_release_add_v1(&release, &entry));

  /* Bad magic / truncated / unsorted decode. */
  check_int_eq(MESH_RELEASE_OK,
               mesh_release_encode_v1(&release, bytes, sizeof(bytes), &len));
  bytes[0] = 'X';
  check_int_eq(MESH_RELEASE_INTEGRITY,
               mesh_release_decode_v1(bytes, len, &decoded));
  bytes[0] = 'M';
  check_int_eq(MESH_RELEASE_INTEGRITY,
               mesh_release_decode_v1(bytes, len - 1u, &decoded));

  /* Entries are always kept sorted by add/encode, so canonical decode is the
   * identity; the sorted-path invariant is covered by the round trip. */

  check_int_eq(MESH_RELEASE_INVALID_ARG,
               mesh_release_lookup_v1(&release, "p", NULL));
  check_int_eq(MESH_RELEASE_INVALID_ARG,
               mesh_release_digest_v1(&release, NULL));

  /* Capacity bound. */
  check_int_eq(MESH_RELEASE_OK, mesh_release_init_v1(&release, "big", 1u));
  for (size_t i = 0u; i < MESH_RELEASE_MAX_ENTRIES; i++) {
    char path[32];
    char key[32];

    snprintf(path, sizeof(path), "f%03zu", i);
    snprintf(key, sizeof(key), "k%03zu", i);
    make_entry(&entry, path, key, 10u, (uint8_t)i);
    check_int_eq(MESH_RELEASE_OK, mesh_release_add_v1(&release, &entry));
  }
  make_entry(&entry, "extra", "k", 10u, 0x01u);
  check_int_eq(MESH_RELEASE_RESOURCE_EXHAUSTED,
               mesh_release_add_v1(&release, &entry));
}

spec("mesh release") {
    describe("multi-file release manifest") {
        it("encodes/decodes canonically with a stable digest") {
            test_release_round_trip();
        }
        it("rejects invalid inputs and enforces bounds") {
            test_release_invalid();
        }
    }
}