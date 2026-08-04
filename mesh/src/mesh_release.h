#ifndef TURBO_P2P_MESH_RELEASE_H
#define TURBO_P2P_MESH_RELEASE_H

#include "m3_object_manifest.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P17: multi-file software release manifest. A release is a versioned set of
 * files, each addressable as an M3 object by a gateway object key (the HTTP
 * download path) and identified by its object digest. The release encodes
 * canonically (entries sorted by path) with an overall digest, so a client
 * can fetch the manifest over HTTP, verify it, then download each file
 * through the local mesh (or a backbone) by key. */

#define MESH_RELEASE_NAME_MAX 64u
#define MESH_RELEASE_PATH_MAX 256u
#define MESH_RELEASE_KEY_MAX 256u
#define MESH_RELEASE_MAX_ENTRIES 64u

typedef enum {
  MESH_RELEASE_OK = 0,
  MESH_RELEASE_INVALID_ARG = -1,
  MESH_RELEASE_RESOURCE_EXHAUSTED = -2,
  MESH_RELEASE_DUPLICATE = -3,
  MESH_RELEASE_NOT_FOUND = -4,
  MESH_RELEASE_INTEGRITY = -5,
} mesh_release_result_t;

typedef struct {
  char path[MESH_RELEASE_PATH_MAX];      /* file path within the release */
  char object_key[MESH_RELEASE_KEY_MAX]; /* gateway object key (bucket/obj) */
  uint64_t size;                         /* file byte size */
  uint8_t object_cid[M3_CHUNK_CID_DIGEST_SIZE]; /* object digest */
} mesh_release_entry_v1_t;

typedef struct {
  char name[MESH_RELEASE_NAME_MAX];
  uint64_t version;
  mesh_release_entry_v1_t entries[MESH_RELEASE_MAX_ENTRIES];
  size_t count; /* entries kept sorted by path (canonical) */
} mesh_release_v1_t;

/** Reset and name a release. The caller zero-initializes before init. */
mesh_release_result_t mesh_release_init_v1(mesh_release_v1_t *release,
                                           const char *name, uint64_t version);

/** Insert one entry in canonical (path) order; rejects duplicate paths. */
mesh_release_result_t mesh_release_add_v1(mesh_release_v1_t *release,
                                          const mesh_release_entry_v1_t *entry);

/** Look up an entry by path. */
mesh_release_result_t mesh_release_lookup_v1(const mesh_release_v1_t *release,
                                             const char *path,
                                             mesh_release_entry_v1_t *out_entry);

/**
 * Encode the canonical release: magic + version + name + entry count, then
 * sorted entries (path, object key, size, object digest). Fails with
 * RESOURCE_EXHAUSTED when out is too small.
 */
mesh_release_result_t mesh_release_encode_v1(const mesh_release_v1_t *release,
                                             uint8_t *out, size_t cap,
                                             size_t *out_len);

/** Decode + validate a canonical release (magic, bounds, sorted paths). */
mesh_release_result_t mesh_release_decode_v1(const uint8_t *bytes, size_t len,
                                             mesh_release_v1_t *out_release);

/** SHA-256 over the canonical encoding (release identity). */
mesh_release_result_t mesh_release_digest_v1(const mesh_release_v1_t *release,
                                             uint8_t out_digest[32]);

/**
 * Format a human-readable release listing:
 *   RELEASE <name> version=<v> files=<n> digest=<hex>
 *   <path> <object_key> <size> <cid-hex>   (one line per file)
 * Fails with RESOURCE_EXHAUSTED when out is too small.
 */
mesh_release_result_t mesh_release_format_v1(const mesh_release_v1_t *release,
                                             char *out, size_t cap,
                                             size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif