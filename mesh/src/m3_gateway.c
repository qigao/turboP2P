#include "m3_gateway.h"

#include "m3_object_manifest.h"
#include "mesh_media_index.h"
#include "mesh_media_playlist.h"
#include "mesh_release.h"

#include <iris/iris.h>
#include <turbo_crypto.h>
#include <turbo_thread.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Nominal per-segment duration for generated media playlists (the gateway has no container metadata). */
#define M3_GATEWAY_PLAYLIST_DURATION_MS 4000u

#include <time.h>

#ifdef TURBO_P2P_M3_RAFT_ENABLED
  #include "m3_gateway_raft.h"
  #include "m3_raft_node.h"
  #include "m3_repair.h"
  #include <turbo_error.h>
#endif

/* Metadata backend abstraction: local store (default) or raft (Phase 2a). */
static int gateway_meta_put_start(m3_gateway_t *g, const char *bucket, const char *object,
                                    const uint8_t *manifest_bytes, size_t manifest_size) {
  int leader = 0;

  g->node_meta_not_leader = 0;
  if (m3_raft_node_is_leader(g->node, &leader) != TURBO_OK || !leader) {
    g->node_meta_not_leader = 1;
    (void)m3_raft_node_leader(g->node, &g->node_lookup_leader_id);
    return -1;
  }
  g->meta_mutation_before = m3_raft_node_applied_index(g->node);
  if (m3_raft_node_propose_put(g->node, g->tenant_id, bucket, object, manifest_bytes,
                               manifest_size) != TURBO_OK) {
    return -1;
  }
  g->meta_mutation_pending = 1;
  return 0;
}

static void gateway_meta_poll(m3_gateway_t *g);

/* Wait for an in-flight node-mode mutation to apply locally. The node event
 * loop is pumped by the caller (m3_gateway_main background thread or an
 * in-process harness), so this only sleeps; pumping here would race that
 * thread on the node context. */
static int gateway_meta_wait(m3_gateway_t *g) {
  for (size_t i = 0u; i < 5000u && g->meta_mutation_pending; i++) {
    turbo_sleep_ms(1);
  }
  return g->meta_mutation_pending ? -1 : 0;
}

static int gateway_meta_put(m3_gateway_t *g, const char *bucket, const char *object,
                            const uint8_t *manifest_bytes, size_t manifest_size) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  if (g->node) {
    if (gateway_meta_put_start(g, bucket, object, manifest_bytes, manifest_size) != 0) {
      return -1;
    }
    /* Pump the node loop until the proposal is applied locally. In a real
     * deployment each peer process pumps its own loop, so this completes. */
    return gateway_meta_wait(g);
  }
  if (g->raft) {
    return m3_gateway_raft_put_v1(g->raft, g->tenant_id, bucket, object, manifest_bytes,
                                  manifest_size) == TURBO_OK
               ? 0
               : -1;
  }
#endif
  return m3_namespace_local_store_apply_put_v1(
             &g->namespace_store, ++g->applied_index, g->tenant_id, (const uint8_t *)bucket,
             strlen(bucket), (const uint8_t *)object, strlen(object), manifest_bytes,
             manifest_size) == M3_NAMESPACE_LOCAL_OK
             ? 0
             : -1;
}

static int gateway_meta_tombstone_start(m3_gateway_t *g, const char *bucket,
                                          const char *object) {
  int leader = 0;

  g->node_meta_not_leader = 0;
  if (m3_raft_node_is_leader(g->node, &leader) != TURBO_OK || !leader) {
    g->node_meta_not_leader = 1;
    (void)m3_raft_node_leader(g->node, &g->node_lookup_leader_id);
    return -1;
  }
  g->meta_mutation_before = m3_raft_node_applied_index(g->node);
  if (m3_raft_node_propose_tombstone(g->node, g->tenant_id, bucket, object) != TURBO_OK) {
    return -1;
  }
  g->meta_mutation_pending = 1;
  return 0;
}

static int gateway_meta_tombstone(m3_gateway_t *g, const char *bucket, const char *object) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  if (g->node) {
    if (gateway_meta_tombstone_start(g, bucket, object) != 0) {
      return -1;
    }
    return gateway_meta_wait(g);
  }
  if (g->raft) {
    return m3_gateway_raft_tombstone_v1(g->raft, g->tenant_id, bucket, object) == TURBO_OK ? 0 : -1;
  }
#endif
  return m3_namespace_local_store_apply_tombstone_v1(
             &g->namespace_store, ++g->applied_index, g->tenant_id, (const uint8_t *)bucket,
             strlen(bucket), (const uint8_t *)object, strlen(object)) == M3_NAMESPACE_LOCAL_OK
             ? 0
             : -1;
}

static int gateway_meta_persist(m3_gateway_t *g) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  if (g->node || g->raft) {
    return 0; /* raft/sqlite persistence replaces the local snapshot */
  }
#endif
  return m3_namespace_local_store_persist_v1(&g->namespace_store, g->store_root) ==
                 M3_NAMESPACE_LOCAL_OK
             ? 0
             : -1;
}

static m3_namespace_lookup_result_t node_lookup_start(void *context,
                                                       const m3_namespace_lookup_request_v1_t *request,
                                                       m3_namespace_lookup_complete_cb complete_cb,
                                                       void *user_data) {
  m3_gateway_t *g = (m3_gateway_t *)context;
  m3_namespace_lookup_adapter_v1_t raft_adapter;
  int leader = 0;

  if (g == NULL || request == NULL || complete_cb == NULL) {
    return M3_NAMESPACE_LOOKUP_INVALID_ARG;
  }
  g->node_lookup_not_leader = 0;
  if (m3_raft_node_is_leader(g->node, &leader) != TURBO_OK || !leader) {
    /* Linearizable reads are leader-only; surface the leader id so the caller
     * can route (HTTP 307/503, or control-plane forwarding). */
    g->node_lookup_not_leader = 1;
    (void)m3_raft_node_leader(g->node, &g->node_lookup_leader_id);
    return M3_NAMESPACE_LOOKUP_UNAVAILABLE;
  }
  raft_adapter = m3_gateway_raft_lookup_v1(m3_raft_node_gateway(g->node));
  return raft_adapter.start(raft_adapter.context, request, complete_cb, user_data);
}

static m3_namespace_lookup_adapter_v1_t gateway_meta_lookup(m3_gateway_t *g) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  if (g->node) {
    m3_namespace_lookup_adapter_v1_t adapter;
    memset(&adapter, 0, sizeof(adapter));
    adapter.context = g;
    adapter.start = node_lookup_start;
    return adapter;
  }
  if (g->raft) {
    return m3_gateway_raft_lookup_v1(g->raft);
  }
#endif
  return m3_namespace_local_store_adapter_v1(&g->namespace_store);
}

/* Leader-routed namespace enumeration for list requests. Returns 0 on
 * success (or clean empty), -1 on error; sets node_lookup_not_leader when the
 * local node is a follower (caller maps to 503/redirect). */
static int gateway_meta_list(m3_gateway_t *g, const uint8_t *bucket, size_t bucket_size,
                             const uint8_t *prefix, size_t prefix_size,
                             m3_namespace_list_cb cb, void *user) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  if (g->node) {
    int leader = 0;

    g->node_lookup_not_leader = 0;
    if (m3_raft_node_is_leader(g->node, &leader) != TURBO_OK || !leader) {
      g->node_lookup_not_leader = 1;
      (void)m3_raft_node_leader(g->node, &g->node_lookup_leader_id);
      return -1;
    }
    return m3_raft_node_list(g->node, g->tenant_id, bucket, bucket_size, prefix,
                             prefix_size, cb, user) == TURBO_OK
               ? 0
               : -1;
  }
#endif
  return m3_namespace_local_store_list_v1(&g->namespace_store, g->tenant_id, bucket,
                                          bucket_size, prefix, prefix_size, cb, user) ==
                 M3_NAMESPACE_LOCAL_OK
             ? 0
             : -1;
}

static void gateway_meta_poll(m3_gateway_t *g) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  if (g->node) {
    (void)m3_raft_node_poll(g->node);
    if (g->meta_mutation_pending &&
        m3_raft_node_applied_index(g->node) > g->meta_mutation_before) {
      g->meta_mutation_pending = 0;
    }
    return;
  }
  if (g->raft) {
    size_t completed = 0u;
    (void)m3_gateway_raft_poll_v1(g->raft, &completed);
  }
#endif
}
/* Per-app gateway binding so more than one gateway can serve in one process.
 * Iris route handlers carry no user_data; they resolve the gateway from
 * req->app via this small registry (with the legacy singleton as fallback). */
typedef struct m3_gateway_app_binding_s {
  void *app;
  m3_gateway_t *gateway;
  struct m3_gateway_app_binding_s *next;
} m3_gateway_app_binding_t;

static m3_gateway_t *g_gateway = NULL; /* legacy singleton fallback */
static m3_gateway_app_binding_t *g_gateway_bindings = NULL;

static m3_gateway_t *gateway_from_req(Req *req) {
  m3_gateway_app_binding_t *binding;

  if (req != NULL && req->app != NULL) {
    for (binding = g_gateway_bindings; binding != NULL; binding = binding->next) {
      if (binding->app == req->app) {
        return binding->gateway;
      }
    }
  }
  return g_gateway;
}

static void gateway_bind_app(void *app, m3_gateway_t *gateway) {
  m3_gateway_app_binding_t *binding;

  for (binding = g_gateway_bindings; binding != NULL; binding = binding->next) {
    if (binding->app == app) {
      binding->gateway = gateway;
      return;
    }
  }
  binding = (m3_gateway_app_binding_t *)calloc(1u, sizeof(*binding));
  if (binding == NULL) {
    return;
  }
  binding->app = app;
  binding->gateway = gateway;
  binding->next = g_gateway_bindings;
  g_gateway_bindings = binding;
}

/* Phase 1 single-node S3-shaped gateway. Handlers resolve the gateway from a
 * module-level singleton (Iris route handlers carry no user_data). */

#define M3_GATEWAY_MAX_CHUNK_BYTES (UINT64_C(64) * 1024 * 1024)

static const char HEX_LOWER[] = "0123456789abcdef";

static int ascii_lower_equal(const char *a, const char *b) {
  while (*a && *b) {
    char ca = *a;
    char cb = *b;
    if (ca >= 'A' && ca <= 'Z')
      ca = (char)(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z')
      cb = (char)(cb - 'A' + 'a');
    if (ca != cb)
      return 0;
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

static void hex_encode(const uint8_t *in, size_t len, char *out) {
  size_t i;
  for (i = 0u; i < len; i++) {
    out[i * 2u] = HEX_LOWER[in[i] >> 4u];
    out[i * 2u + 1u] = HEX_LOWER[in[i] & 0x0Fu];
  }
  out[len * 2u] = '\0';
}

/* S3-style ETag: quoted lowercase hex of the object digest. out must hold at
 * least 2 + 2*M3_CHUNK_CID_DIGEST_SIZE + 1 bytes. */
static void gateway_etag_quoted(const uint8_t *digest, size_t digest_size, char *out) {
  out[0] = '"';
  hex_encode(digest, digest_size, out + 1);
  out[1u + digest_size * 2u] = '"';
  out[1u + digest_size * 2u + 1u] = '\0';
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Decode percent-encoded query values into out (out_cap includes the NUL).
 * '+' is kept literal, matching S3 query semantics. Returns 0 on success or
 * -1 when the input is malformed or the decoded value does not fit. */
static int query_percent_decode(const char *in, char *out, size_t out_cap) {
  size_t o = 0u;

  if (!in) {
    if (out_cap > 0u)
      out[0] = '\0';
    return 0;
  }
  if (out_cap == 0u)
    return -1;
  while (*in) {
    if (*in == '%') {
      int hi;
      int lo;

      if (in[1] == '\0' || in[2] == '\0')
        return -1;
      hi = hex_nibble(in[1]);
      lo = hex_nibble(in[2]);
      if (hi < 0 || lo < 0)
        return -1;
      if (o >= out_cap - 1u)
        return -1;
      out[o++] = (char)((hi << 4) | lo);
      in += 3;
    } else {
      if (o >= out_cap - 1u)
        return -1;
      out[o++] = *in++;
    }
  }
  out[o] = '\0';
  return 0;
}

static const char *gateway_header_lookup(void *context, const char *name) {
  Req *req = (Req *)context;
  int i;

  for (i = 0; i < req->headers.count; i++) {
    if (req->headers.items[i].key && ascii_lower_equal(req->headers.items[i].key, name)) {
      return req->headers.items[i].value;
    }
  }
  return NULL;
}

static void send_s3_error(Res *res, int status, const char *code, const char *message) {
  char xml[512];
  int n = snprintf(xml, sizeof(xml),
                   "<Error><Code>%s</Code><Message>%s</Message>"
                   "<RequestId>m3</RequestId></Error>",
                   code, message);
  if (n < 0 || (size_t)n >= sizeof(xml)) {
    reply(res, status, "application/xml", "", 0);
    return;
  }
  reply(res, status, "application/xml", xml, (size_t)n);
}

static void send_gateway_not_leader(m3_gateway_t *g, Res *res) {
  char leader_str[24];

  snprintf(leader_str, sizeof(leader_str), "%llu",
           (unsigned long long)g->node_lookup_leader_id);
  set_header(res, "X-M3-Leader-Node", leader_str);
  send_s3_error(res, 503, "ServiceUnavailable",
                "Metadata read must be routed to the current raft leader.");
}

/* Verify AWS SigV4 before any state change. Returns 0 on success. */
static int gateway_require_auth(m3_gateway_t *g, Req *req, Res *res) {
  const char *authorization = gateway_header_lookup(req, "Authorization");
  const char *amzdate = gateway_header_lookup(req, "x-amz-date");
  const char *bucket = get_params(req, "bucket");
  const char *object = get_params(req, "object");
  char canonical_uri[2048];
  m3_sigv4_result_t result;

  if (!authorization || !amzdate) {
    send_s3_error(res, 403, "AccessDenied", "Missing signature.");
    return -1;
  }
  if (!bucket || bucket[0] == '\0') {
    send_s3_error(res, 400, "InvalidRequest", "Missing bucket or object.");
    return -1;
  }
  if (object && object[0] != '\0') {
    if (strchr(object, '/') != NULL) {
      send_s3_error(res, 400, "InvalidRequest",
                    "Object keys with '/' are not supported in Phase 1.");
      return -1;
    }
    if (snprintf(canonical_uri, sizeof(canonical_uri), "/%s/%s", bucket, object) >=
        (int)sizeof(canonical_uri)) {
      send_s3_error(res, 400, "InvalidRequest", "Key too long.");
      return -1;
    }
  } else if (snprintf(canonical_uri, sizeof(canonical_uri), "/%s", bucket) >=
             (int)sizeof(canonical_uri)) {
    send_s3_error(res, 400, "InvalidRequest", "Bucket name too long.");
    return -1;
  }
  result =
      m3_sigv4_verify_request_v1(&g->credential, req->method, canonical_uri, NULL, authorization,
                                 amzdate, NULL, gateway_header_lookup, req, (int64_t)time(NULL));
  if (result != M3_SIGV4_OK) {
    send_s3_error(res, 403, "AccessDenied", "Signature verification failed.");
    return -1;
  }
  return 0;
}

typedef struct {
  m3_chunk_cid_v1_t *cids;
  size_t count;
  size_t capacity;
} chunk_list_t;

static int chunk_list_push(chunk_list_t *list, const m3_chunk_cid_v1_t *cid) {
  m3_chunk_cid_v1_t *grown;

  if (list->count >= list->capacity) {
    size_t new_capacity = list->capacity == 0u ? 8u : list->capacity * 2u;
    if (new_capacity > M3_GATEWAY_MAX_CHUNKS)
      return -1;
    grown = (m3_chunk_cid_v1_t *)realloc(list->cids, new_capacity * sizeof(*list->cids));
    if (!grown)
      return -1;
    list->cids = grown;
    list->capacity = new_capacity;
  }
  list->cids[list->count++] = *cid;
  return 0;
}

static uint64_t gateway_now_ms(void) {
  return (uint64_t)time(NULL) * 1000u;
}

static int manifest_chunk_has_placements(const m3_object_manifest_v2_t *manifest,
                                         size_t chunk_index) {
  for (size_t i = 0u; i < manifest->placement_count; i++) {
    if (manifest->placements[i].chunk_index == chunk_index)
      return 1;
  }
  return 0;
}

int m3_gateway_attach_datapane_v1(m3_gateway_t *g, size_t target_replicas,
                                  size_t min_durable_replicas,
                                  const m3_chunk_capability_policy_v1_t *policy) {
  if (!g || !g->initialized || g->datapane_enabled || !policy)
    return -1;
  if (m3_gateway_datapane_init_v1(&g->datapane, g->tenant_id, target_replicas,
                                  min_durable_replicas, policy) !=
      M3_GATEWAY_DATAPANE_OK) {
    return -1;
  }
  g->datapane_enabled = 1;
  return 0;
}

int m3_gateway_register_store_v1(
    m3_gateway_t *g, const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    m3_store_node_v1_t *store) {
  if (!g || !g->initialized || !g->datapane_enabled)
    return -1;
  return m3_gateway_datapane_register_store_v1(&g->datapane, store_node_id,
                                               store_public_key, store) ==
                 M3_GATEWAY_DATAPANE_OK
             ? 0
             : -1;
}

int m3_gateway_attach_mesh_v1(m3_gateway_t *g, p2p_node_t *node,
                              const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE]) {
  if (!g || !g->initialized || !g->datapane_enabled || !node || !private_key)
    return -1;
  return m3_gateway_datapane_attach_mesh_v1(&g->datapane, node, private_key) ==
                 M3_GATEWAY_DATAPANE_OK
             ? 0
             : -1;
}

int m3_gateway_register_mesh_store_v1(
    m3_gateway_t *g, const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
    const uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
    const char *host, int port) {
  if (!g || !g->initialized || !g->datapane_enabled)
    return -1;
  return m3_gateway_datapane_register_mesh_store_v1(
             &g->datapane, store_node_id, store_public_key, host, port) ==
                 M3_GATEWAY_DATAPANE_OK
             ? 0
             : -1;
}

/* Build the object manifest (V2 via the attached data plane, V1 via the local
 * CAS) without touching metadata. Returns 0 on success, 2 on insufficient
 * storage, -1 on error. On success *out_manifest_bytes is owned. */
static int put_object_prepare(m3_gateway_t *g, const uint8_t *body, size_t body_len,
                              uint8_t *object_digest,
                              uint8_t **out_manifest_bytes, size_t *out_manifest_size) {
  uint64_t total = 0u;
  int rc = -1;

  *out_manifest_bytes = NULL;
  *out_manifest_size = 0u;
  if (g->datapane_enabled) {
    uint64_t object_size = 0u;
    m3_object_manifest_owned_v2_t owned = {0};

    {
      m3_gateway_datapane_result_t dp_rc = m3_gateway_datapane_put_object_v1(
          &g->datapane, body, body_len, g->max_chunk_bytes, gateway_now_ms(),
          out_manifest_bytes, out_manifest_size, &object_size);
      if (dp_rc != M3_GATEWAY_DATAPANE_OK)
        return 2;
    }
    if (m3_object_manifest_decode_v2(
            *out_manifest_bytes, *out_manifest_size, M3_GATEWAY_MAX_OBJECT_BYTES,
            M3_GATEWAY_MAX_CHUNKS,
            M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
            &owned) != M3_OBJECT_MANIFEST_OK) {
      goto cleanup;
    }
    memcpy(object_digest, owned.manifest.object_cid.digest, M3_CHUNK_CID_DIGEST_SIZE);
    total = owned.manifest.object_cid.size;
    m3_object_manifest_owned_destroy_v2(&owned);
    return 0;
  }

  {
    chunk_list_t chunks = {0};
    m3_object_manifest_v1_t manifest = {0};
    turbo_crypto_sha256_ctx_t object_ctx;
    size_t offset = 0u;

    turbo_crypto_sha256_init(&object_ctx);
    while (offset < body_len) {
      size_t take = body_len - offset;
      m3_chunk_cid_v1_t cid;
      uint8_t created = 0u;

      if (take > (size_t)g->max_chunk_bytes)
        take = (size_t)g->max_chunk_bytes;
      total += (uint64_t)take;
      if (m3_chunk_cid_calculate_v1(body + offset, take, &cid) != M3_CHUNK_STORE_OK ||
          m3_chunk_store_put_bytes_v1(&g->chunk_store, &cid, body + offset, take,
                                      &created) != M3_CHUNK_STORE_OK ||
          turbo_crypto_sha256_update(&object_ctx, cid.digest, sizeof(cid.digest)) !=
              TURBO_CRYPTO_OK ||
          chunk_list_push(&chunks, &cid) != 0) {
        rc = 2;
        free(chunks.cids);
        return rc;
      }
      offset += take;
    }
    turbo_crypto_sha256_final(&object_ctx, object_digest);
    manifest.version = M3_OBJECT_MANIFEST_VERSION;
    manifest.object_cid.hash_algorithm = M3_CHUNK_STORE_HASH_ALGORITHM_SHA256;
    manifest.object_cid.size = total;
    memcpy(manifest.object_cid.digest, object_digest, sizeof(object_digest));
    manifest.chunks = chunks.cids;
    manifest.chunk_count = chunks.count;
    if (m3_object_manifest_encode_v1(
            &manifest, M3_GATEWAY_MAX_OBJECT_BYTES, M3_GATEWAY_MAX_CHUNKS,
            out_manifest_bytes, out_manifest_size) != M3_OBJECT_MANIFEST_OK) {
      free(chunks.cids);
      return -1;
    }
    free(chunks.cids);
    return 0;
  }

cleanup:
  m3_object_manifest_bytes_free_v2(*out_manifest_bytes);
  *out_manifest_bytes = NULL;
  *out_manifest_size = 0u;
  return rc;
}

int m3_gateway_put_object_start_v1(m3_gateway_t *g, const char *bucket,
                                   const char *object, const uint8_t *body,
                                   size_t body_len, char *etag_out, size_t etag_cap) {
  uint8_t object_digest[M3_CHUNK_CID_DIGEST_SIZE];
  uint8_t *manifest_bytes = NULL;
  size_t manifest_size = 0u;
  int rc;

  if (!g || !g->initialized || !bucket || !object || !etag_out || !etag_cap ||
      (!body && body_len > 0u))
    return -1;
  rc = put_object_prepare(g, body, body_len, object_digest, &manifest_bytes,
                          &manifest_size);
  if (rc != 0)
    return rc;
  if (g->node) {
    if (gateway_meta_put_start(g, bucket, object, manifest_bytes, manifest_size) != 0) {
      rc = g->node_meta_not_leader ? 1 : -1;
      goto cleanup;
    }
  } else if (gateway_meta_put(g, bucket, object, manifest_bytes, manifest_size) != 0) {
    rc = g->node_meta_not_leader ? 1 : -1;
    goto cleanup;
  }
  if (gateway_meta_persist(g) != 0) {
    rc = -1;
    goto cleanup;
  }
  gateway_etag_quoted(object_digest, sizeof(object_digest), etag_out);
  rc = 0;

cleanup:
  m3_object_manifest_bytes_free_v2(manifest_bytes);
  return rc;
}

int m3_gateway_put_object_v1(m3_gateway_t *g, const char *bucket, const char *object,
                             const uint8_t *body, size_t body_len, char *etag_out,
                             size_t etag_cap) {
  int rc = m3_gateway_put_object_start_v1(g, bucket, object, body, body_len, etag_out,
                                          etag_cap);

  if (rc != 0)
    return rc;
  if (g->node && gateway_meta_wait(g) != 0)
    return -1;
  return 0;
}

/* PUT /:bucket/:object */
void m3_handle_put_object(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  const char *bucket;
  const char *object;
  const char *expected_hash;
  turbo_crypto_sha256_ctx_t body_ctx;
  uint8_t body_digest[32];
  char body_digest_hex[65];
  char etag[2u + 2u * M3_CHUNK_CID_DIGEST_SIZE + 1u];
  int rc;

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;

  bucket = get_params(req, "bucket");
  object = get_params(req, "object");
  expected_hash = gateway_header_lookup(req, "x-amz-content-sha256");
  if (!expected_hash || expected_hash[0] == '\0') {
    send_s3_error(res, 400, "InvalidRequest", "x-amz-content-sha256 is required.");
    return;
  }
  if ((uint64_t)req->body_len > M3_GATEWAY_MAX_OBJECT_BYTES) {
    send_s3_error(res, 413, "EntityTooLarge", "Object too large.");
    return;
  }

  /* Verify the payload hash header matches the received body. */
  turbo_crypto_sha256_init(&body_ctx);
  if (req->body_len > 0u &&
      turbo_crypto_sha256_update(&body_ctx, (const uint8_t *)req->body, req->body_len) !=
          TURBO_CRYPTO_OK) {
    send_s3_error(res, 500, "InternalError", "Hash failed.");
    return;
  }
  turbo_crypto_sha256_final(&body_ctx, body_digest);
  hex_encode(body_digest, sizeof(body_digest), body_digest_hex);
  if (strcmp(body_digest_hex, expected_hash) != 0) {
    send_s3_error(res, 400, "BadDigest", "Payload hash mismatch.");
    return;
  }

  rc = m3_gateway_put_object_v1(g, bucket, object, (const uint8_t *)req->body,
                                req->body_len, etag, sizeof(etag));
  if (rc == 1) {
    send_gateway_not_leader(g, res);
    return;
  }
  if (rc == 2) {
    send_s3_error(res, 507, "InsufficientStorage", "Chunk write failed.");
    return;
  }
  if (rc != 0) {
    send_s3_error(res, 500, "InternalError", "Namespace apply failed.");
    return;
  }
  set_header(res, "ETag", etag);
  reply(res, 200, "application/xml", NULL, 0);
}

typedef struct {
  m3_gateway_t *gateway;
  Res *res;
  const char *range_header;
  int want_playlist;
  int want_release;
  int handled;
} get_ctx_t;

/* Parse a single "bytes=..." Range header into [*out_start, *out_end] for an
 * object of total bytes. Supports "a-b", open-ended "a-", and suffix "-n".
 * Returns 0 on a satisfiable range, -1 on malformed or unsatisfiable input
 * (the caller answers 416). */
static int parse_byte_range(const char *header, uint64_t total, uint64_t *out_start,
                            uint64_t *out_end) {
  const char *p;
  char *endptr = NULL;
  uint64_t start;
  uint64_t end;

  if (!header || total == 0u)
    return -1;
  if (strncmp(header, "bytes=", 6u) != 0)
    return -1;
  p = header + 6u;
  if (strchr(p, ',') != NULL)
    return -1; /* multiple ranges unsupported */

  if (*p == '-') {
    /* Suffix range: last N bytes (bytes=-N). */
    uint64_t suffix;

    p++;
    if (*p < '0' || *p > '9')
      return -1;
    errno = 0;
    suffix = strtoull(p, &endptr, 10);
    if (errno == ERANGE || endptr == p || *endptr != '\0')
      return -1;
    if (suffix == 0u)
      return -1; /* bytes=-0 is never satisfiable */
    if (suffix > total)
      suffix = total;
    start = total - suffix;
    end = total - 1u;
  } else {
    if (*p < '0' || *p > '9')
      return -1;
    errno = 0;
    start = strtoull(p, &endptr, 10);
    if (errno == ERANGE || endptr == p || *endptr != '-')
      return -1;
    p = endptr + 1;
    if (*p == '\0') {
      end = total - 1u; /* open-ended: bytes=N- */
    } else {
      if (*p < '0' || *p > '9')
        return -1;
      errno = 0;
      end = strtoull(p, &endptr, 10);
      if (errno == ERANGE || endptr == p || *endptr != '\0')
        return -1;
      if (end > total - 1u)
        return -1;
    }
  }
  if (start > total - 1u || start > end)
    return -1;
  *out_start = start;
  *out_end = end;
  return 0;
}

/* Assemble [range_start, range_end] (absolute object offsets) into a freshly
 * allocated buffer. Each overlapping chunk is read through its placement
 * replicas when the data plane is attached, otherwise through the local CAS.
 * The store verifies the complete chunk CID before any byte is returned, and
 * a replica that cannot serve the range fails the whole read (never a
 * truncated 200). Returns 0 and owns *out_buffer on success. */
int m3_gateway_read_object_v1(m3_gateway_t *g, const uint8_t *manifest_bytes,
                              size_t manifest_size, uint64_t range_start,
                              uint64_t range_end, uint8_t **out_buffer,
                              size_t *out_len) {
  m3_object_manifest_owned_v2_t owned = {0};
  uint8_t *buffer;
  size_t want;
  size_t filled = 0u;
  uint64_t pos = 0u;
  int rc = -1;

  if (out_buffer)
    *out_buffer = NULL;
  if (out_len)
    *out_len = 0u;
  if (!g || !g->initialized || !manifest_bytes || !out_buffer || !out_len ||
      m3_object_manifest_decode_v2(
          manifest_bytes, manifest_size, M3_GATEWAY_MAX_OBJECT_BYTES,
          M3_GATEWAY_MAX_CHUNKS,
          M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
          &owned) != M3_OBJECT_MANIFEST_OK) {
    return -1;
  }
  if (range_start > range_end ||
      range_end >= owned.manifest.object_cid.size) {
    m3_object_manifest_owned_destroy_v2(&owned);
    return -1;
  }
  want = (size_t)(range_end - range_start + 1u);
  buffer = (uint8_t *)malloc(want);
  if (!buffer) {
    m3_object_manifest_owned_destroy_v2(&owned);
    return -1;
  }
  for (size_t i = 0u; i < owned.manifest.chunk_count; i++) {
    const m3_chunk_cid_v1_t *cid = &owned.manifest.chunks[i];
    uint64_t chunk_start = pos;
    uint64_t chunk_end = pos + cid->size - 1u;
    uint64_t read_start;
    uint64_t read_end;
    uint64_t chunk_offset;
    size_t chunk_len;

    pos = chunk_end + 1u;
    if (chunk_end < range_start || chunk_start > range_end)
      continue;
    read_start = chunk_start > range_start ? chunk_start : range_start;
    read_end = chunk_end < range_end ? chunk_end : range_end;
    chunk_offset = read_start - chunk_start;
    chunk_len = (size_t)(read_end - read_start + 1u);
    if (g->datapane_enabled && manifest_chunk_has_placements(&owned.manifest, i)) {
      size_t read = 0u;

      if (m3_gateway_datapane_read_chunk_v1(
              &g->datapane, &owned.manifest, i, cid, chunk_offset, chunk_len,
              gateway_now_ms(), buffer + filled, &read) !=
              M3_GATEWAY_DATAPANE_OK ||
          read != chunk_len) {
        free(buffer);
        m3_object_manifest_owned_destroy_v2(&owned);
        return -1;
      }
      filled += read;
    } else {
      size_t done = 0u;

      while (done < chunk_len) {
        size_t take = chunk_len - done;
        size_t read = 0u;

        if (take > (size_t)g->max_chunk_bytes)
          take = (size_t)g->max_chunk_bytes;
        if (m3_chunk_store_read_range_v1(&g->chunk_store, cid, chunk_offset + done,
                                         take, buffer + filled, &read) !=
                M3_CHUNK_STORE_OK ||
            read == 0u) {
          free(buffer);
          m3_object_manifest_owned_destroy_v2(&owned);
          return -1;
        }
        done += read;
        filled += read;
      }
    }
  }
  *out_buffer = buffer;
  *out_len = filled;
  rc = 0;
  m3_object_manifest_owned_destroy_v2(&owned);
  return rc;
}

/* Serve a committed object manifest with optional HTTP Range support.
 * Shared by the plain object GET and the release-file download route.
 * Mirrors the object-serving tail previously inlined in get_lookup_complete.
 */
static void serve_manifest_object(m3_gateway_t *g, Res *res,
                                  const uint8_t *manifest_bytes,
                                  size_t manifest_size,
                                  const char *range_header) {
  m3_object_manifest_owned_v2_t owned = {0};
  uint64_t total;
  uint64_t range_start = 0u;
  uint64_t range_end = 0u;
  int status = 200;
  char content_range[96];
  char etag[2u + 2u * M3_CHUNK_CID_DIGEST_SIZE + 1u];
  uint8_t *buffer = NULL;
  size_t buffer_len = 0u;

  if (m3_object_manifest_decode_v2(
          manifest_bytes, manifest_size, M3_GATEWAY_MAX_OBJECT_BYTES,
          M3_GATEWAY_MAX_CHUNKS,
          M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
          &owned) != M3_OBJECT_MANIFEST_OK) {
    send_s3_error(res, 404, "NoSuchKey", "The specified key does not exist.");
    return;
  }
  total = owned.manifest.object_cid.size;
  if (range_header && range_header[0]) {
    if (parse_byte_range(range_header, total, &range_start, &range_end) != 0) {
      snprintf(content_range, sizeof(content_range), "bytes */%llu",
               (unsigned long long)total);
      set_header(res, "Content-Range", content_range);
      send_s3_error(res, 416, "InvalidRange", "The requested range is not satisfiable.");
      m3_object_manifest_owned_destroy_v2(&owned);
      return;
    }
    status = 206;
    snprintf(content_range, sizeof(content_range), "bytes %llu-%llu/%llu",
             (unsigned long long)range_start, (unsigned long long)range_end,
             (unsigned long long)total);
    set_header(res, "Content-Range", content_range);
  } else {
    range_start = 0u;
    range_end = total > 0u ? total - 1u : 0u;
  }

  gateway_etag_quoted(owned.manifest.object_cid.digest,
                      sizeof(owned.manifest.object_cid.digest), etag);
  set_header(res, "ETag", etag);
  if (total > 0u &&
      m3_gateway_read_object_v1(g, manifest_bytes, manifest_size, range_start,
                                range_end, &buffer, &buffer_len) != 0) {
    send_s3_error(res, 507, "InsufficientStorage", "Out of memory.");
    m3_object_manifest_owned_destroy_v2(&owned);
    return;
  }
  reply(res, status, "application/octet-stream", buffer, buffer_len);
  free(buffer);
  m3_object_manifest_owned_destroy_v2(&owned);
}

static void get_lookup_complete(m3_namespace_lookup_result_t result,
                                const m3_namespace_lookup_response_v1_t *response,
                                void *user_data) {
  get_ctx_t *ctx = (get_ctx_t *)user_data;
  m3_gateway_t *g = ctx->gateway;
  m3_object_manifest_owned_v2_t owned = {0};
  uint64_t total;

  ctx->handled = 1;
  if (result != M3_NAMESPACE_LOOKUP_OK || !response ||
      m3_object_manifest_decode_v2(
          response->manifest_bytes, response->manifest_size,
          M3_GATEWAY_MAX_OBJECT_BYTES, M3_GATEWAY_MAX_CHUNKS,
          M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
          &owned) != M3_OBJECT_MANIFEST_OK) {
    send_s3_error(ctx->res, 404, "NoSuchKey", "The specified key does not exist.");
    return;
  }
  total = owned.manifest.object_cid.size;
  if (ctx->want_playlist) {
    /* Serve the HLS-style media playlist for the object: a player fetches
     * /:bucket/:object/playlist.m3u8 then each segment's byte range. */
    mesh_media_index_v1_t index;
    size_t playlist_cap = (owned.manifest.chunk_count + 1u) * 96u + 128u;
    char *playlist = (char *)malloc(playlist_cap);
    size_t playlist_len = 0u;

    if (playlist) {
      memset(&index, 0, sizeof(index));
      if (mesh_media_index_build_v1(&index, &owned.manifest,
                                    MESH_MEDIA_INDEX_DEFAULT_SEGMENT_BYTES) ==
              MESH_MEDIA_INDEX_OK &&
          mesh_media_playlist_media_v1(&owned.manifest, &index,
                                       M3_GATEWAY_PLAYLIST_DURATION_MS, playlist,
                                       playlist_cap, &playlist_len) ==
              MESH_MEDIA_PLAYLIST_OK) {
        reply(ctx->res, 200, "application/vnd.apple.mpegurl", playlist,
              playlist_len);
        mesh_media_index_destroy_v1(&index);
        free(playlist);
        m3_object_manifest_owned_destroy_v2(&owned);
        return;
      }
      mesh_media_index_destroy_v1(&index);
      free(playlist);
    }
    send_s3_error(ctx->res, 500, "InternalError",
                  "Playlist generation failed.");
    m3_object_manifest_owned_destroy_v2(&owned);
    return;
  }
  if (ctx->want_release) {
    /* Serve a text listing of the release manifest object: a thin HTTP client
     * can read the release contents without decoding the binary manifest. */
    uint8_t *body = NULL;
    size_t body_len = 0u;
    mesh_release_v1_t release;

    if (total > 0u &&
        m3_gateway_read_object_v1(g, response->manifest_bytes,
                                  response->manifest_size, 0u, total - 1u,
                                  &body, &body_len) == 0 &&
        mesh_release_decode_v1(body, body_len, &release) == MESH_RELEASE_OK) {
      size_t listing_cap = (release.count + 2u) * 384u + 128u;
      char *listing = (char *)malloc(listing_cap);
      size_t listing_len = 0u;

      if (listing &&
          mesh_release_format_v1(&release, listing, listing_cap,
                                 &listing_len) == MESH_RELEASE_OK) {
        uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
        char digest_hex[2u * M3_CHUNK_CID_DIGEST_SIZE + 1u];

        /* Machine-readable anchor for the manifest-level digest: the
         * listing text already carries digest=<hex>; the header lets a
         * client cross-check the served manifest bytes. */
        if (mesh_release_digest_v1(&release, digest) == MESH_RELEASE_OK) {
          hex_encode(digest, sizeof(digest), digest_hex);
          set_header(ctx->res, "X-M3-Release-Digest", digest_hex);
        }
        reply(ctx->res, 200, "text/plain", listing, listing_len);
        free(listing);
        free(body);
        m3_object_manifest_owned_destroy_v2(&owned);
        return;
      }
      free(listing);
    }
    free(body);
    send_s3_error(ctx->res, 500, "InternalError", "Release listing failed.");
    m3_object_manifest_owned_destroy_v2(&owned);
    return;
  }
  serve_manifest_object(g, ctx->res, response->manifest_bytes,
                        response->manifest_size, ctx->range_header);
  m3_object_manifest_owned_destroy_v2(&owned);
}

static int gateway_lookup(m3_gateway_t *g, Req *req, get_ctx_t *ctx) {
  m3_namespace_lookup_request_v1_t request = {0};
  m3_namespace_lookup_adapter_v1_t adapter;

  memcpy(request.tenant_id, g->tenant_id, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)get_params(req, "bucket");
  request.bucket_size = strlen((const char *)request.bucket);
  request.object_key = (const uint8_t *)get_params(req, "object");
  request.object_key_size = strlen((const char *)request.object_key);
  request.require_linearizable = 1u;
  adapter = gateway_meta_lookup(g);
  {
    int lookup_result = adapter.start(adapter.context, &request, get_lookup_complete, ctx);
    if (lookup_result == M3_NAMESPACE_LOOKUP_OK && !ctx->handled) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
      if (g->node) {
        /* The node loop is pumped by the owner (background thread or harness);
         * sleep-poll the completion instead of pumping here to avoid a race. */
        for (size_t i = 0u; i < 5000u && !ctx->handled; i++) {
          turbo_sleep_ms(1);
        }
      } else
#endif
      {
        /* raft reads are asynchronous (read-index barrier); drive poll. */
        for (size_t i = 0u; i < 100000u && !ctx->handled; i++) {
          gateway_meta_poll(g);
        }
      }
    }
    return lookup_result;
  }
}

/* Redirect targets are single path segments served under the object route. */
static int is_safe_redirect_target(const char *target) {
  const char *p;

  if (!target || target[0] == '\0' || target[0] == '/' || target[0] == '.')
    return 0;
  for (p = target; *p; p++) {
    if (*p == '/' || *p == '\\' || *p == ':' || *p == '?' || *p == '#' ||
        *p == ' ' || *p == '\t' || (*p == '.' && p[1] == '.'))
      return 0;
  }
  return 1;
}

/* GET /:bucket/:object — object bytes, or a release entry point:
 * ?listing=1 serves the release manifest listing directly, and
 * ?redirect=<segment> answers 302 to /:bucket/:object/<segment> (e.g.
 * release.txt). Plain GET keeps serving the raw object bytes so the
 * release pull client can fetch the canonical manifest unchanged. */
void m3_handle_get_object(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  get_ctx_t ctx = {0};
  const char *redirect = get_query(req, "redirect");

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;
  if (redirect && redirect[0]) {
    const char *bucket = get_params(req, "bucket");
    const char *object = get_params(req, "object");
    char location[1024];

    if (!bucket || !object || bucket[0] == '\0' || object[0] == '\0') {
      send_s3_error(res, 400, "InvalidRequest", "Missing bucket or object.");
      return;
    }
    if (!is_safe_redirect_target(redirect)) {
      send_s3_error(res, 400, "InvalidRequest", "Unsafe redirect target.");
      return;
    }
    if (snprintf(location, sizeof(location), "/%s/%s/%s", bucket, object,
                 redirect) >= (int)sizeof(location)) {
      send_s3_error(res, 400, "InvalidRequest", "Redirect target too long.");
      return;
    }
    set_header(res, "Location", location);
    reply(res, 302, "text/plain", NULL, 0);
    return;
  }
  ctx.gateway = g;
  ctx.res = res;
  ctx.range_header = gateway_header_lookup(req, "Range");
  if (get_query(req, "listing") != NULL)
    ctx.want_release = 1; /* ?listing=1 serves the release manifest listing */
  if (gateway_lookup(g, req, &ctx) != M3_NAMESPACE_LOOKUP_OK && !ctx.handled) {
    if (g->node_lookup_not_leader) {
      send_gateway_not_leader(g, res);
    } else {
      send_s3_error(res, 404, "NoSuchKey", "The specified key does not exist.");
    }
  }
}

/* GET /:bucket/:object/playlist.m3u8 — HLS media playlist for the object. */
void m3_handle_get_playlist(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  get_ctx_t ctx = {0};

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;
  ctx.gateway = g;
  ctx.res = res;
  ctx.want_playlist = 1;
  if (gateway_lookup(g, req, &ctx) != M3_NAMESPACE_LOOKUP_OK && !ctx.handled) {
    if (g->node_lookup_not_leader) {
      send_gateway_not_leader(g, res);
    } else {
      send_s3_error(res, 404, "NoSuchKey", "The specified key does not exist.");
    }
  }
}

/* GET /:bucket/:object/release.txt — text listing of a release manifest. */
void m3_handle_get_release(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  get_ctx_t ctx = {0};

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;
  ctx.gateway = g;
  ctx.res = res;
  ctx.want_release = 1;
  if (gateway_lookup(g, req, &ctx) != M3_NAMESPACE_LOOKUP_OK && !ctx.handled) {
    if (g->node_lookup_not_leader) {
      send_gateway_not_leader(g, res);
    } else {
      send_s3_error(res, 404, "NoSuchKey", "The specified key does not exist.");
    }
  }
}

/* Synchronous committed-manifest fetch through the metadata adapter.
 * Returns 0 and owns *out (released with free()) on success; -1 otherwise.
 * Sets node_lookup_not_leader on the leader-routed failure path so callers
 * can answer 503 with the leader hint.
 */
typedef struct {
  uint8_t *manifest;
  size_t manifest_size;
  int handled;
  int ok;
} manifest_lookup_ctx_t;

static void manifest_lookup_complete(m3_namespace_lookup_result_t result,
                                     const m3_namespace_lookup_response_v1_t *response,
                                     void *user_data) {
  manifest_lookup_ctx_t *ctx = (manifest_lookup_ctx_t *)user_data;

  ctx->handled = 1;
  if (result != M3_NAMESPACE_LOOKUP_OK || !response || response->manifest_size == 0u)
    return;
  ctx->manifest = (uint8_t *)malloc(response->manifest_size);
  if (!ctx->manifest)
    return;
  memcpy(ctx->manifest, response->manifest_bytes, response->manifest_size);
  ctx->manifest_size = response->manifest_size;
  ctx->ok = 1;
}

static int gateway_fetch_manifest(m3_gateway_t *g, const char *bucket,
                                  const char *object, uint8_t **out,
                                  size_t *out_size) {
  m3_namespace_lookup_request_v1_t request = {0};
  m3_namespace_lookup_adapter_v1_t adapter;
  manifest_lookup_ctx_t ctx = {0};
  int result;

  if (out)
    *out = NULL;
  if (out_size)
    *out_size = 0u;
  if (!g || !g->initialized || !bucket || !object || !out || !out_size)
    return -1;
  memcpy(request.tenant_id, g->tenant_id, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)bucket;
  request.bucket_size = strlen(bucket);
  request.object_key = (const uint8_t *)object;
  request.object_key_size = strlen(object);
  request.require_linearizable = 1u;
  adapter = gateway_meta_lookup(g);
  result = adapter.start(adapter.context, &request, manifest_lookup_complete, &ctx);
  if (result == M3_NAMESPACE_LOOKUP_OK && !ctx.handled) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
    if (g->node) {
      for (size_t i = 0u; i < 5000u && !ctx.handled; i++)
        turbo_sleep_ms(1);
    } else
#endif
    {
      for (size_t i = 0u; i < 100000u && !ctx.handled; i++)
        gateway_meta_poll(g);
    }
  }
  if (ctx.ok) {
    *out = ctx.manifest;
    *out_size = ctx.manifest_size;
    return 0;
  }
  free(ctx.manifest);
  return -1;
}

/* SigV4 auth for the release-file route: the canonical resource is the full
 * request path, so every release file URL is signed independently. */
static int gateway_require_release_file_auth(m3_gateway_t *g, Req *req,
                                             Res *res) {
  const char *authorization = gateway_header_lookup(req, "Authorization");
  const char *amzdate = gateway_header_lookup(req, "x-amz-date");
  m3_sigv4_result_t result;

  if (!authorization || !amzdate) {
    send_s3_error(res, 403, "AccessDenied", "Missing signature.");
    return -1;
  }
  if (!req->path || req->path[0] != '/') {
    send_s3_error(res, 400, "InvalidRequest", "Bad path.");
    return -1;
  }
  result = m3_sigv4_verify_request_v1(
      &g->credential, req->method, req->path, NULL, authorization, amzdate,
      NULL, gateway_header_lookup, req, (int64_t)time(NULL));
  if (result != M3_SIGV4_OK) {
    send_s3_error(res, 403, "AccessDenied", "Signature verification failed.");
    return -1;
  }
  return 0;
}

/* Extract the in-release file path from a request path of the form
 * /<bucket>/<object>/<path...>. Returns the tail or NULL on mismatch. */
static const char *release_path_from_request(const char *path,
                                             const char *bucket,
                                             const char *object,
                                             char *out, size_t cap) {
  const char *p;
  size_t blen = strlen(bucket);
  size_t olen = strlen(object);

  if (!path || path[0] != '/' || !out || cap == 0u)
    return NULL;
  p = path + 1;
  if (strncmp(p, bucket, blen) != 0 || p[blen] != '/')
    return NULL;
  p += blen + 1;
  if (strncmp(p, object, olen) != 0 || p[olen] != '/')
    return NULL;
  p += olen + 1;
  if (*p == '\0' || strlen(p) >= cap)
    return NULL;
  strcpy(out, p);
  return out;
}

/* Split a release entry object key "bucket/object" (exactly one '/'). */
static int split_object_key(const char *key, char *bucket, size_t bucket_cap,
                            char *object, size_t object_cap) {
  const char *slash;

  if (!key || key[0] == '\0')
    return -1;
  slash = strchr(key, '/');
  if (!slash || slash == key || strchr(slash + 1, '/') != NULL)
    return -1; /* exactly "bucket/object" is supported */
  if ((size_t)(slash - key) >= bucket_cap || strlen(slash + 1) >= object_cap)
    return -1;
  memcpy(bucket, key, (size_t)(slash - key));
  bucket[slash - key] = '\0';
  strcpy(object, slash + 1);
  return 0;
}

/* GET /:bucket/:object/* — download one release file by its in-release path.
 * The release manifest object at :bucket/:object maps a file path to an M3
 * object key; this route resolves the path and serves the object bytes (with
 * Range support). The SigV4 signature covers the full request path. */
void m3_handle_get_release_file(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  const char *bucket;
  const char *object;
  char release_path[MESH_RELEASE_PATH_MAX];
  uint8_t *release_manifest = NULL;
  size_t release_manifest_size = 0u;
  uint8_t *release_body = NULL;
  size_t release_body_len = 0u;
  mesh_release_v1_t release;
  mesh_release_entry_v1_t entry;
  char target_bucket[M3_GATEWAY_MAX_BUCKET_BYTES];
  char target_object[M3_GATEWAY_MAX_OBJECT_KEY_BYTES];
  uint8_t *target_manifest = NULL;
  size_t target_manifest_size = 0u;
  uint64_t total;

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_release_file_auth(g, req, res) != 0)
    return;
  bucket = get_params(req, "bucket");
  object = get_params(req, "object");
  if (!bucket || !object || bucket[0] == '\0' || object[0] == '\0') {
    send_s3_error(res, 400, "InvalidRequest", "Missing bucket or object.");
    return;
  }
  if (!release_path_from_request(req->path, bucket, object, release_path,
                                sizeof(release_path))) {
    send_s3_error(res, 400, "InvalidRequest", "Release file path required.");
    return;
  }
  if (gateway_fetch_manifest(g, bucket, object, &release_manifest,
                             &release_manifest_size) != 0) {
    if (g->node_lookup_not_leader)
      send_gateway_not_leader(g, res);
    else
      send_s3_error(res, 404, "NoSuchKey", "Release manifest not found.");
    return;
  }
  {
    m3_object_manifest_owned_v2_t owned = {0};

    if (m3_object_manifest_decode_v2(
            release_manifest, release_manifest_size, M3_GATEWAY_MAX_OBJECT_BYTES,
            M3_GATEWAY_MAX_CHUNKS,
            M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
            &owned) != M3_OBJECT_MANIFEST_OK) {
      free(release_manifest);
      send_s3_error(res, 404, "NoSuchKey", "Release manifest invalid.");
      return;
    }
    total = owned.manifest.object_cid.size;
    m3_object_manifest_owned_destroy_v2(&owned);
    if (total == 0u ||
        m3_gateway_read_object_v1(g, release_manifest, release_manifest_size,
                                  0u, total - 1u, &release_body,
                                  &release_body_len) != 0) {
      free(release_manifest);
      send_s3_error(res, 500, "InternalError", "Release manifest read failed.");
      return;
    }
  }
  free(release_manifest);
  memset(&release, 0, sizeof(release));
  if (mesh_release_decode_v1(release_body, release_body_len, &release) !=
      MESH_RELEASE_OK) {
    free(release_body);
    send_s3_error(res, 500, "InternalError", "Release manifest decode failed.");
    return;
  }
  free(release_body);
  if (mesh_release_lookup_v1(&release, release_path, &entry) != MESH_RELEASE_OK) {
    send_s3_error(res, 404, "NoSuchKey", "Release file not found.");
    return;
  }
  if (split_object_key(entry.object_key, target_bucket, sizeof(target_bucket),
                       target_object, sizeof(target_object)) != 0) {
    send_s3_error(res, 500, "InternalError", "Release file object key invalid.");
    return;
  }
  if (gateway_fetch_manifest(g, target_bucket, target_object, &target_manifest,
                             &target_manifest_size) != 0) {
    if (g->node_lookup_not_leader)
      send_gateway_not_leader(g, res);
    else
      send_s3_error(res, 404, "NoSuchKey", "Release file object not found.");
    return;
  }
  serve_manifest_object(g, res, target_manifest, target_manifest_size,
                        gateway_header_lookup(req, "Range"));
  free(target_manifest);
}

/* HEAD /:bucket/:object */
typedef struct {
  m3_gateway_t *gateway;
  Res *res;
  int handled;
} head_ctx_t;

static void head_lookup_complete(m3_namespace_lookup_result_t result,
                                 const m3_namespace_lookup_response_v1_t *response,
                                 void *user_data) {
  head_ctx_t *ctx = (head_ctx_t *)user_data;
  m3_object_manifest_owned_v2_t owned = {0};
  char etag[2u + 2u * M3_CHUNK_CID_DIGEST_SIZE + 1u];

  ctx->handled = 1;
  if (result != M3_NAMESPACE_LOOKUP_OK || !response ||
      m3_object_manifest_decode_v2(
          response->manifest_bytes, response->manifest_size,
          M3_GATEWAY_MAX_OBJECT_BYTES, M3_GATEWAY_MAX_CHUNKS,
          M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
          &owned) != M3_OBJECT_MANIFEST_OK) {
    send_s3_error(ctx->res, 404, "NoSuchKey", "The specified key does not exist.");
    return;
  }
  gateway_etag_quoted(owned.manifest.object_cid.digest, sizeof(owned.manifest.object_cid.digest),
                      etag);
  /* Do not set Content-Length manually: iris's reply() always emits its own
   * Content-Length from body_len, so a second header would duplicate it
   * (RFC 7230 forbids repeated Content-Length). HEAD reports the ETag only;
   * the object size header is an iris limitation. */
  set_header(ctx->res, "ETag", etag);
  reply(ctx->res, 200, "application/octet-stream", NULL, 0);
  m3_object_manifest_owned_destroy_v2(&owned);
}

/* HEAD /:bucket/:object */
void m3_handle_head_object(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  m3_namespace_lookup_request_v1_t request = {0};
  m3_namespace_lookup_adapter_v1_t adapter;
  head_ctx_t ctx = {0};

  if (!g || !g->initialized) {
    reply(res, 500, "application/xml", NULL, 0);
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;

  memcpy(request.tenant_id, g->tenant_id, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)get_params(req, "bucket");
  request.bucket_size = strlen((const char *)request.bucket);
  request.object_key = (const uint8_t *)get_params(req, "object");
  request.object_key_size = strlen((const char *)request.object_key);
  request.require_linearizable = 1u;
  adapter = gateway_meta_lookup(g);
  ctx.gateway = g;
  ctx.res = res;
  {
    int lookup_result = adapter.start(adapter.context, &request, head_lookup_complete, &ctx);
    if (lookup_result == M3_NAMESPACE_LOOKUP_OK && !ctx.handled) {
      for (size_t i = 0u; i < 100000u && !ctx.handled; i++) {
        gateway_meta_poll(g);
      }
    }
    if (lookup_result != M3_NAMESPACE_LOOKUP_OK && !ctx.handled) {
      if (g->node_lookup_not_leader) {
        send_gateway_not_leader(g, res);
      } else {
        send_s3_error(res, 404, "NoSuchKey", "The specified key does not exist.");
      }
    }
  }
}

/* DELETE /:bucket/:object */
void m3_handle_delete_object(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  const char *bucket;
  const char *object;

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;
  bucket = get_params(req, "bucket");
  object = get_params(req, "object");
  if (gateway_meta_tombstone(g, bucket, object) != 0) {
    if (g->node_meta_not_leader) {
      send_gateway_not_leader(g, res);
    } else {
      send_s3_error(res, 500, "InternalError", "Tombstone failed.");
    }
    return;
  }
  if (gateway_meta_persist(g) != 0) {
    send_s3_error(res, 500, "InternalError", "Namespace persist failed.");
    return;
  }
  reply(res, 204, "application/xml", NULL, 0);
}

/* ---------------------------------------------------------------------------
 * GET /:bucket — ListObjects (S3 ListBucketResult v1)
 * ------------------------------------------------------------------------- */

#define M3_GATEWAY_LIST_DEFAULT_MAX_KEYS 1000u
#define M3_GATEWAY_LIST_MAX_KEYS 1000u
#define M3_GATEWAY_LIST_MAX_XML_BYTES (8u * 1024u * 1024u)

/* Phase 1 does not persist object mtimes; listings use a fixed epoch. */
#define M3_GATEWAY_LIST_LAST_MODIFIED "1970-01-01T00:00:00.000Z"

typedef struct {
  const char *marker; /* start-after key; NULL when absent */
  size_t max_keys;
  char *xml;
  size_t xml_len;
  size_t xml_cap;
  size_t listed;
  uint8_t truncated;
  uint8_t failed;
  char next_marker[M3_GATEWAY_MAX_OBJECT_KEY_BYTES + 1u];
} list_ctx_t;

static int list_xml_reserve(list_ctx_t *ctx, size_t extra) {
  size_t need;
  size_t new_cap;

  if (extra > SIZE_MAX - ctx->xml_len) {
    ctx->failed = 1u;
    return -1;
  }
  need = ctx->xml_len + extra;
  if (need <= ctx->xml_cap)
    return 0;
  new_cap = ctx->xml_cap == 0u ? 4096u : ctx->xml_cap;
  while (new_cap < need && new_cap <= M3_GATEWAY_LIST_MAX_XML_BYTES / 2u) {
    new_cap *= 2u;
  }
  if (new_cap < need)
    new_cap = M3_GATEWAY_LIST_MAX_XML_BYTES;
  if (new_cap < need) {
    ctx->failed = 1u;
    return -1;
  }
  ctx->xml = (char *)realloc(ctx->xml, new_cap);
  if (!ctx->xml) {
    ctx->failed = 1u;
    return -1;
  }
  ctx->xml_cap = new_cap;
  return 0;
}

static void list_xml_append(list_ctx_t *ctx, const char *text) {
  size_t len = strlen(text);

  if (list_xml_reserve(ctx, len) != 0)
    return;
  memcpy(ctx->xml + ctx->xml_len, text, len);
  ctx->xml_len += len;
}

static void list_xml_append_n(list_ctx_t *ctx, const char *text, size_t len) {
  if (list_xml_reserve(ctx, len) != 0)
    return;
  memcpy(ctx->xml + ctx->xml_len, text, len);
  ctx->xml_len += len;
}

static void list_xml_append_u64(list_ctx_t *ctx, uint64_t value) {
  char buf[32];
  int n = snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);

  if (n < 0 || (size_t)n >= sizeof(buf)) {
    ctx->failed = 1u;
    return;
  }
  list_xml_append_n(ctx, buf, (size_t)n);
}

static void list_xml_append_escaped(list_ctx_t *ctx, const char *text, size_t len) {
  size_t i;

  for (i = 0u; i < len; i++) {
    char c = text[i];

    switch (c) {
    case '&':
      list_xml_append(ctx, "&amp;");
      break;
    case '<':
      list_xml_append(ctx, "&lt;");
      break;
    case '>':
      list_xml_append(ctx, "&gt;");
      break;
    case '"':
      list_xml_append(ctx, "&quot;");
      break;
    case '\'':
      list_xml_append(ctx, "&apos;");
      break;
    default:
      list_xml_append_n(ctx, text + i, 1u);
      break;
    }
  }
}

static int list_key_cmp(const uint8_t *key, size_t key_size, const char *marker) {
  size_t marker_len = strlen(marker);
  size_t n = key_size < marker_len ? key_size : marker_len;
  int cmp = n == 0u ? 0 : memcmp(key, marker, n);

  if (cmp != 0)
    return cmp;
  return key_size < marker_len ? -1 : (key_size > marker_len ? 1 : 0);
}

static void list_objects_cb(const uint8_t *bucket, size_t bucket_size, const uint8_t *object_key,
                            size_t object_key_size, const uint8_t *manifest_bytes,
                            size_t manifest_size, void *user_data) {
  list_ctx_t *ctx = (list_ctx_t *)user_data;
  m3_object_manifest_owned_v2_t owned = {0};
  char etag[2u + 2u * M3_CHUNK_CID_DIGEST_SIZE + 1u];

  (void)bucket;
  (void)bucket_size;
  if (ctx->failed)
    return;
  if (ctx->marker && ctx->marker[0] &&
      list_key_cmp(object_key, object_key_size, ctx->marker) <= 0) {
    return;
  }
  if (ctx->listed >= ctx->max_keys) {
    ctx->truncated = 1u;
    return;
  }
  if (m3_object_manifest_decode_v2(
          manifest_bytes, manifest_size, M3_GATEWAY_MAX_OBJECT_BYTES,
          M3_GATEWAY_MAX_CHUNKS,
          M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
          &owned) != M3_OBJECT_MANIFEST_OK) {
    ctx->failed = 1u;
    return;
  }
  if (object_key_size > sizeof(ctx->next_marker) - 1u) {
    m3_object_manifest_owned_destroy_v2(&owned);
    ctx->failed = 1u;
    return;
  }
  gateway_etag_quoted(owned.manifest.object_cid.digest, sizeof(owned.manifest.object_cid.digest),
                      etag);
  memcpy(ctx->next_marker, object_key, object_key_size);
  ctx->next_marker[object_key_size] = '\0';

  list_xml_append(ctx, "<Contents><Key>");
  list_xml_append_escaped(ctx, (const char *)object_key, object_key_size);
  list_xml_append(ctx, "</Key><LastModified>");
  list_xml_append(ctx, M3_GATEWAY_LIST_LAST_MODIFIED);
  list_xml_append(ctx, "</LastModified><ETag>");
  list_xml_append(ctx, etag);
  list_xml_append(ctx, "</ETag><Size>");
  list_xml_append_u64(ctx, owned.manifest.object_cid.size);
  list_xml_append(ctx, "</Size></Contents>");
  ctx->listed++;
  m3_object_manifest_owned_destroy_v2(&owned);
}

/* GET /:bucket */
static void list_buckets_cb(const uint8_t *bucket, size_t bucket_size,
                             const uint8_t *object_key, size_t object_key_size,
                             const uint8_t *manifest_bytes, size_t manifest_size,
                             void *user_data) {
  list_ctx_t *ctx = (list_ctx_t *)user_data;
  (void)object_key;
  (void)object_key_size;
  (void)manifest_bytes;
  (void)manifest_size;
  if (ctx->failed || bucket == NULL || bucket_size == 0u)
    return;
  list_xml_append(ctx, "<Bucket><Name>");
  list_xml_append_escaped(ctx, (const char *)bucket, bucket_size);
  list_xml_append(ctx, "</Name></Bucket>");
}

void m3_handle_list_objects(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  const char *bucket;
  const char *prefix_raw;
  const char *marker_raw;
  const char *max_keys_raw;
  char prefix[M3_GATEWAY_MAX_OBJECT_KEY_BYTES + 1u];
  char marker[M3_GATEWAY_MAX_OBJECT_KEY_BYTES + 1u];
  size_t max_keys = M3_GATEWAY_LIST_DEFAULT_MAX_KEYS;
  list_ctx_t ctx = {0};
  m3_namespace_local_result_t result;

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;
  bucket = get_params(req, "bucket");
  if (!bucket || bucket[0] == '\0') {
    send_s3_error(res, 400, "InvalidRequest", "Missing bucket.");
    return;
  }

  prefix_raw = get_query(req, "prefix");
  marker_raw = get_query(req, "marker");
  prefix[0] = '\0';
  marker[0] = '\0';
  if (prefix_raw && query_percent_decode(prefix_raw, prefix, sizeof(prefix)) != 0) {
    send_s3_error(res, 400, "InvalidArgument", "prefix is invalid or too long.");
    return;
  }
  if (marker_raw && query_percent_decode(marker_raw, marker, sizeof(marker)) != 0) {
    send_s3_error(res, 400, "InvalidArgument", "marker is invalid or too long.");
    return;
  }
  max_keys_raw = get_query(req, "max-keys");
  if (max_keys_raw) {
    char *endptr = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(max_keys_raw, &endptr, 10);
    if (errno == ERANGE || endptr == max_keys_raw || *endptr != '\0' || parsed == 0u) {
      send_s3_error(res, 400, "InvalidArgument", "max-keys must be an integer between 1 and 1000.");
      return;
    }
    max_keys = parsed > M3_GATEWAY_LIST_MAX_KEYS ? M3_GATEWAY_LIST_MAX_KEYS : (size_t)parsed;
  }

  ctx.marker = marker[0] != '\0' ? marker : NULL;
  ctx.max_keys = max_keys;

  list_xml_append(&ctx, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  list_xml_append(&ctx, "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
  list_xml_append(&ctx, "<Name>");
  list_xml_append_escaped(&ctx, bucket, strlen(bucket));
  list_xml_append(&ctx, "</Name><Prefix>");
  list_xml_append_escaped(&ctx, prefix, strlen(prefix));
  list_xml_append(&ctx, "</Prefix><Marker>");
  list_xml_append_escaped(&ctx, marker, strlen(marker));
  list_xml_append(&ctx, "</Marker><MaxKeys>");
  list_xml_append_u64(&ctx, max_keys);
  list_xml_append(&ctx, "</MaxKeys>");

  result = gateway_meta_list(g, (const uint8_t *)bucket, strlen(bucket),
                              (const uint8_t *)prefix, strlen(prefix),
                              list_objects_cb, &ctx);
  if (result != 0 || ctx.failed) {
    free(ctx.xml);
    if (g->node_lookup_not_leader) {
      send_gateway_not_leader(g, res);
    } else {
      send_s3_error(res, 500, "InternalError", "List failed.");
    }
    return;
  }

  list_xml_append(&ctx, "<IsTruncated>");
  list_xml_append(&ctx, ctx.truncated ? "true" : "false");
  list_xml_append(&ctx, "</IsTruncated>");
  if (ctx.truncated) {
    list_xml_append(&ctx, "<NextMarker>");
    list_xml_append_escaped(&ctx, ctx.next_marker, strlen(ctx.next_marker));
    list_xml_append(&ctx, "</NextMarker>");
  }
  list_xml_append(&ctx, "</ListBucketResult>");
  if (ctx.failed) {
    free(ctx.xml);
    send_s3_error(res, 500, "InternalError", "List failed.");
    return;
  }
  reply(res, 200, "application/xml", ctx.xml, ctx.xml_len);
  free(ctx.xml);
}

/* GET / — Phase 1 returns an empty bucket list. */
void m3_handle_list_buckets(Req *req, Res *res) {
  m3_gateway_t *g = gateway_from_req(req);
  list_ctx_t ctx = {0};

  if (!g || !g->initialized) {
    send_s3_error(res, 500, "InternalError", "Gateway not initialized.");
    return;
  }
  if (gateway_require_auth(g, req, res) != 0)
    return;
  list_xml_append(&ctx, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  list_xml_append(&ctx,
                  "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                  "<Owner><ID>m3</ID><DisplayName>m3</DisplayName></Owner><Buckets>");
  if (gateway_meta_list(g, NULL, 0u, NULL, 0u, list_buckets_cb, &ctx) != 0 || ctx.failed) {
    free(ctx.xml);
    if (g->node_lookup_not_leader) {
      send_gateway_not_leader(g, res);
    } else {
      send_s3_error(res, 500, "InternalError", "List failed.");
    }
    return;
  }
  list_xml_append(&ctx, "</Buckets></ListAllMyBucketsResult>");
  reply(res, 200, "application/xml", ctx.xml ? ctx.xml : "", ctx.xml ? ctx.xml_len : 0u);
  free(ctx.xml);
}

int m3_gateway_init_v1(m3_gateway_t *gateway, const char *store_root, uint64_t max_chunk_bytes,
                       const m3_sigv4_credential_v1_t *credential, size_t namespace_capacity) {
  m3_chunk_store_result_t store_result;
  m3_namespace_local_result_t ns_result;

  if (!gateway || !store_root || store_root[0] == '\0' || !credential || max_chunk_bytes == 0u ||
      max_chunk_bytes > M3_GATEWAY_MAX_CHUNK_BYTES || !credential->access_key[0] ||
      !credential->region || !credential->service) {
    return -1;
  }
  memset(gateway, 0, sizeof(*gateway));
  store_result = m3_chunk_store_open_v1(&gateway->chunk_store, store_root, max_chunk_bytes);
  if (store_result != M3_CHUNK_STORE_OK) {
    fprintf(stderr, "m3_gateway_init_node_v1: chunk store open failed rc=%d\n", (int)store_result);
    return -1;
  }
  ns_result = m3_namespace_local_store_init_v1(
      &gateway->namespace_store, namespace_capacity, M3_GATEWAY_MAX_BUCKET_BYTES,
      M3_GATEWAY_MAX_OBJECT_KEY_BYTES, M3_GATEWAY_MAX_MANIFEST_BYTES, M3_GATEWAY_MAX_OBJECT_BYTES,
      M3_GATEWAY_MAX_CHUNKS);
  if (ns_result != M3_NAMESPACE_LOCAL_OK) {
    fprintf(stderr, "m3_gateway_init_node_v1: namespace init failed rc=%d\n", (int)ns_result);
    m3_chunk_store_close_v1(&gateway->chunk_store);
    return -1;
  }
  ns_result =
      m3_namespace_local_store_load_v1(&gateway->namespace_store, store_root, namespace_capacity);
  if (ns_result != M3_NAMESPACE_LOCAL_OK) {
    m3_namespace_local_store_destroy_v1(&gateway->namespace_store);
    m3_chunk_store_close_v1(&gateway->chunk_store);
    return -1;
  }
  gateway->applied_index = gateway->namespace_store.applied_index;
  gateway->credential = *credential;
  strncpy(gateway->store_root, store_root, sizeof(gateway->store_root) - 1u);
  gateway->max_chunk_bytes = max_chunk_bytes;
  memcpy(gateway->tenant_id, "m3-gateway-default-tenant-0001", sizeof(gateway->tenant_id));
  gateway->tenant_id[sizeof(gateway->tenant_id) - 1u] = 0u;
  gateway->initialized = 1u;
  g_gateway = gateway;
  return 0;
}

int m3_gateway_init_raft_v1(m3_gateway_t *gateway, const char *store_root, uint64_t max_chunk_bytes,
                            const m3_sigv4_credential_v1_t *credential, size_t namespace_capacity,
                            const struct m3_gateway_raft_config_s *raft_config) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  m3_chunk_store_result_t store_result;
  m3_namespace_local_result_t ns_result;
  int result;

  if (!gateway || !store_root || store_root[0] == '\0' || !credential || max_chunk_bytes == 0u ||
      max_chunk_bytes > M3_GATEWAY_MAX_CHUNK_BYTES || !credential->access_key[0] ||
      !credential->region || !credential->service || !raft_config) {
    return -1;
  }
  memset(gateway, 0, sizeof(*gateway));
  store_result = m3_chunk_store_open_v1(&gateway->chunk_store, store_root, max_chunk_bytes);
  if (store_result != M3_CHUNK_STORE_OK) {
    fprintf(stderr, "m3_gateway_init_node_v1: chunk store open failed rc=%d\n", (int)store_result);
    return -1;
  }
  ns_result = m3_namespace_local_store_init_v1(
      &gateway->namespace_store, namespace_capacity, M3_GATEWAY_MAX_BUCKET_BYTES,
      M3_GATEWAY_MAX_OBJECT_KEY_BYTES, M3_GATEWAY_MAX_MANIFEST_BYTES, M3_GATEWAY_MAX_OBJECT_BYTES,
      M3_GATEWAY_MAX_CHUNKS);
  if (ns_result != M3_NAMESPACE_LOCAL_OK) {
    fprintf(stderr, "m3_gateway_init_node_v1: namespace init failed rc=%d\n", (int)ns_result);
    m3_chunk_store_close_v1(&gateway->chunk_store);
    return -1;
  }
  gateway->credential = *credential;
  strncpy(gateway->store_root, store_root, sizeof(gateway->store_root) - 1u);
  gateway->max_chunk_bytes = max_chunk_bytes;
  memcpy(gateway->tenant_id, "m3-gateway-default-tenant-0001", sizeof(gateway->tenant_id));
  gateway->tenant_id[sizeof(gateway->tenant_id) - 1u] = 0u;
  result = m3_gateway_raft_open_v1((const m3_gateway_raft_config_v1_t *)raft_config,
                                   &gateway->namespace_store, &gateway->raft);
  if (result != TURBO_OK) {
    m3_namespace_local_store_destroy_v1(&gateway->namespace_store);
    m3_chunk_store_close_v1(&gateway->chunk_store);
    return -1;
  }
  gateway->initialized = 1u;
  g_gateway = gateway;
  return 0;
#else
  (void)gateway;
  (void)store_root;
  (void)max_chunk_bytes;
  (void)credential;
  (void)namespace_capacity;
  (void)raft_config;
  return -1; /* raft metadata requires TURBOP2P_BUILD_TURBORAFT_M3 */
#endif
}

int m3_gateway_init_node_v1(m3_gateway_t *gateway, const char *store_root,
                            uint64_t max_chunk_bytes,
                            const m3_sigv4_credential_v1_t *credential,
                            size_t namespace_capacity,
                            const struct m3_raft_node_config_s *node_config) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
  m3_chunk_store_result_t store_result;
  m3_namespace_local_result_t ns_result;
  int result;

  if (!gateway || !store_root || store_root[0] == '\0' || !credential || max_chunk_bytes == 0u ||
      max_chunk_bytes > M3_GATEWAY_MAX_CHUNK_BYTES || !credential->access_key[0] ||
      !credential->region || !credential->service || !node_config) {
    return -1;
  }
  memset(gateway, 0, sizeof(*gateway));
  store_result = m3_chunk_store_open_v1(&gateway->chunk_store, store_root, max_chunk_bytes);
  if (store_result != M3_CHUNK_STORE_OK) {
    fprintf(stderr, "m3_gateway_init_node_v1: chunk store open failed rc=%d\n", (int)store_result);
    return -1;
  }
  ns_result = m3_namespace_local_store_init_v1(
      &gateway->namespace_store, namespace_capacity, M3_GATEWAY_MAX_BUCKET_BYTES,
      M3_GATEWAY_MAX_OBJECT_KEY_BYTES, M3_GATEWAY_MAX_MANIFEST_BYTES, M3_GATEWAY_MAX_OBJECT_BYTES,
      M3_GATEWAY_MAX_CHUNKS);
  if (ns_result != M3_NAMESPACE_LOCAL_OK) {
    fprintf(stderr, "m3_gateway_init_node_v1: namespace init failed rc=%d\n", (int)ns_result);
    m3_chunk_store_close_v1(&gateway->chunk_store);
    return -1;
  }
  gateway->credential = *credential;
  strncpy(gateway->store_root, store_root, sizeof(gateway->store_root) - 1u);
  gateway->max_chunk_bytes = max_chunk_bytes;
  memcpy(gateway->tenant_id, "m3-gateway-default-tenant-0001", sizeof(gateway->tenant_id));
  gateway->tenant_id[sizeof(gateway->tenant_id) - 1u] = 0u;
  result = m3_raft_node_create((const m3_raft_node_config_t *)node_config, &gateway->node);
  if (result != TURBO_OK) {
    fprintf(stderr, "m3_gateway_init_node_v1: raft node create failed rc=%d\n", result);
    m3_namespace_local_store_destroy_v1(&gateway->namespace_store);
    m3_chunk_store_close_v1(&gateway->chunk_store);
    return -1;
  }
  gateway->initialized = 1u;
  g_gateway = gateway;
  return 0;
#else
  (void)gateway;
  (void)store_root;
  (void)max_chunk_bytes;
  (void)credential;
  (void)namespace_capacity;
  (void)node_config;
  return -1; /* raft node metadata requires TURBOP2P_BUILD_TURBORAFT_M3 */
#endif
}

static void gateway_unbind_gateway(m3_gateway_t *gateway) {
  m3_gateway_app_binding_t *binding;
  m3_gateway_app_binding_t *prev = NULL;

  for (binding = g_gateway_bindings; binding != NULL; binding = binding->next) {
    if (binding->gateway == gateway) {
      if (prev != NULL) {
        prev->next = binding->next;
      } else {
        g_gateway_bindings = binding->next;
      }
      free(binding);
      return;
    }
    prev = binding;
  }
}

void m3_gateway_destroy_v1(m3_gateway_t *gateway) {
  if (!gateway)
    return;
  gateway_unbind_gateway(gateway);
  if (gateway->initialized) {
#ifdef TURBO_P2P_M3_RAFT_ENABLED
    if (gateway->node_lookup_bridge != NULL) {
      /* Release a single-flight read that never completed; the raft adapter
       * backing it is destroyed with the node, so the bridge cannot fire. */
      free(gateway->node_lookup_bridge);
      gateway->node_lookup_bridge = NULL;
    }
    gateway->meta_mutation_pending = 0;
    if (gateway->node) {
      m3_raft_node_destroy(gateway->node);
      gateway->node = NULL;
    }
    if (gateway->raft) {
      m3_gateway_raft_close_v1(gateway->raft);
      gateway->raft = NULL;
    }
#endif
    m3_namespace_local_store_destroy_v1(&gateway->namespace_store);
    m3_chunk_store_close_v1(&gateway->chunk_store);
    gateway->initialized = 0u;
  }
  if (g_gateway == gateway)
    g_gateway = NULL;
}

void m3_gateway_register_routes_v1(void *app) {
  iris_app_t *iris = (iris_app_t *)app;

  if (g_gateway != NULL) {
    gateway_bind_app(app, g_gateway);
  }
  iris_app_put(iris, "/:bucket/:object", m3_handle_put_object);
  iris_app_get(iris, "/:bucket/:object/playlist.m3u8", m3_handle_get_playlist);
  iris_app_get(iris, "/:bucket/:object/release.txt", m3_handle_get_release);
  iris_app_get(iris, "/:bucket/:object", m3_handle_get_object);
  iris_app_get(iris, "/:bucket/:object/*", m3_handle_get_release_file);
  iris_app_route(iris, "HEAD", "/:bucket/:object", NO_MW, m3_handle_head_object);
  iris_app_delete(iris, "/:bucket/:object", m3_handle_delete_object);
  iris_app_get(iris, "/", m3_handle_list_buckets);
  iris_app_get(iris, "/:bucket", m3_handle_list_objects);
}

/* ── Public metadata integration surface (multi-node raft mode) ── */
#ifdef TURBO_P2P_M3_RAFT_ENABLED

typedef struct m3_gateway_meta_lookup_bridge_s {
  int done;
  int ok;
  uint8_t *out;
  size_t cap;
  size_t *out_size;
} m3_gateway_meta_lookup_bridge_v1_t;

static void meta_lookup_complete_v1(m3_namespace_lookup_result_t result,
                                    const m3_namespace_lookup_response_v1_t *response,
                                    void *user_data) {
  m3_gateway_meta_lookup_bridge_v1_t *bridge =
      (m3_gateway_meta_lookup_bridge_v1_t *)user_data;

  bridge->done = 1;
  if (result == M3_NAMESPACE_LOOKUP_OK && response != NULL &&
      response->manifest_size <= bridge->cap) {
    memcpy(bridge->out, response->manifest_bytes, response->manifest_size);
    *bridge->out_size = response->manifest_size;
    bridge->ok = 1;
  }
}

int m3_gateway_meta_put_v1(m3_gateway_t *gateway, const char *bucket,
                           const char *object, const uint8_t *manifest_bytes,
                           size_t manifest_size) {
  if (!gateway || !gateway->initialized) {
    return -1;
  }
  if (gateway_meta_put(gateway, bucket, object, manifest_bytes, manifest_size) != 0) {
    return gateway->node_meta_not_leader ? 1 : -1;
  }
  return 0;
}

int m3_gateway_meta_tombstone_v1(m3_gateway_t *gateway, const char *bucket,
                                 const char *object) {
  if (!gateway || !gateway->initialized) {
    return -1;
  }
  if (gateway_meta_tombstone(gateway, bucket, object) != 0) {
    return gateway->node_meta_not_leader ? 1 : -1;
  }
  return 0;
}

int m3_gateway_meta_put_start_v1(m3_gateway_t *gateway, const char *bucket,
                                 const char *object, const uint8_t *manifest_bytes,
                                 size_t manifest_size) {
  if (!gateway || !gateway->initialized || !gateway->node) {
    return -1;
  }
  if (gateway_meta_put_start(gateway, bucket, object, manifest_bytes, manifest_size) != 0) {
    return gateway->node_meta_not_leader ? 1 : -1;
  }
  return 0;
}

int m3_gateway_meta_tombstone_start_v1(m3_gateway_t *gateway, const char *bucket,
                                       const char *object) {
  if (!gateway || !gateway->initialized || !gateway->node) {
    return -1;
  }
  if (gateway_meta_tombstone_start(gateway, bucket, object) != 0) {
    return gateway->node_meta_not_leader ? 1 : -1;
  }
  return 0;
}

int m3_gateway_meta_mutation_pending_v1(const m3_gateway_t *gateway) {
  return (gateway && gateway->node) ? gateway->meta_mutation_pending : 0;
}

int m3_gateway_meta_lookup_start_v1(m3_gateway_t *gateway, const char *bucket,
                                    const char *object, uint8_t *manifest_out,
                                    size_t manifest_cap, size_t *manifest_size,
                                    m3_gateway_lookup_result_v1_t *out) {
  m3_namespace_lookup_request_v1_t request = {0};
  m3_namespace_lookup_adapter_v1_t adapter;
  m3_gateway_meta_lookup_bridge_v1_t *bridge;
  m3_namespace_lookup_result_t result;

  if (!gateway || !gateway->initialized || !gateway->node || !bucket || !object ||
      !out || !manifest_out || manifest_cap == 0u || !manifest_size) {
    return -1;
  }
  if (gateway->node_lookup_bridge != NULL) {
    return -1; /* single-flight in-progress read */
  }
  memset(out, 0, sizeof(*out));
  *manifest_size = 0u;
  bridge = (m3_gateway_meta_lookup_bridge_v1_t *)calloc(1u, sizeof(*bridge));
  if (bridge == NULL) {
    return -1;
  }
  bridge->out = manifest_out;
  bridge->cap = manifest_cap;
  bridge->out_size = manifest_size;

  memcpy(request.tenant_id, gateway->tenant_id, sizeof(request.tenant_id));
  request.bucket = (const uint8_t *)bucket;
  request.bucket_size = strlen(bucket);
  request.object_key = (const uint8_t *)object;
  request.object_key_size = strlen(object);
  request.require_linearizable = 1u;
  adapter = gateway_meta_lookup(gateway);
  result = adapter.start(adapter.context, &request, meta_lookup_complete_v1, bridge);
  if (result != M3_NAMESPACE_LOOKUP_OK) {
    free(bridge);
    if (gateway->node_lookup_not_leader) {
      out->not_leader = 1;
      out->leader_id = gateway->node_lookup_leader_id;
      return 1;
    }
    return result == M3_NAMESPACE_LOOKUP_NOT_FOUND ? 0 : -1;
  }
  gateway->node_lookup_bridge = bridge;
  return 0;
}

int m3_gateway_meta_lookup_try_v1(m3_gateway_t *gateway,
                                  m3_gateway_lookup_result_v1_t *out,
                                  int *out_done) {
  m3_gateway_meta_lookup_bridge_v1_t *bridge;

  if (!gateway || !out || !out_done) {
    return -1;
  }
  bridge = gateway->node_lookup_bridge;
  if (bridge == NULL) {
    *out_done = 1;
    return 0;
  }
  if (!bridge->done) {
    *out_done = 0;
    return 0;
  }
  out->found = bridge->ok;
  out->applied_index = gateway->node ? m3_raft_node_applied_index(gateway->node)
                                     : gateway->applied_index;
  free(bridge);
  gateway->node_lookup_bridge = NULL;
  *out_done = 1;
  return 0;
}

int m3_gateway_meta_lookup_v1(m3_gateway_t *gateway, const char *bucket,
                              const char *object, uint8_t *manifest_out,
                              size_t manifest_cap, size_t *manifest_size,
                              m3_gateway_lookup_result_v1_t *out) {
  int done = 0;
  int result;

  result = m3_gateway_meta_lookup_start_v1(gateway, bucket, object, manifest_out,
                                           manifest_cap, manifest_size, out);
  if (result != 0) {
    return result;
  }
  /* The node loop is pumped by the owner (pump thread or harness); sleep-poll
   * here so this convenience path never races that thread on the node. */
  for (size_t i = 0u; i < 5000u && !done; i++) {
    turbo_sleep_ms(1);
    (void)m3_gateway_meta_lookup_try_v1(gateway, out, &done);
  }
  return done ? 0 : -1;
}

void m3_gateway_poll_v1(m3_gateway_t *gateway) {
  if (gateway) {
    gateway_meta_poll(gateway);
  }
}

int m3_gateway_meta_list_v1(m3_gateway_t *gateway, const char *bucket,
                            const char *prefix,
                            void (*callback)(const uint8_t *bucket, size_t bucket_size,
                                             const uint8_t *object_key, size_t object_key_size,
                                             const uint8_t *manifest_bytes,
                                             size_t manifest_size, void *user_data),
                            void *user_data) {
  if (!gateway || !gateway->initialized || callback == NULL) {
    return -1;
  }
  if (gateway_meta_list(gateway, (const uint8_t *)bucket, bucket ? strlen(bucket) : 0u,
                        (const uint8_t *)prefix, prefix ? strlen(prefix) : 0u, callback,
                        user_data) != 0) {
    return gateway->node_lookup_not_leader ? 1 : -1;
  }
  return 0;
}

int m3_gateway_leader_v1(const m3_gateway_t *gateway, tr_raft_node_id_t *out_leader_id) {
  if (!out_leader_id) {
    return -1;
  }
  *out_leader_id = 0u;
  if (gateway && gateway->node) {
    return m3_raft_node_leader(gateway->node, out_leader_id);
  }
  return 0;
}

static int gateway_meta_update_placement_start(m3_gateway_t *g, const char *bucket,
                                               const char *object,
                                               const uint8_t *manifest_bytes,
                                               size_t manifest_size) {
  int leader = 0;

  g->node_meta_not_leader = 0;
  if (m3_raft_node_is_leader(g->node, &leader) != TURBO_OK || !leader) {
    g->node_meta_not_leader = 1;
    (void)m3_raft_node_leader(g->node, &g->node_lookup_leader_id);
    return -1;
  }
  g->meta_mutation_before = m3_raft_node_applied_index(g->node);
  if (m3_raft_node_propose_update_placement(g->node, g->tenant_id, bucket, object,
                                            manifest_bytes, manifest_size) !=
      TURBO_OK) {
    return -1;
  }
  g->meta_mutation_pending = 1;
  return 0;
}

int m3_gateway_repair_object_start_v1(m3_gateway_t *g, const char *bucket,
                                      const char *object, size_t target_replicas,
                                      uint64_t now_ms, int *out_changed) {
  uint8_t manifest[M3_GATEWAY_MAX_MANIFEST_BYTES];
  m3_gateway_lookup_result_v1_t lookup;
  m3_object_manifest_owned_v2_t decoded = {0};
  m3_object_manifest_owned_v2_t updated = {0};
  size_t manifest_size = 0u;
  uint8_t *encoded = NULL;
  size_t encoded_size = 0u;
  m3_repair_result_t repair_result;
  int rc;

  if (out_changed)
    *out_changed = 0;
  if (!g || !g->initialized || !g->datapane_enabled || !bucket || !object ||
      !out_changed || target_replicas == 0u)
    return -1;
  if (m3_gateway_meta_lookup_v1(g, bucket, object, manifest, sizeof(manifest),
                                &manifest_size, &lookup) != 0 || !lookup.found) {
    return lookup.not_leader ? 1 : -1;
  }
  if (m3_object_manifest_decode_v2(
          manifest, manifest_size, M3_GATEWAY_MAX_OBJECT_BYTES,
          M3_GATEWAY_MAX_CHUNKS,
          M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES,
          &decoded) != M3_OBJECT_MANIFEST_OK) {
    return -1;
  }
  repair_result = m3_repair_execute_v1(&g->datapane, &decoded.manifest,
                                       target_replicas, now_ms, &updated);
  if (repair_result == M3_REPAIR_NOT_AVAILABLE) {
    m3_object_manifest_owned_destroy_v2(&decoded);
    return 0;
  }
  if (repair_result != M3_REPAIR_OK) {
    m3_object_manifest_owned_destroy_v2(&decoded);
    return -1;
  }
  if (updated.manifest.placement_count == decoded.manifest.placement_count) {
    m3_object_manifest_owned_destroy_v2(&decoded);
    m3_object_manifest_owned_destroy_v2(&updated);
    return 0;
  }
  *out_changed = 1;
  if (m3_object_manifest_encode_v2(
          &updated.manifest, M3_GATEWAY_MAX_OBJECT_BYTES, M3_GATEWAY_MAX_CHUNKS,
          M3_GATEWAY_MAX_CHUNKS * M3_GATEWAY_DATAPANE_MAX_STORES, &encoded,
          &encoded_size) != M3_OBJECT_MANIFEST_OK) {
    m3_object_manifest_owned_destroy_v2(&decoded);
    m3_object_manifest_owned_destroy_v2(&updated);
    return -1;
  }
  rc = gateway_meta_update_placement_start(g, bucket, object, encoded, encoded_size);
  m3_object_manifest_bytes_free_v2(encoded);
  m3_object_manifest_owned_destroy_v2(&decoded);
  m3_object_manifest_owned_destroy_v2(&updated);
  return rc;
}

int m3_gateway_repair_object_v1(m3_gateway_t *g, const char *bucket,
                                const char *object, size_t target_replicas,
                                uint64_t now_ms, int *out_changed) {
  int rc = m3_gateway_repair_object_start_v1(g, bucket, object, target_replicas,
                                             now_ms, out_changed);

  if (rc != 0)
    return rc;
  if (g->node && gateway_meta_wait(g) != 0)
    return -1;
  return 0;
}

#endif /* TURBO_P2P_M3_RAFT_ENABLED */
