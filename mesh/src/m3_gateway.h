#ifndef M3_GATEWAY_H
#define M3_GATEWAY_H

#include "m3_chunk_store.h"
#include "m3_gateway_datapane.h"
#include "m3_gateway_sigv4.h"
#include "m3_namespace_local_store.h"

#include <stddef.h>
#include <stdint.h>

#ifdef TURBO_P2P_M3_RAFT_ENABLED
#include <turboraft/raft_core.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define M3_GATEWAY_TENANT_ID_SIZE 32u
#define M3_GATEWAY_MAX_BUCKET_BYTES 128u
#define M3_GATEWAY_MAX_OBJECT_KEY_BYTES 1024u
#define M3_GATEWAY_MAX_MANIFEST_BYTES 65536u
#define M3_GATEWAY_MAX_OBJECT_BYTES (UINT64_C(64) * 1024 * 1024 * 1024)
#define M3_GATEWAY_MAX_CHUNKS 4096u

/**
 * Phase 1 single-node M3 gateway state.
 *
 * Object identity: an object is content-addressed by
 * SHA-256(concat(chunk digest)) with size = sum(chunk sizes); single-chunk
 * objects therefore have object_cid == chunk_cid. Object keys must not
 * contain '/' in Phase 1 (the Iris route parameter is single-segment).
 */
struct m3_gateway_raft_s;
struct m3_gateway_raft_config_s;
struct m3_raft_node;
struct m3_raft_node_config_s;

typedef struct {
  m3_chunk_store_v1_t chunk_store;
  m3_namespace_local_store_v1_t namespace_store;
  m3_sigv4_credential_v1_t credential;
  struct m3_gateway_raft_s *raft;    /* non-NULL in Phase 2a raft metadata mode */
  struct m3_raft_node *node;         /* non-NULL in multi-node raft metadata mode */
  int node_lookup_not_leader;        /* last node-mode lookup was not the leader */
  int node_meta_not_leader;          /* last node-mode mutation was not the leader */
  int meta_mutation_pending;         /* a node-mode mutation is awaiting apply */
  uint64_t meta_mutation_before;     /* applied index captured at proposal time */
  struct m3_gateway_meta_lookup_bridge_s *node_lookup_bridge; /* in-flight read */
  tr_raft_node_id_t node_lookup_leader_id; /* leader id for the not-leader result */
  uint8_t tenant_id[M3_GATEWAY_TENANT_ID_SIZE];
  uint64_t applied_index;
  char store_root[TURBO_FS_MAX_PATH];
  uint64_t max_chunk_bytes;
  m3_gateway_datapane_v1_t datapane; /* data-plane client; enabled when stores are registered */
  int datapane_enabled;
  uint8_t initialized;
} m3_gateway_t;

/**
 * Open the chunk store and namespace for one gateway instance.
 *
 * store_root must be an existing absolute directory (the parent is not
 * created). The credential is copied; the caller keeps ownership of the
 * secret bytes and must wipe them.
 */
int m3_gateway_init_v1(m3_gateway_t *gateway, const char *store_root, uint64_t max_chunk_bytes,
                       const m3_sigv4_credential_v1_t *credential, size_t namespace_capacity);

void m3_gateway_destroy_v1(m3_gateway_t *gateway);

/**
 * Open the gateway with a raft metadata backend (Phase 2a, single voter).
 * raft_config is a m3_gateway_raft_config_v1_t*; the namespace store is still
 * initialized locally as the raft state machine target.
 */
int m3_gateway_init_raft_v1(m3_gateway_t *gateway, const char *store_root, uint64_t max_chunk_bytes,
                            const m3_sigv4_credential_v1_t *credential, size_t namespace_capacity,
                            const struct m3_gateway_raft_config_s *raft_config);

/**
 * Open the gateway with a multi-node raft node backend (Phase 2b+). The
 * gateway embeds an m3_raft_node as a voter; metadata writes replicate through
 * raft and reads are served via the linearizable read-index barrier on the
 * leader (followers report NOT_LEADER so the caller can route to the leader).
 * node_config is a m3_raft_node_config_v1_t* and is copied.
 */
int m3_gateway_init_node_v1(m3_gateway_t *gateway, const char *store_root,
                            uint64_t max_chunk_bytes,
                            const m3_sigv4_credential_v1_t *credential,
                            size_t namespace_capacity,
                            const struct m3_raft_node_config_s *node_config);

/**
 * Attach the data-plane client: enable cross-node chunk replication with
 * target_replicas writes and min_durable_replicas before any metadata commit.
 * Must be called before m3_gateway_register_store_v1().
 */
int m3_gateway_attach_datapane_v1(m3_gateway_t *gateway, size_t target_replicas,
                                  size_t min_durable_replicas,
                                  const m3_chunk_capability_policy_v1_t *policy);

/**
 * Register one in-process store node (P3). store_public_key is the store's
 * Ed25519 key used to verify durable receipts.
 */
int m3_gateway_register_store_v1(m3_gateway_t *gateway,
                                 const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
                                 const uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
                                 m3_store_node_v1_t *store);

/**
 * Attach the authenticated p2p transport for mesh stores (P4). node is the
 * gateway's p2p node (loop pumped externally); private_key is its identity
 * key used to sign chunk capabilities. Must be called before
 * m3_gateway_register_mesh_store_v1().
 */
int m3_gateway_attach_mesh_v1(m3_gateway_t *gateway, p2p_node_t *node,
                              const uint8_t private_key[MESH_MGMT_ED25519_PRIVATE_KEY_SIZE]);

/**
 * Register one store reachable over p2p at host:port. store_public_key
 * verifies durable receipts; chunk payloads are capped by the mesh transport.
 */
int m3_gateway_register_mesh_store_v1(m3_gateway_t *gateway,
                                      const uint8_t store_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE],
                                      const uint8_t store_public_key[MESH_MGMT_ED25519_PUBLIC_KEY_SIZE],
                                      const char *host, int port);

/**
 * Object-level PUT used by the HTTP handler and tests. Chunks the body,
 * durably replicates to the attached store nodes (falling back to the local
 * CAS when no store is attached), and proposes the manifest through the
 * metadata backend. Returns 0 on success (etag filled), 1 when not the leader,
 * -1 on error.
 */
int m3_gateway_put_object_v1(m3_gateway_t *gateway, const char *bucket,
                             const char *object, const uint8_t *body,
                             size_t body_len, char *etag_out, size_t etag_cap);

/**
 * Non-blocking PUT start: prepares the manifest (replicating chunks to the
 * attached store nodes) and proposes it. Returns 0 when accepted (etag filled;
 * completion observed via m3_gateway_meta_mutation_pending_v1 while the node
 * loops are pumped), 1 when not the leader, 2 on insufficient storage, -1 on
 * error.
 */
int m3_gateway_put_object_start_v1(m3_gateway_t *gateway, const char *bucket,
                                   const char *object, const uint8_t *body,
                                   size_t body_len, char *etag_out, size_t etag_cap);

/**
 * Assemble [range_start, range_end] (absolute object offsets) from the
 * committed manifest, reading chunks through the placement replicas when
 * present and the local CAS otherwise. On success *out_buffer is owned by the
 * caller and released with free(). Returns 0 on success, -1 on error.
 */
int m3_gateway_read_object_v1(m3_gateway_t *gateway,
                              const uint8_t *manifest_bytes, size_t manifest_size,
                              uint64_t range_start, uint64_t range_end,
                              uint8_t **out_buffer, size_t *out_len);

/**
 * Register the Phase 1 S3-shaped routes on an Iris app. Handlers resolve the
 * gateway from a module-level singleton; only one live gateway is supported.
 */
void m3_gateway_register_routes_v1(void *app);
/**
 * Register the Phase 1 S3-shaped routes on an Iris app. Handlers resolve the
 * gateway from a module-level singleton; only one live gateway is supported.
 */
void m3_gateway_register_routes_v1(void *app);

#ifdef TURBO_P2P_M3_RAFT_ENABLED
/** Metadata integration surface (multi-node mode): 0 ok, 1 not-leader, -1 error. */
int m3_gateway_meta_put_v1(m3_gateway_t *gateway, const char *bucket,
                           const char *object, const uint8_t *manifest_bytes,
                           size_t manifest_size);
int m3_gateway_meta_tombstone_v1(m3_gateway_t *gateway, const char *bucket,
                                 const char *object);

/**
 * Non-blocking mutation start for multi-node mode: returns 0 when the proposal
 * is accepted (completion is observed via m3_gateway_meta_mutation_pending_v1
 * while the caller pumps the participating node loops), 1 when not the leader,
 * -1 on error. Blocking callers can use m3_gateway_meta_put_v1 instead.
 */
int m3_gateway_meta_put_start_v1(m3_gateway_t *gateway, const char *bucket,
                                 const char *object, const uint8_t *manifest_bytes,
                                 size_t manifest_size);
int m3_gateway_meta_tombstone_start_v1(m3_gateway_t *gateway, const char *bucket,
                                       const char *object);
/** TRUE while a started mutation has not yet been applied locally. */
int m3_gateway_meta_mutation_pending_v1(const m3_gateway_t *gateway);

typedef struct {
  int found;
  int not_leader;
  tr_raft_node_id_t leader_id;
  uint64_t applied_index;
} m3_gateway_lookup_result_v1_t;

/** Leader-aware metadata lookup. Manifest is copied into manifest_out. */
int m3_gateway_meta_lookup_v1(m3_gateway_t *gateway, const char *bucket,
                              const char *object, uint8_t *manifest_out,
                              size_t manifest_cap, size_t *manifest_size,
                              m3_gateway_lookup_result_v1_t *out);

/**
 * Non-blocking leader-aware lookup start for multi-node mode: returns 0 when
 * the read-index barrier is in flight (completion observed via
 * m3_gateway_meta_lookup_try_v1 while the caller pumps the participating node
 * loops), 1 when not the leader, -1 on error. manifest_out must outlive the
 * in-flight lookup. Blocking callers can use m3_gateway_meta_lookup_v1.
 */
int m3_gateway_meta_lookup_start_v1(m3_gateway_t *gateway, const char *bucket,
                                    const char *object, uint8_t *manifest_out,
                                    size_t manifest_cap, size_t *manifest_size,
                                    m3_gateway_lookup_result_v1_t *out);
/** Non-blocking completion check; sets *out_done when the read finished. */
int m3_gateway_meta_lookup_try_v1(m3_gateway_t *gateway,
                                  m3_gateway_lookup_result_v1_t *out,
                                  int *out_done);

/**
 * Leader-routed namespace enumeration (ListObjects): returns 0 on success,
 * 1 when the local node is not the leader, -1 on error. callback matches
 * m3_namespace_list_cb; manifests are borrowed for the callback only.
 */
int m3_gateway_meta_list_v1(m3_gateway_t *gateway, const char *bucket,
                            const char *prefix,
                            void (*callback)(const uint8_t *bucket, size_t bucket_size,
                                             const uint8_t *object_key, size_t object_key_size,
                                             const uint8_t *manifest_bytes,
                                             size_t manifest_size, void *user_data),
                            void *user_data);

/** Pump the embedded raft node event loop (metadata progress). */
void m3_gateway_poll_v1(m3_gateway_t *gateway);

/** Current raft leader id (0 when unknown). */
int m3_gateway_leader_v1(const m3_gateway_t *gateway, tr_raft_node_id_t *out_leader_id);

/**
 * Leader-aware repair of one object: reads the committed manifest, backfills
 * under-replicated chunks onto unused stores and proposes UPDATE_PLACEMENT.
 * Non-blocking start returns 0 when accepted (completion observed via
 * m3_gateway_meta_mutation_pending_v1), 1 when not the leader, -1 on error.
 * *out_changed is set when the manifest gained at least one placement.
 */
int m3_gateway_repair_object_start_v1(m3_gateway_t *gateway, const char *bucket,
                                      const char *object, size_t target_replicas,
                                      uint64_t now_ms, int *out_changed);
/** Blocking variant of m3_gateway_repair_object_start_v1. */
int m3_gateway_repair_object_v1(m3_gateway_t *gateway, const char *bucket,
                                const char *object, size_t target_replicas,
                                uint64_t now_ms, int *out_changed);
#endif /* TURBO_P2P_M3_RAFT_ENABLED */

#ifdef __cplusplus
}
#endif

#endif
