#ifndef M3_RAFT_NODE_H
#define M3_RAFT_NODE_H

#include "m3_gateway_raft.h"

#include <turboraft/raft_coronet_peer_service.h>
#include <turboraft/raft_coronet_transport.h>

#include <CoroNet/turbo_coro_socket.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_RAFT_NODE_MAX_PEERS TR_RAFT_CORONET_MAX_PEERS

/**
 * One remote raft voter's endpoint and certificate identity. The fingerprint
 * (sha256:<64 hex>) is the peer's TLS leaf certificate hash registered in the
 * identity registry; it must match what the peer presents during mTLS.
 */
typedef struct m3_raft_node_peer_config_s {
  tr_raft_node_id_t node_id;
  char connect_host[TR_RAFT_CORONET_ENDPOINT_HOST_CAPACITY];
  char request_host[TR_RAFT_CORONET_ENDPOINT_HOST_CAPACITY];
  int port;
  char certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY];
} m3_raft_node_peer_config_t;

/**
 * M3 raft node runtime: CoroNet event loop + TLS listener + outbound dial
 * schedulers + tr_raft_coronet_peer_service + m3_gateway_raft. Strings are
 * copied at create time and owned by the node.
 */
typedef struct m3_raft_node_config_s {
  tr_raft_node_id_t node_id;
  /* Optional 16-byte cluster id. NULL uses a fixed M3 default so all nodes
   * in a deployment agree. */
  const tr_raft_cluster_id_t *cluster_id;
  const char *listen_host; /* e.g. "127.0.0.1" */
  int listen_port;
  const char *sqlite_path;
  const char *cert_file;
  const char *key_file;
  const char *ca_file; /* trust bundle for peer certificate verification */
  const tr_raft_node_id_t *voters;
  size_t voter_count;
  const m3_raft_node_peer_config_t *peers;
  size_t peer_count;
  size_t max_snapshot_bytes;
  size_t max_pending_reads;
} m3_raft_node_config_t;

typedef struct m3_raft_node m3_raft_node_t;

/**
 * Creates the node: coro context, identity registry, peer service, TLS
 * listener (inbound) and outbound schedulers for peers with a larger node id
 * (deterministic dial direction), then the raft service wired to the peer
 * service transport. Starts a persistent stepper coroutine that drives
 * reconnects.
 */
int m3_raft_node_create(const m3_raft_node_config_t *config, m3_raft_node_t **out_node);

/** Pumps the event loop and drives one raft poll. */
int m3_raft_node_poll(m3_raft_node_t *node);

/** Runs poll until done(ctx, node) is true or the deadline expires. */
void m3_raft_node_run_until(m3_raft_node_t *node, uint64_t timeout_ms,
                            int (*done)(void *ctx, m3_raft_node_t *node), void *ctx);

/**
 * Non-blocking PUT proposal. Completion is observed by polling until
 * applied_index advances on a quorum (m3_raft_node_applied_index).
 */
int m3_raft_node_propose_put(m3_raft_node_t *node,
                             const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                             const char *bucket, const char *object,
                             const uint8_t *manifest_bytes, size_t manifest_size);

/** Non-blocking tombstone proposal; completion observed via applied_index. */
int m3_raft_node_propose_tombstone(m3_raft_node_t *node,
                                   const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                                   const char *bucket, const char *object);

/** Propose a placement-only update (repair): the manifest must decode and
 *  carry the same object version as the committed one. */
int m3_raft_node_propose_update_placement(
    m3_raft_node_t *node,
    const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
    const char *bucket, const char *object, const uint8_t *manifest_bytes,
    size_t manifest_size);

/** Local raft applied index (commit target of the namespace store). */
uint64_t m3_raft_node_applied_index(const m3_raft_node_t *node);

/** TRUE when this node is the current leader. */
int m3_raft_node_is_leader(const m3_raft_node_t *node, int *out_leader);

/** Current leader id (0 when unknown). Read/linearizable requests must route
 * to the leader (read-index is leader-only). */
int m3_raft_node_leader(const m3_raft_node_t *node, tr_raft_node_id_t *out_leader_id);

/** Borrowed raft gateway handle (read adapter + poll source) for clients that
 * embed the node (e.g. the M3 gateway). Valid until node destroy. */
m3_gateway_raft_v1_t *m3_raft_node_gateway(const m3_raft_node_t *node);

/**
 * Closes the outbound session to one peer (transient partition) without
 * discarding queued messages. The dial scheduler is reset so the next
 * peer_service_step reconnects. Returns TURBO_OK on acceptance.
 */
int m3_raft_node_disconnect_peer(m3_raft_node_t *node, tr_raft_node_id_t peer_node_id);

typedef struct m3_raft_node_status_s {
  int leader;
  uint64_t applied_index;
  size_t connected_peers; /* live sessions (readers) */
  size_t queued_messages; /* pending outbound payloads */
  int last_pump_error;
  uint64_t dropped_messages; /* transport drops on bounded-queue backpressure */
  int raft_faulted;
  int raft_fault_cause;
  int raft_stage; /* last runtime stage when faulted (diagnostic) */
} m3_raft_node_status_t;

/** Diagnostic snapshot for orchestration and tests. */
int m3_raft_node_status(const m3_raft_node_t *node, m3_raft_node_status_t *out);

typedef struct m3_raft_node_lookup_s m3_raft_node_lookup_t;

/**
 * Enumerates the raft-replicated namespace store: buckets when bucket is NULL,
 * otherwise objects under bucket filtered by prefix. Manifest bytes are
 * borrowed and valid only during the callback. Leader-only for consistency
 * with linearizable reads (callers route lists to the leader).
 */
typedef void (*m3_raft_node_list_cb)(const uint8_t *bucket, size_t bucket_size,
                                     const uint8_t *object_key, size_t object_key_size,
                                     const uint8_t *manifest_bytes, size_t manifest_size,
                                     void *user_data);

int m3_raft_node_list(m3_raft_node_t *node,
                      const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                      const uint8_t *bucket, size_t bucket_size, const uint8_t *prefix,
                      size_t prefix_size, m3_raft_node_list_cb callback, void *user_data);

/**
 * Reads a committed object back with a linearizable read-index barrier.
 * Leader-only: followers return TURBO_EPROTO (reads must route to the leader).
 * Blocks by pumping this node's event loop until the barrier completes.
 */
int m3_raft_node_lookup(m3_raft_node_t *node,
                        const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                        const char *bucket, const char *object, int *out_found);

/**
 * Two-phase variant for callers that drive several node event loops (e.g. an
 * in-process multi-node harness): start the barrier, pump the participating
 * nodes, then poll the handle. The read-index barrier needs peer loops to
 * respond, so callers must pump peers too.
 */
int m3_raft_node_lookup_start(m3_raft_node_t *node,
                              const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                              const char *bucket, const char *object,
                              m3_raft_node_lookup_t **out_handle);
/** Non-blocking: sets *out_done when the barrier completed, *out_found then. */
int m3_raft_node_lookup_try(m3_raft_node_lookup_t *handle, int *out_found,
                            int *out_done);
/** Releases the handle; the pending read completes during a later poll. */
void m3_raft_node_lookup_release(m3_raft_node_lookup_t *handle);

/**
 * Stops the listener, drains the peer service and closes the raft stack and
 * coroutine context. Safe to call once; node is freed.
 */
void m3_raft_node_destroy(m3_raft_node_t *node);

#ifdef __cplusplus
}
#endif

#endif
