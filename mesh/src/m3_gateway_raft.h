#ifndef M3_GATEWAY_RAFT_H
#define M3_GATEWAY_RAFT_H

#include "m3_namespace_raft_adapter.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct m3_gateway_raft_s m3_gateway_raft_v1_t;

/**
 * Phase 2a raft metadata backend for the M3 gateway. The namespace store is
 * borrowed and acts as the raft state machine target; SQLite provides the
 * raft log/snapshot persistence. A single voter (self-elected leader) with a
 * no-op transport covers Phase 2a; multi-voter membership (Phase 2b+) injects
 * a real transport so proposals and replication flow to peer nodes.
 */
typedef struct m3_gateway_raft_config_s {
  const char *sqlite_path; /* ":memory:" or an absolute file path */
  tr_raft_node_id_t self_id;
  const tr_raft_node_id_t *voters;
  size_t voter_count;
  size_t max_snapshot_bytes;
  size_t max_pending_reads;
  /* Optional borrowed transport (e.g. tr_raft_coronet_peer_service_enqueue).
   * NULL keeps the single-node discard transport. Must outlive the raft. */
  const tr_raft_transport_t *transport;
} m3_gateway_raft_config_v1_t;

int m3_gateway_raft_open_v1(const m3_gateway_raft_config_v1_t *config,
                            m3_namespace_local_store_v1_t *store, m3_gateway_raft_v1_t **out_raft);
void m3_gateway_raft_close_v1(m3_gateway_raft_v1_t *raft);

/** Drive raft progress; call from the gateway event loop. */
int m3_gateway_raft_poll_v1(m3_gateway_raft_v1_t *raft, size_t *out_completed);

/** Borrowed service handle used by transport on_message routing. */
tr_raft_service_t *m3_gateway_raft_service_v1(m3_gateway_raft_v1_t *raft);

/** Non-blocking propose; completion is observed via applied_index/poll. */
int m3_gateway_raft_propose_v1(m3_gateway_raft_v1_t *raft, uint64_t command_id,
                               const m3_namespace_raft_command_v1_t *command,
                               tr_raft_operation_status_t *out_receipt);

/** Local applied index of the namespace store (raft commit target). */
uint64_t m3_gateway_raft_applied_index_v1(const m3_gateway_raft_v1_t *raft);

/** Role snapshot: out_is_leader set when this node is the current leader. */
int m3_gateway_raft_role_v1(const m3_gateway_raft_v1_t *raft, tr_raft_role_t *out_role);

/** Current leader id (0 when no leader is known). */
int m3_gateway_raft_leader_v1(const m3_gateway_raft_v1_t *raft,
                              tr_raft_node_id_t *out_leader_id);

/** Raft service diagnostic snapshot (faulted/cause/runtime). */
int m3_gateway_raft_service_status_v1(const m3_gateway_raft_v1_t *raft,
                                      tr_raft_service_status_t *out_status);

/** Submit a PUT and wait until it is applied to the local store. */
int m3_gateway_raft_put_v1(m3_gateway_raft_v1_t *raft,
                           const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                           const char *bucket, const char *object, const uint8_t *manifest_bytes,
                           size_t manifest_size);

/** Submit a tombstone and wait until it is applied. */
int m3_gateway_raft_tombstone_v1(m3_gateway_raft_v1_t *raft,
                                 const uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE],
                                 const char *bucket, const char *object);

m3_namespace_lookup_adapter_v1_t m3_gateway_raft_lookup_v1(m3_gateway_raft_v1_t *raft);

#ifdef __cplusplus
}
#endif

#endif
