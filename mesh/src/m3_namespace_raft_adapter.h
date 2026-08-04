#ifndef M3_NAMESPACE_RAFT_ADAPTER_H
#define M3_NAMESPACE_RAFT_ADAPTER_H

#include "m3_namespace_local_store.h"

#include <turboraft/raft_service.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_NAMESPACE_RAFT_COMMAND_VERSION 1u
#define M3_NAMESPACE_RAFT_MAX_PENDING_READS 1024u

typedef enum {
  M3_NAMESPACE_RAFT_COMMAND_PUT = 1,
  M3_NAMESPACE_RAFT_COMMAND_TOMBSTONE = 2,
  M3_NAMESPACE_RAFT_COMMAND_UPDATE_PLACEMENT = 3,
} m3_namespace_raft_command_type_t;

/** Borrowed command view. The canonical encoder copies all bytes. */
typedef struct {
  m3_namespace_raft_command_type_t type;
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  const uint8_t *bucket;
  size_t bucket_size;
  const uint8_t *object_key;
  size_t object_key_size;
  const uint8_t *manifest_bytes;
  size_t manifest_size;
} m3_namespace_raft_command_v1_t;

typedef struct m3_namespace_raft_adapter_s m3_namespace_raft_adapter_v1_t;

/** Exact canonical frame bounded by TR_RAFT_MAX_ENTRY_BYTES. */
int m3_namespace_raft_command_encode_v1(
    const m3_namespace_raft_command_v1_t *command, uint8_t *output,
    size_t output_capacity, size_t *out_size);
/** Decoded pointers borrow the input frame. */
int m3_namespace_raft_command_decode_v1(
    const uint8_t *bytes, size_t size,
    m3_namespace_raft_command_v1_t *out_command);

/** The store is borrowed and must remain open until adapter destruction. */
int m3_namespace_raft_adapter_create_v1(
    m3_namespace_local_store_v1_t *store, size_t max_pending_reads,
    m3_namespace_raft_adapter_v1_t **out_adapter);
void m3_namespace_raft_adapter_destroy_v1(
    m3_namespace_raft_adapter_v1_t *adapter);

tr_raft_state_machine_t m3_namespace_raft_state_machine_v1(
    m3_namespace_raft_adapter_v1_t *adapter);

/** The adapter must exclusively consume this dedicated service's read states. */
int m3_namespace_raft_adapter_bind_service_v1(
    m3_namespace_raft_adapter_v1_t *adapter, tr_raft_service_t *service);

m3_namespace_lookup_adapter_v1_t m3_namespace_raft_lookup_adapter_v1(
    m3_namespace_raft_adapter_v1_t *adapter);

/** Callbacks may enqueue reads but must not destroy the adapter during poll. */
int m3_namespace_raft_adapter_poll_v1(
    m3_namespace_raft_adapter_v1_t *adapter, size_t *out_completed);

/** Submit bounded metadata and return its Raft fencing receipt. */
int m3_namespace_raft_propose_v1(
    m3_namespace_raft_adapter_v1_t *adapter, uint64_t command_id,
    const m3_namespace_raft_command_v1_t *command,
    tr_raft_operation_status_t *out_receipt);

#ifdef __cplusplus
}
#endif

#endif
