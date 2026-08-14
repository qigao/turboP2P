#ifndef MESH_CONTROL_DURABLE_OUTBOX_H
#define MESH_CONTROL_DURABLE_OUTBOX_H

#include "mesh_control_primitives.h"
#include "turbo_fs.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_DURABLE_OUTBOX_VERSION_V1 1u
#define MESH_CONTROL_DURABLE_OUTBOX_AUTH_KEY_SIZE_V1 32u
#define MESH_CONTROL_DURABLE_OUTBOX_MAX_ENTRIES_V1 4096u
#define MESH_CONTROL_DURABLE_OUTBOX_MAX_BYTES_V1 (64u * 1024u * 1024u)

typedef enum {
  MESH_CONTROL_DURABLE_OUTBOX_OK = 0,
  MESH_CONTROL_DURABLE_OUTBOX_INVALID_ARG = -1,
  MESH_CONTROL_DURABLE_OUTBOX_INVALID_STATE = -2,
  MESH_CONTROL_DURABLE_OUTBOX_IO = -3,
  MESH_CONTROL_DURABLE_OUTBOX_LOCKED = -4,
  MESH_CONTROL_DURABLE_OUTBOX_CORRUPT = -5,
  MESH_CONTROL_DURABLE_OUTBOX_AUTH_FAILED = -6,
  MESH_CONTROL_DURABLE_OUTBOX_RESOURCE_EXHAUSTED = -7,
  MESH_CONTROL_DURABLE_OUTBOX_CONFLICT = -8,
  MESH_CONTROL_DURABLE_OUTBOX_NOT_FOUND = -9,
  MESH_CONTROL_DURABLE_OUTBOX_FENCED = -10
} mesh_control_durable_outbox_result_t;

typedef enum {
  MESH_CONTROL_DURABLE_OUTBOX_PENDING = 1,
  MESH_CONTROL_DURABLE_OUTBOX_CLAIMED = 2,
  MESH_CONTROL_DURABLE_OUTBOX_ACKED = 3
} mesh_control_durable_outbox_state_v1_t;

typedef struct {
  const char *path;
  size_t entry_capacity;
  size_t session_capacity;
  size_t byte_capacity;
  size_t max_payload_size;
  uint64_t max_claim_lease_ms;
  uint64_t ack_retention_ms;
  /** Independent local secret loaded from secure storage; never sent. */
  uint8_t authentication_key[MESH_CONTROL_DURABLE_OUTBOX_AUTH_KEY_SIZE_V1];
} mesh_control_durable_outbox_config_v1_t;

typedef struct {
  uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint64_t sequence;
  const uint8_t *payload;
  size_t payload_size;
  uint64_t created_at_ms;
} mesh_control_durable_outbox_message_v1_t;

/**
 * Borrowed immutable view. payload is valid until the next mutating call or
 * close. ACKED views intentionally carry no retained payload.
 */
typedef struct {
  uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t payload_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t claimed_session_id[MESH_CONTROL_ID_SIZE];
  uint64_t sequence;
  uint64_t created_at_ms;
  uint64_t lease_generation;
  uint64_t claimed_session_generation;
  uint64_t lease_expires_at_ms;
  uint64_t acked_at_ms;
  uint32_t delivery_attempts;
  mesh_control_durable_outbox_state_v1_t state;
  const uint8_t *payload;
  size_t payload_size;
} mesh_control_durable_outbox_view_v1_t;

typedef struct {
  uint64_t generation;
  size_t entries;
  size_t pending;
  size_t claimed;
  size_t acked;
  size_t retained_payload_bytes;
  size_t retained_sessions;
  size_t active_sessions;
  uint64_t submitted;
  uint64_t claimed_total;
  uint64_t acknowledged;
  uint64_t reclaimed;
  uint64_t recovered_sessions;
  uint64_t fenced_sessions;
  uint64_t compacted;
} mesh_control_durable_outbox_stats_v1_t;

typedef struct mesh_control_durable_outbox_entry_v1
    mesh_control_durable_outbox_entry_v1_t;
typedef struct mesh_control_durable_outbox_session_v1
    mesh_control_durable_outbox_session_v1_t;

/**
 * Synchronous single-owner durable outbox. Every mutation fsyncs an
 * authenticated snapshot before returning success. Calls may block and must
 * run on a persistence worker, never on a CoroNet/Iris callback.
 */
typedef struct {
  mesh_control_durable_outbox_config_v1_t config;
  mesh_control_durable_outbox_entry_v1_t *entries;
  mesh_control_durable_outbox_session_v1_t *sessions;
  char path[TURBO_FS_MAX_PATH];
  char temp_path[TURBO_FS_MAX_PATH + 5u];
  char lock_path[TURBO_FS_MAX_PATH + 6u];
  turbo_file_t lock_file;
  uint64_t generation;
  size_t count;
  size_t retained_payload_bytes;
  mesh_control_durable_outbox_stats_v1_t counters;
  uint8_t open;
  uint8_t faulted;
} mesh_control_durable_outbox_v1_t;

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_open_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const mesh_control_durable_outbox_config_v1_t *config,
    size_t *out_recovered_claims);

void mesh_control_durable_outbox_close_v1(
    mesh_control_durable_outbox_v1_t *outbox);

/** Durable and idempotent by message_id; conflicting reuse is rejected. */
mesh_control_durable_outbox_result_t mesh_control_durable_outbox_submit_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const mesh_control_durable_outbox_message_v1_t *message,
    mesh_control_durable_outbox_view_v1_t *out_view);

/**
 * Durably activates one authenticated session for a target. A different
 * session increments the monotonic generation and atomically requeues claims
 * owned by the previous generation. Repeating the active session is
 * idempotent.
 */
mesh_control_durable_outbox_result_t
mesh_control_durable_outbox_activate_session_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE], uint64_t connected_at_ms,
    uint64_t *out_session_generation, size_t *out_released_claims);

/** Deactivates only the exact current generation; stale disconnects are fenced. */
mesh_control_durable_outbox_result_t
mesh_control_durable_outbox_deactivate_session_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation);

/**
 * Claims the oldest eligible message for target_node_id and binds it to the
 * authenticated online session. Expired claims are durably reclaimed.
 */
mesh_control_durable_outbox_result_t mesh_control_durable_outbox_claim_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation, uint64_t now_ms, uint64_t lease_ms,
    mesh_control_durable_outbox_view_v1_t *out_view);

/** Exact session and lease generation are required; retries are idempotent. */
mesh_control_durable_outbox_result_t mesh_control_durable_outbox_ack_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation, uint64_t lease_generation,
    uint64_t acked_at_ms);

/** Returns a live claim to PENDING after a transport failure. */
mesh_control_durable_outbox_result_t mesh_control_durable_outbox_release_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    const uint8_t session_id[MESH_CONTROL_ID_SIZE],
    uint64_t session_generation, uint64_t lease_generation);

/**
 * Compatibility helper for callers that only need to requeue an old claim.
 * New Controller code must use activate_session_v1 so future claims are also
 * checked against the durable authoritative session generation.
 */
mesh_control_durable_outbox_result_t
mesh_control_durable_outbox_fence_target_session_v1(
    mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE],
    const uint8_t new_session_id[MESH_CONTROL_ID_SIZE], size_t *out_released);

/** Removes ACKED tombstones whose retention interval has elapsed. */
mesh_control_durable_outbox_result_t mesh_control_durable_outbox_compact_v1(
    mesh_control_durable_outbox_v1_t *outbox, uint64_t now_ms,
    size_t *out_removed);

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_get_v1(
    const mesh_control_durable_outbox_v1_t *outbox,
    const uint8_t message_id[MESH_CONTROL_ID_SIZE],
    mesh_control_durable_outbox_view_v1_t *out_view);

mesh_control_durable_outbox_result_t mesh_control_durable_outbox_get_stats_v1(
    const mesh_control_durable_outbox_v1_t *outbox,
    mesh_control_durable_outbox_stats_v1_t *out_stats);

#ifdef __cplusplus
}
#endif

#endif
