#ifndef TURBO_P2P_MESH_MGMT_REPLAY_H
#define TURBO_P2P_MESH_MGMT_REPLAY_H

#include "mesh_mgmt_envelope.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_REPLAY_CACHE_MAX 8192u
#define MESH_MGMT_REPLAY_TTL_MAX_MS 600000u

typedef enum {
    MESH_MGMT_REPLAY_OK = 0,
    MESH_MGMT_REPLAY_INVALID_ARG = -1,
    MESH_MGMT_REPLAY_INVALID_SCHEMA = -2,
    MESH_MGMT_REPLAY_BINDING_MISMATCH = -3,
    MESH_MGMT_REPLAY_REPLAYED = -4,
    MESH_MGMT_REPLAY_EXPIRED = -5,
    MESH_MGMT_REPLAY_RESOURCE_EXHAUSTED = -6,
    MESH_MGMT_REPLAY_STALE_PREPARATION = -7,
} mesh_mgmt_replay_result_t;

typedef struct {
    size_t capacity;
    uint64_t ttl_ms;
} mesh_mgmt_replay_config_v1_t;

typedef struct {
    uint8_t principal_key[32];
    uint64_t principal_epoch;
    uint64_t incarnation;
    uint8_t session_id[16];
} mesh_mgmt_replay_binding_v1_t;

typedef struct {
    uint8_t message_id[16];
    uint64_t expires_at_ms;
    uint8_t occupied;
} mesh_mgmt_replay_entry_v1_t;

typedef struct {
    uint64_t generation;
    uint64_t sequence;
    uint64_t cache_expires_at_ms;
    size_t cache_slot;
    uint8_t message_id[16];
    uint8_t prepared;
} mesh_mgmt_replay_preparation_v1_t;

/**
 * Per-authenticated-origin replay state. One event-loop owner must serialize
 * prepare/commit/destroy calls; this type does not provide internal locking.
 */
typedef struct {
    mesh_mgmt_replay_config_v1_t config;
    mesh_mgmt_replay_binding_v1_t binding;
    mesh_mgmt_replay_entry_v1_t *entries;
    uint64_t last_sequence;
    uint64_t generation;
    uint8_t has_sequence;
    uint8_t bound;
} mesh_mgmt_replay_gate_v1_t;

mesh_mgmt_replay_result_t mesh_mgmt_replay_init_v1(
    mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_replay_config_v1_t *config);

void mesh_mgmt_replay_destroy_v1(mesh_mgmt_replay_gate_v1_t *gate);

mesh_mgmt_replay_result_t mesh_mgmt_replay_bind_v1(
    mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_replay_binding_v1_t *binding);

/**
 * Validate without mutating the replay fact source. Commit only after all
 * payload parsing and authorization needed by the caller have succeeded.
 * Time is O(config.capacity), bounded by 8192 entries; no allocation occurs.
 */
mesh_mgmt_replay_result_t mesh_mgmt_replay_prepare_v1(
    const mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_header_v1_t *header,
    uint64_t now_ms,
    mesh_mgmt_replay_preparation_v1_t *out_preparation);

mesh_mgmt_replay_result_t mesh_mgmt_replay_commit_v1(
    mesh_mgmt_replay_gate_v1_t *gate,
    const mesh_mgmt_replay_preparation_v1_t *preparation);

#ifdef __cplusplus
}
#endif

#endif
