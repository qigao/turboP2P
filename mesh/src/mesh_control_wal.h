#ifndef MESH_CONTROL_WAL_H
#define MESH_CONTROL_WAL_H

#include "mesh_control_owner.h"
#include "mesh_mgmt_codec.h"
#include "turbo_fs.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_WAL_VERSION_V1 1u
#define MESH_CONTROL_WAL_AUTH_KEY_SIZE_V1 32u
#define MESH_CONTROL_WAL_MAX_RECORDS_V1 4096u
#define MESH_CONTROL_WAL_MAX_FILE_SIZE_V1 67535104u
#define MESH_CONTROL_WAL_FILE_HEADER_SIZE_V1 256u
#define MESH_CONTROL_WAL_RECORD_OVERHEAD_V1 104u
#define MESH_CONTROL_WAL_MAX_RECORD_SIZE_V1                                                        \
  (MESH_CONTROL_WAL_RECORD_OVERHEAD_V1 + MESH_MGMT_FRAME_MAX)

typedef enum {
  MESH_CONTROL_WAL_RECORD_SIGNED_INTENT = 1,
  MESH_CONTROL_WAL_RECORD_OPERATION_RESULT = 2
} mesh_control_wal_record_type_v1_t;

typedef enum {
  MESH_CONTROL_WAL_OPERATION_SUCCEEDED = 1,
  MESH_CONTROL_WAL_OPERATION_FAILED = 2
} mesh_control_wal_operation_outcome_v1_t;

typedef enum {
  MESH_CONTROL_WAL_OK = 0,
  MESH_CONTROL_WAL_INVALID_ARG = -1,
  MESH_CONTROL_WAL_INVALID_STATE = -2,
  MESH_CONTROL_WAL_IO = -3,
  MESH_CONTROL_WAL_COMMIT_UNKNOWN = -4,
  MESH_CONTROL_WAL_LOCKED = -5,
  MESH_CONTROL_WAL_CORRUPT = -6,
  MESH_CONTROL_WAL_AUTH_FAILED = -7,
  MESH_CONTROL_WAL_BINDING_MISMATCH = -8,
  MESH_CONTROL_WAL_CONFLICT = -9,
  MESH_CONTROL_WAL_RESOURCE_EXHAUSTED = -10,
  MESH_CONTROL_WAL_CALLBACK_FAILED = -11
} mesh_control_wal_result_t;

typedef struct {
  const char *path;
  size_t record_capacity;
  size_t byte_capacity;
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t controller_principal[MESH_CONTROL_DIGEST_SIZE];
  uint8_t controller_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint64_t principal_epoch;
  uint64_t incarnation;
  uint64_t certificate_serial;
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  /** Independent local secret loaded from secure storage; never sent. */
  uint8_t authentication_key[MESH_CONTROL_WAL_AUTH_KEY_SIZE_V1];
} mesh_control_wal_config_v1_t;

typedef struct {
  uint8_t operation_id[MESH_CONTROL_ID_SIZE];
  uint16_t resource_kind;
  uint16_t action;
  uint16_t outcome;
  uint16_t reserved;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint64_t desired_epoch;
} mesh_control_wal_operation_result_v1_t;

typedef struct {
  uint64_t log_index;
  uint64_t accepted_at_ms;
  uint16_t record_type;
  uint16_t reserved;
  const uint8_t *signed_frame;
  size_t signed_frame_size;
  mesh_control_wal_operation_result_v1_t operation_result;
} mesh_control_wal_record_view_v1_t;

typedef int (*mesh_control_wal_replay_fn)(void *context,
                                          const mesh_control_wal_record_view_v1_t *record);

typedef struct {
  uint64_t base_index;
  uint64_t tail_index;
  size_t record_count;
  size_t record_capacity;
  size_t file_size;
  size_t byte_capacity;
  uint8_t open;
  uint8_t faulted;
} mesh_control_wal_stats_v1_t;

/**
 * Synchronous single-writer append-only intent journal. Calls may block and
 * must run on a persistence worker, never a CoroNet/Iris event loop. The
 * struct must be zero-initialized and all calls are single-owner.
 */
typedef struct {
  mesh_control_wal_config_v1_t config;
  char path[TURBO_FS_MAX_PATH];
  char lock_path[TURBO_FS_MAX_PATH];
  turbo_file_t lock_file;
  uint64_t base_index;
  uint64_t tail_index;
  uint8_t base_authenticator[MESH_CONTROL_DIGEST_SIZE];
  uint8_t tail_previous_authenticator[MESH_CONTROL_DIGEST_SIZE];
  uint8_t tail_authenticator[MESH_CONTROL_DIGEST_SIZE];
  size_t record_count;
  size_t file_size;
  uint8_t open;
  uint8_t faulted;
} mesh_control_wal_v1_t;

mesh_control_wal_result_t mesh_control_wal_open_v1(mesh_control_wal_v1_t *wal,
                                                   const mesh_control_wal_config_v1_t *config);

/**
 * Appends and fsyncs one original, already signed MMP CONTROL frame. The
 * expected index must be tail+1. Retrying the exact tail record with the same
 * expected index is idempotent. Any ambiguous write faults the handle; reopen
 * and inspect the tail before retrying.
 */
mesh_control_wal_result_t
mesh_control_wal_append_v1(mesh_control_wal_v1_t *wal, uint64_t expected_index,
                           uint64_t accepted_at_ms, const uint8_t *signed_frame,
                           size_t signed_frame_size, uint64_t *out_log_index);

mesh_control_wal_result_t mesh_control_wal_append_operation_result_v1(
    mesh_control_wal_v1_t *wal, uint64_t expected_index, uint64_t recorded_at_ms,
    const mesh_control_wal_operation_result_v1_t *operation_result, uint64_t *out_log_index);

/**
 * Replays records with log_index > after_index in order. The frame view is
 * borrowed only for the callback duration and must not be retained.
 */
mesh_control_wal_result_t mesh_control_wal_replay_v1(const mesh_control_wal_v1_t *wal,
                                                     uint64_t after_index,
                                                     mesh_control_wal_replay_fn callback,
                                                     void *context, size_t *out_replayed);

/**
 * Atomically replaces a fully checkpointed WAL with an empty authenticated
 * segment anchored at the current tail. checkpoint_index must equal tail.
 */
mesh_control_wal_result_t mesh_control_wal_compact_v1(mesh_control_wal_v1_t *wal,
                                                      uint64_t checkpoint_index);

mesh_control_wal_result_t mesh_control_wal_get_stats_v1(const mesh_control_wal_v1_t *wal,
                                                        mesh_control_wal_stats_v1_t *out_stats);

void mesh_control_wal_close_v1(mesh_control_wal_v1_t *wal);

#ifdef __cplusplus
}
#endif

#endif
