#ifndef TURBO_P2P_MESH_MGMT_EXECUTION_H
#define TURBO_P2P_MESH_MGMT_EXECUTION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_SCHEMA_V1 1u
#define MESH_MGMT_EXECUTION_ID_SIZE 16u
#define MESH_MGMT_EXECUTION_DIGEST_SIZE 32u
#define MESH_MGMT_EXECUTION_SIGNATURE_SIZE 64u
#define MESH_MGMT_EXECUTION_MAX_REFS 8u
#define MESH_MGMT_EXECUTION_INLINE_INPUT_MAX 4096u
#define MESH_MGMT_EXECUTION_JOURNAL_MAX 4096u

typedef enum {
  MESH_MGMT_EXECUTION_OK = 0,
  MESH_MGMT_EXECUTION_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_INVALID_SCHEMA = -2,
  MESH_MGMT_EXECUTION_BINDING_MISMATCH = -3,
  MESH_MGMT_EXECUTION_EXPIRED = -4,
  MESH_MGMT_EXECUTION_DENIED = -5,
  MESH_MGMT_EXECUTION_CONFLICT = -6,
  MESH_MGMT_EXECUTION_INVALID_STATE = -7,
  MESH_MGMT_EXECUTION_RESOURCE_EXHAUSTED = -8,
  MESH_MGMT_EXECUTION_NOT_FOUND = -9,
} mesh_mgmt_execution_result_t;

typedef enum {
  MESH_MGMT_EXECUTION_OPERATION_NONE = 0,
  MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_WASM = 1,
  MESH_MGMT_EXECUTION_OPERATION_RUN_PRESTAGED_NATIVE = 2,
} mesh_mgmt_execution_operation_t;

typedef enum {
  MESH_MGMT_EXECUTION_CAP_CORE = 1u << 0,
  MESH_MGMT_EXECUTION_CAP_UTILS = 1u << 1,
  MESH_MGMT_EXECUTION_CAP_HTTP = 1u << 2,
  MESH_MGMT_EXECUTION_CAP_FILE_READ = 1u << 3,
  MESH_MGMT_EXECUTION_CAP_FILE_WRITE = 1u << 4,
  MESH_MGMT_EXECUTION_CAP_APP = 1u << 5,
  MESH_MGMT_EXECUTION_CAP_MESH_SERVICE = 1u << 6,
  MESH_MGMT_EXECUTION_CAP_ALL = 0x7fu,
} mesh_mgmt_execution_capability_t;

/**
 * Exact capability profile of the V1 raw-WASM loader. Raw modules do not
 * carry an immutable application manifest, so this profile is intentionally
 * fixed until package-manifest loading is introduced.
 */
#define MESH_MGMT_EXECUTION_RAW_WASM_CAPABILITIES_V1                        \
  (MESH_MGMT_EXECUTION_CAP_CORE | MESH_MGMT_EXECUTION_CAP_UTILS |           \
   MESH_MGMT_EXECUTION_CAP_APP)

typedef enum {
  MESH_MGMT_EXECUTION_INPUT_NONE = 0,
  MESH_MGMT_EXECUTION_INPUT_INLINE = 1,
  MESH_MGMT_EXECUTION_INPUT_M3_OBJECT = 2,
  MESH_MGMT_EXECUTION_INPUT_PRESTAGED_OBJECT = 3,
} mesh_mgmt_execution_input_kind_t;

typedef enum {
  MESH_MGMT_EXECUTION_OUTPUT_NONE = 0,
  MESH_MGMT_EXECUTION_OUTPUT_DIGEST = 1,
  MESH_MGMT_EXECUTION_OUTPUT_M3_OBJECT = 2,
} mesh_mgmt_execution_output_mode_t;

typedef enum {
  MESH_MGMT_EXECUTION_STATE_NONE = 0,
  MESH_MGMT_EXECUTION_STATE_RECEIVED = 1,
  MESH_MGMT_EXECUTION_STATE_AUTHORIZED = 2,
  MESH_MGMT_EXECUTION_STATE_ACCEPTED = 3,
  MESH_MGMT_EXECUTION_STATE_STAGING = 4,
  MESH_MGMT_EXECUTION_STATE_RUNNING = 5,
  MESH_MGMT_EXECUTION_STATE_SUCCEEDED = 6,
  MESH_MGMT_EXECUTION_STATE_FAILED = 7,
  MESH_MGMT_EXECUTION_STATE_EXPIRED = 8,
  MESH_MGMT_EXECUTION_STATE_CANCELLED = 9,
  MESH_MGMT_EXECUTION_STATE_FAILED_INDETERMINATE = 10,
  MESH_MGMT_EXECUTION_STATE_REJECTED = 11,
} mesh_mgmt_execution_state_t;

typedef struct {
  uint32_t module_bytes;
  uint32_t stack_bytes;
  uint32_t linear_memory_bytes;
  uint64_t timeout_ms;
  uint64_t control_flow_steps;
  uint32_t host_calls;
  uint64_t copied_guest_bytes;
  uint64_t input_bytes;
  uint64_t stdout_bytes;
  uint64_t stderr_bytes;
} mesh_mgmt_execution_limits_v1_t;

typedef struct {
  uint16_t version;
  uint8_t grant_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t mesh_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t policy_epoch;
  uint8_t subject_principal[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint64_t deployment_generation;
  uint8_t package_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  mesh_mgmt_execution_operation_t operation;
  uint32_t capabilities;
  uint8_t mount_ids[MESH_MGMT_EXECUTION_MAX_REFS][MESH_MGMT_EXECUTION_ID_SIZE];
  size_t mount_count;
  uint8_t service_ids[MESH_MGMT_EXECUTION_MAX_REFS][MESH_MGMT_EXECUTION_ID_SIZE];
  size_t service_count;
  uint8_t provider_ids[MESH_MGMT_EXECUTION_MAX_REFS][MESH_MGMT_EXECUTION_ID_SIZE];
  size_t provider_count;
  mesh_mgmt_execution_limits_v1_t max_limits;
  uint64_t not_before_ms;
  uint64_t expires_at_ms;
  uint8_t issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t signature[MESH_MGMT_EXECUTION_SIGNATURE_SIZE];
} mesh_mgmt_execution_grant_v1_t;

typedef struct {
  uint16_t version;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t grant_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint64_t deployment_generation;
  uint8_t package_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  mesh_mgmt_execution_input_kind_t input_kind;
  uint8_t input_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t input_length;
  uint8_t inline_input[MESH_MGMT_EXECUTION_INLINE_INPUT_MAX];
  size_t inline_input_size;
  mesh_mgmt_execution_output_mode_t output_mode;
  uint64_t deadline_ms;
  uint8_t request_nonce[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE];
} mesh_mgmt_execution_request_v1_t;

typedef struct {
  uint32_t requested_capabilities;
  uint32_t host_capabilities;
  uint32_t hard_capabilities;
  mesh_mgmt_execution_limits_v1_t requested_limits;
  mesh_mgmt_execution_limits_v1_t host_limits;
  mesh_mgmt_execution_limits_v1_t hard_limits;
} mesh_mgmt_execution_authorization_input_v1_t;

typedef struct {
  uint32_t capabilities;
  mesh_mgmt_execution_limits_v1_t limits;
} mesh_mgmt_execution_effective_policy_v1_t;

typedef struct {
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  mesh_mgmt_execution_state_t state;
  int32_t result_code;
  uint64_t generation;
  uint8_t occupied;
} mesh_mgmt_execution_journal_entry_v1_t;

/**
 * Bounded in-memory E0 journal simulator. It models durable import/export and
 * state invariants but performs no file I/O. One owner must serialize calls.
 */
typedef struct {
  mesh_mgmt_execution_journal_entry_v1_t *entries;
  size_t capacity;
  size_t count;
  uint64_t generation;
} mesh_mgmt_execution_journal_v1_t;

/**
 * Structural validation only. This does not authenticate the signature.
 */
mesh_mgmt_execution_result_t mesh_mgmt_execution_grant_validate_v1(
    const mesh_mgmt_execution_grant_v1_t *grant, uint64_t now_ms);

mesh_mgmt_execution_result_t mesh_mgmt_execution_request_validate_v1(
    const mesh_mgmt_execution_request_v1_t *request, uint64_t now_ms);

mesh_mgmt_execution_result_t mesh_mgmt_execution_request_bind_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request);

mesh_mgmt_execution_result_t mesh_mgmt_execution_authorize_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_authorization_input_v1_t *input,
    mesh_mgmt_execution_effective_policy_v1_t *out_effective);

int mesh_mgmt_execution_state_is_terminal_v1(mesh_mgmt_execution_state_t state);

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_init_v1(
    mesh_mgmt_execution_journal_v1_t *journal, size_t capacity);

void mesh_mgmt_execution_journal_destroy_v1(
    mesh_mgmt_execution_journal_v1_t *journal);

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_submit_v1(
    mesh_mgmt_execution_journal_v1_t *journal,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    const uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry);

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_get_v1(
    const mesh_mgmt_execution_journal_v1_t *journal,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_journal_entry_v1_t *out_entry);

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_transition_v1(
    mesh_mgmt_execution_journal_v1_t *journal,
    const uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE],
    mesh_mgmt_execution_state_t next_state, int32_t result_code,
    mesh_mgmt_execution_journal_entry_v1_t *out_entry);

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_recover_v1(
    mesh_mgmt_execution_journal_v1_t *journal, size_t *out_recovered);

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_export_v1(
    const mesh_mgmt_execution_journal_v1_t *journal,
    mesh_mgmt_execution_journal_entry_v1_t *out_entries, size_t out_capacity,
    size_t *out_count);

mesh_mgmt_execution_result_t mesh_mgmt_execution_journal_import_v1(
    mesh_mgmt_execution_journal_v1_t *journal,
    const mesh_mgmt_execution_journal_entry_v1_t *entries, size_t entry_count);

#ifdef __cplusplus
}
#endif

#endif
