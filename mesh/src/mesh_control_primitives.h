#ifndef MESH_CONTROL_PRIMITIVES_H
#define MESH_CONTROL_PRIMITIVES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_SCHEMA_V1 1u
#define MESH_CONTROL_ID_SIZE 16u
#define MESH_CONTROL_DIGEST_SIZE 32u
#define MESH_CONTROL_NODE_ID_SIZE 32u
#define MESH_CONTROL_MAX_FRAME_SIZE_V1 (64u * 1024u)
#define MESH_CONTROL_MAX_STATUS_SNAPSHOT_SIZE_V1 (256u * 1024u)
#define MESH_CONTROL_OUTBOX_MAX_ENTRIES_V1 4096u
#define MESH_CONTROL_OUTBOX_MAX_RETAINED_BYTES_V1 (64u * 1024u * 1024u)

typedef enum {
  MESH_CONTROL_OK = 0,
  MESH_CONTROL_INVALID_ARG = -1,
  MESH_CONTROL_INVALID_STATE = -2,
  MESH_CONTROL_CONFLICT = -3,
  MESH_CONTROL_RESOURCE_EXHAUSTED = -4,
  MESH_CONTROL_CLOSED = -5,
  MESH_CONTROL_EMPTY = -6,
  MESH_CONTROL_UNAUTHORIZED = -7,
  MESH_CONTROL_STALE_EPOCH = -8,
  MESH_CONTROL_UNSUPPORTED = -9,
  MESH_CONTROL_UNKNOWN_COMMIT = -10,
  MESH_CONTROL_TIMEOUT = -11,
  MESH_CONTROL_PROVIDER_UNAVAILABLE = -12
} mesh_control_result_t;

typedef enum {
  MESH_CONTROL_MESSAGE_HELLO = 1,
  MESH_CONTROL_MESSAGE_INTENT = 2,
  MESH_CONTROL_MESSAGE_OBSERVATION = 3,
  MESH_CONTROL_MESSAGE_OPERATION = 4,
  MESH_CONTROL_MESSAGE_EVENT = 5,
  MESH_CONTROL_MESSAGE_RECEIPT = 6
} mesh_control_message_kind_v1_t;

typedef enum {
  MESH_CONTROL_RESOURCE_NONE = 0,
  MESH_CONTROL_RESOURCE_NODE = 1,
  MESH_CONTROL_RESOURCE_NETWORK = 2,
  MESH_CONTROL_RESOURCE_FUNCTION = 3,
  MESH_CONTROL_RESOURCE_SERVICE = 4,
  MESH_CONTROL_RESOURCE_ROUTE = 5,
  MESH_CONTROL_RESOURCE_RELEASE = 6
} mesh_control_resource_kind_v1_t;

typedef enum {
  MESH_CONTROL_OPERATION_SUBMITTED = 1,
  MESH_CONTROL_OPERATION_ACCEPTED = 2,
  MESH_CONTROL_OPERATION_RUNNING = 3,
  MESH_CONTROL_OPERATION_SUCCEEDED = 4,
  MESH_CONTROL_OPERATION_FAILED = 5,
  MESH_CONTROL_OPERATION_REJECTED = 6,
  MESH_CONTROL_OPERATION_EXPIRED = 7,
  MESH_CONTROL_OPERATION_INTERRUPTED = 8
} mesh_control_operation_state_v1_t;

typedef enum {
  MESH_CONTROL_DESIRED_APPLY = 1,
  MESH_CONTROL_DESIRED_DELETE = 2
} mesh_control_desired_action_v1_t;

typedef enum {
  MESH_CONTROL_FUNCTION_BUILTIN = 1,
  MESH_CONTROL_FUNCTION_WASM = 2,
  MESH_CONTROL_FUNCTION_NATIVE = 3
} mesh_control_function_runtime_v1_t;

typedef enum {
  MESH_CONTROL_FUNCTION_STAGED = 1,
  MESH_CONTROL_FUNCTION_RUNNING = 2,
  MESH_CONTROL_FUNCTION_STOPPED = 3
} mesh_control_function_state_v1_t;

typedef enum {
  MESH_CONTROL_FUNCTION_FLAG_PRESTAGED = 1u << 0,
  MESH_CONTROL_FUNCTION_FLAG_OUT_OF_PROCESS = 1u << 1
} mesh_control_function_flags_v1_t;

typedef enum {
  MESH_CONTROL_PERMISSION_OBSERVE = 1ull << 0,
  MESH_CONTROL_PERMISSION_MANAGE = 1ull << 1,
  MESH_CONTROL_PERMISSION_RUN_BUILTIN = 1ull << 2,
  MESH_CONTROL_PERMISSION_RUN_NATIVE = 1ull << 3,
  MESH_CONTROL_PERMISSION_RUN_WASM = 1ull << 4
} mesh_control_permission_v1_t;

#define MESH_CONTROL_PERMISSION_KNOWN_V1                                  \
  (MESH_CONTROL_PERMISSION_OBSERVE | MESH_CONTROL_PERMISSION_MANAGE |     \
   MESH_CONTROL_PERMISSION_RUN_BUILTIN |                                 \
   MESH_CONTROL_PERMISSION_RUN_NATIVE | MESH_CONTROL_PERMISSION_RUN_WASM)

/**
 * Transport-neutral control metadata. H2, WebSocket and MMP adapters must
 * authenticate the enclosing transport/envelope before submitting it to the
 * domain owner. payload_digest is a binding supplied by that authenticated
 * envelope; this module validates shape and invariants, not signatures.
 */
typedef struct {
  uint16_t schema_version;
  uint16_t kind;
  uint32_t flags;
  uint8_t message_id[MESH_CONTROL_ID_SIZE];
  uint8_t request_id[MESH_CONTROL_ID_SIZE];
  uint8_t mesh_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t origin_principal[MESH_CONTROL_DIGEST_SIZE];
  uint8_t origin_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint8_t session_id[MESH_CONTROL_ID_SIZE];
  uint8_t target_node_id[MESH_CONTROL_NODE_ID_SIZE];
  uint16_t resource_kind;
  uint16_t reserved;
  uint8_t resource_id[MESH_CONTROL_DIGEST_SIZE];
  uint64_t epoch;
  uint64_t sequence;
  uint64_t issued_at_ms;
  uint64_t expires_at_ms;
  uint64_t principal_epoch;
  uint64_t incarnation;
  uint64_t certificate_serial;
  uint64_t precondition_epoch;
  uint8_t payload_digest[MESH_CONTROL_DIGEST_SIZE];
  size_t payload_size;
} mesh_control_envelope_v1_t;

typedef struct {
  uint64_t memory_bytes;
  uint64_t cpu_time_ms;
  uint64_t input_bytes;
  uint64_t output_bytes;
  uint32_t concurrency;
  uint32_t host_calls;
} mesh_control_function_limits_v1_t;

/**
 * Immutable function assignment. It intentionally contains no host path,
 * URL, argv or raw executable bytes. artifact_digest identifies content that
 * was already staged through the artifact/data plane.
 */
typedef struct {
  uint16_t schema_version;
  uint16_t runtime;
  uint16_t desired_state;
  uint16_t reserved;
  uint32_t flags;
  uint8_t function_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t provider_id[MESH_CONTROL_DIGEST_SIZE];
  uint8_t artifact_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t config_digest[MESH_CONTROL_DIGEST_SIZE];
  uint8_t network_policy_digest[MESH_CONTROL_DIGEST_SIZE];
  uint64_t generation;
  uint64_t required_capabilities;
  mesh_control_function_limits_v1_t limits;
} mesh_control_function_spec_v1_t;

mesh_control_result_t mesh_control_envelope_validate_v1(
    const mesh_control_envelope_v1_t *envelope);

mesh_control_result_t mesh_control_function_spec_validate_v1(
    const mesh_control_function_spec_v1_t *spec);

/**
 * Authorization is the intersection of the signed grant and immutable local
 * policy. Staging requires MANAGE. RUNNING additionally requires the
 * runtime-specific RUN permission. A deployment can therefore advertise
 * WASM in its schema while omitting RUN_WASM locally until the sandbox is
 * production-ready.
 */
mesh_control_result_t mesh_control_function_authorize_v1(
    const mesh_control_function_spec_v1_t *spec,
    uint64_t granted_permissions, uint64_t local_permissions,
    uint64_t *out_effective_permissions);

int mesh_control_operation_state_is_terminal_v1(
    mesh_control_operation_state_v1_t state);

int mesh_control_operation_transition_allowed_v1(
    mesh_control_operation_state_v1_t from,
    mesh_control_operation_state_v1_t to);

#ifdef __cplusplus
}
#endif

#endif
