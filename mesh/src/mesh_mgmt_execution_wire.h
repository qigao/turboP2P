#ifndef TURBO_P2P_MESH_MGMT_EXECUTION_WIRE_H
#define TURBO_P2P_MESH_MGMT_EXECUTION_WIRE_H

#include "mesh_mgmt_execution_result.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_GRANT_CANONICAL_BASE_SIZE_V1 342u
#define MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1                  \
  (MESH_MGMT_EXECUTION_GRANT_CANONICAL_BASE_SIZE_V1 +                    \
   3u * MESH_MGMT_EXECUTION_MAX_REFS * MESH_MGMT_EXECUTION_ID_SIZE)
#define MESH_MGMT_EXECUTION_COMMAND_REQUEST_OVERHEAD_SIZE_V1 108u
#define MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V1                  \
  (MESH_MGMT_EXECUTION_COMMAND_REQUEST_OVERHEAD_SIZE_V1 +                \
   MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1 +                     \
   MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1)
#define MESH_MGMT_EXECUTION_COMMAND_VERSION_V1 1u
#define MESH_MGMT_EXECUTION_COMMAND_VERSION_V2 2u
#define MESH_MGMT_EXECUTION_LEASE_PROOF_SIZE_V2 32u
#define MESH_MGMT_EXECUTION_COMMAND_REQUEST_OVERHEAD_SIZE_V2             \
  (MESH_MGMT_EXECUTION_COMMAND_REQUEST_OVERHEAD_SIZE_V1 + 4u +           \
   MESH_MGMT_EXECUTION_LEASE_PROOF_SIZE_V2)
#define MESH_MGMT_EXECUTION_COMMAND_REQUEST_MAX_SIZE_V2                  \
  (MESH_MGMT_EXECUTION_COMMAND_REQUEST_OVERHEAD_SIZE_V2 +                \
   MESH_MGMT_EXECUTION_GRANT_CANONICAL_MAX_SIZE_V1 +                     \
   MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1)
#define MESH_MGMT_EXECUTION_COMMAND_RESULT_SIZE_V1 543u
#define MESH_MGMT_EXECUTION_STATUS_CANONICAL_SIZE_V1 116u
#define MESH_MGMT_EXECUTION_COMMAND_STATUS_SIZE_V1 152u

typedef enum {
  MESH_MGMT_EXECUTION_STATUS_DISABLED = 1,
  MESH_MGMT_EXECUTION_STATUS_INVALID_COMMAND = 2,
  MESH_MGMT_EXECUTION_STATUS_AUTH_FAILED = 3,
  MESH_MGMT_EXECUTION_STATUS_CONFLICT = 4,
  MESH_MGMT_EXECUTION_STATUS_BUSY = 5,
  MESH_MGMT_EXECUTION_STATUS_INDETERMINATE = 6,
  MESH_MGMT_EXECUTION_STATUS_STORE_FAILED = 7,
  MESH_MGMT_EXECUTION_STATUS_INTERNAL = 8
} mesh_mgmt_execution_status_code_v1_t;

typedef struct {
  uint16_t version;
  uint16_t code;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t responder_node_id[32];
} mesh_mgmt_execution_status_v1_t;

typedef enum {
  MESH_MGMT_EXECUTION_WIRE_OK = 0,
  MESH_MGMT_EXECUTION_WIRE_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_WIRE_INVALID_SCHEMA = -2,
  MESH_MGMT_EXECUTION_WIRE_RESOURCE_EXHAUSTED = -3,
  MESH_MGMT_EXECUTION_WIRE_CRYPTO_FAILED = -4,
  MESH_MGMT_EXECUTION_WIRE_AUTH_FAILED = -5,
  MESH_MGMT_EXECUTION_WIRE_EXPIRED = -6,
} mesh_mgmt_execution_wire_result_t;

typedef struct {
  uint64_t fencing_token;
  uint64_t worker_generation;
  uint64_t quorum_read_index;
  uint64_t lease_expires_at_ms;
} mesh_mgmt_execution_lease_proof_v2_t;

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_grant_encode_canonical_v1(
    const mesh_mgmt_execution_grant_v1_t *grant, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_grant_decode_canonical_v1(
    const uint8_t *canonical, size_t canonical_size,
    mesh_mgmt_execution_grant_v1_t *out_grant);

mesh_mgmt_execution_wire_result_t mesh_mgmt_execution_grant_sign_v1(
    mesh_mgmt_execution_grant_v1_t *grant,
    const uint8_t private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]);

mesh_mgmt_execution_wire_result_t mesh_mgmt_execution_grant_verify_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const uint8_t expected_issuer_key[MESH_MGMT_EXECUTION_DIGEST_SIZE],
    uint64_t now_ms);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_request_encode_v1(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_request_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_grant_v1_t *out_grant,
    mesh_mgmt_execution_request_v1_t *out_request);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_request_encode_v2(
    const mesh_mgmt_execution_grant_v1_t *grant,
    const mesh_mgmt_execution_request_v1_t *request,
    const mesh_mgmt_execution_lease_proof_v2_t *proof, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_request_decode_v2(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_grant_v1_t *out_grant,
    mesh_mgmt_execution_request_v1_t *out_request,
    mesh_mgmt_execution_lease_proof_v2_t *out_proof);

/* Explicit version dispatch. V1 returns a zero proof; unknown versions fail. */
mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_request_decode_compatible_v2(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_grant_v1_t *out_grant,
    mesh_mgmt_execution_request_v1_t *out_request, uint16_t *out_version,
    mesh_mgmt_execution_lease_proof_v2_t *out_proof);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_result_encode_v1(
    const mesh_mgmt_execution_result_v1_t *result, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_result_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_result_v1_t *out_result);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_status_encode_v1(
    const mesh_mgmt_execution_status_v1_t *status, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_mgmt_execution_wire_result_t
mesh_mgmt_execution_command_status_decode_v1(
    const uint8_t *payload, size_t payload_size,
    mesh_mgmt_execution_status_v1_t *out_status);

int mesh_mgmt_execution_status_is_retryable_v1(uint16_t code);

#ifdef __cplusplus
}
#endif

#endif
