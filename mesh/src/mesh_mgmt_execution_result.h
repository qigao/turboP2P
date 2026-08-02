#ifndef TURBO_P2P_MESH_MGMT_EXECUTION_RESULT_H
#define TURBO_P2P_MESH_MGMT_EXECUTION_RESULT_H

#include "mesh_mgmt_execution.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_MGMT_EXECUTION_RESULT_VERSION_V1 1u
#define MESH_MGMT_EXECUTION_RESULT_CANONICAL_SIZE_V1 439u
#define MESH_MGMT_EXECUTION_REQUEST_CANONICAL_BASE_SIZE_V1 246u
#define MESH_MGMT_EXECUTION_REQUEST_CANONICAL_MAX_SIZE_V1                  \
  (MESH_MGMT_EXECUTION_REQUEST_CANONICAL_BASE_SIZE_V1 +                    \
   MESH_MGMT_EXECUTION_INLINE_INPUT_MAX)

typedef enum {
  MESH_MGMT_EXECUTION_RESULT_OK = 0,
  MESH_MGMT_EXECUTION_RESULT_INVALID_ARG = -1,
  MESH_MGMT_EXECUTION_RESULT_INVALID_SCHEMA = -2,
  MESH_MGMT_EXECUTION_RESULT_RESOURCE_EXHAUSTED = -3,
  MESH_MGMT_EXECUTION_RESULT_CRYPTO_FAILED = -4,
  MESH_MGMT_EXECUTION_RESULT_AUTH_FAILED = -5,
} mesh_mgmt_execution_result_codec_result_t;

typedef struct {
  uint64_t invocations;
  uint64_t host_calls;
  uint64_t copied_guest_bytes;
  uint64_t modules_loaded;
  uint64_t modules_rejected;
  uint32_t open_handles;
} mesh_mgmt_execution_usage_v1_t;

typedef struct {
  uint16_t version;
  uint8_t command_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t request_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t target_node_id[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t deployment_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint64_t deployment_generation;
  uint8_t package_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t policy_epoch;
  uint8_t grant_id[MESH_MGMT_EXECUTION_ID_SIZE];
  mesh_mgmt_execution_state_t state;
  int32_t runtime_code;
  int32_t runtime_stage;
  int32_t guest_exit_code;
  mesh_mgmt_execution_usage_v1_t usage;
  uint64_t stdout_bytes;
  uint64_t stderr_bytes;
  uint8_t stdout_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t stderr_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t has_output_artifact;
  uint8_t output_artifact_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint64_t started_at_ms;
  uint64_t finished_at_ms;
  uint64_t worker_generation;
  uint8_t correlation_id[MESH_MGMT_EXECUTION_ID_SIZE];
  uint8_t signer_public_key[MESH_MGMT_EXECUTION_DIGEST_SIZE];
  uint8_t signature[MESH_MGMT_EXECUTION_SIGNATURE_SIZE];
} mesh_mgmt_execution_result_v1_t;

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_request_encode_canonical_v1(
    const mesh_mgmt_execution_request_v1_t *request, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_request_decode_canonical_v1(
    const uint8_t *canonical, size_t canonical_size,
    mesh_mgmt_execution_request_v1_t *out_request);

/**
 * Compute the canonical request identity used by the command journal and
 * signed result. The digest algorithm is BLAKE2b-256 with a V1 domain prefix.
 */
mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_request_digest_v1(
    const mesh_mgmt_execution_request_v1_t *request,
    uint8_t out_digest[MESH_MGMT_EXECUTION_DIGEST_SIZE]);

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_validate_v1(
    const mesh_mgmt_execution_result_v1_t *result);

/**
 * Encode all signed fields in canonical network byte order. The signature is
 * intentionally excluded; signer_public_key is included.
 */
mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_encode_canonical_v1(
    const mesh_mgmt_execution_result_v1_t *result, uint8_t *output,
    size_t output_capacity, size_t *out_size);

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_decode_canonical_v1(
    const uint8_t *canonical, size_t canonical_size,
    mesh_mgmt_execution_result_v1_t *out_result);

mesh_mgmt_execution_result_codec_result_t mesh_mgmt_execution_result_sign_v1(
    mesh_mgmt_execution_result_v1_t *result,
    const uint8_t private_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]);

mesh_mgmt_execution_result_codec_result_t
mesh_mgmt_execution_result_verify_v1(
    const mesh_mgmt_execution_result_v1_t *result,
    const uint8_t expected_signer_public_key[MESH_MGMT_EXECUTION_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
