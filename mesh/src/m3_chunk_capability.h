#ifndef M3_CHUNK_CAPABILITY_H
#define M3_CHUNK_CAPABILITY_H

#include "m3_chunk_store.h"

#include <turbo_uuid.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_CHUNK_CAPABILITY_TENANT_ID_SIZE 32u
#define M3_CHUNK_CAPABILITY_NODE_ID_SIZE 32u

typedef enum {
  M3_CHUNK_OPERATION_READ = 1,
  M3_CHUNK_OPERATION_PUT = 2,
} m3_chunk_operation_v1_t;

typedef enum {
  M3_CHUNK_CAPABILITY_OK = 0,
  M3_CHUNK_CAPABILITY_INVALID_ARG = -1,
  M3_CHUNK_CAPABILITY_INVALID_CLAIMS = -2,
  M3_CHUNK_CAPABILITY_NOT_YET_VALID = -3,
  M3_CHUNK_CAPABILITY_EXPIRED = -4,
  M3_CHUNK_CAPABILITY_TENANT_MISMATCH = -5,
  M3_CHUNK_CAPABILITY_AUDIENCE_MISMATCH = -6,
  M3_CHUNK_CAPABILITY_REQUEST_MISMATCH = -7,
  M3_CHUNK_CAPABILITY_OPERATION_MISMATCH = -8,
  M3_CHUNK_CAPABILITY_CID_MISMATCH = -9,
  M3_CHUNK_CAPABILITY_RANGE_DENIED = -10,
  M3_CHUNK_CAPABILITY_RESOURCE_EXHAUSTED = -11,
} m3_chunk_capability_result_t;

/**
 * Claims produced by a signature-verification boundary.
 *
 * This type is not itself proof of authenticity. A codec/verifier must bind
 * these claims to the issuer and signature before calling the evaluator.
 */
typedef struct {
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  m3_chunk_cid_v1_t cid;
  m3_chunk_operation_v1_t operation;
  uint64_t range_offset;
  uint64_t range_length;
  uint8_t audience_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  turbo_uuid_t request_id;
  uint64_t issued_at_ms;
  uint64_t expires_at_ms;
} m3_chunk_capability_claims_v1_t;

typedef struct {
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  m3_chunk_cid_v1_t cid;
  m3_chunk_operation_v1_t operation;
  uint64_t range_offset;
  uint64_t range_length;
  uint8_t local_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  turbo_uuid_t request_id;
  uint64_t now_ms;
} m3_chunk_access_request_v1_t;

typedef struct {
  uint64_t max_ttl_ms;
  uint64_t max_read_bytes;
  uint64_t max_put_bytes;
} m3_chunk_capability_policy_v1_t;

/**
 * Effective access passed to the chunk store adapter after authorization.
 *
 * It contains no path, endpoint, signer credential, or execution permission.
 */
typedef struct {
  uint8_t tenant_id[M3_CHUNK_CAPABILITY_TENANT_ID_SIZE];
  m3_chunk_cid_v1_t cid;
  m3_chunk_operation_v1_t operation;
  uint64_t range_offset;
  uint64_t range_length;
  uint8_t audience_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  turbo_uuid_t request_id;
  uint64_t expires_at_ms;
} m3_chunk_authorized_access_v1_t;

/**
 * Evaluate already-verified claims against one request and local limits.
 *
 * READ requests may select a subset of the capability range. PUT requests
 * must bind the complete immutable CID. On failure out_access is zeroed.
 * Replay consumption is intentionally owned by the caller's request journal.
 */
m3_chunk_capability_result_t m3_chunk_capability_authorize_v1(
    const m3_chunk_capability_claims_v1_t *claims,
    const m3_chunk_access_request_v1_t *request,
    const m3_chunk_capability_policy_v1_t *policy,
    m3_chunk_authorized_access_v1_t *out_access);

#ifdef __cplusplus
}
#endif

#endif
