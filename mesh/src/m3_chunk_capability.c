#include "m3_chunk_capability.h"

#include <stddef.h>
#include <string.h>

static int bytes_are_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < length; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static int operation_is_valid(m3_chunk_operation_v1_t operation) {
  return operation == M3_CHUNK_OPERATION_READ ||
         operation == M3_CHUNK_OPERATION_PUT;
}

static int cid_is_valid(const m3_chunk_cid_v1_t *cid) {
  return cid &&
         cid->hash_algorithm == M3_CHUNK_STORE_HASH_ALGORITHM_SHA256 &&
         bytes_are_nonzero(cid->digest, sizeof(cid->digest));
}

static int cid_equal(const m3_chunk_cid_v1_t *left,
                     const m3_chunk_cid_v1_t *right) {
  return cid_is_valid(left) && cid_is_valid(right) &&
         left->hash_algorithm == right->hash_algorithm &&
         left->size == right->size &&
         memcmp(left->digest, right->digest, sizeof(left->digest)) == 0;
}

static int range_is_valid(uint64_t offset, uint64_t length,
                          uint64_t object_size) {
  return offset <= object_size && length <= object_size - offset;
}

static int range_contains(uint64_t outer_offset, uint64_t outer_length,
                          uint64_t inner_offset, uint64_t inner_length) {
  uint64_t outer_end;
  uint64_t inner_end;

  if (outer_length > UINT64_MAX - outer_offset ||
      inner_length > UINT64_MAX - inner_offset)
    return 0;
  outer_end = outer_offset + outer_length;
  inner_end = inner_offset + inner_length;
  return inner_offset >= outer_offset && inner_end <= outer_end;
}

static int claims_are_valid(const m3_chunk_capability_claims_v1_t *claims,
                            const m3_chunk_capability_policy_v1_t *policy) {
  uint64_t ttl;

  if (!claims || !policy || policy->max_ttl_ms == 0u ||
      policy->max_read_bytes == 0u || policy->max_put_bytes == 0u ||
      !bytes_are_nonzero(claims->tenant_id, sizeof(claims->tenant_id)) ||
      !bytes_are_nonzero(claims->audience_node_id,
                         sizeof(claims->audience_node_id)) ||
      !bytes_are_nonzero(claims->request_id.bytes,
                         sizeof(claims->request_id.bytes)) ||
      !operation_is_valid(claims->operation) || !cid_is_valid(&claims->cid) ||
      claims->issued_at_ms >= claims->expires_at_ms ||
      !range_is_valid(claims->range_offset, claims->range_length,
                      claims->cid.size)) {
    return 0;
  }
  ttl = claims->expires_at_ms - claims->issued_at_ms;
  if (ttl > policy->max_ttl_ms)
    return 0;
  if (claims->operation == M3_CHUNK_OPERATION_PUT &&
      (claims->range_offset != 0u ||
       claims->range_length != claims->cid.size)) {
    return 0;
  }
  return 1;
}

m3_chunk_capability_result_t m3_chunk_capability_authorize_v1(
    const m3_chunk_capability_claims_v1_t *claims,
    const m3_chunk_access_request_v1_t *request,
    const m3_chunk_capability_policy_v1_t *policy,
    m3_chunk_authorized_access_v1_t *out_access) {
  uint64_t operation_limit;

  if (out_access)
    memset(out_access, 0, sizeof(*out_access));
  if (!claims || !request || !policy || !out_access)
    return M3_CHUNK_CAPABILITY_INVALID_ARG;
  if (!claims_are_valid(claims, policy))
    return M3_CHUNK_CAPABILITY_INVALID_CLAIMS;
  if (!operation_is_valid(request->operation) ||
      !cid_is_valid(&request->cid) ||
      !bytes_are_nonzero(request->tenant_id, sizeof(request->tenant_id)) ||
      !bytes_are_nonzero(request->local_node_id,
                         sizeof(request->local_node_id)) ||
      !bytes_are_nonzero(request->request_id.bytes,
                         sizeof(request->request_id.bytes)) ||
      !range_is_valid(request->range_offset, request->range_length,
                      request->cid.size)) {
    return M3_CHUNK_CAPABILITY_INVALID_ARG;
  }

  if (request->now_ms < claims->issued_at_ms)
    return M3_CHUNK_CAPABILITY_NOT_YET_VALID;
  if (request->now_ms >= claims->expires_at_ms)
    return M3_CHUNK_CAPABILITY_EXPIRED;
  if (memcmp(request->tenant_id, claims->tenant_id,
             sizeof(request->tenant_id)) != 0) {
    return M3_CHUNK_CAPABILITY_TENANT_MISMATCH;
  }
  if (memcmp(request->local_node_id, claims->audience_node_id,
             sizeof(request->local_node_id)) != 0) {
    return M3_CHUNK_CAPABILITY_AUDIENCE_MISMATCH;
  }
  if (!turbo_uuid_equal(&request->request_id, &claims->request_id))
    return M3_CHUNK_CAPABILITY_REQUEST_MISMATCH;
  if (request->operation != claims->operation)
    return M3_CHUNK_CAPABILITY_OPERATION_MISMATCH;
  if (!cid_equal(&request->cid, &claims->cid))
    return M3_CHUNK_CAPABILITY_CID_MISMATCH;
  if (!range_contains(claims->range_offset, claims->range_length,
                      request->range_offset, request->range_length)) {
    return M3_CHUNK_CAPABILITY_RANGE_DENIED;
  }

  operation_limit = request->operation == M3_CHUNK_OPERATION_READ
                        ? policy->max_read_bytes
                        : policy->max_put_bytes;
  if (request->range_length > operation_limit ||
      request->range_length > SIZE_MAX) {
    return M3_CHUNK_CAPABILITY_RESOURCE_EXHAUSTED;
  }
  if (request->operation == M3_CHUNK_OPERATION_PUT &&
      (request->range_offset != 0u ||
       request->range_length != request->cid.size)) {
    return M3_CHUNK_CAPABILITY_RANGE_DENIED;
  }

  memcpy(out_access->tenant_id, request->tenant_id,
         sizeof(out_access->tenant_id));
  out_access->cid = request->cid;
  out_access->operation = request->operation;
  out_access->range_offset = request->range_offset;
  out_access->range_length = request->range_length;
  memcpy(out_access->audience_node_id, request->local_node_id,
         sizeof(out_access->audience_node_id));
  out_access->request_id = request->request_id;
  out_access->expires_at_ms = claims->expires_at_ms;
  return M3_CHUNK_CAPABILITY_OK;
}
