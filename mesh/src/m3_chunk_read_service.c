#include "m3_chunk_read_service.h"

#include <string.h>

static int bytes_are_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0; i < length; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

static m3_chunk_read_service_result_t map_capability_result(
    m3_chunk_capability_result_t result) {
  switch (result) {
  case M3_CHUNK_CAPABILITY_OK:
    return M3_CHUNK_READ_SERVICE_OK;
  case M3_CHUNK_CAPABILITY_NOT_YET_VALID:
    return M3_CHUNK_READ_SERVICE_NOT_YET_VALID;
  case M3_CHUNK_CAPABILITY_EXPIRED:
    return M3_CHUNK_READ_SERVICE_EXPIRED;
  case M3_CHUNK_CAPABILITY_RESOURCE_EXHAUSTED:
    return M3_CHUNK_READ_SERVICE_RESOURCE_EXHAUSTED;
  case M3_CHUNK_CAPABILITY_INVALID_ARG:
    return M3_CHUNK_READ_SERVICE_INVALID_ARG;
  case M3_CHUNK_CAPABILITY_INVALID_CLAIMS:
  case M3_CHUNK_CAPABILITY_TENANT_MISMATCH:
  case M3_CHUNK_CAPABILITY_AUDIENCE_MISMATCH:
  case M3_CHUNK_CAPABILITY_REQUEST_MISMATCH:
  case M3_CHUNK_CAPABILITY_OPERATION_MISMATCH:
  case M3_CHUNK_CAPABILITY_CID_MISMATCH:
  case M3_CHUNK_CAPABILITY_RANGE_DENIED:
  default:
    return M3_CHUNK_READ_SERVICE_AUTH_DENIED;
  }
}

static m3_chunk_read_service_result_t map_store_result(
    m3_chunk_access_store_result_t result) {
  switch (result) {
  case M3_CHUNK_ACCESS_STORE_OK:
    return M3_CHUNK_READ_SERVICE_OK;
  case M3_CHUNK_ACCESS_STORE_EXPIRED:
    return M3_CHUNK_READ_SERVICE_EXPIRED;
  case M3_CHUNK_ACCESS_STORE_RESOURCE_EXHAUSTED:
    return M3_CHUNK_READ_SERVICE_RESOURCE_EXHAUSTED;
  case M3_CHUNK_ACCESS_STORE_NOT_FOUND:
    return M3_CHUNK_READ_SERVICE_NOT_FOUND;
  case M3_CHUNK_ACCESS_STORE_CORRUPT:
    return M3_CHUNK_READ_SERVICE_CORRUPT;
  case M3_CHUNK_ACCESS_STORE_DIGEST_MISMATCH:
    return M3_CHUNK_READ_SERVICE_DIGEST_MISMATCH;
  case M3_CHUNK_ACCESS_STORE_INVALID_ARG:
    return M3_CHUNK_READ_SERVICE_INVALID_ARG;
  case M3_CHUNK_ACCESS_STORE_INVALID_ACCESS:
    return M3_CHUNK_READ_SERVICE_AUTH_DENIED;
  case M3_CHUNK_ACCESS_STORE_IO:
  case M3_CHUNK_ACCESS_STORE_CSPRNG_FAILED:
  case M3_CHUNK_ACCESS_STORE_LOCKED:
  default:
    return M3_CHUNK_READ_SERVICE_IO;
  }
}

static int stored_result_is_valid(int32_t result) {
  return result <= M3_CHUNK_READ_SERVICE_OK &&
         result >= M3_CHUNK_READ_SERVICE_INTERNAL;
}

m3_chunk_read_service_result_t m3_chunk_read_service_init_v1(
    m3_chunk_read_service_v1_t *service, m3_chunk_store_v1_t *store,
    m3_chunk_replay_journal_v1_t *replay,
    const m3_chunk_capability_policy_v1_t *policy,
    const uint8_t local_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE]) {
  if (!service || service->initialized || !store || !store->open || !replay ||
      !replay->entries || !policy || policy->max_ttl_ms == 0u ||
      policy->max_read_bytes == 0u || policy->max_put_bytes == 0u ||
      !bytes_are_nonzero(local_node_id,
                         M3_CHUNK_CAPABILITY_NODE_ID_SIZE)) {
    return M3_CHUNK_READ_SERVICE_INVALID_ARG;
  }

  memset(service, 0, sizeof(*service));
  service->store = store;
  service->replay = replay;
  service->policy = *policy;
  memcpy(service->local_node_id, local_node_id,
         sizeof(service->local_node_id));
  service->initialized = 1u;
  return M3_CHUNK_READ_SERVICE_OK;
}

void m3_chunk_read_service_destroy_v1(
    m3_chunk_read_service_v1_t *service) {
  if (!service)
    return;
  memset(service, 0, sizeof(*service));
}

m3_chunk_read_service_result_t m3_chunk_read_service_execute_v1(
    m3_chunk_read_service_v1_t *service,
    const m3_chunk_capability_claims_v1_t *verified_claims,
    const m3_chunk_access_request_v1_t *request, uint8_t *buffer,
    size_t buffer_size, size_t *out_read, uint8_t *out_replayed) {
  m3_chunk_access_request_v1_t bound_request;
  m3_chunk_authorized_access_v1_t access;
  m3_chunk_replay_begin_v1_t begin;
  m3_chunk_capability_result_t capability_result;
  m3_chunk_replay_result_t replay_result;
  m3_chunk_access_store_result_t store_result;
  m3_chunk_read_service_result_t result;

  if (out_read)
    *out_read = 0u;
  if (out_replayed)
    *out_replayed = 0u;
  if (!service || !service->initialized || !verified_claims || !request ||
      !out_read || !out_replayed) {
    return M3_CHUNK_READ_SERVICE_INVALID_ARG;
  }
  if (request->operation == M3_CHUNK_OPERATION_PUT)
    return M3_CHUNK_READ_SERVICE_MUTATION_DISABLED;
  if (request->operation != M3_CHUNK_OPERATION_READ)
    return M3_CHUNK_READ_SERVICE_INVALID_ARG;

  bound_request = *request;
  memcpy(bound_request.local_node_id, service->local_node_id,
         sizeof(bound_request.local_node_id));
  capability_result = m3_chunk_capability_authorize_v1(
      verified_claims, &bound_request, &service->policy, &access);
  result = map_capability_result(capability_result);
  if (result != M3_CHUNK_READ_SERVICE_OK)
    return result;

  replay_result = m3_chunk_replay_begin_request_v1(
      service->replay, &access, bound_request.now_ms, &begin);
  if (replay_result == M3_CHUNK_REPLAY_CONFLICT)
    return M3_CHUNK_READ_SERVICE_CONFLICT;
  if (replay_result == M3_CHUNK_REPLAY_EXPIRED)
    return M3_CHUNK_READ_SERVICE_EXPIRED;
  if (replay_result == M3_CHUNK_REPLAY_RESOURCE_EXHAUSTED)
    return M3_CHUNK_READ_SERVICE_RESOURCE_EXHAUSTED;
  if (replay_result != M3_CHUNK_REPLAY_OK)
    return M3_CHUNK_READ_SERVICE_INTERNAL;

  if (begin.kind == M3_CHUNK_REPLAY_BEGIN_IN_PROGRESS) {
    *out_replayed = 1u;
    return M3_CHUNK_READ_SERVICE_IN_PROGRESS;
  }
  if (begin.kind == M3_CHUNK_REPLAY_BEGIN_COMPLETED) {
    *out_replayed = 1u;
    if (!stored_result_is_valid(begin.result_code))
      return M3_CHUNK_READ_SERVICE_INTERNAL;
    if (begin.result_code != M3_CHUNK_READ_SERVICE_OK)
      return (m3_chunk_read_service_result_t)begin.result_code;
  } else if (begin.kind != M3_CHUNK_REPLAY_BEGIN_NEW) {
    return M3_CHUNK_READ_SERVICE_INTERNAL;
  }

  store_result = m3_chunk_access_store_read_v1(
      service->store, &access, bound_request.now_ms, buffer, buffer_size,
      out_read);
  result = map_store_result(store_result);
  if (begin.kind == M3_CHUNK_REPLAY_BEGIN_COMPLETED)
    return result;

  replay_result = m3_chunk_replay_complete_request_v1(
      service->replay, &access, (int32_t)result);
  if (replay_result != M3_CHUNK_REPLAY_OK) {
    *out_read = 0u;
    return M3_CHUNK_READ_SERVICE_INTERNAL;
  }
  return result;
}
