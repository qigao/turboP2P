#ifndef M3_CHUNK_READ_SERVICE_H
#define M3_CHUNK_READ_SERVICE_H

#include "m3_chunk_access_store.h"
#include "m3_chunk_replay.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_CHUNK_READ_SERVICE_OK = 0,
  M3_CHUNK_READ_SERVICE_INVALID_ARG = -1,
  M3_CHUNK_READ_SERVICE_MUTATION_DISABLED = -2,
  M3_CHUNK_READ_SERVICE_AUTH_DENIED = -3,
  M3_CHUNK_READ_SERVICE_NOT_YET_VALID = -4,
  M3_CHUNK_READ_SERVICE_EXPIRED = -5,
  M3_CHUNK_READ_SERVICE_CONFLICT = -6,
  M3_CHUNK_READ_SERVICE_IN_PROGRESS = -7,
  M3_CHUNK_READ_SERVICE_RESOURCE_EXHAUSTED = -8,
  M3_CHUNK_READ_SERVICE_NOT_FOUND = -9,
  M3_CHUNK_READ_SERVICE_CORRUPT = -10,
  M3_CHUNK_READ_SERVICE_DIGEST_MISMATCH = -11,
  M3_CHUNK_READ_SERVICE_IO = -12,
  M3_CHUNK_READ_SERVICE_INTERNAL = -13,
} m3_chunk_read_service_result_t;

/**
 * Read-only composition root. It borrows store and replay journal.
 *
 * All calls, including init/destroy, run on one owner loop. The local node ID
 * is the audience fact and cannot be supplied by an individual request.
 */
typedef struct {
  m3_chunk_store_v1_t *store;
  m3_chunk_replay_journal_v1_t *replay;
  m3_chunk_capability_policy_v1_t policy;
  uint8_t local_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE];
  uint8_t initialized;
} m3_chunk_read_service_v1_t;

m3_chunk_read_service_result_t m3_chunk_read_service_init_v1(
    m3_chunk_read_service_v1_t *service, m3_chunk_store_v1_t *store,
    m3_chunk_replay_journal_v1_t *replay,
    const m3_chunk_capability_policy_v1_t *policy,
    const uint8_t local_node_id[M3_CHUNK_CAPABILITY_NODE_ID_SIZE]);

void m3_chunk_read_service_destroy_v1(
    m3_chunk_read_service_v1_t *service);

/**
 * Authorize and execute one READ from already signature-verified claims.
 *
 * PUT is explicitly disabled until the replay journal has a durable format.
 * out_replayed is one when the UUID binding already existed.
 */
m3_chunk_read_service_result_t m3_chunk_read_service_execute_v1(
    m3_chunk_read_service_v1_t *service,
    const m3_chunk_capability_claims_v1_t *verified_claims,
    const m3_chunk_access_request_v1_t *request, uint8_t *buffer,
    size_t buffer_size, size_t *out_read, uint8_t *out_replayed);

#ifdef __cplusplus
}
#endif

#endif
