#ifndef M3_CHUNK_FETCH_SERVICE_H
#define M3_CHUNK_FETCH_SERVICE_H

#include "m3_chunk_store.h"
#include "p2p.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_CHUNK_FETCH_OK = 0,
  M3_CHUNK_FETCH_INVALID_ARG = -1,
  M3_CHUNK_FETCH_INVALID_STATE = -2,
  M3_CHUNK_FETCH_BUSY = -3,
  M3_CHUNK_FETCH_IO = -4,
  M3_CHUNK_FETCH_NETWORK = -5,
  M3_CHUNK_FETCH_INTEGRITY = -6,
  M3_CHUNK_FETCH_STORE_FAILED = -7,
  M3_CHUNK_FETCH_RESOURCE_EXHAUSTED = -8,
} m3_chunk_fetch_result_t;

typedef void (*m3_chunk_fetch_complete_cb)(
    m3_chunk_fetch_result_t result, const m3_chunk_cid_v1_t *cid,
    uint8_t created, void *user_data);

struct m3_chunk_fetch_request_s;

/**
 * Owner-loop M3 chunk fetch composition.
 *
 * The service borrows node and store. seed_root must be an existing absolute
 * directory controlled by the node. Successful downloads remain there as
 * stable P2P seed files and are also published into the immutable M3 CAS.
 * The caller must zero-initialize the service before the first init call.
 */
typedef struct {
  p2p_node_t *node;
  m3_chunk_store_v1_t *store;
  char seed_root[TURBO_FS_MAX_PATH];
  uint64_t max_fetch_bytes;
  size_t max_pending;
  size_t pending_count;
  struct m3_chunk_fetch_request_s *pending;
  uint8_t open;
} m3_chunk_fetch_service_v1_t;

m3_chunk_fetch_result_t m3_chunk_fetch_service_init_v1(
    m3_chunk_fetch_service_v1_t *service, p2p_node_t *node,
    m3_chunk_store_v1_t *store, const char *seed_root,
    uint64_t max_fetch_bytes, size_t max_pending);

/**
 * Close an idle service.
 *
 * Returns BUSY while asynchronous fetches still own callbacks into service.
 */
m3_chunk_fetch_result_t m3_chunk_fetch_service_close_v1(
    m3_chunk_fetch_service_v1_t *service);

/**
 * Fetch one CID through the P2P swarm and import it into the local CAS.
 *
 * A valid stable seed-cache hit may invoke complete_cb before this function
 * returns and re-announces that file as a P2P provider. Otherwise complete_cb
 * runs on the P2P node event loop. A successful return means completion is
 * delivered through complete_cb, not that bytes are already available.
 */
m3_chunk_fetch_result_t m3_chunk_fetch_service_fetch_v1(
    m3_chunk_fetch_service_v1_t *service,
    const m3_chunk_cid_v1_t *cid,
    m3_chunk_fetch_complete_cb complete_cb, void *user_data);

#ifdef __cplusplus
}
#endif

#endif
