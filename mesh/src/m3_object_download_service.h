#ifndef M3_OBJECT_DOWNLOAD_SERVICE_H
#define M3_OBJECT_DOWNLOAD_SERVICE_H

#include "m3_chunk_fetch_service.h"
#include "m3_object_manifest.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  M3_OBJECT_DOWNLOAD_OK = 0,
  M3_OBJECT_DOWNLOAD_INVALID_ARG = -1,
  M3_OBJECT_DOWNLOAD_INVALID_STATE = -2,
  M3_OBJECT_DOWNLOAD_BUSY = -3,
  M3_OBJECT_DOWNLOAD_OUTPUT_EXISTS = -4,
  M3_OBJECT_DOWNLOAD_IO = -5,
  M3_OBJECT_DOWNLOAD_FETCH_FAILED = -6,
  M3_OBJECT_DOWNLOAD_INTEGRITY = -7,
  M3_OBJECT_DOWNLOAD_RESOURCE_EXHAUSTED = -8,
  M3_OBJECT_DOWNLOAD_CRYPTO_FAILED = -9,
} m3_object_download_result_t;

typedef void (*m3_object_download_complete_cb)(
    m3_object_download_result_t result,
    const m3_chunk_cid_v1_t *object_cid, const char *output_path,
    void *user_data);

struct m3_object_download_request_s;

/** Owner-loop object assembly service. All dependencies are borrowed. */
typedef struct {
  m3_chunk_fetch_service_v1_t *fetch_service;
  m3_chunk_store_v1_t *store;
  uint64_t max_object_bytes;
  size_t max_chunks;
  size_t max_pending;
  size_t pending_count;
  struct m3_object_download_request_s *pending;
  uint8_t open;
} m3_object_download_service_v1_t;

/** The caller must zero-initialize service before the first init call. */
m3_object_download_result_t m3_object_download_service_init_v1(
    m3_object_download_service_v1_t *service,
    m3_chunk_fetch_service_v1_t *fetch_service,
    m3_chunk_store_v1_t *store, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_pending);

/** Returns BUSY while requests still own asynchronous callbacks. */
m3_object_download_result_t m3_object_download_service_close_v1(
    m3_object_download_service_v1_t *service);

/**
 * Download and atomically publish one object to a previously absent absolute
 * output path. Completion may run inline when every chunk is already cached.
 */
m3_object_download_result_t m3_object_download_service_start_v1(
    m3_object_download_service_v1_t *service,
    const m3_object_manifest_v1_t *manifest, const char *output_path,
    m3_object_download_complete_cb complete_cb, void *user_data);

#ifdef __cplusplus
}
#endif

#endif
