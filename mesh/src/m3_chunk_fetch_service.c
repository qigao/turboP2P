#include "m3_chunk_fetch_service.h"

#include <stdlib.h>
#include <string.h>

typedef struct m3_chunk_fetch_request_s {
  m3_chunk_fetch_service_v1_t *service;
  m3_chunk_cid_v1_t cid;
  m3_chunk_fetch_complete_cb complete_cb;
  void *user_data;
  char seed_path[TURBO_FS_MAX_PATH];
  struct m3_chunk_fetch_request_s *next;
} m3_chunk_fetch_request_t;

static int cid_is_valid(const m3_chunk_cid_v1_t *cid) {
  uint8_t aggregate = 0u;

  if (!cid ||
      cid->hash_algorithm != M3_CHUNK_STORE_HASH_ALGORITHM_SHA256) {
    return 0;
  }
  for (size_t i = 0; i < sizeof(cid->digest); i++)
    aggregate |= cid->digest[i];
  return aggregate != 0u;
}

static int cid_equal(const m3_chunk_cid_v1_t *left,
                     const m3_chunk_cid_v1_t *right) {
  return left && right &&
         left->hash_algorithm == right->hash_algorithm &&
         left->size == right->size &&
         memcmp(left->digest, right->digest, sizeof(left->digest)) == 0;
}

static void digest_to_hex(
    const uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE], char output[65]) {
  static const char digits[] = "0123456789abcdef";

  for (size_t i = 0; i < M3_CHUNK_CID_DIGEST_SIZE; i++) {
    output[i * 2u] = digits[digest[i] >> 4u];
    output[i * 2u + 1u] = digits[digest[i] & 0x0fu];
  }
  output[64] = '\0';
}

static m3_chunk_fetch_result_t seed_path_for_cid(
    const m3_chunk_fetch_service_v1_t *service,
    const m3_chunk_cid_v1_t *cid, char output[TURBO_FS_MAX_PATH]) {
  char key[65];

  if (!service || !cid || !output)
    return M3_CHUNK_FETCH_INVALID_ARG;
  digest_to_hex(cid->digest, key);
  if (turbo_fs_path_join(output, TURBO_FS_MAX_PATH, service->seed_root,
                         key) != 0) {
    return M3_CHUNK_FETCH_INVALID_ARG;
  }
  return M3_CHUNK_FETCH_OK;
}

static m3_chunk_fetch_result_t map_store_result(
    m3_chunk_store_result_t result) {
  switch (result) {
  case M3_CHUNK_STORE_OK:
    return M3_CHUNK_FETCH_OK;
  case M3_CHUNK_STORE_CORRUPT:
  case M3_CHUNK_STORE_DIGEST_MISMATCH:
    return M3_CHUNK_FETCH_INTEGRITY;
  case M3_CHUNK_STORE_RESOURCE_EXHAUSTED:
    return M3_CHUNK_FETCH_RESOURCE_EXHAUSTED;
  case M3_CHUNK_STORE_IO:
  case M3_CHUNK_STORE_NOT_FOUND:
    return M3_CHUNK_FETCH_IO;
  case M3_CHUNK_STORE_INVALID_ARG:
  case M3_CHUNK_STORE_LOCKED:
  case M3_CHUNK_STORE_CSPRNG_FAILED:
  default:
    return M3_CHUNK_FETCH_STORE_FAILED;
  }
}

static m3_chunk_fetch_result_t import_seed(
    m3_chunk_fetch_service_v1_t *service, const m3_chunk_cid_v1_t *cid,
    const char *seed_path, uint8_t *out_created) {
  turbo_fs_stat_t stat;
  turbo_fs_buf_t bytes = {0};
  m3_chunk_store_result_t store_result;

  if (!service || !cid || !seed_path || !out_created)
    return M3_CHUNK_FETCH_INVALID_ARG;
  *out_created = 0u;
  if (turbo_fs_lstat(seed_path, &stat) != 0)
    return M3_CHUNK_FETCH_IO;
  if (!stat.is_file || stat.is_symlink || stat.size != cid->size ||
      stat.size > service->max_fetch_bytes || stat.size > SIZE_MAX) {
    return M3_CHUNK_FETCH_INTEGRITY;
  }
  if (turbo_fs_read_file(seed_path, &bytes) != 0)
    return M3_CHUNK_FETCH_IO;
  if (bytes.len != (size_t)cid->size) {
    turbo_fs_buf_free(&bytes);
    return M3_CHUNK_FETCH_INTEGRITY;
  }
  store_result = m3_chunk_store_put_bytes_v1(
      service->store, cid, (const uint8_t *)bytes.base, bytes.len,
      out_created);
  turbo_fs_buf_free(&bytes);
  return map_store_result(store_result);
}

static m3_chunk_fetch_request_t *find_pending(
    const m3_chunk_fetch_service_v1_t *service,
    const m3_chunk_cid_v1_t *cid) {
  m3_chunk_fetch_request_t *request;

  if (!service || !cid)
    return NULL;
  request = service->pending;
  while (request) {
    if (cid_equal(&request->cid, cid))
      return request;
    request = request->next;
  }
  return NULL;
}

static void unlink_pending(m3_chunk_fetch_request_t *request) {
  m3_chunk_fetch_request_t **current;
  m3_chunk_fetch_service_v1_t *service;

  if (!request || !request->service)
    return;
  service = request->service;
  current = (m3_chunk_fetch_request_t **)&service->pending;
  while (*current) {
    if (*current == request) {
      *current = request->next;
      request->next = NULL;
      if (service->pending_count > 0u)
        service->pending_count--;
      return;
    }
    current = &(*current)->next;
  }
}

static void finish_request(m3_chunk_fetch_request_t *request,
                           m3_chunk_fetch_result_t result,
                           uint8_t created) {
  m3_chunk_fetch_complete_cb complete_cb;
  m3_chunk_cid_v1_t cid;
  void *user_data;

  if (!request)
    return;
  complete_cb = request->complete_cb;
  user_data = request->user_data;
  cid = request->cid;
  unlink_pending(request);
  free(request);
  complete_cb(result, &cid, created, user_data);
}

static void on_p2p_fetch_complete(p2p_transfer_t *transfer, int success,
                                  const char *error_msg, void *user_data) {
  m3_chunk_fetch_request_t *request =
      (m3_chunk_fetch_request_t *)user_data;
  m3_chunk_fetch_result_t result;
  uint8_t created = 0u;

  (void)transfer;
  (void)error_msg;
  if (!request || !request->service)
    return;
  if (!success) {
    (void)turbo_fs_unlink(request->seed_path);
    finish_request(request, M3_CHUNK_FETCH_NETWORK, 0u);
    return;
  }
  result = import_seed(request->service, &request->cid,
                       request->seed_path, &created);
  finish_request(request, result, created);
}

m3_chunk_fetch_result_t m3_chunk_fetch_service_init_v1(
    m3_chunk_fetch_service_v1_t *service, p2p_node_t *node,
    m3_chunk_store_v1_t *store, const char *seed_root,
    uint64_t max_fetch_bytes, size_t max_pending) {
  turbo_fs_stat_t stat;

  if (!service || service->open || !node || !store || !store->open ||
      !seed_root || !turbo_fs_path_is_absolute(seed_root) ||
      strlen(seed_root) >= sizeof(service->seed_root) ||
      max_fetch_bytes == 0u ||
      max_fetch_bytes > store->max_chunk_bytes || max_pending == 0u) {
    return M3_CHUNK_FETCH_INVALID_ARG;
  }
  if (turbo_fs_lstat(seed_root, &stat) != 0 || !stat.is_directory ||
      stat.is_symlink) {
    return M3_CHUNK_FETCH_IO;
  }
  memset(service, 0, sizeof(*service));
  service->node = node;
  service->store = store;
  memcpy(service->seed_root, seed_root, strlen(seed_root) + 1u);
  service->max_fetch_bytes = max_fetch_bytes;
  service->max_pending = max_pending;
  service->open = 1u;
  return M3_CHUNK_FETCH_OK;
}

m3_chunk_fetch_result_t m3_chunk_fetch_service_close_v1(
    m3_chunk_fetch_service_v1_t *service) {
  if (!service || !service->open)
    return M3_CHUNK_FETCH_INVALID_STATE;
  if (service->pending_count != 0u || service->pending)
    return M3_CHUNK_FETCH_BUSY;
  memset(service, 0, sizeof(*service));
  return M3_CHUNK_FETCH_OK;
}

m3_chunk_fetch_result_t m3_chunk_fetch_service_fetch_v1(
    m3_chunk_fetch_service_v1_t *service,
    const m3_chunk_cid_v1_t *cid,
    m3_chunk_fetch_complete_cb complete_cb, void *user_data) {
  m3_chunk_fetch_request_t *request;
  turbo_fs_stat_t stat;
  char key[65];
  char seed_path[TURBO_FS_MAX_PATH];
  uint8_t created = 0u;
  m3_chunk_fetch_result_t result;
  int p2p_result;

  if (!service || !service->open || !cid_is_valid(cid) || !complete_cb ||
      cid->size > service->max_fetch_bytes || cid->size > SIZE_MAX) {
    return M3_CHUNK_FETCH_INVALID_ARG;
  }
  if (find_pending(service, cid))
    return M3_CHUNK_FETCH_BUSY;
  result = seed_path_for_cid(service, cid, seed_path);
  if (result != M3_CHUNK_FETCH_OK)
    return result;

  if (turbo_fs_lstat(seed_path, &stat) == 0) {
    result = import_seed(service, cid, seed_path, &created);
    if (result != M3_CHUNK_FETCH_OK)
      return result;
    digest_to_hex(cid->digest, key);
    {
      char announced_key[65];
      int announce_result =
          p2p_put_file(service->node, seed_path, announced_key);
      if (announce_result != P2P_OK)
        return M3_CHUNK_FETCH_NETWORK;
      if (strcmp(announced_key, key) != 0)
        return M3_CHUNK_FETCH_INTEGRITY;
    }
    complete_cb(M3_CHUNK_FETCH_OK, cid, created, user_data);
    return M3_CHUNK_FETCH_OK;
  }
  if (service->pending_count >= service->max_pending)
    return M3_CHUNK_FETCH_RESOURCE_EXHAUSTED;
  request = (m3_chunk_fetch_request_t *)calloc(1, sizeof(*request));
  if (!request)
    return M3_CHUNK_FETCH_RESOURCE_EXHAUSTED;
  request->service = service;
  request->cid = *cid;
  request->complete_cb = complete_cb;
  request->user_data = user_data;
  memcpy(request->seed_path, seed_path, strlen(seed_path) + 1u);
  request->next = service->pending;
  service->pending = request;
  service->pending_count++;

  digest_to_hex(cid->digest, key);
  p2p_result = p2p_get_file_async(service->node, key, request->seed_path,
                                  on_p2p_fetch_complete, request);
  if (p2p_result != P2P_OK) {
    unlink_pending(request);
    free(request);
    return M3_CHUNK_FETCH_NETWORK;
  }
  return M3_CHUNK_FETCH_OK;
}
