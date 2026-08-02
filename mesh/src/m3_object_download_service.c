#include "m3_object_download_service.h"

#include <openssl/evp.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <turbo_uuid.h>

#define M3_OBJECT_DOWNLOAD_FILE_MODE 0600

typedef struct m3_object_download_request_s {
  m3_object_download_service_v1_t *service;
  m3_chunk_cid_v1_t object_cid;
  m3_chunk_cid_v1_t *chunks;
  size_t chunk_count;
  size_t next_chunk;
  uint64_t bytes_written;
  turbo_file_t file;
  EVP_MD_CTX *hash;
  char output_path[TURBO_FS_MAX_PATH];
  char temp_path[TURBO_FS_MAX_PATH];
  m3_object_download_complete_cb complete_cb;
  void *user_data;
  uint8_t driving;
  uint8_t inline_ready;
  m3_chunk_fetch_result_t inline_result;
  struct m3_object_download_request_s *next;
} m3_object_download_request_t;

static m3_object_download_request_t *find_output(
    const m3_object_download_service_v1_t *service,
    const char *output_path) {
  m3_object_download_request_t *request;

  if (!service || !output_path)
    return NULL;
  request = service->pending;
  while (request) {
    if (strcmp(request->output_path, output_path) == 0)
      return request;
    request = request->next;
  }
  return NULL;
}

static void unlink_pending(m3_object_download_request_t *request) {
  m3_object_download_request_t **current;
  m3_object_download_service_v1_t *service;

  if (!request || !request->service)
    return;
  service = request->service;
  current = (m3_object_download_request_t **)&service->pending;
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

static void finish_request(m3_object_download_request_t *request,
                           m3_object_download_result_t result) {
  m3_object_download_complete_cb complete_cb;
  m3_chunk_cid_v1_t object_cid;
  char output_path[TURBO_FS_MAX_PATH];
  void *user_data;

  if (!request)
    return;
  if (request->file != TURBO_INVALID_FILE) {
    (void)turbo_fs_close(request->file);
    request->file = TURBO_INVALID_FILE;
  }
  if (result != M3_OBJECT_DOWNLOAD_OK)
    (void)turbo_fs_unlink(request->temp_path);
  complete_cb = request->complete_cb;
  user_data = request->user_data;
  object_cid = request->object_cid;
  memcpy(output_path, request->output_path,
         strlen(request->output_path) + 1u);
  unlink_pending(request);
  EVP_MD_CTX_free(request->hash);
  free(request->chunks);
  free(request);
  complete_cb(result, &object_cid, output_path, user_data);
}

static m3_object_download_result_t map_fetch_result(
    m3_chunk_fetch_result_t result) {
  switch (result) {
  case M3_CHUNK_FETCH_OK:
    return M3_OBJECT_DOWNLOAD_OK;
  case M3_CHUNK_FETCH_INTEGRITY:
    return M3_OBJECT_DOWNLOAD_INTEGRITY;
  case M3_CHUNK_FETCH_RESOURCE_EXHAUSTED:
    return M3_OBJECT_DOWNLOAD_RESOURCE_EXHAUSTED;
  case M3_CHUNK_FETCH_IO:
  case M3_CHUNK_FETCH_STORE_FAILED:
    return M3_OBJECT_DOWNLOAD_IO;
  case M3_CHUNK_FETCH_INVALID_ARG:
  case M3_CHUNK_FETCH_INVALID_STATE:
  case M3_CHUNK_FETCH_BUSY:
  case M3_CHUNK_FETCH_NETWORK:
  default:
    return M3_OBJECT_DOWNLOAD_FETCH_FAILED;
  }
}

static m3_object_download_result_t write_all(
    turbo_file_t file, const uint8_t *bytes, size_t size) {
  size_t offset = 0u;

  while (offset < size) {
    size_t batch = size - offset;
    int written;

    if (batch > INT_MAX)
      batch = INT_MAX;
    written = turbo_fs_write(file, (const char *)bytes + offset, batch);
    if (written <= 0)
      return M3_OBJECT_DOWNLOAD_IO;
    offset += (size_t)written;
  }
  return M3_OBJECT_DOWNLOAD_OK;
}

static m3_object_download_result_t append_current_chunk(
    m3_object_download_request_t *request) {
  const m3_chunk_cid_v1_t *cid;
  uint8_t *bytes = NULL;
  size_t size;
  size_t read_size = 0u;
  m3_chunk_store_result_t read_result;
  m3_object_download_result_t result = M3_OBJECT_DOWNLOAD_OK;

  if (!request || request->next_chunk >= request->chunk_count)
    return M3_OBJECT_DOWNLOAD_INVALID_STATE;
  cid = &request->chunks[request->next_chunk];
  size = (size_t)cid->size;
  if (size > 0u) {
    bytes = (uint8_t *)malloc(size);
    if (!bytes)
      return M3_OBJECT_DOWNLOAD_RESOURCE_EXHAUSTED;
  }
  read_result = m3_chunk_store_read_range_v1(
      request->service->store, cid, 0u, size, bytes, &read_size);
  if (read_result != M3_CHUNK_STORE_OK || read_size != size) {
    result = read_result == M3_CHUNK_STORE_CORRUPT ||
                     read_result == M3_CHUNK_STORE_DIGEST_MISMATCH
                 ? M3_OBJECT_DOWNLOAD_INTEGRITY
                 : M3_OBJECT_DOWNLOAD_IO;
    goto cleanup;
  }
  result = write_all(request->file, bytes, size);
  if (result != M3_OBJECT_DOWNLOAD_OK)
    goto cleanup;
  if (EVP_DigestUpdate(request->hash, bytes, size) != 1) {
    result = M3_OBJECT_DOWNLOAD_CRYPTO_FAILED;
    goto cleanup;
  }
  if (request->bytes_written > UINT64_MAX - cid->size) {
    result = M3_OBJECT_DOWNLOAD_INTEGRITY;
    goto cleanup;
  }
  request->bytes_written += cid->size;

cleanup:
  free(bytes);
  return result;
}

static m3_object_download_result_t publish_object(
    m3_object_download_request_t *request) {
  turbo_fs_stat_t stat;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
  unsigned int digest_size = 0u;

  if (!request || request->bytes_written != request->object_cid.size)
    return M3_OBJECT_DOWNLOAD_INTEGRITY;
  if (EVP_DigestFinal_ex(request->hash, digest, &digest_size) != 1 ||
      digest_size != sizeof(digest)) {
    return M3_OBJECT_DOWNLOAD_CRYPTO_FAILED;
  }
  if (memcmp(digest, request->object_cid.digest, sizeof(digest)) != 0)
    return M3_OBJECT_DOWNLOAD_INTEGRITY;
  if (turbo_fs_fsync(request->file) != 0)
    return M3_OBJECT_DOWNLOAD_IO;
  if (turbo_fs_close(request->file) != 0) {
    request->file = TURBO_INVALID_FILE;
    return M3_OBJECT_DOWNLOAD_IO;
  }
  request->file = TURBO_INVALID_FILE;
  if (turbo_fs_lstat(request->output_path, &stat) == 0)
    return M3_OBJECT_DOWNLOAD_OUTPUT_EXISTS;
  if (turbo_fs_rename(request->temp_path, request->output_path) != 0)
    return M3_OBJECT_DOWNLOAD_IO;
  return M3_OBJECT_DOWNLOAD_OK;
}

static void drive_request(m3_object_download_request_t *request);

static void on_chunk_fetched(m3_chunk_fetch_result_t result,
                             const m3_chunk_cid_v1_t *cid,
                             uint8_t created, void *user_data) {
  m3_object_download_request_t *request =
      (m3_object_download_request_t *)user_data;
  m3_object_download_result_t object_result;

  (void)cid;
  (void)created;
  if (!request)
    return;
  if (request->driving) {
    request->inline_result = result;
    request->inline_ready = 1u;
    return;
  }
  object_result = map_fetch_result(result);
  if (object_result != M3_OBJECT_DOWNLOAD_OK) {
    finish_request(request, object_result);
    return;
  }
  object_result = append_current_chunk(request);
  if (object_result != M3_OBJECT_DOWNLOAD_OK) {
    finish_request(request, object_result);
    return;
  }
  request->next_chunk++;
  drive_request(request);
}

static void drive_request(m3_object_download_request_t *request) {
  m3_object_download_result_t object_result;
  m3_chunk_fetch_result_t fetch_result;

  if (!request || request->driving)
    return;
  request->driving = 1u;
  while (request->next_chunk < request->chunk_count) {
    request->inline_ready = 0u;
    fetch_result = m3_chunk_fetch_service_fetch_v1(
        request->service->fetch_service,
        &request->chunks[request->next_chunk], on_chunk_fetched, request);
    if (fetch_result != M3_CHUNK_FETCH_OK) {
      request->driving = 0u;
      finish_request(request, map_fetch_result(fetch_result));
      return;
    }
    if (!request->inline_ready) {
      request->driving = 0u;
      return;
    }
    object_result = map_fetch_result(request->inline_result);
    if (object_result != M3_OBJECT_DOWNLOAD_OK) {
      request->driving = 0u;
      finish_request(request, object_result);
      return;
    }
    object_result = append_current_chunk(request);
    if (object_result != M3_OBJECT_DOWNLOAD_OK) {
      request->driving = 0u;
      finish_request(request, object_result);
      return;
    }
    request->next_chunk++;
  }
  request->driving = 0u;
  object_result = publish_object(request);
  finish_request(request, object_result);
}

m3_object_download_result_t m3_object_download_service_init_v1(
    m3_object_download_service_v1_t *service,
    m3_chunk_fetch_service_v1_t *fetch_service,
    m3_chunk_store_v1_t *store, uint64_t max_object_bytes,
    size_t max_chunks, size_t max_pending) {
  if (!service || service->open || !fetch_service || !fetch_service->open ||
      !store || !store->open || fetch_service->store != store ||
      max_object_bytes == 0u || max_chunks == 0u || max_pending == 0u) {
    return M3_OBJECT_DOWNLOAD_INVALID_ARG;
  }
  memset(service, 0, sizeof(*service));
  service->fetch_service = fetch_service;
  service->store = store;
  service->max_object_bytes = max_object_bytes;
  service->max_chunks = max_chunks;
  service->max_pending = max_pending;
  service->open = 1u;
  return M3_OBJECT_DOWNLOAD_OK;
}

m3_object_download_result_t m3_object_download_service_close_v1(
    m3_object_download_service_v1_t *service) {
  if (!service || !service->open)
    return M3_OBJECT_DOWNLOAD_INVALID_STATE;
  if (service->pending_count != 0u || service->pending)
    return M3_OBJECT_DOWNLOAD_BUSY;
  memset(service, 0, sizeof(*service));
  return M3_OBJECT_DOWNLOAD_OK;
}

m3_object_download_result_t m3_object_download_service_start_v1(
    m3_object_download_service_v1_t *service,
    const m3_object_manifest_v1_t *manifest, const char *output_path,
    m3_object_download_complete_cb complete_cb, void *user_data) {
  m3_object_download_request_t *request;
  turbo_fs_stat_t stat;
  turbo_uuid_t uuid;
  char uuid_text[TURBO_UUID_STRING_SIZE];
  int path_length;
  if (!service || !service->open || !output_path || !complete_cb ||
      !turbo_fs_path_is_absolute(output_path) ||
      strlen(output_path) >= TURBO_FS_MAX_PATH)
    return M3_OBJECT_DOWNLOAD_INVALID_ARG;
  if (m3_object_manifest_validate_v1(
          manifest, service->max_object_bytes,
          service->max_chunks) != M3_OBJECT_MANIFEST_OK) {
    return M3_OBJECT_DOWNLOAD_INVALID_ARG;
  }
  if (find_output(service, output_path))
    return M3_OBJECT_DOWNLOAD_BUSY;
  if (turbo_fs_lstat(output_path, &stat) == 0)
    return M3_OBJECT_DOWNLOAD_OUTPUT_EXISTS;
  if (service->pending_count >= service->max_pending)
    return M3_OBJECT_DOWNLOAD_RESOURCE_EXHAUSTED;
  if (turbo_uuid_v4_generate(&uuid) != 0 ||
      turbo_uuid_format(&uuid, uuid_text, sizeof(uuid_text)) != 0) {
    return M3_OBJECT_DOWNLOAD_CRYPTO_FAILED;
  }
  request = (m3_object_download_request_t *)calloc(1, sizeof(*request));
  if (!request)
    return M3_OBJECT_DOWNLOAD_RESOURCE_EXHAUSTED;
  request->file = TURBO_INVALID_FILE;
  request->chunks = (m3_chunk_cid_v1_t *)calloc(
      manifest->chunk_count, sizeof(*request->chunks));
  if (manifest->chunk_count > 0u && !request->chunks) {
    free(request);
    return M3_OBJECT_DOWNLOAD_RESOURCE_EXHAUSTED;
  }
  request->hash = EVP_MD_CTX_new();
  if (!request->hash ||
      EVP_DigestInit_ex(request->hash, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(request->hash);
    free(request->chunks);
    free(request);
    return M3_OBJECT_DOWNLOAD_CRYPTO_FAILED;
  }
  request->service = service;
  request->object_cid = manifest->object_cid;
  request->chunk_count = manifest->chunk_count;
  request->complete_cb = complete_cb;
  request->user_data = user_data;
  if (manifest->chunk_count > 0u) {
    memcpy(request->chunks, manifest->chunks,
           manifest->chunk_count * sizeof(*request->chunks));
  }
  memcpy(request->output_path, output_path, strlen(output_path) + 1u);
  path_length = snprintf(request->temp_path, sizeof(request->temp_path),
                         "%s.m3-%s.part", output_path, uuid_text);
  if (path_length < 0 ||
      (size_t)path_length >= sizeof(request->temp_path)) {
    EVP_MD_CTX_free(request->hash);
    free(request->chunks);
    free(request);
    return M3_OBJECT_DOWNLOAD_INVALID_ARG;
  }
  request->file = turbo_fs_open(
      request->temp_path,
      TURBO_FS_O_WRONLY | TURBO_FS_O_CREAT | TURBO_FS_O_TRUNC,
      M3_OBJECT_DOWNLOAD_FILE_MODE);
  if (request->file == TURBO_INVALID_FILE) {
    EVP_MD_CTX_free(request->hash);
    free(request->chunks);
    free(request);
    return M3_OBJECT_DOWNLOAD_IO;
  }
  request->next = service->pending;
  service->pending = request;
  service->pending_count++;
  drive_request(request);
  return M3_OBJECT_DOWNLOAD_OK;
}
