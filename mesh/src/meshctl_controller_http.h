#ifndef MESHCTL_CONTROLLER_HTTP_H
#define MESHCTL_CONTROLLER_HTTP_H

#include <stddef.h>
#include <stdint.h>

#define MESHCTL_PRODUCT_MEDIA_TYPE "application/vnd.turbop2p.control+json;version=1"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  MESHCTL_PRODUCT_ENDPOINT_CAPACITY = 2048,
  MESHCTL_PRODUCT_ID_CAPACITY = 129,
  MESHCTL_PRODUCT_SUBJECT_CAPACITY = 257,
  MESHCTL_PRODUCT_PATH_CAPACITY = 512,
  MESHCTL_PRODUCT_ROUTE_CAPACITY = 1024,
  MESHCTL_PRODUCT_DIAGNOSTIC_CAPACITY = 4096,
  MESHCTL_PRODUCT_DEFAULT_TIMEOUT_MS = 10000,
  MESHCTL_PRODUCT_MAX_TIMEOUT_MS = 30000,
  MESHCTL_PRODUCT_DEFAULT_PAGE_SIZE = 100,
  MESHCTL_PRODUCT_MAX_PAGE_SIZE = 1000,
  MESHCTL_PRODUCT_MAX_RESPONSE_SIZE = 1024 * 1024,
  MESHCTL_PRODUCT_MAX_RESPONSE_HEADER_SIZE = 32 * 1024,
  MESHCTL_PRODUCT_MAX_REQUEST_SIZE = 64 * 1024
};

typedef struct {
  char endpoint[MESHCTL_PRODUCT_ENDPOINT_CAPACITY];
  char mesh[MESHCTL_PRODUCT_ID_CAPACITY];
  char ca_file[MESHCTL_PRODUCT_PATH_CAPACITY];
  char cert_file[MESHCTL_PRODUCT_PATH_CAPACITY];
  char key_file[MESHCTL_PRODUCT_PATH_CAPACITY];
  uint32_t timeout_ms;
  uint32_t page_size;
} meshctl_product_common_options_t;

typedef enum {
  MESHCTL_CONTROLLER_OK = 0,
  MESHCTL_CONTROLLER_INVALID_ARGUMENT,
  MESHCTL_CONTROLLER_TIMEOUT,
  MESHCTL_CONTROLLER_TRANSPORT_ERROR,
  MESHCTL_CONTROLLER_PROTOCOL_ERROR,
  MESHCTL_CONTROLLER_NO_MEMORY
} meshctl_controller_result_t;

typedef struct {
  int status_code;
  /** Owned, NUL-terminated copy of exactly body_size response bytes. */
  char *body;
  size_t body_size;
} meshctl_controller_response_t;

typedef enum {
  MESHCTL_CONTROLLER_METHOD_GET = 1,
  MESHCTL_CONTROLLER_METHOD_POST
} meshctl_controller_method_t;

/** Borrowed request views remain valid only for the callback invocation. */
typedef struct {
  meshctl_controller_method_t method;
  const char *route;
  const char *content_type;
  const char *body;
  size_t body_size;
} meshctl_controller_request_t;

typedef meshctl_controller_result_t (*meshctl_controller_request_fn)(
    void *context, const meshctl_product_common_options_t *options,
    const meshctl_controller_request_t *request, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response);

typedef meshctl_controller_result_t (*meshctl_controller_query_fn)(
    void *context, const meshctl_product_common_options_t *options,
    const char *route, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response);

typedef struct {
  /** Preferred typed request transport. Required by POST commands. */
  meshctl_controller_request_fn request;
  /** Compatibility path for existing read-only GET integrations. */
  meshctl_controller_query_fn query;
  void *context;
} meshctl_controller_client_t;

/** Bodyless GET with the same ownership, admission and drain contract below. */
meshctl_controller_result_t meshctl_controller_query_http2(
    void *context, const meshctl_product_common_options_t *options,
    const char *route, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response);

/**
 * Submit one synchronous HTTP/2+mTLS request. No retry, redirect or H1 fallback.
 * options/request are borrowed for this call; context is unused. remaining_ms
 * must be in [1, MESHCTL_PRODUCT_MAX_TIMEOUT_MS]. Certificate and hostname
 * verification are mandatory. GET is bodyless; POST requires the v1 media type
 * and at most MESHCTL_PRODUCT_MAX_REQUEST_SIZE bytes.
 *
 * out_response must have no live body on entry. Successful calls return an
 * independently owned, terminated JSON body (including for non-2xx HTTP status).
 * After valid admission, failures leave out_response empty. Invalid arguments
 * leave it unchanged. The HTTP-result budget may be followed by terminal drain
 * before this function returns. No transport/profile owner escapes the call.
 */
meshctl_controller_result_t meshctl_controller_request_http2(
    void *context, const meshctl_product_common_options_t *options,
    const meshctl_controller_request_t *request, uint32_t remaining_ms,
    meshctl_controller_response_t *out_response);

/** Free the owned body and zero the response. Repeated calls and NULL are safe. */
void meshctl_controller_response_destroy(
    meshctl_controller_response_t *response);

#ifdef __cplusplus
}
#endif

#endif
