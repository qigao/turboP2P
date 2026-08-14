#ifndef MESH_PRODUCT_CONTROLLER_IRIS_H
#define MESH_PRODUCT_CONTROLLER_IRIS_H

#include "mesh_control_primitives.h"

#include <iris/iris.h>
#include <turbo_selector.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_PRODUCT_CONTROLLER_NODES_PATH_V1 \
  "/v1/meshes/:mesh/nodes"
#define MESH_PRODUCT_CONTROLLER_NODE_PATH_V1 \
  "/v1/meshes/:mesh/nodes/:node"
#define MESH_PRODUCT_CONTROLLER_OPERATION_PATH_V1 \
  "/v1/meshes/:mesh/operations/:operation"
#define MESH_PRODUCT_CONTROLLER_PLACEMENT_PLAN_PATH_V1 \
  "/v1/meshes/:mesh/placements:plan"
#define MESH_PRODUCT_CONTROLLER_NETWORKS_PATH_V1 \
  "/v1/meshes/:mesh/networks"
#define MESH_PRODUCT_CONTROLLER_NETWORK_PATH_V1 \
  "/v1/meshes/:mesh/networks/:network"
#define MESH_PRODUCT_CONTROLLER_NETWORK_PLAN_PATH_V1 \
  "/v1/meshes/:mesh/networks:plan"
#define MESH_PRODUCT_CONTROLLER_NETWORK_APPLY_PATH_V1 \
  "/v1/meshes/:mesh/networks:apply"
#define MESH_PRODUCT_CONTROLLER_NETWORK_DELETE_PATH_V1 \
  "/v1/meshes/:mesh/networks/:network:delete"
#define MESH_PRODUCT_CONTROLLER_MEDIA_TYPE_V1 \
  "application/vnd.turbop2p.control+json;version=1"
#define MESH_PRODUCT_SELECTOR_DIGEST_SIZE_V1 32u
#define MESH_PRODUCT_NETWORK_DRAIN_MAX_MS_V1 300000u

typedef enum {
  MESH_PRODUCT_QUERY_NODES_LIST = 1,
  MESH_PRODUCT_QUERY_NODE_GET,
  MESH_PRODUCT_QUERY_OPERATION_GET,
  MESH_PRODUCT_QUERY_PLACEMENT_PLAN,
  MESH_PRODUCT_QUERY_NETWORKS_LIST,
  MESH_PRODUCT_QUERY_NETWORK_GET,
  MESH_PRODUCT_QUERY_NETWORK_PLAN,
  MESH_PRODUCT_QUERY_NETWORK_APPLY,
  MESH_PRODUCT_QUERY_NETWORK_DELETE
} mesh_product_query_kind_v1_t;

typedef mesh_control_result_t (*mesh_product_controller_authorize_fn)(
    void *context, const char *peer_certificate_sha256, const char *mesh,
    mesh_product_query_kind_v1_t query_kind);

/**
 * Render one immutable JSON query result into caller-owned bounded storage.
 * out_size receives the required bytes on RESOURCE_EXHAUSTED. The callback is
 * read-only and must not advance desired state, operation state or cursors.
 */
typedef mesh_control_result_t (*mesh_product_controller_query_fn)(
    void *context, mesh_product_query_kind_v1_t query_kind,
    const char *mesh, const char *resource_id, uint32_t page_limit,
    char *output, size_t output_capacity, size_t *out_size);

typedef struct {
  uint32_t selector_language_version;
  const char *subject;
  const char *selector;
  /** SHA-256 of the canonical selector bytes. */
  uint8_t selector_digest[MESH_PRODUCT_SELECTOR_DIGEST_SIZE_V1];
  /** Borrowed immutable program valid only during the plan callback. */
  const turbo_selector_program_t *selector_program;
  size_t predicate_count;
  /** Local monotonic deadline. The planner must stop and fail when reached. */
  uint64_t deadline_ms;
} mesh_product_placement_plan_v1_t;

/**
 * Plan against one immutable inventory generation. The request strings are
 * borrowed only for this call and selector is already canonicalized by the
 * authoritative Controller adapter. selector_program may be evaluated
 * synchronously against the callback's immutable inventory snapshot; it must
 * not be retained. The callback remains read-only.
 */
typedef mesh_control_result_t (*mesh_product_controller_plan_fn)(
    void *context, const char *mesh,
    const mesh_product_placement_plan_v1_t *request, char *output,
    size_t output_capacity, size_t *out_size);

typedef struct {
  mesh_product_query_kind_v1_t kind;
  const char *network; /* non-NULL only for DELETE */
  const char *document;
  size_t document_size;
  /** Parsed nonzero DELETE drain budget; zero for PLAN/APPLY. */
  uint32_t drain_timeout_ms;
  uint64_t deadline_ms;
} mesh_product_network_request_v1_t;

/**
 * Execute a validated, bounded Network plan/apply/delete request. APPLY and
 * DELETE must return a durable operation/receipt document; transport success
 * alone is not a commit acknowledgement.
 */
typedef mesh_control_result_t (*mesh_product_controller_network_fn)(
    void *context, const char *mesh,
    const mesh_product_network_request_v1_t *request, char *output,
    size_t output_capacity, size_t *out_size);

typedef struct {
  mesh_product_controller_authorize_fn authorize;
  mesh_product_controller_query_fn query;
  /** Optional; when NULL the placement plan route is not registered. */
  mesh_product_controller_plan_fn plan;
  /** Optional; when NULL Network mutation routes are not registered. */
  mesh_product_controller_network_fn network;
  void *context;
  size_t max_response_bytes;
  uint32_t max_page_items;
  /** Required when plan is configured; range 1..65536 bytes. */
  size_t max_plan_request_bytes;
  /** Required when plan is configured; range 1..120000 milliseconds. */
  uint32_t plan_timeout_ms;
  /** Required when network is configured; each is bounded by plan maxima. */
  size_t max_network_request_bytes;
  uint32_t network_timeout_ms;
} mesh_product_controller_iris_config_v1_t;

typedef struct {
  uint8_t accepting;
  uint64_t received;
  uint64_t authorized;
  uint64_t succeeded;
  uint64_t rejected_auth;
  uint64_t rejected_input;
  uint64_t rejected_source;
} mesh_product_controller_iris_stats_v1_t;

typedef struct {
  iris_app_t *app;
  mesh_product_controller_iris_config_v1_t config;
  atomic_bool accepting;
  atomic_uint_fast64_t received;
  atomic_uint_fast64_t authorized;
  atomic_uint_fast64_t succeeded;
  atomic_uint_fast64_t rejected_auth;
  atomic_uint_fast64_t rejected_input;
  atomic_uint_fast64_t rejected_source;
  uint8_t initialized;
} mesh_product_controller_iris_v1_t;

/** Register read-only Product Controller routes on an explicit app. */
mesh_control_result_t mesh_product_controller_iris_register_v1(
    mesh_product_controller_iris_v1_t *adapter, iris_app_t *app,
    const mesh_product_controller_iris_config_v1_t *config);

/**
 * Authorize and execute a typed query without HTTP parsing. output is
 * caller-owned; no bytes are written on a failed result.
 */
mesh_control_result_t mesh_product_controller_iris_query_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256,
    mesh_product_query_kind_v1_t query_kind, const char *mesh,
    const char *resource_id, uint32_t page_limit, char *output,
    size_t output_capacity, size_t *out_size);

/**
 * Authorize, compile and canonicalize one selector before invoking plan.
 * selector is a borrowed size-delimited UTF-8 view.
 */
mesh_control_result_t mesh_product_controller_iris_plan_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256, const char *mesh,
    const char *subject, uint32_t selector_language_version,
    const char *selector, size_t selector_size, char *output,
    size_t output_capacity, size_t *out_size);

/** Parse the strict V1 JSON adapter format, then execute plan_v1. */
mesh_control_result_t mesh_product_controller_iris_plan_json_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256, const char *mesh,
    const char *body, size_t body_size, char *output,
    size_t output_capacity, size_t *out_size);

/** Validate JSON, authorize, apply one shared monotonic deadline, then invoke network callback. */
mesh_control_result_t mesh_product_controller_iris_network_json_v1(
    mesh_product_controller_iris_v1_t *adapter,
    const char *peer_certificate_sha256, const char *mesh,
    mesh_product_query_kind_v1_t kind, const char *network,
    const char *body, size_t body_size, char *output,
    size_t output_capacity, size_t *out_size);

mesh_control_result_t mesh_product_controller_iris_close_v1(
    mesh_product_controller_iris_v1_t *adapter);

mesh_control_result_t mesh_product_controller_iris_get_stats_v1(
    const mesh_product_controller_iris_v1_t *adapter,
    mesh_product_controller_iris_stats_v1_t *out_stats);

/** Iris callbacks must be quiescent before destroy. The app remains borrowed. */
void mesh_product_controller_iris_destroy_v1(
    mesh_product_controller_iris_v1_t *adapter);

#ifdef __cplusplus
}
#endif

#endif
