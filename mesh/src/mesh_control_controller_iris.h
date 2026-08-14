#ifndef MESH_CONTROL_CONTROLLER_IRIS_H
#define MESH_CONTROL_CONTROLLER_IRIS_H

#include "mesh_control_controller_session.h"
#include "mesh_control_mmp.h"

#include <iris/iris.h>
#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_CONTROLLER_SYNC_PATH_V1 "/v1/agent/sync"
#define MESH_CONTROL_CONTROLLER_SYNC_MEDIA_TYPE_V1 \
  "application/vnd.turbop2p.agent-sync;version=1"
#define MESH_CONTROL_CONTROLLER_SUBMIT_PATH_V1 "/v1/controller/outbox"
#define MESH_CONTROL_CONTROLLER_SUBMIT_MEDIA_TYPE_V1 \
  "application/vnd.turbop2p.mmp;version=1"

typedef mesh_control_result_t (*mesh_control_controller_submit_authorize_fn)(
    void *context, const mesh_mgmt_verified_envelope_v1_t *verified,
    const mesh_control_envelope_v1_t *envelope, uint64_t now_ms);

typedef struct {
  mesh_control_controller_session_v1_t *controller;
  coro_context_t *context;
  /** Protocol wall clock for signed lifetime and durable lease semantics. */
  uint64_t (*now_ms)(void *context);
  void *now_context;
  uint64_t persistence_timeout_ms;
  /** NULL disables the northbound durable-submit endpoint. */
  const char *submit_peer_certificate_sha256;
  mesh_control_controller_submit_authorize_fn authorize_submit;
  void *submit_context;
} mesh_control_controller_iris_config_v1_t;

typedef struct {
  uint64_t received;
  uint64_t succeeded;
  uint64_t rejected_transport;
  uint64_t rejected_protocol;
  uint64_t rejected_busy;
  uint64_t timed_out;
  uint64_t submitted;
  uint64_t active_callbacks;
  uint8_t accepting;
} mesh_control_controller_iris_stats_v1_t;

typedef struct {
  iris_app_t *app;
  mesh_control_controller_iris_config_v1_t config;
  atomic_bool accepting;
  atomic_uint_fast64_t received;
  atomic_uint_fast64_t succeeded;
  atomic_uint_fast64_t rejected_transport;
  atomic_uint_fast64_t rejected_protocol;
  atomic_uint_fast64_t rejected_busy;
  atomic_uint_fast64_t timed_out;
  atomic_uint_fast64_t submitted;
  atomic_uint_fast64_t active_callbacks;
  /** One bounded response scratch matches the session's single in-flight RPC. */
  uint8_t *response_storage;
  uint8_t initialized;
  uint8_t maintenance_running;
} mesh_control_controller_iris_v1_t;

/** Registers the binary mTLS H1/H2 agent-outbound sync endpoint. */
mesh_control_result_t mesh_control_controller_iris_register_v1(
    mesh_control_controller_iris_v1_t *adapter, iris_app_t *app,
    const mesh_control_controller_iris_config_v1_t *config);

mesh_control_result_t mesh_control_controller_iris_close_v1(
    mesh_control_controller_iris_v1_t *adapter);

mesh_control_result_t mesh_control_controller_iris_get_stats_v1(
    const mesh_control_controller_iris_v1_t *adapter,
    mesh_control_controller_iris_stats_v1_t *out_stats);

/** Active Iris callbacks and the managed maintenance coroutine must quiesce. */
void mesh_control_controller_iris_destroy_v1(
    mesh_control_controller_iris_v1_t *adapter);

#ifdef __cplusplus
}
#endif

#endif
