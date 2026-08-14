#ifndef MESH_CONTROL_IRIS_H
#define MESH_CONTROL_IRIS_H

#include "mesh_control_channel.h"
#include "mesh_control_mmp.h"

#include <iris/iris.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_CONTROL_IRIS_PATH_V1 "/v1/control"

typedef mesh_control_result_t (*mesh_control_iris_transport_authorize_fn)(
    void *context,
    const char peer_certificate_sha256[CORO_TLS_PEER_CERT_SHA256_CAPACITY]);

/**
 * Stateless message authorization callback. It checks trust, mesh/target
 * binding, current time and certificate policy. It must not commit replay or
 * desired state: the single domain owner performs those mutations only after
 * this adapter has successfully published the message to its bounded channel.
 * All pointers are borrowed for the duration of the callback.
 */
typedef mesh_control_result_t (*mesh_control_iris_admit_fn)(
    void *context, const mesh_mgmt_verified_envelope_v1_t *verified,
    const mesh_control_envelope_v1_t *envelope, const uint8_t *body,
    size_t body_size);

typedef struct {
  mesh_control_channel_v1_t *inbound;
  mesh_control_iris_transport_authorize_fn authorize_transport;
  mesh_control_iris_admit_fn admit;
  void *auth_context;
} mesh_control_iris_config_v1_t;

typedef struct {
  uint8_t accepting;
  uint64_t received;
  uint64_t queued;
  uint64_t rejected_transport;
  uint64_t rejected_protocol;
  uint64_t rejected_admission;
  uint64_t rejected_backpressure;
} mesh_control_iris_stats_v1_t;

typedef struct {
  iris_app_t *app;
  mesh_control_iris_config_v1_t config;
  atomic_bool accepting;
  atomic_uint_fast64_t received;
  atomic_uint_fast64_t queued;
  atomic_uint_fast64_t rejected_transport;
  atomic_uint_fast64_t rejected_protocol;
  atomic_uint_fast64_t rejected_admission;
  atomic_uint_fast64_t rejected_backpressure;
  uint8_t initialized;
} mesh_control_iris_v1_t;

/**
 * Bind the H1 RFC6455/H2 RFC8441 route on an explicit Iris app. Both transport
 * authorization and signed-message admission are mandatory and fail closed.
 */
mesh_control_result_t mesh_control_iris_register_v1(
    mesh_control_iris_v1_t *adapter, iris_app_t *app,
    const mesh_control_iris_config_v1_t *config);

/**
 * Verify, decode, admit and copy one complete binary WebSocket message. This
 * entry is also usable by tests and future H2 request adapters.
 */
mesh_control_result_t mesh_control_iris_receive_frame_v1(
    mesh_control_iris_v1_t *adapter, const uint8_t *frame, size_t frame_size);

/** Stops admission of new frames. It does not close the caller-owned channel. */
mesh_control_result_t mesh_control_iris_close_v1(
    mesh_control_iris_v1_t *adapter);

mesh_control_result_t mesh_control_iris_get_stats_v1(
    const mesh_control_iris_v1_t *adapter,
    mesh_control_iris_stats_v1_t *out_stats);

/**
 * The Iris server must be stopped and its callbacks quiescent first. The app
 * and channel remain caller-owned.
 */
void mesh_control_iris_destroy_v1(mesh_control_iris_v1_t *adapter);

#ifdef __cplusplus
}
#endif

#endif
