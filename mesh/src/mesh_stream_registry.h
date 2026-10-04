#ifndef TURBO_P2P_MESH_STREAM_REGISTRY_H
#define TURBO_P2P_MESH_STREAM_REGISTRY_H

#include "mesh_stream_channel.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_REGISTRY_CAPACITY_MAX 4096u

typedef enum {
  MESH_STREAM_REGISTRY_OK = 0,
  MESH_STREAM_REGISTRY_INTERRUPTED = 1,
  MESH_STREAM_REGISTRY_INVALID_ARG = -1,
  MESH_STREAM_REGISTRY_INVALID_STATE = -2,
  MESH_STREAM_REGISTRY_DUPLICATE = -3,
  MESH_STREAM_REGISTRY_CAPACITY_EXHAUSTED = -4,
  MESH_STREAM_REGISTRY_PEER_LIMIT = -5,
  MESH_STREAM_REGISTRY_STALE_HANDLE = -6,
  MESH_STREAM_REGISTRY_CHANNEL_ERROR = -7,
  MESH_STREAM_REGISTRY_AUTH_REQUIRED = -8,
} mesh_stream_registry_result_t;

typedef struct {
  size_t capacity;
  size_t max_channels_per_peer;
  uint64_t owner_generation;
} mesh_stream_registry_config_v1_t;

typedef struct mesh_stream_registry_v1 mesh_stream_registry_v1_t;

typedef struct {
  const mesh_stream_registry_v1_t *registry;
  size_t slot;
  uint64_t registry_generation;
  uint64_t generation;
} mesh_stream_channel_handle_v1_t;

typedef struct {
  mesh_stream_channel_admission_v1_t admission;
  mesh_stream_transport_config_v1_t transport;
  mesh_stream_transport_io_v1_t io;
  mesh_stream_transport_event_fn on_event;
  void *event_context;
} mesh_stream_registry_open_v1_t;

/** Called once when a registered async channel retires, before slot reuse.
 * Same owner loop, no reentry. The borrowed context must survive retirement. */
typedef void (*mesh_stream_registry_retire_fn)(void *context);

typedef struct {
  mesh_stream_registry_open_v1_t channel;
  mesh_stream_transport_async_send_fn send_async;
  mesh_stream_registry_retire_fn on_retire;
  void *retire_context;
} mesh_stream_registry_async_open_v1_t;

typedef struct {
  mesh_stream_channel_admission_v1_t admission;
  mesh_stream_channel_state_t state;
  mesh_stream_transport_result_t last_transport_result;
  mesh_stream_session_result_t last_session_result;
  int last_io_result;
  int last_application_result;
  uint64_t received_bytes;
  uint64_t received_frames;
  uint64_t sent_control_frames;
} mesh_stream_registry_channel_info_v1_t;

typedef struct {
  size_t capacity;
  size_t max_channels_per_peer;
  uint64_t owner_generation;
  size_t occupied_channels;
  size_t peak_occupied_channels;
  size_t ready_channels;
  size_t terminal_channels;
} mesh_stream_registry_stats_v1_t;

typedef struct {
  mesh_stream_channel_v1_t channel;
  uint64_t generation;
  uint8_t occupied;
  mesh_stream_registry_retire_fn on_retire;
  void *retire_context;
} mesh_stream_registry_slot_v1_t;

/**
 * Internal bounded owner-loop registry. Open/revoke/stats scan at most capacity
 * slots; handle-based data operations are O(1). All calls are serialized and
 * callbacks must not reenter. Neither registry nor channels
 * own their I/O contexts or CoroNet sockets. owner_generation must change each
 * time storage at this registry address is initialized for a new owner life.
 * The caller must zero-initialize this object before its first init.
 */
struct mesh_stream_registry_v1 {
  mesh_stream_registry_config_v1_t config;
  mesh_stream_registry_slot_v1_t *slots;
  size_t occupied_channels;
  size_t peak_occupied_channels;
};

mesh_stream_registry_result_t
mesh_stream_registry_init_v1(mesh_stream_registry_v1_t *registry,
                             const mesh_stream_registry_config_v1_t *config);

/** Quiesce all receive/send callbacks first. Retires then frees every channel. */
void mesh_stream_registry_destroy_v1(mesh_stream_registry_v1_t *registry);

mesh_stream_registry_result_t
mesh_stream_registry_open_v1(mesh_stream_registry_v1_t *registry,
                             const mesh_stream_registry_open_v1_t *request,
                             mesh_stream_channel_handle_v1_t *out_handle);

/** Explicit async admission; no synchronous fallback. Retired slots retain
 * quota and diagnostics until release. Null send_async is rejected. */
mesh_stream_registry_result_t mesh_stream_registry_open_async_v1(
    mesh_stream_registry_v1_t *registry, const mesh_stream_registry_async_open_v1_t *request,
    mesh_stream_channel_handle_v1_t *out_handle);

/** Internal adapter-only borrow, valid solely during the serialized owner call.
 * Never retain the pointer across release/destroy or invoke data operations on
 * a TLS-bound channel directly; route those through its authenticated adapter. */
mesh_stream_registry_result_t mesh_stream_registry_borrow_channel_v1(
    mesh_stream_registry_v1_t *registry, mesh_stream_channel_handle_v1_t handle,
    mesh_stream_channel_v1_t **out_channel);

mesh_stream_registry_result_t mesh_stream_registry_complete_send_v1(
    mesh_stream_registry_v1_t *registry, mesh_stream_channel_handle_v1_t handle,
    uint64_t admission_generation, uint64_t token, int status, size_t bytes, size_t *out_frames);

mesh_stream_registry_result_t mesh_stream_registry_feed_v1(mesh_stream_registry_v1_t *registry,
                                                           mesh_stream_channel_handle_v1_t handle,
                                                           const uint8_t *bytes, size_t len,
                                                           size_t *out_frames);

mesh_stream_registry_result_t
mesh_stream_registry_pump_once_v1(mesh_stream_registry_v1_t *registry,
                                  mesh_stream_channel_handle_v1_t handle, size_t *out_frames);

mesh_stream_registry_result_t mesh_stream_registry_close_v1(mesh_stream_registry_v1_t *registry,
                                                            mesh_stream_channel_handle_v1_t handle);

/**
 * Revoke only channels for the matching remote identity and admission
 * generation. out_revoked counts READY channels transitioned to REVOKED.
 */
mesh_stream_registry_result_t
mesh_stream_registry_revoke_peer_v1(mesh_stream_registry_v1_t *registry,
                                    const uint8_t remote_peer_id[MESH_STREAM_CHANNEL_PEER_ID_SIZE],
                                    uint64_t admission_generation, size_t *out_revoked);

/** Release a terminal slot after quiescing all receive/send callbacks.
 * READY channels must first be closed or revoked; retirement alone does not
 * prove that backend callbacks have stopped. */
mesh_stream_registry_result_t
mesh_stream_registry_release_v1(mesh_stream_registry_v1_t *registry,
                                mesh_stream_channel_handle_v1_t handle);

mesh_stream_registry_result_t
mesh_stream_registry_query_channel_v1(const mesh_stream_registry_v1_t *registry,
                                      mesh_stream_channel_handle_v1_t handle,
                                      mesh_stream_registry_channel_info_v1_t *out_info);

mesh_stream_registry_result_t
mesh_stream_registry_query_stats_v1(const mesh_stream_registry_v1_t *registry,
                                    mesh_stream_registry_stats_v1_t *out_stats);

#ifdef __cplusplus
}
#endif

#endif
