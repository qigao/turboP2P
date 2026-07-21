#ifndef TURBO_P2P_MESH_STREAM_SESSION_H
#define TURBO_P2P_MESH_STREAM_SESSION_H

#include "mesh_stream_codec.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_CONTENT_TYPE_MAX 64u

typedef enum {
  MESH_STREAM_SESSION_OK = 0,
  MESH_STREAM_SESSION_NEED_MORE = 1,
  MESH_STREAM_SESSION_INVALID_ARG = -1,
  MESH_STREAM_SESSION_INVALID_FRAME = -2,
  MESH_STREAM_SESSION_INVALID_SCHEMA = -3,
  MESH_STREAM_SESSION_INVALID_STATE = -4,
  MESH_STREAM_SESSION_BINDING_MISMATCH = -5,
  MESH_STREAM_SESSION_OUT_OF_ORDER = -6,
  MESH_STREAM_SESSION_FLOW_CONTROL = -7,
  MESH_STREAM_SESSION_RESOURCE_EXHAUSTED = -8,
  MESH_STREAM_SESSION_STALE_PREPARATION = -9,
  MESH_STREAM_SESSION_UNAUTHORIZED = -10,
} mesh_stream_session_result_t;

typedef enum {
  MESH_STREAM_CLASS_BLOB = 1,
  MESH_STREAM_CLASS_MEDIA = 2,
  MESH_STREAM_CLASS_DIAGNOSTIC = 3,
  MESH_STREAM_CLASS_APPLICATION = 4,
} mesh_stream_class_t;

#define MESH_STREAM_CLASS_BLOB_MASK (1u << 0u)
#define MESH_STREAM_CLASS_MEDIA_MASK (1u << 1u)
#define MESH_STREAM_CLASS_DIAGNOSTIC_MASK (1u << 2u)
#define MESH_STREAM_CLASS_APPLICATION_MASK (1u << 3u)
#define MESH_STREAM_CLASS_KNOWN_MASK 0x0fu

typedef enum {
  MESH_STREAM_SESSION_AWAIT_OPEN = 0,
  MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND = 1,
  MESH_STREAM_SESSION_ACTIVE = 2,
  MESH_STREAM_SESSION_END_RECEIVED = 3,
  MESH_STREAM_SESSION_CANCELLED = 4,
  MESH_STREAM_SESSION_CLOSED = 5,
} mesh_stream_session_state_t;

typedef struct {
  uint8_t stream_id[MESH_STREAM_ID_SIZE];
  uint64_t stream_epoch;
  size_t max_frame_size;
  uint64_t initial_receive_window;
  uint64_t max_receive_window;
  uint64_t max_total_size;
  uint32_t allowed_class_mask;
  uint8_t allow_unknown_total_size;
} mesh_stream_receiver_config_v1_t;

typedef struct {
  uint8_t stream_class;
  uint8_t total_size_known;
  uint64_t total_size;
  size_t content_type_len;
  char content_type[MESH_STREAM_CONTENT_TYPE_MAX + 1u];
} mesh_stream_open_v1_t;

typedef struct {
  mesh_stream_frame_view_t frame;
  mesh_stream_open_v1_t open;
  uint16_t reason_code;
} mesh_stream_receive_event_v1_t;

typedef struct {
  uint64_t generation;
  uint64_t sequence;
  uint64_t offset;
  size_t payload_len;
  mesh_stream_open_v1_t open;
  uint16_t reason_code;
  uint8_t frame_type;
  uint8_t flags;
  uint8_t prepared;
} mesh_stream_receive_preparation_v1_t;

typedef struct {
  mesh_stream_frame_input_t frame;
  uint64_t generation;
  uint64_t previous_limit;
  uint64_t grant;
  uint8_t prepared;
} mesh_stream_control_preparation_v1_t;

/**
 * Receiver half of one authorized, unidirectional stream. The authenticated
 * channel must supply the stream binding and authorization policy in config.
 * One event-loop owner must serialize all calls; this type has no locks.
 */
typedef struct {
  mesh_stream_receiver_config_v1_t config;
  mesh_stream_session_state_t state;
  uint64_t next_receive_sequence;
  uint64_t committed_offset;
  uint64_t receive_limit;
  uint64_t next_control_sequence;
  uint64_t generation;
  uint64_t total_size;
  uint8_t stream_class;
  uint8_t total_size_known;
  uint8_t initialized;
} mesh_stream_receiver_session_v1_t;

mesh_stream_session_result_t
mesh_stream_receiver_init_v1(mesh_stream_receiver_session_v1_t *session,
                             const mesh_stream_receiver_config_v1_t *config);

/**
 * Decode and validate one inbound frame without changing session state.
 * Returned frame views borrow bytes. Commit only after the application has
 * accepted or consumed the event while bytes is still alive.
 */
mesh_stream_session_result_t
mesh_stream_receiver_prepare_v1(const mesh_stream_receiver_session_v1_t *session,
                                const uint8_t *bytes, size_t available,
                                mesh_stream_receive_event_v1_t *out_event,
                                mesh_stream_receive_preparation_v1_t *out_preparation,
                                size_t *out_consumed, size_t *out_required);

mesh_stream_session_result_t
mesh_stream_receiver_commit_v1(mesh_stream_receiver_session_v1_t *session,
                               const mesh_stream_receive_preparation_v1_t *preparation);

/** Prepare an ACCEPT descriptor. Commit only after the encoded frame is sent. */
mesh_stream_session_result_t
mesh_stream_receiver_prepare_accept_v1(const mesh_stream_receiver_session_v1_t *session,
                                       mesh_stream_control_preparation_v1_t *out_preparation);

/**
 * Prepare an absolute WINDOW_UPDATE descriptor without changing advertised
 * credit. grant must fit both the configured outstanding window and total size.
 */
mesh_stream_session_result_t
mesh_stream_receiver_prepare_window_v1(const mesh_stream_receiver_session_v1_t *session,
                                       uint64_t grant,
                                       mesh_stream_control_preparation_v1_t *out_preparation);

mesh_stream_session_result_t
mesh_stream_receiver_commit_control_v1(mesh_stream_receiver_session_v1_t *session,
                                       const mesh_stream_control_preparation_v1_t *preparation);

#ifdef __cplusplus
}
#endif

#endif
