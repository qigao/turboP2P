#include "mesh_stream_transport.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static mesh_stream_transport_result_t transport_fail(mesh_stream_transport_v1_t *transport,
                                                     mesh_stream_transport_result_t result) {
  transport->state = MESH_STREAM_TRANSPORT_FAILED;
  return result;
}

static mesh_stream_transport_result_t
send_prepared_control(mesh_stream_transport_v1_t *transport,
                      const mesh_stream_control_preparation_v1_t *preparation) {
  uint8_t encoded[MESH_STREAM_FIXED_HEADER_SIZE];
  size_t encoded_len = 0u;
  mesh_stream_codec_result_t codec_result;
  mesh_stream_session_result_t session_result;
  int io_result = 0;

  if (transport->sent_control_frames == UINT64_MAX)
    return transport_fail(transport, MESH_STREAM_TRANSPORT_RESOURCE_EXHAUSTED);

  codec_result =
      mesh_stream_frame_encode(&preparation->frame, transport->config.receiver.max_frame_size,
                               encoded, sizeof(encoded), &encoded_len);
  if (codec_result != MESH_STREAM_CODEC_OK) {
    transport->last_session_result = MESH_STREAM_SESSION_INVALID_FRAME;
    return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
  }
  io_result = transport->io.send(transport->io.context, encoded, encoded_len);
  if (io_result != 0) {
    transport->last_io_result = io_result;
    return transport_fail(transport, MESH_STREAM_TRANSPORT_IO_ERROR);
  }
  session_result = mesh_stream_receiver_commit_control_v1(&transport->session, preparation);
  if (session_result != MESH_STREAM_SESSION_OK) {
    transport->last_session_result = session_result;
    return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
  }
  transport->sent_control_frames++;
  return MESH_STREAM_TRANSPORT_OK;
}

static mesh_stream_transport_result_t send_accept(mesh_stream_transport_v1_t *transport) {
  mesh_stream_control_preparation_v1_t preparation;
  mesh_stream_session_result_t session_result =
      mesh_stream_receiver_prepare_accept_v1(&transport->session, &preparation);

  if (session_result != MESH_STREAM_SESSION_OK) {
    transport->last_session_result = session_result;
    return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
  }
  return send_prepared_control(transport, &preparation);
}

static uint64_t stream_total_limit(const mesh_stream_receiver_session_v1_t *session) {
  return session->total_size_known ? session->total_size : session->config.max_total_size;
}

static mesh_stream_transport_result_t replenish_window(mesh_stream_transport_v1_t *transport) {
  mesh_stream_control_preparation_v1_t preparation;
  mesh_stream_receiver_session_v1_t *session = &transport->session;
  mesh_stream_session_result_t session_result;
  uint64_t outstanding = 0u;
  uint64_t target = 0u;
  uint64_t grant = 0u;
  uint64_t total_limit = 0u;
  uint64_t remaining_limit = 0u;

  if (session->state != MESH_STREAM_SESSION_ACTIVE)
    return MESH_STREAM_TRANSPORT_OK;
  outstanding = session->receive_limit - session->committed_offset;
  if (outstanding > transport->config.window_update_threshold)
    return MESH_STREAM_TRANSPORT_OK;
  target = session->config.initial_receive_window;
  if (outstanding >= target)
    return MESH_STREAM_TRANSPORT_OK;
  grant = target - outstanding;
  total_limit = stream_total_limit(session);
  if (session->receive_limit > total_limit) {
    transport->last_session_result = MESH_STREAM_SESSION_INVALID_STATE;
    return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
  }
  remaining_limit = total_limit - session->receive_limit;
  if (grant > remaining_limit)
    grant = remaining_limit;
  if (grant == 0u)
    return MESH_STREAM_TRANSPORT_OK;

  session_result = mesh_stream_receiver_prepare_window_v1(session, grant, &preparation);
  if (session_result != MESH_STREAM_SESSION_OK) {
    transport->last_session_result = session_result;
    return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
  }
  return send_prepared_control(transport, &preparation);
}

static void consume_frame(mesh_stream_transport_v1_t *transport, size_t consumed) {
  transport->buffer_begin += consumed;
  if (transport->buffer_begin == transport->buffer_end) {
    transport->buffer_begin = 0u;
    transport->buffer_end = 0u;
  }
}

static mesh_stream_transport_result_t drain_frames(mesh_stream_transport_v1_t *transport,
                                                   size_t *out_frames) {
  while (transport->buffer_begin < transport->buffer_end) {
    mesh_stream_receive_event_v1_t event;
    mesh_stream_receive_preparation_v1_t preparation;
    mesh_stream_session_result_t session_result;
    mesh_stream_transport_result_t transport_result;
    size_t available = transport->buffer_end - transport->buffer_begin;
    size_t consumed = 0u;
    size_t required = 0u;
    uint8_t frame_type = 0u;
    int application_result = 0;

    session_result = mesh_stream_receiver_prepare_v1(
        &transport->session, transport->buffer + transport->buffer_begin, available, &event,
        &preparation, &consumed, &required);
    if (session_result == MESH_STREAM_SESSION_NEED_MORE)
      return MESH_STREAM_TRANSPORT_OK;
    if (session_result != MESH_STREAM_SESSION_OK) {
      transport->last_session_result = session_result;
      return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
    }
    if (transport->received_frames == UINT64_MAX || *out_frames == SIZE_MAX)
      return transport_fail(transport, MESH_STREAM_TRANSPORT_RESOURCE_EXHAUSTED);

    application_result = transport->on_event(transport->event_context, &event);
    if (application_result != 0) {
      transport->last_application_result = application_result;
      return transport_fail(transport, MESH_STREAM_TRANSPORT_APPLICATION_REJECTED);
    }
    session_result = mesh_stream_receiver_commit_v1(&transport->session, &preparation);
    if (session_result != MESH_STREAM_SESSION_OK) {
      transport->last_session_result = session_result;
      return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
    }

    frame_type = preparation.frame_type;
    consume_frame(transport, consumed);
    transport->received_frames++;
    (*out_frames)++;
    if (frame_type == MESH_STREAM_FRAME_OPEN) {
      transport_result = send_accept(transport);
      if (transport_result != MESH_STREAM_TRANSPORT_OK)
        return transport_result;
    } else if (frame_type == MESH_STREAM_FRAME_DATA) {
      transport_result = replenish_window(transport);
      if (transport_result != MESH_STREAM_TRANSPORT_OK)
        return transport_result;
    }

    if (transport->session.state == MESH_STREAM_SESSION_CANCELLED ||
        transport->session.state == MESH_STREAM_SESSION_CLOSED) {
      if (transport->buffer_begin != transport->buffer_end) {
        transport->last_session_result = MESH_STREAM_SESSION_INVALID_STATE;
        return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
      }
      transport->state = MESH_STREAM_TRANSPORT_CLOSED;
      return MESH_STREAM_TRANSPORT_OK;
    }
  }
  return MESH_STREAM_TRANSPORT_OK;
}

static void compact_buffer(mesh_stream_transport_v1_t *transport) {
  size_t buffered = transport->buffer_end - transport->buffer_begin;

  if (transport->buffer_begin == 0u)
    return;
  if (buffered != 0u)
    memmove(transport->buffer, transport->buffer + transport->buffer_begin, buffered);
  transport->buffer_begin = 0u;
  transport->buffer_end = buffered;
}

mesh_stream_transport_result_t
mesh_stream_transport_init_v1(mesh_stream_transport_v1_t *transport,
                              const mesh_stream_transport_config_v1_t *config,
                              const mesh_stream_transport_io_v1_t *io,
                              mesh_stream_transport_event_fn on_event, void *event_context) {
  mesh_stream_session_result_t session_result;
  int io_result = 0;

  if (!transport || !config || !io || !io->recv || !io->release_recv || !io->send ||
      !io->set_send_hwm || !io->set_receive_timeout || !on_event ||
      config->window_update_threshold == 0u ||
      config->window_update_threshold > config->receiver.initial_receive_window ||
      config->receive_timeout_ms < MESH_STREAM_RECV_TIMEOUT_MIN_MS ||
      config->receive_timeout_ms > MESH_STREAM_RECV_TIMEOUT_MAX_MS ||
      config->send_high_watermark < MESH_STREAM_FIXED_HEADER_SIZE ||
      config->send_high_watermark > MESH_STREAM_SEND_HWM_MAX) {
    return MESH_STREAM_TRANSPORT_INVALID_ARG;
  }
  memset(transport, 0, sizeof(*transport));
  session_result = mesh_stream_receiver_init_v1(&transport->session, &config->receiver);
  if (session_result != MESH_STREAM_SESSION_OK) {
    transport->last_session_result = session_result;
    return MESH_STREAM_TRANSPORT_INVALID_ARG;
  }
  transport->buffer = (uint8_t *)malloc(config->receiver.max_frame_size);
  if (!transport->buffer)
    return MESH_STREAM_TRANSPORT_NO_MEMORY;
  io_result = io->set_send_hwm(io->context, config->send_high_watermark);
  if (io_result != 0) {
    transport->last_io_result = io_result;
    free(transport->buffer);
    transport->buffer = NULL;
    return MESH_STREAM_TRANSPORT_IO_ERROR;
  }
  io_result = io->set_receive_timeout(io->context, config->receive_timeout_ms);
  if (io_result != 0) {
    transport->last_io_result = io_result;
    free(transport->buffer);
    transport->buffer = NULL;
    return MESH_STREAM_TRANSPORT_IO_ERROR;
  }
  transport->config = *config;
  transport->io = *io;
  transport->on_event = on_event;
  transport->event_context = event_context;
  transport->state = MESH_STREAM_TRANSPORT_READY;
  return MESH_STREAM_TRANSPORT_OK;
}

void mesh_stream_transport_destroy_v1(mesh_stream_transport_v1_t *transport) {
  if (!transport)
    return;
  free(transport->buffer);
  memset(transport, 0, sizeof(*transport));
}

mesh_stream_transport_result_t mesh_stream_transport_feed_v1(mesh_stream_transport_v1_t *transport,
                                                             const uint8_t *bytes, size_t len,
                                                             size_t *out_frames) {
  size_t cursor = 0u;
  size_t frames = 0u;

  if (!transport || !out_frames || (!bytes && len != 0u))
    return MESH_STREAM_TRANSPORT_INVALID_ARG;
  *out_frames = 0u;
  if (transport->state != MESH_STREAM_TRANSPORT_READY || !transport->buffer)
    return MESH_STREAM_TRANSPORT_INVALID_STATE;

  while (cursor < len) {
    mesh_stream_transport_result_t result = drain_frames(transport, &frames);
    size_t space = 0u;
    size_t copy_len = 0u;

    if (result != MESH_STREAM_TRANSPORT_OK) {
      *out_frames = frames;
      return result;
    }
    if (transport->state != MESH_STREAM_TRANSPORT_READY) {
      transport->last_session_result = MESH_STREAM_SESSION_INVALID_STATE;
      *out_frames = frames;
      return transport_fail(transport, MESH_STREAM_TRANSPORT_SESSION_ERROR);
    }
    if (transport->buffer_end == transport->config.receiver.max_frame_size)
      compact_buffer(transport);
    space = transport->config.receiver.max_frame_size - transport->buffer_end;
    if (space == 0u) {
      *out_frames = frames;
      return transport_fail(transport, MESH_STREAM_TRANSPORT_RESOURCE_EXHAUSTED);
    }
    copy_len = len - cursor;
    if (copy_len > space)
      copy_len = space;
    if ((uint64_t)copy_len > UINT64_MAX - transport->received_bytes) {
      *out_frames = frames;
      return transport_fail(transport, MESH_STREAM_TRANSPORT_RESOURCE_EXHAUSTED);
    }
    memcpy(transport->buffer + transport->buffer_end, bytes + cursor, copy_len);
    transport->buffer_end += copy_len;
    transport->received_bytes += copy_len;
    cursor += copy_len;
  }

  {
    mesh_stream_transport_result_t result = drain_frames(transport, &frames);
    *out_frames = frames;
    return result;
  }
}

mesh_stream_transport_result_t
mesh_stream_transport_pump_once_v1(mesh_stream_transport_v1_t *transport, size_t *out_frames) {
  uint8_t *bytes = NULL;
  size_t len = 0u;
  int io_result = 0;
  mesh_stream_transport_result_t result;

  if (!transport || !out_frames)
    return MESH_STREAM_TRANSPORT_INVALID_ARG;
  *out_frames = 0u;
  if (transport->state != MESH_STREAM_TRANSPORT_READY || !transport->buffer)
    return MESH_STREAM_TRANSPORT_INVALID_STATE;
  io_result = transport->io.recv(transport->io.context, &bytes, &len);
  if (io_result != 0) {
    transport->last_io_result = io_result;
    if (bytes)
      transport->io.release_recv(transport->io.context, bytes);
    return transport_fail(transport, MESH_STREAM_TRANSPORT_IO_ERROR);
  }
  if (!bytes && len == 0u)
    return MESH_STREAM_TRANSPORT_INTERRUPTED;
  if (!bytes || len == 0u) {
    if (bytes)
      transport->io.release_recv(transport->io.context, bytes);
    transport->last_io_result = -1;
    return transport_fail(transport, MESH_STREAM_TRANSPORT_IO_ERROR);
  }
  result = mesh_stream_transport_feed_v1(transport, bytes, len, out_frames);
  transport->io.release_recv(transport->io.context, bytes);
  return result;
}
