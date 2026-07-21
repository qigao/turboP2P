#include "mesh_stream_channel.h"

#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t len) {
  uint8_t combined = 0u;
  size_t index = 0u;

  for (index = 0u; index < len; index++)
    combined |= bytes[index];
  return combined == 0u;
}

static int admission_is_valid(const mesh_stream_channel_admission_v1_t *admission,
                              const mesh_stream_transport_config_v1_t *config) {
  return admission && config && admission->generation != 0u && admission->stream_epoch != 0u &&
         !bytes_are_zero(admission->remote_peer_id, sizeof(admission->remote_peer_id)) &&
         memcmp(admission->stream_id, config->receiver.stream_id, sizeof(admission->stream_id)) ==
             0 &&
         admission->stream_epoch == config->receiver.stream_epoch;
}

static void channel_release_transport(mesh_stream_channel_v1_t *channel,
                                      mesh_stream_channel_state_t terminal_state,
                                      mesh_stream_transport_result_t transport_result) {
  channel->last_transport_result = transport_result;
  channel->last_session_result = channel->transport.last_session_result;
  channel->last_io_result = channel->transport.last_io_result;
  channel->last_application_result = channel->transport.last_application_result;
  channel->received_bytes = channel->transport.received_bytes;
  channel->received_frames = channel->transport.received_frames;
  channel->sent_control_frames = channel->transport.sent_control_frames;
  mesh_stream_transport_destroy_v1(&channel->transport);
  channel->state = terminal_state;
}

static mesh_stream_channel_result_t
channel_validate_operation(const mesh_stream_channel_v1_t *channel, uint64_t admission_generation) {
  if (!channel || admission_generation == 0u)
    return MESH_STREAM_CHANNEL_INVALID_ARG;
  if (channel->state == MESH_STREAM_CHANNEL_UNINITIALIZED)
    return MESH_STREAM_CHANNEL_INVALID_STATE;
  if (channel->admission.generation != admission_generation)
    return MESH_STREAM_CHANNEL_STALE_ADMISSION;
  return MESH_STREAM_CHANNEL_OK;
}

static mesh_stream_channel_result_t
channel_finish_transport_call(mesh_stream_channel_v1_t *channel,
                              mesh_stream_transport_result_t transport_result) {
  if (transport_result == MESH_STREAM_TRANSPORT_INTERRUPTED)
    return MESH_STREAM_CHANNEL_INTERRUPTED;
  if (transport_result != MESH_STREAM_TRANSPORT_OK) {
    channel_release_transport(channel, MESH_STREAM_CHANNEL_FAILED, transport_result);
    return MESH_STREAM_CHANNEL_TRANSPORT_ERROR;
  }
  if (channel->transport.state == MESH_STREAM_TRANSPORT_READY)
    return MESH_STREAM_CHANNEL_OK;
  if (channel->transport.state == MESH_STREAM_TRANSPORT_CLOSED) {
    channel_release_transport(channel, MESH_STREAM_CHANNEL_CLOSED, transport_result);
    return MESH_STREAM_CHANNEL_OK;
  }
  channel_release_transport(channel, MESH_STREAM_CHANNEL_FAILED,
                            MESH_STREAM_TRANSPORT_INVALID_STATE);
  return MESH_STREAM_CHANNEL_TRANSPORT_ERROR;
}

mesh_stream_channel_result_t mesh_stream_channel_init_v1(
    mesh_stream_channel_v1_t *channel, const mesh_stream_channel_admission_v1_t *admission,
    const mesh_stream_transport_config_v1_t *config, const mesh_stream_transport_io_v1_t *io,
    mesh_stream_transport_event_fn on_event, void *event_context) {
  mesh_stream_transport_result_t transport_result;

  if (!channel || !admission_is_valid(admission, config) || !io || !on_event)
    return MESH_STREAM_CHANNEL_INVALID_ARG;
  if (channel->state != MESH_STREAM_CHANNEL_UNINITIALIZED || channel->transport.buffer)
    return MESH_STREAM_CHANNEL_INVALID_STATE;

  memset(channel, 0, sizeof(*channel));
  channel->admission = *admission;
  transport_result =
      mesh_stream_transport_init_v1(&channel->transport, config, io, on_event, event_context);
  channel->last_transport_result = transport_result;
  if (transport_result != MESH_STREAM_TRANSPORT_OK) {
    channel->last_session_result = channel->transport.last_session_result;
    channel->last_io_result = channel->transport.last_io_result;
    mesh_stream_transport_destroy_v1(&channel->transport);
    memset(&channel->admission, 0, sizeof(channel->admission));
    return MESH_STREAM_CHANNEL_TRANSPORT_ERROR;
  }
  channel->state = MESH_STREAM_CHANNEL_READY;
  return MESH_STREAM_CHANNEL_OK;
}

void mesh_stream_channel_destroy_v1(mesh_stream_channel_v1_t *channel) {
  if (!channel)
    return;
  mesh_stream_transport_destroy_v1(&channel->transport);
  memset(channel, 0, sizeof(*channel));
}

mesh_stream_channel_result_t mesh_stream_channel_feed_v1(mesh_stream_channel_v1_t *channel,
                                                         uint64_t admission_generation,
                                                         const uint8_t *bytes, size_t len,
                                                         size_t *out_frames) {
  mesh_stream_channel_result_t validation_result;
  mesh_stream_transport_result_t transport_result;

  if (!out_frames || (!bytes && len != 0u))
    return MESH_STREAM_CHANNEL_INVALID_ARG;
  *out_frames = 0u;
  validation_result = channel_validate_operation(channel, admission_generation);
  if (validation_result != MESH_STREAM_CHANNEL_OK)
    return validation_result;
  if (channel->state != MESH_STREAM_CHANNEL_READY)
    return MESH_STREAM_CHANNEL_INVALID_STATE;
  transport_result = mesh_stream_transport_feed_v1(&channel->transport, bytes, len, out_frames);
  return channel_finish_transport_call(channel, transport_result);
}

mesh_stream_channel_result_t mesh_stream_channel_pump_once_v1(mesh_stream_channel_v1_t *channel,
                                                              uint64_t admission_generation,
                                                              size_t *out_frames) {
  mesh_stream_channel_result_t validation_result;
  mesh_stream_transport_result_t transport_result;

  if (!out_frames)
    return MESH_STREAM_CHANNEL_INVALID_ARG;
  *out_frames = 0u;
  validation_result = channel_validate_operation(channel, admission_generation);
  if (validation_result != MESH_STREAM_CHANNEL_OK)
    return validation_result;
  if (channel->state != MESH_STREAM_CHANNEL_READY)
    return MESH_STREAM_CHANNEL_INVALID_STATE;
  transport_result = mesh_stream_transport_pump_once_v1(&channel->transport, out_frames);
  return channel_finish_transport_call(channel, transport_result);
}

mesh_stream_channel_result_t mesh_stream_channel_revoke_v1(mesh_stream_channel_v1_t *channel,
                                                           uint64_t admission_generation) {
  mesh_stream_channel_result_t validation_result =
      channel_validate_operation(channel, admission_generation);

  if (validation_result != MESH_STREAM_CHANNEL_OK)
    return validation_result;
  if (channel->state == MESH_STREAM_CHANNEL_READY) {
    channel_release_transport(channel, MESH_STREAM_CHANNEL_REVOKED, MESH_STREAM_TRANSPORT_OK);
  }
  return MESH_STREAM_CHANNEL_OK;
}

mesh_stream_channel_result_t mesh_stream_channel_close_v1(mesh_stream_channel_v1_t *channel,
                                                          uint64_t admission_generation) {
  mesh_stream_channel_result_t validation_result =
      channel_validate_operation(channel, admission_generation);

  if (validation_result != MESH_STREAM_CHANNEL_OK)
    return validation_result;
  if (channel->state == MESH_STREAM_CHANNEL_READY) {
    channel_release_transport(channel, MESH_STREAM_CHANNEL_CLOSED, MESH_STREAM_TRANSPORT_OK);
  }
  return MESH_STREAM_CHANNEL_OK;
}
