#include "mesh_stream_session.h"

#include <limits.h>
#include <string.h>

#define MESH_STREAM_OPEN_CLASS_FIELD 1u
#define MESH_STREAM_OPEN_TOTAL_SIZE_FIELD 2u
#define MESH_STREAM_OPEN_CONTENT_TYPE_FIELD 3u
#define MESH_STREAM_REASON_FIELD 1u
#define MESH_STREAM_UNKNOWN_TOTAL_SIZE UINT64_MAX

typedef struct {
  uint16_t type;
  const uint8_t *value;
  size_t length;
} mesh_stream_tlv_view_t;

static uint16_t read_u16(const uint8_t *bytes) {
  return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static uint64_t read_u64(const uint8_t *bytes) {
  uint64_t value = 0u;
  size_t index = 0u;

  for (index = 0u; index < sizeof(value); index++)
    value = (value << 8u) | bytes[index];
  return value;
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  uint8_t aggregate = 0u;
  size_t index = 0u;

  for (index = 0u; index < length; index++)
    aggregate |= bytes[index];
  return aggregate == 0u;
}

static int read_tlv(const uint8_t *metadata, size_t metadata_len, size_t *cursor,
                    mesh_stream_tlv_view_t *out_view) {
  size_t remaining = 0u;
  uint16_t length = 0u;

  if (!metadata || !cursor || !out_view || *cursor > metadata_len)
    return 0;
  remaining = metadata_len - *cursor;
  if (remaining < MESH_STREAM_TLV_PREFIX_SIZE)
    return 0;
  out_view->type = read_u16(metadata + *cursor);
  length = read_u16(metadata + *cursor + sizeof(uint16_t));
  if ((size_t)length > remaining - MESH_STREAM_TLV_PREFIX_SIZE)
    return 0;
  out_view->length = length;
  out_view->value = metadata + *cursor + MESH_STREAM_TLV_PREFIX_SIZE;
  *cursor += MESH_STREAM_TLV_PREFIX_SIZE + (size_t)length;
  return 1;
}

static int content_type_is_valid(const uint8_t *value, size_t length) {
  size_t index = 0u;

  if (!value || length == 0u || length > MESH_STREAM_CONTENT_TYPE_MAX)
    return 0;
  for (index = 0u; index < length; index++) {
    if (value[index] < 0x21u || value[index] > 0x7eu)
      return 0;
  }
  return 1;
}

static int parse_open(const mesh_stream_frame_view_t *frame, mesh_stream_open_v1_t *out_open) {
  mesh_stream_tlv_view_t field;
  size_t cursor = 0u;
  uint64_t encoded_total = 0u;

  memset(out_open, 0, sizeof(*out_open));
  if (!read_tlv(frame->metadata, frame->metadata_len, &cursor, &field) ||
      field.type != MESH_STREAM_OPEN_CLASS_FIELD || field.length != 1u) {
    return 0;
  }
  out_open->stream_class = field.value[0];
  if (!read_tlv(frame->metadata, frame->metadata_len, &cursor, &field) ||
      field.type != MESH_STREAM_OPEN_TOTAL_SIZE_FIELD || field.length != sizeof(uint64_t)) {
    return 0;
  }
  encoded_total = read_u64(field.value);
  if (encoded_total != MESH_STREAM_UNKNOWN_TOTAL_SIZE) {
    out_open->total_size_known = 1u;
    out_open->total_size = encoded_total;
  }
  if (cursor < frame->metadata_len) {
    if (!read_tlv(frame->metadata, frame->metadata_len, &cursor, &field) ||
        field.type != MESH_STREAM_OPEN_CONTENT_TYPE_FIELD ||
        !content_type_is_valid(field.value, field.length)) {
      return 0;
    }
    out_open->content_type_len = field.length;
    memcpy(out_open->content_type, field.value, field.length);
    out_open->content_type[field.length] = '\0';
  }
  return cursor == frame->metadata_len;
}

static int parse_reason(const mesh_stream_frame_view_t *frame, uint16_t *out_reason) {
  mesh_stream_tlv_view_t field;
  size_t cursor = 0u;

  if (!read_tlv(frame->metadata, frame->metadata_len, &cursor, &field) ||
      field.type != MESH_STREAM_REASON_FIELD || field.length != sizeof(uint16_t) ||
      cursor != frame->metadata_len) {
    return 0;
  }
  *out_reason = read_u16(field.value);
  return 1;
}

static mesh_stream_session_result_t map_codec_result(mesh_stream_codec_result_t result) {
  switch (result) {
  case MESH_STREAM_CODEC_OK:
    return MESH_STREAM_SESSION_OK;
  case MESH_STREAM_CODEC_NEED_MORE:
    return MESH_STREAM_SESSION_NEED_MORE;
  case MESH_STREAM_CODEC_INVALID_ARG:
    return MESH_STREAM_SESSION_INVALID_ARG;
  case MESH_STREAM_CODEC_RESOURCE_EXHAUSTED:
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  case MESH_STREAM_CODEC_INVALID_FRAME:
  default:
    return MESH_STREAM_SESSION_INVALID_FRAME;
  }
}

static int class_is_allowed(const mesh_stream_receiver_session_v1_t *session,
                            uint8_t stream_class) {
  uint32_t mask = 0u;

  if (stream_class < MESH_STREAM_CLASS_BLOB || stream_class > MESH_STREAM_CLASS_APPLICATION) {
    return 0;
  }
  mask = 1u << ((uint32_t)stream_class - 1u);
  return (session->config.allowed_class_mask & mask) != 0u;
}

static mesh_stream_session_result_t
validate_open(const mesh_stream_receiver_session_v1_t *session,
              const mesh_stream_frame_view_t *frame,
              mesh_stream_receive_preparation_v1_t *preparation) {
  if (session->state != MESH_STREAM_SESSION_AWAIT_OPEN)
    return MESH_STREAM_SESSION_INVALID_STATE;
  if (frame->sequence != 0u || frame->offset != 0u)
    return MESH_STREAM_SESSION_OUT_OF_ORDER;
  if (!parse_open(frame, &preparation->open)) {
    return MESH_STREAM_SESSION_INVALID_SCHEMA;
  }
  if (!class_is_allowed(session, preparation->open.stream_class) ||
      (!preparation->open.total_size_known && !session->config.allow_unknown_total_size)) {
    return MESH_STREAM_SESSION_UNAUTHORIZED;
  }
  if (preparation->open.total_size_known &&
      preparation->open.total_size > session->config.max_total_size) {
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  }
  return MESH_STREAM_SESSION_OK;
}

static mesh_stream_session_result_t validate_data(const mesh_stream_receiver_session_v1_t *session,
                                                  const mesh_stream_frame_view_t *frame) {
  uint64_t end_offset = 0u;

  if (session->state != MESH_STREAM_SESSION_ACTIVE)
    return MESH_STREAM_SESSION_INVALID_STATE;
  if (session->next_receive_sequence == UINT64_MAX)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  if (frame->sequence != session->next_receive_sequence ||
      frame->offset != session->committed_offset) {
    return MESH_STREAM_SESSION_OUT_OF_ORDER;
  }
  if ((uint64_t)frame->payload_len > UINT64_MAX - frame->offset)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  end_offset = frame->offset + (uint64_t)frame->payload_len;
  if (end_offset > session->receive_limit)
    return MESH_STREAM_SESSION_FLOW_CONTROL;
  if (end_offset > session->config.max_total_size)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  if (session->total_size_known && end_offset > session->total_size)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  if ((frame->flags & MESH_STREAM_FLAG_END_STREAM) != 0u && session->total_size_known &&
      end_offset != session->total_size) {
    return MESH_STREAM_SESSION_INVALID_SCHEMA;
  }
  return MESH_STREAM_SESSION_OK;
}

static mesh_stream_session_result_t
validate_terminal_control(const mesh_stream_receiver_session_v1_t *session,
                          const mesh_stream_frame_view_t *frame,
                          mesh_stream_receive_preparation_v1_t *preparation) {
  if (session->next_receive_sequence == UINT64_MAX)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  if (frame->sequence != session->next_receive_sequence ||
      frame->offset != session->committed_offset) {
    return MESH_STREAM_SESSION_OUT_OF_ORDER;
  }
  if (!parse_reason(frame, &preparation->reason_code))
    return MESH_STREAM_SESSION_INVALID_SCHEMA;
  if (frame->type == MESH_STREAM_FRAME_CLOSE)
    return session->state == MESH_STREAM_SESSION_END_RECEIVED ? MESH_STREAM_SESSION_OK
                                                              : MESH_STREAM_SESSION_INVALID_STATE;
  return session->state == MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND ||
                 session->state == MESH_STREAM_SESSION_ACTIVE ||
                 session->state == MESH_STREAM_SESSION_END_RECEIVED
             ? MESH_STREAM_SESSION_OK
             : MESH_STREAM_SESSION_INVALID_STATE;
}

mesh_stream_session_result_t
mesh_stream_receiver_init_v1(mesh_stream_receiver_session_v1_t *session,
                             const mesh_stream_receiver_config_v1_t *config) {
  if (!session || !config || bytes_are_zero(config->stream_id, sizeof(config->stream_id)) ||
      config->stream_epoch == 0u || config->max_frame_size < MESH_STREAM_FIXED_HEADER_SIZE ||
      config->max_frame_size > MESH_STREAM_FRAME_MAX || config->initial_receive_window == 0u ||
      config->max_receive_window < config->initial_receive_window ||
      config->max_total_size < config->initial_receive_window || config->allowed_class_mask == 0u ||
      (config->allowed_class_mask & ~MESH_STREAM_CLASS_KNOWN_MASK) != 0u ||
      config->allow_unknown_total_size > 1u) {
    return MESH_STREAM_SESSION_INVALID_ARG;
  }
  memset(session, 0, sizeof(*session));
  session->config = *config;
  session->state = MESH_STREAM_SESSION_AWAIT_OPEN;
  session->receive_limit = config->initial_receive_window;
  session->initialized = 1u;
  return MESH_STREAM_SESSION_OK;
}

mesh_stream_session_result_t
mesh_stream_receiver_prepare_v1(const mesh_stream_receiver_session_v1_t *session,
                                const uint8_t *bytes, size_t available,
                                mesh_stream_receive_event_v1_t *out_event,
                                mesh_stream_receive_preparation_v1_t *out_preparation,
                                size_t *out_consumed, size_t *out_required) {
  mesh_stream_frame_view_t frame;
  mesh_stream_codec_result_t codec_result;
  mesh_stream_session_result_t result = MESH_STREAM_SESSION_OK;
  size_t decoded_consumed = 0u;

  if (!session || !session->initialized || !out_event || !out_preparation || !out_consumed ||
      !out_required) {
    return MESH_STREAM_SESSION_INVALID_ARG;
  }
  memset(out_event, 0, sizeof(*out_event));
  memset(out_preparation, 0, sizeof(*out_preparation));
  *out_consumed = 0u;
  *out_required = MESH_STREAM_LENGTH_PREFIX_SIZE;
  if (session->state == MESH_STREAM_SESSION_CANCELLED ||
      session->state == MESH_STREAM_SESSION_CLOSED) {
    return MESH_STREAM_SESSION_INVALID_STATE;
  }
  codec_result = mesh_stream_frame_decode(bytes, available, session->config.max_frame_size, &frame,
                                          &decoded_consumed, out_required);
  if (codec_result != MESH_STREAM_CODEC_OK)
    return map_codec_result(codec_result);
  if (memcmp(frame.stream_id, session->config.stream_id, sizeof(frame.stream_id)) != 0 ||
      frame.stream_epoch != session->config.stream_epoch) {
    return MESH_STREAM_SESSION_BINDING_MISMATCH;
  }

  out_preparation->generation = session->generation;
  out_preparation->frame_type = frame.type;
  out_preparation->flags = frame.flags;
  out_preparation->sequence = frame.sequence;
  out_preparation->offset = frame.offset;
  out_preparation->payload_len = frame.payload_len;
  switch (frame.type) {
  case MESH_STREAM_FRAME_OPEN:
    result = validate_open(session, &frame, out_preparation);
    break;
  case MESH_STREAM_FRAME_DATA:
    result = validate_data(session, &frame);
    break;
  case MESH_STREAM_FRAME_CANCEL:
  case MESH_STREAM_FRAME_CLOSE:
    result = validate_terminal_control(session, &frame, out_preparation);
    break;
  case MESH_STREAM_FRAME_ACCEPT:
  case MESH_STREAM_FRAME_WINDOW_UPDATE:
  default:
    result = MESH_STREAM_SESSION_INVALID_STATE;
    break;
  }
  if (result != MESH_STREAM_SESSION_OK) {
    memset(out_preparation, 0, sizeof(*out_preparation));
    return result;
  }
  out_preparation->prepared = 1u;
  out_event->frame = frame;
  out_event->open = out_preparation->open;
  out_event->reason_code = out_preparation->reason_code;
  *out_consumed = decoded_consumed;
  return MESH_STREAM_SESSION_OK;
}

static int receive_preparation_matches(const mesh_stream_receiver_session_v1_t *session,
                                       const mesh_stream_receive_preparation_v1_t *preparation) {
  if (preparation->generation != session->generation)
    return 0;
  switch (preparation->frame_type) {
  case MESH_STREAM_FRAME_OPEN:
    return session->state == MESH_STREAM_SESSION_AWAIT_OPEN && preparation->sequence == 0u &&
           preparation->offset == 0u && preparation->payload_len == 0u;
  case MESH_STREAM_FRAME_DATA:
    return session->state == MESH_STREAM_SESSION_ACTIVE &&
           preparation->sequence == session->next_receive_sequence &&
           preparation->offset == session->committed_offset &&
           (uint64_t)preparation->payload_len <= session->receive_limit - session->committed_offset;
  case MESH_STREAM_FRAME_CANCEL:
    return (session->state == MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND ||
            session->state == MESH_STREAM_SESSION_ACTIVE ||
            session->state == MESH_STREAM_SESSION_END_RECEIVED) &&
           preparation->sequence == session->next_receive_sequence &&
           preparation->offset == session->committed_offset;
  case MESH_STREAM_FRAME_CLOSE:
    return session->state == MESH_STREAM_SESSION_END_RECEIVED &&
           preparation->sequence == session->next_receive_sequence &&
           preparation->offset == session->committed_offset;
  default:
    return 0;
  }
}

mesh_stream_session_result_t
mesh_stream_receiver_commit_v1(mesh_stream_receiver_session_v1_t *session,
                               const mesh_stream_receive_preparation_v1_t *preparation) {
  if (!session || !session->initialized || !preparation || !preparation->prepared) {
    return MESH_STREAM_SESSION_INVALID_ARG;
  }
  if (!receive_preparation_matches(session, preparation))
    return MESH_STREAM_SESSION_STALE_PREPARATION;
  switch (preparation->frame_type) {
  case MESH_STREAM_FRAME_OPEN:
    session->stream_class = preparation->open.stream_class;
    session->total_size_known = preparation->open.total_size_known;
    session->total_size = preparation->open.total_size;
    if (session->total_size_known && session->receive_limit > session->total_size) {
      session->receive_limit = session->total_size;
    }
    session->next_receive_sequence = 1u;
    session->state = MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND;
    break;
  case MESH_STREAM_FRAME_DATA:
    session->committed_offset += (uint64_t)preparation->payload_len;
    session->next_receive_sequence++;
    if ((preparation->flags & MESH_STREAM_FLAG_END_STREAM) != 0u)
      session->state = MESH_STREAM_SESSION_END_RECEIVED;
    break;
  case MESH_STREAM_FRAME_CANCEL:
    session->next_receive_sequence++;
    session->state = MESH_STREAM_SESSION_CANCELLED;
    break;
  case MESH_STREAM_FRAME_CLOSE:
    session->next_receive_sequence++;
    session->state = MESH_STREAM_SESSION_CLOSED;
    break;
  default:
    return MESH_STREAM_SESSION_STALE_PREPARATION;
  }
  session->generation++;
  return MESH_STREAM_SESSION_OK;
}

static void prepare_control_frame(const mesh_stream_receiver_session_v1_t *session, uint8_t type,
                                  uint64_t offset,
                                  mesh_stream_control_preparation_v1_t *out_preparation) {
  memset(out_preparation, 0, sizeof(*out_preparation));
  out_preparation->frame.type = type;
  memcpy(out_preparation->frame.stream_id, session->config.stream_id,
         sizeof(out_preparation->frame.stream_id));
  out_preparation->frame.stream_epoch = session->config.stream_epoch;
  out_preparation->frame.sequence = session->next_control_sequence;
  out_preparation->frame.offset = offset;
  out_preparation->generation = session->generation;
  out_preparation->previous_limit = session->receive_limit;
  out_preparation->prepared = 1u;
}

mesh_stream_session_result_t
mesh_stream_receiver_prepare_accept_v1(const mesh_stream_receiver_session_v1_t *session,
                                       mesh_stream_control_preparation_v1_t *out_preparation) {
  if (!session || !session->initialized || !out_preparation)
    return MESH_STREAM_SESSION_INVALID_ARG;
  memset(out_preparation, 0, sizeof(*out_preparation));
  if (session->state != MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND)
    return MESH_STREAM_SESSION_INVALID_STATE;
  if (session->next_control_sequence == UINT64_MAX)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  prepare_control_frame(session, MESH_STREAM_FRAME_ACCEPT, session->receive_limit, out_preparation);
  return MESH_STREAM_SESSION_OK;
}

mesh_stream_session_result_t
mesh_stream_receiver_prepare_window_v1(const mesh_stream_receiver_session_v1_t *session,
                                       uint64_t grant,
                                       mesh_stream_control_preparation_v1_t *out_preparation) {
  uint64_t outstanding = 0u;
  uint64_t new_limit = 0u;

  if (!session || !session->initialized || !out_preparation || grant == 0u)
    return MESH_STREAM_SESSION_INVALID_ARG;
  memset(out_preparation, 0, sizeof(*out_preparation));
  if (session->state != MESH_STREAM_SESSION_ACTIVE)
    return MESH_STREAM_SESSION_INVALID_STATE;
  if (session->next_control_sequence == UINT64_MAX)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  outstanding = session->receive_limit - session->committed_offset;
  if (grant > session->config.max_receive_window - outstanding)
    return MESH_STREAM_SESSION_FLOW_CONTROL;
  if (grant > UINT64_MAX - session->receive_limit)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  new_limit = session->receive_limit + grant;
  if (new_limit > session->config.max_total_size)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  if (session->total_size_known && new_limit > session->total_size)
    return MESH_STREAM_SESSION_RESOURCE_EXHAUSTED;
  prepare_control_frame(session, MESH_STREAM_FRAME_WINDOW_UPDATE, new_limit, out_preparation);
  out_preparation->grant = grant;
  return MESH_STREAM_SESSION_OK;
}

mesh_stream_session_result_t
mesh_stream_receiver_commit_control_v1(mesh_stream_receiver_session_v1_t *session,
                                       const mesh_stream_control_preparation_v1_t *preparation) {
  uint8_t type = 0u;

  if (!session || !session->initialized || !preparation || !preparation->prepared) {
    return MESH_STREAM_SESSION_INVALID_ARG;
  }
  type = preparation->frame.type;
  if (preparation->generation != session->generation ||
      preparation->frame.sequence != session->next_control_sequence ||
      session->next_control_sequence == UINT64_MAX ||
      preparation->previous_limit != session->receive_limit || preparation->frame.flags != 0u ||
      preparation->frame.metadata_len != 0u || preparation->frame.payload_len != 0u ||
      memcmp(preparation->frame.stream_id, session->config.stream_id,
             sizeof(preparation->frame.stream_id)) != 0 ||
      preparation->frame.stream_epoch != session->config.stream_epoch) {
    return MESH_STREAM_SESSION_STALE_PREPARATION;
  }
  if (type == MESH_STREAM_FRAME_ACCEPT) {
    if (session->state != MESH_STREAM_SESSION_AWAIT_ACCEPT_SEND ||
        preparation->frame.offset != session->receive_limit || preparation->grant != 0u) {
      return MESH_STREAM_SESSION_STALE_PREPARATION;
    }
    session->state = MESH_STREAM_SESSION_ACTIVE;
  } else if (type == MESH_STREAM_FRAME_WINDOW_UPDATE) {
    uint64_t outstanding = session->receive_limit - session->committed_offset;

    if (session->state != MESH_STREAM_SESSION_ACTIVE || preparation->grant == 0u ||
        preparation->grant > UINT64_MAX - session->receive_limit ||
        preparation->grant > session->config.max_receive_window - outstanding ||
        preparation->frame.offset != session->receive_limit + preparation->grant ||
        preparation->frame.offset > session->config.max_total_size ||
        (session->total_size_known && preparation->frame.offset > session->total_size)) {
      return MESH_STREAM_SESSION_STALE_PREPARATION;
    }
    session->receive_limit = preparation->frame.offset;
  } else {
    return MESH_STREAM_SESSION_STALE_PREPARATION;
  }
  session->next_control_sequence++;
  session->generation++;
  return MESH_STREAM_SESSION_OK;
}
