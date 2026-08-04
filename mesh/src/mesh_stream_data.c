#include "mesh_stream_data.h"

#include <turbo_crypto.h>
#include <turbo_thread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAME_HEADER_SIZE 32u
#define LENGTH_PREFIX_SIZE 4u

#define HDR_VERSION_OFFSET 4u
#define HDR_TYPE_OFFSET 5u
#define HDR_FLAGS_OFFSET 6u
#define HDR_SEQ_OFFSET 8u
#define HDR_BLOCK_OFFSET 12u
#define HDR_OFFSET_OFFSET 16u
#define HDR_PAYLOAD_LEN_OFFSET 24u

static const uint8_t FRAME_MAGIC[4] = {'M', 'S', 'D', '1'};

#define SLOT_FREE 0u
#define SLOT_PRESENT 1u

typedef struct {
  uint64_t seq;
  uint8_t state;
  uint8_t retransmit_count;
  uint64_t sent_at_ms;
  size_t len;
  uint8_t *bytes;
} msd_slot_t;

struct mesh_stream_data_s {
  mesh_stream_data_role_t role;
  mesh_stream_data_config_v1_t config;
  mesh_stream_data_io_v1_t io;

  uint8_t *recv_buf;
  size_t recv_len;
  size_t recv_cap;

  /* sender */
  uint8_t *send_pool;
  msd_slot_t *send_slots;
  uint64_t next_seq;
  uint64_t base_seq;
  uint64_t skip_until_seq;
  uint64_t committed_offset;
  size_t in_flight;
  uint8_t *staging;
  size_t staging_len;
  uint8_t opened;
  uint8_t finish_sent;
  uint8_t closed;

  /* receiver */
  uint8_t *reorder_pool;
  msd_slot_t *reorder_slots;
  uint64_t next_expected;
  uint64_t delivered_bytes;
  uint64_t open_total_size;
  uint8_t open_seen;
  uint8_t complete;
};

static void write_u32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)(value >> 24u);
  out[1] = (uint8_t)(value >> 16u);
  out[2] = (uint8_t)(value >> 8u);
  out[3] = (uint8_t)value;
}

static uint32_t read_u32(const uint8_t in[4]) {
  return ((uint32_t)in[0] << 24u) | ((uint32_t)in[1] << 16u) |
         ((uint32_t)in[2] << 8u) | (uint32_t)in[3];
}

static void write_u64(uint8_t out[8], uint64_t value) {
  for (size_t i = 0u; i < 8u; i++)
    out[i] = (uint8_t)(value >> (56u - i * 8u));
}

static uint64_t read_u64(const uint8_t in[8]) {
  uint64_t value = 0u;

  for (size_t i = 0u; i < 8u; i++)
    value = (value << 8u) | in[i];
  return value;
}

static size_t frame_total_size(size_t payload_len) {
  return LENGTH_PREFIX_SIZE + FRAME_HEADER_SIZE + payload_len;
}

static size_t frame_payload_len(const uint8_t *frame) {
  return (size_t)read_u32(frame + LENGTH_PREFIX_SIZE + HDR_PAYLOAD_LEN_OFFSET);
}

static size_t encode_frame(uint8_t type, uint64_t seq, uint64_t block_index,
                           uint64_t offset, const uint8_t *payload, size_t payload_len,
                           uint8_t *output, size_t cap) {
  size_t total = frame_total_size(payload_len);
  uint8_t *header;

  if (total > cap)
    return 0u;
  write_u32(output, (uint32_t)(FRAME_HEADER_SIZE + payload_len));
  header = output + LENGTH_PREFIX_SIZE;
  memcpy(header, FRAME_MAGIC, sizeof(FRAME_MAGIC));
  header[HDR_VERSION_OFFSET] = MESH_STREAM_DATA_VERSION;
  header[HDR_TYPE_OFFSET] = type;
  header[HDR_FLAGS_OFFSET] = 0u;
  write_u32(header + HDR_SEQ_OFFSET, (uint32_t)seq);
  write_u32(header + HDR_BLOCK_OFFSET, (uint32_t)block_index);
  write_u64(header + HDR_OFFSET_OFFSET, offset);
  write_u32(header + HDR_PAYLOAD_LEN_OFFSET, (uint32_t)payload_len);
  if (payload_len > 0u)
    memcpy(header + FRAME_HEADER_SIZE, payload, payload_len);
  return total;
}

/* Returns 1 when a complete frame is decoded; 0 when more bytes are needed. */
static int decode_frame(const uint8_t *bytes, size_t available, uint8_t *out_type,
                        uint64_t *out_seq, uint64_t *out_block, uint64_t *out_offset,
                        const uint8_t **out_payload, size_t *out_payload_len) {
  const uint8_t *header;
  size_t payload_len;
  size_t total;

  if (available < LENGTH_PREFIX_SIZE + FRAME_HEADER_SIZE)
    return 0;
  header = bytes + LENGTH_PREFIX_SIZE;
  if (memcmp(header, FRAME_MAGIC, sizeof(FRAME_MAGIC)) != 0 ||
      header[HDR_VERSION_OFFSET] != MESH_STREAM_DATA_VERSION)
    return -1;
  payload_len = (size_t)read_u32(header + HDR_PAYLOAD_LEN_OFFSET);
  total = frame_total_size(payload_len);
  if (available < total)
    return 0;
  *out_type = header[HDR_TYPE_OFFSET];
  *out_seq = read_u32(header + HDR_SEQ_OFFSET);
  *out_block = read_u32(header + HDR_BLOCK_OFFSET);
  *out_offset = read_u64(header + HDR_OFFSET_OFFSET);
  *out_payload = header + FRAME_HEADER_SIZE;
  *out_payload_len = payload_len;
  return 1;
}

static int config_is_valid(const mesh_stream_data_config_v1_t *config) {
  return config && config->block_size > 0u && config->block_size <= 1024u * 1024u &&
         config->window_blocks > 0u && config->window_blocks <= 256u;
}

mesh_stream_data_t *mesh_stream_data_create(mesh_stream_data_role_t role,
                                            const mesh_stream_data_config_v1_t *config,
                                            const mesh_stream_data_io_v1_t *io) {
  mesh_stream_data_t *stream;
  size_t send_pool_size;
  size_t reorder_pool_size;

  if ((role != MESH_STREAM_DATA_ROLE_SENDER &&
       role != MESH_STREAM_DATA_ROLE_RECEIVER) ||
      !config_is_valid(config) || !io || !io->send || !io->recv)
    return NULL;
  stream = (mesh_stream_data_t *)calloc(1, sizeof(*stream));
  if (!stream)
    return NULL;
  stream->role = role;
  stream->config = *config;
  stream->io = *io;
  stream->recv_cap = frame_total_size(MESH_STREAM_DATA_HASH_SIZE + config->block_size);
  stream->recv_buf = (uint8_t *)malloc(stream->recv_cap);
  if (!stream->recv_buf)
    goto failed;

  send_pool_size = (size_t)config->window_blocks * (size_t)config->block_size;
  reorder_pool_size = MESH_STREAM_DATA_REORDER_SLOTS * (size_t)config->block_size;
  stream->send_pool = (uint8_t *)malloc(send_pool_size);
  stream->send_slots =
      (msd_slot_t *)calloc((size_t)config->window_blocks, sizeof(*stream->send_slots));
  stream->reorder_pool = (uint8_t *)malloc(reorder_pool_size);
  stream->reorder_slots =
      (msd_slot_t *)calloc(MESH_STREAM_DATA_REORDER_SLOTS, sizeof(*stream->reorder_slots));
  stream->staging = (uint8_t *)malloc((size_t)config->block_size);
  if (!stream->send_pool || !stream->send_slots || !stream->reorder_pool ||
      !stream->reorder_slots || !stream->staging) {
    goto failed;
  }
  for (size_t i = 0u; i < config->window_blocks; i++)
    stream->send_slots[i].bytes = stream->send_pool + i * (size_t)config->block_size;
  for (size_t i = 0u; i < MESH_STREAM_DATA_REORDER_SLOTS; i++)
    stream->reorder_slots[i].bytes = stream->reorder_pool + i * (size_t)config->block_size;
  return stream;

failed:
  mesh_stream_data_destroy(stream);
  return NULL;
}

void mesh_stream_data_destroy(mesh_stream_data_t *stream) {
  if (!stream)
    return;
  free(stream->recv_buf);
  free(stream->send_pool);
  free(stream->send_slots);
  free(stream->reorder_pool);
  free(stream->reorder_slots);
  free(stream->staging);
  free(stream);
}

static int hash_block(const uint8_t *bytes, size_t len,
                      uint8_t digest[MESH_STREAM_DATA_HASH_SIZE]) {
  return turbo_crypto_sha256(bytes, len, digest) == TURBO_CRYPTO_OK ? 0 : -1;
}

static int io_send(mesh_stream_data_t *stream, const uint8_t *frame, size_t len) {
  return stream->io.send(stream->io.context, frame, len) == 0 ? 0 : -1;
}

static int send_open(mesh_stream_data_t *stream) {
  uint8_t frame[MESH_STREAM_DATA_MAX_FRAME];
  uint8_t payload[MESH_STREAM_DATA_STREAM_ID_SIZE + 8u];
  size_t frame_len;

  memcpy(payload, stream->config.stream_id, sizeof(stream->config.stream_id));
  write_u64(payload + MESH_STREAM_DATA_STREAM_ID_SIZE, stream->config.total_size);
  frame_len = encode_frame(MESH_STREAM_DATA_FRAME_OPEN, 0u, 0u, 0u, payload, sizeof(payload),
                           frame, sizeof(frame));
  if (frame_len == 0u || io_send(stream, frame, frame_len) != 0)
    return MESH_STREAM_DATA_IO;
  stream->opened = 1u;
  return MESH_STREAM_DATA_OK;
}

static int send_data(mesh_stream_data_t *stream, uint64_t seq, const uint8_t *block,
                     size_t block_len, uint64_t now_ms) {
  if (now_ms == 0u)
    now_ms = turbo_monotonic_ms();
  uint8_t frame[MESH_STREAM_DATA_MAX_FRAME];
  uint8_t *payload = frame + LENGTH_PREFIX_SIZE + FRAME_HEADER_SIZE;
  size_t frame_len;
  size_t slot_index = (size_t)(seq % stream->config.window_blocks);
  msd_slot_t *slot = &stream->send_slots[slot_index];
  uint64_t offset = seq * stream->config.block_size;

  if (hash_block(block, block_len, payload) != 0)
    return MESH_STREAM_DATA_INTEGRITY;
  memcpy(payload + MESH_STREAM_DATA_HASH_SIZE, block, block_len);
  frame_len = encode_frame(MESH_STREAM_DATA_FRAME_DATA, seq, seq, offset, payload,
                           MESH_STREAM_DATA_HASH_SIZE + block_len, frame, sizeof(frame));
  if (frame_len == 0u)
    return MESH_STREAM_DATA_RESOURCE_EXHAUSTED;
  if (io_send(stream, frame, frame_len) != 0)
    return MESH_STREAM_DATA_IO;
  slot->seq = seq;
  slot->state = SLOT_PRESENT;
  slot->len = block_len;
  slot->sent_at_ms = now_ms;
  memcpy(slot->bytes, block, block_len);
  return MESH_STREAM_DATA_OK;
}

mesh_stream_data_result_t mesh_stream_data_sender_start(mesh_stream_data_t *stream) {
  if (!stream || stream->role != MESH_STREAM_DATA_ROLE_SENDER || stream->opened)
    return MESH_STREAM_DATA_INVALID_ARG;
  return send_open(stream);
}

mesh_stream_data_result_t mesh_stream_data_sender_feed(mesh_stream_data_t *stream,
                                                       const uint8_t *bytes, size_t len,
                                                       size_t *out_consumed) {
  size_t consumed = 0u;
  size_t block_size;

  if (out_consumed)
    *out_consumed = 0u;
  if (!stream || stream->role != MESH_STREAM_DATA_ROLE_SENDER || !out_consumed ||
      (!bytes && len > 0u) || !stream->opened)
    return MESH_STREAM_DATA_INVALID_ARG;
  block_size = (size_t)stream->config.block_size;
  while (consumed < len) {
    size_t take;

    if (stream->in_flight >= stream->config.window_blocks)
      break;
    take = block_size - stream->staging_len;
    if (take > len - consumed)
      take = len - consumed;
    memcpy(stream->staging + stream->staging_len, bytes + consumed, take);
    stream->staging_len += take;
    consumed += take;
    if (stream->staging_len < block_size)
      break;
    if (stream->next_seq < stream->skip_until_seq) {
      /* Resume: this block was already delivered on a previous connection. */
      stream->next_seq++;
      stream->staging_len = 0u;
      continue;
    }
    {
      mesh_stream_data_result_t sr = send_data(stream, stream->next_seq, stream->staging,
                                               block_size, 0u);

      if (sr != MESH_STREAM_DATA_OK)
        return MESH_STREAM_DATA_IO;
    }
    stream->next_seq++;
    stream->in_flight++;
    stream->staging_len = 0u;
  }
  *out_consumed = consumed;
  return consumed == 0u ? MESH_STREAM_DATA_AGAIN : MESH_STREAM_DATA_OK;
}

mesh_stream_data_result_t mesh_stream_data_sender_finish(mesh_stream_data_t *stream) {
  uint8_t frame[MESH_STREAM_DATA_MAX_FRAME];
  size_t frame_len;

  if (!stream || stream->role != MESH_STREAM_DATA_ROLE_SENDER || stream->finish_sent)
    return MESH_STREAM_DATA_INVALID_ARG;
  /* Flush the partial tail block before closing the stream. */
  if (stream->staging_len > 0u) {
    if (stream->next_seq >= stream->skip_until_seq) {
      if (send_data(stream, stream->next_seq, stream->staging, stream->staging_len, 0u) !=
          MESH_STREAM_DATA_OK) {
        return MESH_STREAM_DATA_IO;
      }
      stream->next_seq++;
      stream->in_flight++;
    }
    stream->staging_len = 0u;
  }
  frame_len = encode_frame(MESH_STREAM_DATA_FRAME_CLOSE, stream->next_seq, 0u, 0u, NULL, 0u,
                           frame, sizeof(frame));
  if (frame_len == 0u || io_send(stream, frame, frame_len) != 0)
    return MESH_STREAM_DATA_IO;
  stream->finish_sent = 1u;
  return MESH_STREAM_DATA_OK;
}

static void free_slot(msd_slot_t *slot) {
  slot->state = SLOT_FREE;
  slot->len = 0u;
  slot->retransmit_count = 0u;
  slot->sent_at_ms = 0u;
}

static int sender_handle_ack(mesh_stream_data_t *stream, uint64_t ack_seq) {
  if (ack_seq > stream->base_seq) {
    for (uint64_t seq = stream->base_seq; seq < ack_seq; seq++) {
      msd_slot_t *slot = &stream->send_slots[seq % stream->config.window_blocks];

      if (slot->state == SLOT_PRESENT && slot->seq == seq) {
        free_slot(slot);
        if (stream->in_flight > 0u)
          stream->in_flight--;
      }
    }
    stream->base_seq = ack_seq;
    stream->committed_offset = ack_seq * stream->config.block_size;
  }
  return MESH_STREAM_DATA_OK;
}

static int sender_handle_nack(mesh_stream_data_t *stream, const uint8_t *payload,
                              size_t payload_len, uint64_t now_ms) {
  size_t count;
  size_t i;

  if (payload_len < 4u)
    return MESH_STREAM_DATA_CORRUPT;
  count = read_u32(payload);
  if (payload_len != 4u + count * 4u || count > MESH_STREAM_DATA_NACK_MAX_ENTRIES)
    return MESH_STREAM_DATA_CORRUPT;
  for (i = 0u; i < count; i++) {
    uint64_t seq = read_u32(payload + 4u + i * 4u);
    msd_slot_t *slot = &stream->send_slots[seq % stream->config.window_blocks];

    if (slot->state == SLOT_PRESENT && slot->seq == seq &&
        slot->retransmit_count < stream->config.max_retransmits) {
      if (send_data(stream, seq, slot->bytes, slot->len, now_ms) != MESH_STREAM_DATA_OK)
        return MESH_STREAM_DATA_IO;
      slot->retransmit_count++;
    }
  }
  return MESH_STREAM_DATA_OK;
}

static int sender_handle_resume(mesh_stream_data_t *stream, const uint8_t *payload,
                                size_t payload_len) {
  uint64_t committed_offset;
  uint64_t next_expected;

  if (payload_len != MESH_STREAM_DATA_STREAM_ID_SIZE + 8u + 4u)
    return MESH_STREAM_DATA_CORRUPT;
  if (memcmp(payload, stream->config.stream_id, sizeof(stream->config.stream_id)) != 0)
    return MESH_STREAM_DATA_CORRUPT;
  committed_offset = read_u64(payload + MESH_STREAM_DATA_STREAM_ID_SIZE);
  next_expected = read_u32(payload + MESH_STREAM_DATA_STREAM_ID_SIZE + 8u);
  if (next_expected > stream->skip_until_seq) {
    /* Blocks below next_expected were already delivered; skip them. */
    for (uint64_t seq = stream->base_seq; seq < next_expected; seq++) {
      msd_slot_t *slot = &stream->send_slots[seq % stream->config.window_blocks];

      if (slot->state == SLOT_PRESENT && slot->seq == seq) {
        free_slot(slot);
        if (stream->in_flight > 0u)
          stream->in_flight--;
      }
    }
    stream->base_seq = next_expected;
    /* The feed's skip branch consumes input for blocks below skip_until_seq,
     * so next_seq must stay at the input start (0) for the skip to align the
     * remaining bytes with the resumed sequence numbers. */
    stream->skip_until_seq = next_expected;
  }
  stream->committed_offset = committed_offset;
  return MESH_STREAM_DATA_OK;
}

static int drain_inbound(mesh_stream_data_t *stream, uint64_t now_ms) {
  while (1) {
    size_t got = 0u;
    uint8_t type;
    uint64_t seq;
    uint64_t block;
    uint64_t offset;
    const uint8_t *payload;
    size_t payload_len;
    int decoded;

    if (stream->io.recv(stream->io.context, stream->recv_buf + stream->recv_len,
                        stream->recv_cap - stream->recv_len, &got) != 0) {
      return MESH_STREAM_DATA_IO;
    }
    stream->recv_len += got;
    decoded = decode_frame(stream->recv_buf, stream->recv_len, &type, &seq, &block, &offset,
                           &payload, &payload_len);
    if (decoded < 0)
      return MESH_STREAM_DATA_CORRUPT;
    if (decoded == 0) {
      if (stream->recv_len == stream->recv_cap)
        return MESH_STREAM_DATA_CORRUPT;
      return MESH_STREAM_DATA_OK;
    }
    {
      size_t total = frame_total_size(payload_len);

      if (stream->role == MESH_STREAM_DATA_ROLE_SENDER) {
        int result = MESH_STREAM_DATA_OK;

        if (type == MESH_STREAM_DATA_FRAME_ACK) {
          result = sender_handle_ack(stream, seq);
        } else if (type == MESH_STREAM_DATA_FRAME_NACK) {
          result = sender_handle_nack(stream, payload, payload_len, now_ms);
        } else if (type == MESH_STREAM_DATA_FRAME_RESUME) {
          result = sender_handle_resume(stream, payload, payload_len);
        }
        if (result != MESH_STREAM_DATA_OK)
          return result;
      }
      memmove(stream->recv_buf, stream->recv_buf + total, stream->recv_len - total);
      stream->recv_len -= total;
    }
  }
}

mesh_stream_data_result_t mesh_stream_data_sender_pump(mesh_stream_data_t *stream) {
  if (!stream || stream->role != MESH_STREAM_DATA_ROLE_SENDER)
    return MESH_STREAM_DATA_INVALID_ARG;
  return (mesh_stream_data_result_t)drain_inbound(stream, 0u);
}

static int receiver_send_ack(mesh_stream_data_t *stream, uint64_t ack_seq) {
  uint8_t frame[MESH_STREAM_DATA_MAX_FRAME];
  size_t frame_len;

  frame_len = encode_frame(MESH_STREAM_DATA_FRAME_ACK, ack_seq, 0u, 0u, NULL, 0u, frame,
                           sizeof(frame));
  if (frame_len == 0u)
    return MESH_STREAM_DATA_RESOURCE_EXHAUSTED;
  return io_send(stream, frame, frame_len) == 0 ? MESH_STREAM_DATA_OK : MESH_STREAM_DATA_IO;
}

static int receiver_send_nack(mesh_stream_data_t *stream, uint64_t first_missing,
                              uint64_t last_missing) {
  uint8_t frame[MESH_STREAM_DATA_MAX_FRAME];
  uint8_t payload[4u + MESH_STREAM_DATA_NACK_MAX_ENTRIES * 4u];
  size_t count = 0u;
  size_t frame_len;

  for (uint64_t seq = first_missing; seq < last_missing && count < MESH_STREAM_DATA_NACK_MAX_ENTRIES;
       seq++) {
    write_u32(payload + 4u + count * 4u, (uint32_t)seq);
    count++;
  }
  if (count == 0u)
    return MESH_STREAM_DATA_OK;
  write_u32(payload, (uint32_t)count);
  frame_len = encode_frame(MESH_STREAM_DATA_FRAME_NACK, first_missing, 0u, 0u, payload,
                           4u + count * 4u, frame, sizeof(frame));
  if (frame_len == 0u)
    return MESH_STREAM_DATA_RESOURCE_EXHAUSTED;
  return io_send(stream, frame, frame_len) == 0 ? MESH_STREAM_DATA_OK : MESH_STREAM_DATA_IO;
}

static void receiver_deliver_contiguous(mesh_stream_data_t *stream, uint8_t *out_bytes,
                                        size_t cap, size_t *out_len) {
  size_t filled = 0u;

  while (filled < cap) {
    size_t slot_index = (size_t)(stream->next_expected % MESH_STREAM_DATA_REORDER_SLOTS);
    msd_slot_t *slot = &stream->reorder_slots[slot_index];
    size_t take;

    if (slot->state != SLOT_PRESENT || slot->seq != stream->next_expected)
      break;
    take = slot->len;
    if (take > cap - filled)
      break;
    memcpy(out_bytes + filled, slot->bytes, take);
    filled += take;
    stream->delivered_bytes += take;
    stream->next_expected++;
    free_slot(slot);
  }
  *out_len = filled;
  if (filled > 0u)
    (void)receiver_send_ack(stream, stream->next_expected);
  if (stream->delivered_bytes >= stream->open_total_size)
    stream->complete = 1u;
}

static int receiver_handle_data(mesh_stream_data_t *stream, uint64_t seq, uint64_t offset,
                                const uint8_t *payload, size_t payload_len) {
  uint8_t digest[MESH_STREAM_DATA_HASH_SIZE];
  size_t block_len;
  size_t slot_index;
  msd_slot_t *slot;

  if (payload_len < MESH_STREAM_DATA_HASH_SIZE)
    return MESH_STREAM_DATA_CORRUPT;
  block_len = payload_len - MESH_STREAM_DATA_HASH_SIZE;
  if (block_len > (size_t)stream->config.block_size)
    return MESH_STREAM_DATA_CORRUPT;
  if (hash_block(payload + MESH_STREAM_DATA_HASH_SIZE, block_len, digest) != 0)
    return MESH_STREAM_DATA_INTEGRITY;
  if (memcmp(digest, payload, sizeof(digest)) != 0) {
    /* Corrupt block: drop it and ask for a retransmit. */
    return receiver_send_nack(stream, seq, seq + 1u);
  }
  if (seq < stream->next_expected) {
    /* Duplicate: slide the sender forward. */
    return receiver_send_ack(stream, stream->next_expected);
  }
  slot_index = (size_t)(seq % MESH_STREAM_DATA_REORDER_SLOTS);
  slot = &stream->reorder_slots[slot_index];
  if (slot->state == SLOT_PRESENT && slot->seq != seq) {
    /* Out of the reorder window: request it again. */
    return receiver_send_nack(stream, seq, seq + 1u);
  }
  memcpy(slot->bytes, payload + MESH_STREAM_DATA_HASH_SIZE, block_len);
  slot->seq = seq;
  slot->len = block_len;
  slot->state = SLOT_PRESENT;
  if (seq > stream->next_expected)
    (void)receiver_send_nack(stream, stream->next_expected, seq);
  return MESH_STREAM_DATA_OK;
}

mesh_stream_data_result_t mesh_stream_data_receiver_pump(mesh_stream_data_t *stream,
                                                         uint8_t *out_bytes, size_t cap,
                                                         size_t *out_len) {
  size_t filled = 0u;

  if (out_len)
    *out_len = 0u;
  if (!stream || stream->role != MESH_STREAM_DATA_ROLE_RECEIVER || !out_len ||
      (!out_bytes && cap > 0u))
    return MESH_STREAM_DATA_INVALID_ARG;
  if (stream->complete)
    return MESH_STREAM_DATA_END;

  while (1) {
    size_t got = 0u;
    uint8_t type;
    uint64_t seq;
    uint64_t block;
    uint64_t offset;
    const uint8_t *payload;
    size_t payload_len;
    int decoded;

    if (stream->io.recv(stream->io.context, stream->recv_buf + stream->recv_len,
                        stream->recv_cap - stream->recv_len, &got) != 0) {
      return MESH_STREAM_DATA_IO;
    }
    stream->recv_len += got;
    decoded = decode_frame(stream->recv_buf, stream->recv_len, &type, &seq, &block, &offset,
                           &payload, &payload_len);
    if (decoded < 0)
      return MESH_STREAM_DATA_CORRUPT;
    if (decoded == 0) {
      if (stream->recv_len == stream->recv_cap)
        return MESH_STREAM_DATA_CORRUPT;
      break;
    }
    {
      size_t total = frame_total_size(payload_len);
      int result = MESH_STREAM_DATA_OK;

      if (type == MESH_STREAM_DATA_FRAME_OPEN) {
        if (payload_len != MESH_STREAM_DATA_STREAM_ID_SIZE + 8u ||
            memcmp(payload, stream->config.stream_id, sizeof(stream->config.stream_id)) != 0) {
          return MESH_STREAM_DATA_CORRUPT;
        }
        stream->open_total_size = read_u64(payload + MESH_STREAM_DATA_STREAM_ID_SIZE);
        stream->open_seen = 1u;
      } else if (type == MESH_STREAM_DATA_FRAME_DATA) {
        result = receiver_handle_data(stream, seq, offset, payload, payload_len);
        if (result == MESH_STREAM_DATA_OK) {
          size_t delivered = 0u;

          receiver_deliver_contiguous(stream, out_bytes + filled, cap - filled, &delivered);
          filled += delivered;
        }
      } else if (type == MESH_STREAM_DATA_FRAME_CLOSE) {
        if (stream->delivered_bytes >= stream->open_total_size)
          stream->complete = 1u;
      }
      if (result != MESH_STREAM_DATA_OK)
        return result;
      memmove(stream->recv_buf, stream->recv_buf + total, stream->recv_len - total);
      stream->recv_len -= total;
      if (stream->complete)
        break;
    }
  }
  if (stream->complete) {
    *out_len = filled;
    return filled > 0u ? MESH_STREAM_DATA_OK : MESH_STREAM_DATA_END;
  }
  *out_len = filled;
  return filled > 0u ? MESH_STREAM_DATA_OK : MESH_STREAM_DATA_AGAIN;
}

uint64_t mesh_stream_data_receiver_committed(const mesh_stream_data_t *stream) {
  return stream ? stream->delivered_bytes : 0u;
}

mesh_stream_data_result_t mesh_stream_data_receiver_send_resume(
    mesh_stream_data_t *stream, uint64_t committed_offset, uint64_t next_expected) {
  uint8_t frame[MESH_STREAM_DATA_MAX_FRAME];
  uint8_t payload[MESH_STREAM_DATA_STREAM_ID_SIZE + 8u + 4u];
  size_t frame_len;

  if (!stream || stream->role != MESH_STREAM_DATA_ROLE_RECEIVER)
    return MESH_STREAM_DATA_INVALID_ARG;
  /* Adopt the commit point: blocks below next_expected are already delivered
   * by the previous connection, so the peer must not wait for them. */
  stream->next_expected = next_expected;
  stream->delivered_bytes = committed_offset;
  memcpy(payload, stream->config.stream_id, sizeof(stream->config.stream_id));
  write_u64(payload + MESH_STREAM_DATA_STREAM_ID_SIZE, committed_offset);
  write_u32(payload + MESH_STREAM_DATA_STREAM_ID_SIZE + 8u, (uint32_t)next_expected);
  frame_len = encode_frame(MESH_STREAM_DATA_FRAME_RESUME, next_expected, 0u, 0u, payload,
                           sizeof(payload), frame, sizeof(frame));
  if (frame_len == 0u)
    return MESH_STREAM_DATA_RESOURCE_EXHAUSTED;
  return io_send(stream, frame, frame_len) == 0 ? MESH_STREAM_DATA_OK : MESH_STREAM_DATA_IO;
}

int mesh_stream_data_complete(const mesh_stream_data_t *stream) {
  return stream && stream->complete;
}

mesh_stream_data_result_t mesh_stream_data_tick(mesh_stream_data_t *stream, uint64_t now_ms) {
  if (!stream || stream->role != MESH_STREAM_DATA_ROLE_SENDER)
    return MESH_STREAM_DATA_INVALID_ARG;
  if (stream->config.resend_timeout_ms == 0u)
    return MESH_STREAM_DATA_OK;
  if (now_ms == 0u)
    now_ms = turbo_monotonic_ms();
  for (size_t i = 0u; i < stream->config.window_blocks; i++) {
    msd_slot_t *slot = &stream->send_slots[i];

    if (slot->state == SLOT_PRESENT && now_ms > slot->sent_at_ms &&
        now_ms - slot->sent_at_ms >= stream->config.resend_timeout_ms &&
        slot->retransmit_count < stream->config.max_retransmits) {
      if (send_data(stream, slot->seq, slot->bytes, slot->len, now_ms) != MESH_STREAM_DATA_OK)
        return MESH_STREAM_DATA_IO;
      slot->retransmit_count++;
    }
  }
  return MESH_STREAM_DATA_OK;
}
