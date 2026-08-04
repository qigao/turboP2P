#include "mesh_stream_live.h"

#include <stdlib.h>
#include <string.h>

/* P5: live edge streaming. Frames are datagram-sized (one recv == one
 * frame): [magic4][type u8][seq u32][len u32][payload]. Data shards are
 * numbered with a monotonic seq; in FEC mode a group of fec_data_shards data
 * shards plus one parity shard occupies fec_data_shards+1 consecutive seqs so
 * both peers derive group/position from seq alone. The receiver keeps a
 * bounded reorder window and skips (never retransmits) blocks that are no
 * longer recoverable, so delivery latency stays bounded. */

#define FRAME_MAGIC_SIZE 4u
#define FRAME_HEADER_SIZE 13u /* magic4 + type1 + seq4 + len4 */
#define FRAME_TYPE_OFFSET 4u
#define FRAME_SEQ_OFFSET 5u
#define FRAME_LEN_OFFSET 9u
#define FRAME_PAYLOAD_OFFSET 13u
#define FRAME_TYPE_DATA 1u
#define FRAME_TYPE_PARITY 2u
#define FRAME_TYPE_CLOSE 3u
#define SLOT_EMPTY UINT64_MAX

static const uint8_t FRAME_MAGIC[4] = {'M', 'S', 'L', '1'};

typedef struct {
  uint64_t group;            /* SLOT_EMPTY when unused */
  uint8_t present;           /* bitmask of present data shards */
  uint8_t parity_present;
  uint8_t delivered_count;   /* data shards delivered/skipped so far */
  uint8_t *data[MESH_STREAM_LIVE_MAX_SHARDS];
  size_t data_len[MESH_STREAM_LIVE_MAX_SHARDS];
  uint8_t *parity;
  size_t parity_len;
} msl_group_t;

struct mesh_stream_live_s {
  mesh_stream_live_role_t role;
  mesh_stream_live_config_v1_t config;
  mesh_stream_live_io_v1_t io;
  uint64_t data_shards;  /* effective, >= 1 */
  uint64_t parity_shards; /* 0 or 1 */
  uint64_t stride;       /* data_shards + parity_shards */

  uint8_t *frame_buf;
  size_t frame_cap;

  /* sender */
  uint8_t *group_pool; /* (data_shards + parity) x max_block staging */
  size_t group_len;    /* uniform shard length of the in-flight group */
  size_t group_count;  /* buffered data shards in the in-flight group */
  uint64_t produced_seq;
  uint8_t finish_sent;

  /* receiver */
  msl_group_t *groups;
  uint8_t *group_data_pool; /* window x (data_shards + parity) x max_block */
  uint64_t next_group;
  uint64_t live_edge_group;
  uint64_t max_seq_seen;
  uint64_t delivered;
  uint64_t skipped;
  uint64_t recovered;
  uint8_t closed;
  uint8_t drained;
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

static uint64_t slot_data_index(const mesh_stream_live_t *live, size_t slot,
                                size_t shard) {
  return slot * (live->data_shards + live->parity_shards) + shard;
}

mesh_stream_live_result_t mesh_stream_live_fec_xor_encode(
    const uint8_t *const *data, const size_t *lens, size_t data_count,
    uint8_t *parity, size_t parity_cap, size_t *out_parity_len) {
  size_t max_len = 0u;

  if (!data || !lens || data_count == 0u || data_count > MESH_STREAM_LIVE_MAX_SHARDS ||
      !parity || !out_parity_len) {
    return MESH_STREAM_LIVE_INVALID_ARG;
  }
  for (size_t i = 0u; i < data_count; i++) {
    if (lens[i] > max_len)
      max_len = lens[i];
  }
  if (max_len > parity_cap)
    return MESH_STREAM_LIVE_INVALID_ARG;
  memset(parity, 0, max_len);
  for (size_t i = 0u; i < data_count; i++) {
    for (size_t j = 0u; j < lens[i]; j++)
      parity[j] ^= data[i][j];
  }
  *out_parity_len = max_len;
  return MESH_STREAM_LIVE_OK;
}

mesh_stream_live_result_t mesh_stream_live_fec_xor_recover(
    uint8_t *const *shards, const size_t *lens, size_t data_count,
    const uint8_t *present, size_t parity_len, const uint8_t *parity) {
  size_t missing_index = SIZE_MAX;
  size_t missing_count = 0u;

  if (!shards || !lens || data_count == 0u || data_count > MESH_STREAM_LIVE_MAX_SHARDS ||
      !present || !parity) {
    return MESH_STREAM_LIVE_INVALID_ARG;
  }
  for (size_t i = 0u; i < data_count; i++) {
    if (!present[i]) {
      missing_index = i;
      missing_count++;
    }
  }
  if (missing_count != 1u)
    return MESH_STREAM_LIVE_INTEGRITY;
  for (size_t j = 0u; j < parity_len && j < lens[missing_index]; j++) {
    uint8_t value = parity[j];

    for (size_t i = 0u; i < data_count; i++) {
      if (present[i] && j < lens[i])
        value ^= shards[i][j];
    }
    shards[missing_index][j] = value;
  }
  return MESH_STREAM_LIVE_OK;
}

static mesh_stream_live_result_t send_frame(mesh_stream_live_t *live, uint8_t type,
                                            uint64_t seq, const uint8_t *payload,
                                            size_t len) {
  uint8_t *frame = live->frame_buf;

  memcpy(frame, FRAME_MAGIC, FRAME_MAGIC_SIZE);
  frame[FRAME_TYPE_OFFSET] = type;
  write_u32(frame + FRAME_SEQ_OFFSET, (uint32_t)seq);
  write_u32(frame + FRAME_LEN_OFFSET, (uint32_t)len);
  if (len > 0u)
    memcpy(frame + FRAME_PAYLOAD_OFFSET, payload, len);
  if (live->io.send(live->io.context, frame, FRAME_HEADER_SIZE + len) != 0)
    return MESH_STREAM_LIVE_IO;
  return MESH_STREAM_LIVE_OK;
}

mesh_stream_live_t *mesh_stream_live_create(mesh_stream_live_role_t role,
                                            const mesh_stream_live_config_v1_t *config,
                                            const mesh_stream_live_io_v1_t *io) {
  mesh_stream_live_t *live;
  uint64_t data_shards;
  uint64_t parity_shards;
  size_t frame_cap;
  size_t pool_blocks;

  if ((role != MESH_STREAM_LIVE_ROLE_SENDER && role != MESH_STREAM_LIVE_ROLE_RECEIVER) ||
      !config || !io || !io->send || !io->recv ||
      config->window_groups == 0u || config->window_groups > MESH_STREAM_LIVE_MAX_WINDOW_GROUPS ||
      config->skip_gap_groups == 0u ||
      config->max_block_bytes == 0u ||
      config->max_block_bytes > MESH_STREAM_LIVE_MAX_BLOCK_BYTES ||
      config->fec_data_shards > MESH_STREAM_LIVE_MAX_SHARDS ||
      config->fec_parity_shards > 1u ||
      (config->fec_data_shards == 0u && config->fec_parity_shards != 0u)) {
    return NULL;
  }
  data_shards = config->fec_data_shards > 0u ? config->fec_data_shards : 1u;
  parity_shards = config->fec_parity_shards;

  live = (mesh_stream_live_t *)calloc(1, sizeof(*live));
  if (!live)
    return NULL;
  live->role = role;
  live->config = *config;
  live->io = *io;
  live->data_shards = data_shards;
  live->parity_shards = parity_shards;
  live->stride = data_shards + parity_shards;
  frame_cap = (size_t)config->max_block_bytes + FRAME_HEADER_SIZE;
  live->frame_cap = frame_cap;
  live->frame_buf = (uint8_t *)malloc(frame_cap);
  if (!live->frame_buf)
    goto fail;

  pool_blocks = (size_t)(data_shards + parity_shards);
  live->group_pool = (uint8_t *)malloc(pool_blocks * (size_t)config->max_block_bytes);
  if (!live->group_pool)
    goto fail;

  if (role == MESH_STREAM_LIVE_ROLE_RECEIVER) {
    size_t slot_blocks = (size_t)(data_shards + parity_shards);
    size_t total_blocks = (size_t)config->window_groups * slot_blocks;

    live->groups =
        (msl_group_t *)calloc((size_t)config->window_groups, sizeof(*live->groups));
    live->group_data_pool = (uint8_t *)malloc(total_blocks * (size_t)config->max_block_bytes);
    if (!live->groups || !live->group_data_pool)
      goto fail;
    for (size_t s = 0u; s < (size_t)config->window_groups; s++) {
      live->groups[s].group = SLOT_EMPTY;
      for (size_t p = 0u; p < data_shards; p++) {
        size_t idx = slot_data_index(live, s, p);
        live->groups[s].data[p] =
            live->group_data_pool + idx * (size_t)config->max_block_bytes;
      }
      if (parity_shards > 0u) {
        size_t idx = slot_data_index(live, s, data_shards);
        live->groups[s].parity =
            live->group_data_pool + idx * (size_t)config->max_block_bytes;
      }
    }
    live->next_group = config->join_seq / live->stride;
    live->live_edge_group = live->next_group;
  }
  return live;

fail:
  mesh_stream_live_destroy(live);
  return NULL;
}

void mesh_stream_live_destroy(mesh_stream_live_t *live) {
  if (!live)
    return;
  free(live->group_data_pool);
  free(live->groups);
  free(live->group_pool);
  free(live->frame_buf);
  free(live);
}

mesh_stream_live_result_t mesh_stream_live_sender_produce(mesh_stream_live_t *live,
                                                          const uint8_t *bytes, size_t len,
                                                          uint64_t *out_seq) {
  uint64_t seq;
  mesh_stream_live_result_t rc;

  if (!live || live->role != MESH_STREAM_LIVE_ROLE_SENDER || !bytes || len == 0u ||
      len > live->config.max_block_bytes || !out_seq || live->finish_sent) {
    return MESH_STREAM_LIVE_INVALID_ARG;
  }
  seq = live->produced_seq;
  if (live->parity_shards == 0u) {
    /* No FEC: each block is its own single-shard group. */
    rc = send_frame(live, FRAME_TYPE_DATA, seq, bytes, len);
    if (rc != MESH_STREAM_LIVE_OK)
      return rc;
    live->produced_seq++;
    live->max_seq_seen = seq;
    *out_seq = seq;
    return MESH_STREAM_LIVE_OK;
  }
  /* FEC mode: buffer into the in-flight group; all shards must be equal
   * length so recovery is exact. */
  if (live->group_count > 0u && len != live->group_len)
    return MESH_STREAM_LIVE_INVALID_ARG;
  {
    uint8_t *buf = live->group_pool + live->group_count * live->config.max_block_bytes;

    memcpy(buf, bytes, len);
  }
  live->group_len = len;
  live->group_count++;
  if (live->group_count < live->data_shards) {
    *out_seq = seq + live->group_count - 1u; /* this block's seq in the group */
    return MESH_STREAM_LIVE_OK;
  }
  /* Group full: compute parity, then send data shards + parity. */
  {
    const uint8_t *ptrs[MESH_STREAM_LIVE_MAX_SHARDS];
    size_t lens[MESH_STREAM_LIVE_MAX_SHARDS];
    uint8_t *parity = live->group_pool + live->data_shards * live->config.max_block_bytes;
    size_t parity_len = 0u;

    live->group_count = 0u;
    for (size_t i = 0u; i < live->data_shards; i++) {
      ptrs[i] = live->group_pool + i * live->config.max_block_bytes;
      lens[i] = live->group_len;
    }
    rc = mesh_stream_live_fec_xor_encode(ptrs, lens, (size_t)live->data_shards, parity,
                                         (size_t)live->config.max_block_bytes, &parity_len);
    if (rc != MESH_STREAM_LIVE_OK)
      return rc;
    for (size_t i = 0u; i < live->data_shards; i++) {
      rc = send_frame(live, FRAME_TYPE_DATA, seq + i, ptrs[i], lens[i]);
      if (rc != MESH_STREAM_LIVE_OK)
        return rc;
    }
    rc = send_frame(live, FRAME_TYPE_PARITY, seq + live->data_shards, parity, parity_len);
    if (rc != MESH_STREAM_LIVE_OK)
      return rc;
  }
  live->produced_seq += live->stride;
  live->max_seq_seen = seq + live->data_shards;
  *out_seq = seq + live->data_shards - 1u; /* last data shard of the group */
  return MESH_STREAM_LIVE_OK;
}

mesh_stream_live_result_t mesh_stream_live_sender_finish(mesh_stream_live_t *live) {
  if (!live || live->role != MESH_STREAM_LIVE_ROLE_SENDER)
    return MESH_STREAM_LIVE_INVALID_ARG;
  if (live->finish_sent)
    return MESH_STREAM_LIVE_OK;
  if (live->parity_shards > 0u && live->group_count > 0u) {
    /* Flush a partial group without parity protection. */
    for (size_t i = 0u; i < live->group_count; i++) {
      mesh_stream_live_result_t rc = send_frame(
          live, FRAME_TYPE_DATA, live->produced_seq + i,
          live->group_pool + i * live->config.max_block_bytes, live->group_len);

      if (rc != MESH_STREAM_LIVE_OK)
        return rc;
    }
    live->produced_seq += live->group_count;
    live->group_count = 0u;
  }
  {
    mesh_stream_live_result_t rc =
        send_frame(live, FRAME_TYPE_CLOSE, live->produced_seq, NULL, 0u);

    if (rc != MESH_STREAM_LIVE_OK)
      return rc;
  }
  live->finish_sent = 1u;
  return MESH_STREAM_LIVE_OK;
}

int mesh_stream_live_frame_complete_v1(const uint8_t *bytes, size_t len,
                                       size_t *out_frame_len) {
  uint32_t payload_len;

  if (!bytes || !out_frame_len)
    return 0;
  if (len < FRAME_HEADER_SIZE)
    return 0;
  payload_len = read_u32(bytes + FRAME_LEN_OFFSET);
  if ((size_t)payload_len > len - FRAME_HEADER_SIZE)
    return 0;
  *out_frame_len = FRAME_HEADER_SIZE + (size_t)payload_len;
  return 1;
}

static void handle_frame(mesh_stream_live_t *live, uint8_t type, uint64_t seq,
                         const uint8_t *payload, size_t len) {
  uint64_t group;
  uint64_t pos;
  msl_group_t *slot;

  if (type == FRAME_TYPE_CLOSE) {
    live->closed = 1u;
    return;
  }
  if (seq < live->config.join_seq)
    return;
  group = seq / live->stride;
  pos = seq % live->stride;
  if (type == FRAME_TYPE_DATA && pos >= live->data_shards)
    return;
  if (type == FRAME_TYPE_PARITY &&
      (live->parity_shards == 0u || pos != live->data_shards)) {
    return;
  }
  if (group < live->next_group || group >= live->next_group + live->config.window_groups)
    return; /* stale or outside the reorder window */
  if (group > live->live_edge_group)
    live->live_edge_group = group;
  if (seq > live->max_seq_seen)
    live->max_seq_seen = seq;

  slot = &live->groups[group % live->config.window_groups];
  if (slot->group != group) {
    slot->group = group;
    slot->present = 0u;
    slot->parity_present = 0u;
    slot->delivered_count = 0u;
  } else if (slot->delivered_count > 0u) {
    return; /* group already being delivered; ignore late/duplicate frames */
  }
  if (type == FRAME_TYPE_DATA) {
    size_t shard = (size_t)pos;

    if (slot->present & (uint8_t)(1u << shard))
      return; /* duplicate */
    memcpy(slot->data[shard], payload, len);
    slot->data_len[shard] = len;
    slot->present |= (uint8_t)(1u << shard);
  } else {
    if (slot->parity_present)
      return; /* duplicate */
    memcpy(slot->parity, payload, len);
    slot->parity_len = len;
    slot->parity_present = 1u;
  }
}

mesh_stream_live_result_t mesh_stream_live_receiver_pump(mesh_stream_live_t *live,
                                                         uint8_t *out_bytes, size_t cap,
                                                         size_t *out_len, uint64_t *out_seq) {
  if (!live || live->role != MESH_STREAM_LIVE_ROLE_RECEIVER || !out_len)
    return MESH_STREAM_LIVE_INVALID_ARG;
  *out_len = 0u;

  /* Drain the io (datagram semantics: one recv == one frame). */
  for (;;) {
    size_t got = 0u;

    if (live->io.recv(live->io.context, live->frame_buf, live->frame_cap, &got) != 0)
      return MESH_STREAM_LIVE_IO;
    if (got == 0u)
      break;
    if (got < FRAME_HEADER_SIZE ||
        memcmp(live->frame_buf, FRAME_MAGIC, FRAME_MAGIC_SIZE) != 0) {
      return MESH_STREAM_LIVE_CORRUPT;
    }
    {
      uint8_t type = live->frame_buf[FRAME_TYPE_OFFSET];
      uint64_t seq = read_u32(live->frame_buf + FRAME_SEQ_OFFSET);
      uint64_t len = read_u32(live->frame_buf + FRAME_LEN_OFFSET);

      if (len > live->config.max_block_bytes || FRAME_HEADER_SIZE + len > got ||
          (type != FRAME_TYPE_DATA && type != FRAME_TYPE_PARITY &&
           type != FRAME_TYPE_CLOSE)) {
        return MESH_STREAM_LIVE_CORRUPT;
      }
      handle_frame(live, type, seq, live->frame_buf + FRAME_PAYLOAD_OFFSET, (size_t)len);
    }
  }

  if (live->drained)
    return MESH_STREAM_LIVE_END;

  /* Advance delivery in order; missing blocks are skipped once they are no
   * longer recoverable (beyond the skip gap, or after CLOSE). */
  if (out_bytes && cap > 0u) {
    for (;;) {
      msl_group_t *slot = &live->groups[live->next_group % live->config.window_groups];

      if (slot->group != live->next_group) {

        /* Group never arrived. */
        if (!live->closed &&
            (live->live_edge_group < live->next_group ||
             live->live_edge_group - live->next_group <
                 live->config.skip_gap_groups)) {
          return MESH_STREAM_LIVE_AGAIN; /* wait for it */
        }
        live->skipped += live->data_shards;
        live->next_group++;
        if (live->closed && live->next_group > live->live_edge_group) {
          live->drained = 1u;
          return MESH_STREAM_LIVE_END;
        }
        continue;
      }
      if (slot->delivered_count < live->data_shards) {
        size_t pos = slot->delivered_count;

        if (!(slot->present & (uint8_t)(1u << pos))) {
          /* Retry recovery on every encounter: a shard may arrive late
           * (reordered across groups), turning an unrecoverable gap into a
           * recoverable one. */
          if (live->parity_shards > 0u && slot->parity_present) {
            size_t missing_count = 0u;
            size_t missing[MESH_STREAM_LIVE_MAX_SHARDS];

            for (size_t p = 0u; p < live->data_shards; p++) {
              if (!(slot->present & (uint8_t)(1u << p)))
                missing[missing_count++] = p;
            }
            if (missing_count <= live->parity_shards) {
              uint8_t *ptrs[MESH_STREAM_LIVE_MAX_SHARDS];
              size_t lens[MESH_STREAM_LIVE_MAX_SHARDS];
              uint8_t present_bytes[MESH_STREAM_LIVE_MAX_SHARDS];
              size_t parity_len = slot->parity_len;

              for (size_t p = 0u; p < live->data_shards; p++) {
                ptrs[p] = slot->data[p];
                lens[p] = slot->data_len[p];
                present_bytes[p] = (slot->present & (uint8_t)(1u << p)) ? 1u : 0u;
              }
              /* FEC groups are uniform-length: missing shards recover at the
               * parity length, which equals the group's shard length. */
              for (size_t m = 0u; m < missing_count; m++)
                lens[missing[m]] = parity_len;
              if (mesh_stream_live_fec_xor_recover(
                      ptrs, lens, (size_t)live->data_shards, present_bytes, parity_len,
                      slot->parity) == MESH_STREAM_LIVE_OK) {
                for (size_t m = 0u; m < missing_count; m++) {
                  slot->present |= (uint8_t)(1u << missing[m]);
                  slot->data_len[missing[m]] = parity_len;
                }
                live->recovered += missing_count;
              }
            }
          }
          if (!(slot->present & (uint8_t)(1u << pos))) {
            /* Still missing. */
            if (!live->closed &&
                live->live_edge_group - live->next_group < live->config.skip_gap_groups) {
              return MESH_STREAM_LIVE_AGAIN; /* wait */
            }
            live->skipped++;
            slot->delivered_count++;
            continue;
          }
        }
        {
          size_t dlen = slot->data_len[pos];

          if (dlen > cap)
            return MESH_STREAM_LIVE_INVALID_ARG; /* caller buffer too small */
          memcpy(out_bytes, slot->data[pos], dlen);
          *out_len = dlen;
          if (out_seq)
            *out_seq = live->next_group * live->stride + pos;
          slot->delivered_count++;
          live->delivered++;
        }
        return MESH_STREAM_LIVE_OK;
      }
      /* Group fully handled; free the slot and move on. */
      slot->group = SLOT_EMPTY;
      slot->delivered_count = 0u;
      live->next_group++;
      if (live->closed && live->next_group > live->live_edge_group) {
        live->drained = 1u;
        return MESH_STREAM_LIVE_END;
      }
    }
  }
  if (live->closed && live->next_group > live->live_edge_group) {
    live->drained = 1u;
    return MESH_STREAM_LIVE_END;
  }
  return MESH_STREAM_LIVE_AGAIN;
}

uint64_t mesh_stream_live_live_edge(const mesh_stream_live_t *live) {
  return live ? live->max_seq_seen : 0u;
}

uint64_t mesh_stream_live_delivered(const mesh_stream_live_t *live) {
  return live ? live->delivered : 0u;
}

uint64_t mesh_stream_live_skipped(const mesh_stream_live_t *live) {
  return live ? live->skipped : 0u;
}

uint64_t mesh_stream_live_recovered(const mesh_stream_live_t *live) {
  return live ? live->recovered : 0u;
}

int mesh_stream_live_complete(const mesh_stream_live_t *live) {
  if (!live)
    return 0;
  if (live->role == MESH_STREAM_LIVE_ROLE_SENDER)
    return live->finish_sent;
  return live->drained;
}