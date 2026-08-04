#ifndef TURBO_P2P_MESH_STREAM_LIVE_H
#define TURBO_P2P_MESH_STREAM_LIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P5: live edge streaming session. A sender produces seq-numbered blocks into
 * a sliding window; a receiver joins at the live edge (or a time-shift
 * offset), buffers a bounded reorder window and skips blocks that are no
 * longer recoverable (LIVE_SKIP) instead of retransmitting them, keeping the
 * end-to-end latency bounded. Optional per-group XOR erasure coding recovers
 * one lost data shard per group; the same codec shape is what a Reed-Solomon
 * backend (turbo_kcp FEC) would provide in the KCP-bound adapter. */

#define MESH_STREAM_LIVE_VERSION 1u
#define MESH_STREAM_LIVE_STREAM_ID_SIZE 16u
#define MESH_STREAM_LIVE_MAX_BLOCK_BYTES (64u * 1024u)
#define MESH_STREAM_LIVE_MAX_SHARDS 8u
#define MESH_STREAM_LIVE_DEFAULT_WINDOW_GROUPS 16u
#define MESH_STREAM_LIVE_DEFAULT_SKIP_GAP_GROUPS 4u
#define MESH_STREAM_LIVE_MAX_WINDOW_GROUPS 256u
#define MESH_STREAM_LIVE_FRAME_HEADER_SIZE 13u /* magic4 + type1 + seq4 + len4 */

typedef enum {
  MESH_STREAM_LIVE_OK = 0,
  MESH_STREAM_LIVE_AGAIN = 1,
  MESH_STREAM_LIVE_END = 2,
  MESH_STREAM_LIVE_INVALID_ARG = -1,
  MESH_STREAM_LIVE_CORRUPT = -2,
  MESH_STREAM_LIVE_INTEGRITY = -3,
  MESH_STREAM_LIVE_IO = -4,
  MESH_STREAM_LIVE_RESOURCE_EXHAUSTED = -5,
} mesh_stream_live_result_t;

typedef enum {
  MESH_STREAM_LIVE_ROLE_SENDER = 1,
  MESH_STREAM_LIVE_ROLE_RECEIVER = 2,
} mesh_stream_live_role_t;

/**
 * Pluggable byte transport with the same contract as the other mesh stream
 * modules: send copies/consumes before returning; recv fills up to cap and
 * reports zero bytes when nothing is available (non-blocking). The io is not
 * owned. A KCP-backed adapter implements these over turbo_kcp_send/recv.
 */
typedef struct {
  int (*send)(void *context, const uint8_t *bytes, size_t len);
  int (*recv)(void *context, uint8_t *bytes, size_t cap, size_t *out_len);
  void *context;
} mesh_stream_live_io_v1_t;

typedef struct {
  uint8_t stream_id[MESH_STREAM_LIVE_STREAM_ID_SIZE];
  uint64_t window_groups;   /* bounded reorder window (receiver) */
  uint64_t skip_gap_groups; /* LIVE_SKIP when a group lags the live edge this much */
  uint64_t max_block_bytes;
  uint64_t fec_data_shards;   /* 0 disables FEC (each block is its own group); FEC groups require equal-length shards */
  uint64_t fec_parity_shards; /* XOR codec supports 0 or 1 */
  uint64_t join_seq;          /* receiver: first seq to accept (time-shift) */
} mesh_stream_live_config_v1_t;

typedef struct mesh_stream_live_s mesh_stream_live_t;

/* ---- FEC codec (XOR, one parity shard per group) ------------------------- */

/**
 * Encode one parity shard as the byte-wise XOR of data_count data shards.
 * Shards may differ in length; the parity length is the longest shard length
 * (shorter shards are zero-padded for the XOR). Requires data_count >= 1 and
 * parity_cap >= max shard length.
 */
mesh_stream_live_result_t mesh_stream_live_fec_xor_encode(
    const uint8_t *const *data, const size_t *lens, size_t data_count,
    uint8_t *parity, size_t parity_cap, size_t *out_parity_len);

/**
 * Recover the single missing data shard (XOR erasure capability is one shard
 * per group). `shards[i]` must be a writable buffer and `lens[i]` its length;
 * `present` bit i is non-zero when shard i holds valid data. Fails with
 * MESH_STREAM_LIVE_INTEGRITY when zero or more than one shard is missing.
 */
mesh_stream_live_result_t mesh_stream_live_fec_xor_recover(
    uint8_t *const *shards, const size_t *lens, size_t data_count,
    const uint8_t *present, size_t parity_len, const uint8_t *parity);

/* ---- session ------------------------------------------------------------- */

/**
 * Create one live session endpoint. Both roles allocate their bounded
 * buffers on create and free on destroy; the io is borrowed. In FEC mode the
 * sender buffers one in-flight group (fec_data_shards data + parity) and the
 * receiver buffers window_groups groups.
 */
mesh_stream_live_t *mesh_stream_live_create(mesh_stream_live_role_t role,
                                            const mesh_stream_live_config_v1_t *config,
                                            const mesh_stream_live_io_v1_t *io);
void mesh_stream_live_destroy(mesh_stream_live_t *live);

/* ---- sender -------------------------------------------------------------- */

/**
 * Produce one block. In FEC mode the block is buffered into the current
 * group; when the group fills, the data shards plus the parity shard are sent
 * as consecutive frames. Returns the assigned seq in *out_seq.
 */
mesh_stream_live_result_t mesh_stream_live_sender_produce(mesh_stream_live_t *live,
                                                          const uint8_t *bytes, size_t len,
                                                          uint64_t *out_seq);

/** Send CLOSE; the receiver then drains and reports END. */
mesh_stream_live_result_t mesh_stream_live_sender_finish(mesh_stream_live_t *live);

/* ---- receiver ------------------------------------------------------------ */

/**
 * Process inbound frames and deliver the next in-order block. Returns OK with
 * *out_len > 0 (seq in *out_seq), AGAIN when nothing is deliverable yet, or
 * END when the stream closed and every accepted group was delivered or
 * skipped. Missing blocks that are no longer recoverable (beyond the skip
 * gap, or after CLOSE) are counted as skipped and never block delivery.
 */
mesh_stream_live_result_t mesh_stream_live_receiver_pump(mesh_stream_live_t *live,
                                                         uint8_t *out_bytes, size_t cap,
                                                         size_t *out_len, uint64_t *out_seq);

/* ---- both ---------------------------------------------------------------- */

/**
 * Report whether bytes[0..len) holds one complete wire frame (the declared
 * payload length fits); *out_frame_len receives the full frame length. Used
 * by stream transports to reassemble frames from a byte stream (KCP).
 */
int mesh_stream_live_frame_complete_v1(const uint8_t *bytes, size_t len,
                                       size_t *out_frame_len);

/** Highest seq produced (sender) or seen (receiver); the live edge. */
uint64_t mesh_stream_live_live_edge(const mesh_stream_live_t *live);
/** Blocks delivered to the application. */
uint64_t mesh_stream_live_delivered(const mesh_stream_live_t *live);
/** Blocks skipped because they were no longer recoverable (LIVE_SKIP). */
uint64_t mesh_stream_live_skipped(const mesh_stream_live_t *live);
/** Blocks reconstructed from FEC parity. */
uint64_t mesh_stream_live_recovered(const mesh_stream_live_t *live);
/** True after CLOSE was sent (sender) or the stream was drained (receiver). */
int mesh_stream_live_complete(const mesh_stream_live_t *live);

#ifdef __cplusplus
}
#endif

#endif