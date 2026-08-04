#ifndef TURBO_P2P_MESH_STREAM_DATA_H
#define TURBO_P2P_MESH_STREAM_DATA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_DATA_VERSION 1u
#define MESH_STREAM_DATA_STREAM_ID_SIZE 16u
#define MESH_STREAM_DATA_HASH_SIZE 32u
#define MESH_STREAM_DATA_DEFAULT_BLOCK_BYTES (64u * 1024u)
#define MESH_STREAM_DATA_DEFAULT_WINDOW_BLOCKS 16u
#define MESH_STREAM_DATA_MAX_FRAME (MESH_STREAM_DATA_DEFAULT_BLOCK_BYTES + 512u)
#define MESH_STREAM_DATA_REORDER_SLOTS 32u
#define MESH_STREAM_DATA_NACK_MAX_ENTRIES 64u
#define MESH_STREAM_DATA_DEFAULT_RESEND_TIMEOUT_MS 500u

typedef enum {
  MESH_STREAM_DATA_OK = 0,
  MESH_STREAM_DATA_AGAIN = 1,
  MESH_STREAM_DATA_END = 2,
  MESH_STREAM_DATA_INVALID_ARG = -1,
  MESH_STREAM_DATA_BUSY = -2,
  MESH_STREAM_DATA_CORRUPT = -3,
  MESH_STREAM_DATA_INTEGRITY = -4,
  MESH_STREAM_DATA_IO = -5,
  MESH_STREAM_DATA_RESOURCE_EXHAUSTED = -6,
} mesh_stream_data_result_t;

typedef enum {
  MESH_STREAM_DATA_ROLE_SENDER = 1,
  MESH_STREAM_DATA_ROLE_RECEIVER = 2,
} mesh_stream_data_role_t;

typedef enum {
  MESH_STREAM_DATA_FRAME_OPEN = 1,
  MESH_STREAM_DATA_FRAME_DATA = 2,
  MESH_STREAM_DATA_FRAME_ACK = 3,
  MESH_STREAM_DATA_FRAME_NACK = 4,
  MESH_STREAM_DATA_FRAME_RESUME = 5,
  MESH_STREAM_DATA_FRAME_CLOSE = 6,
} mesh_stream_data_frame_type_t;

/**
 * Pluggable byte transport. send copies/consumes before returning. recv fills
 * up to cap and reports zero bytes when nothing is available (non-blocking);
 * the owner pumps the other side to make progress. The io is not owned.
 */
typedef struct {
  int (*send)(void *context, const uint8_t *bytes, size_t len);
  int (*recv)(void *context, uint8_t *bytes, size_t cap, size_t *out_len);
  void *context;
} mesh_stream_data_io_v1_t;

typedef struct {
  uint8_t stream_id[MESH_STREAM_DATA_STREAM_ID_SIZE];
  uint64_t total_size;
  uint64_t block_size;
  uint64_t window_blocks;
  uint64_t max_retransmits;
  uint64_t resend_timeout_ms;
} mesh_stream_data_config_v1_t;

typedef struct mesh_stream_data_s mesh_stream_data_t;

/**
 * Create one stream endpoint. The sender buffers unacked blocks (window x
 * block bytes) and the receiver buffers out-of-order blocks; both allocate on
 * create and are freed by destroy. Zero-initialize nothing; create owns all
 * memory.
 */
mesh_stream_data_t *mesh_stream_data_create(mesh_stream_data_role_t role,
                                            const mesh_stream_data_config_v1_t *config,
                                            const mesh_stream_data_io_v1_t *io);
void mesh_stream_data_destroy(mesh_stream_data_t *stream);

/* ---- sender ------------------------------------------------------------- */

/**
 * Send the OPEN frame advertising total_size. The receiver must have been
 * created with the same stream id and total size.
 */
mesh_stream_data_result_t mesh_stream_data_sender_start(mesh_stream_data_t *stream);

/**
 * Feed bytes into the stream. Returns MESH_STREAM_DATA_AGAIN when the send
 * window is full (out_consumed is zero); the caller retries after pumping.
 * On success out_consumed is the bytes accepted (possibly less than len when
 * the window filled mid-feed).
 */
mesh_stream_data_result_t mesh_stream_data_sender_feed(mesh_stream_data_t *stream,
                                                       const uint8_t *bytes, size_t len,
                                                       size_t *out_consumed);

/** Send CLOSE after all bytes were fed; the receiver then reports END. */
mesh_stream_data_result_t mesh_stream_data_sender_finish(mesh_stream_data_t *stream);

/**
 * Process inbound ACK/NACK/RESUME frames. Call frequently (each loop turn);
 * NACKs trigger selective retransmit of the missing blocks.
 */
mesh_stream_data_result_t mesh_stream_data_sender_pump(mesh_stream_data_t *stream);

/* ---- receiver ----------------------------------------------------------- */

/**
 * Process inbound frames and deliver the next contiguous bytes. Returns OK
 * with out_len > 0, AGAIN when no data is available yet, or END when the
 * stream is complete.
 */
mesh_stream_data_result_t mesh_stream_data_receiver_pump(mesh_stream_data_t *stream,
                                                         uint8_t *out_bytes, size_t cap,
                                                         size_t *out_len);

/** Bytes delivered to the application in order (resume point). */
uint64_t mesh_stream_data_receiver_committed(const mesh_stream_data_t *stream);

/**
 * Advertise a previous commit point (reconnect): the peer skips blocks below
 * next_expected and resumes from committed_offset. Send before the peer's
 * sender starts feeding.
 */
mesh_stream_data_result_t mesh_stream_data_receiver_send_resume(
    mesh_stream_data_t *stream, uint64_t committed_offset, uint64_t next_expected);

/* ---- both --------------------------------------------------------------- */

/**
 * Timer-based retransmit of unacked blocks older than resend_timeout_ms.
 * NACK-driven retransmit happens in sender_pump; tick covers the case where a
 * NACK itself was lost.
 */
mesh_stream_data_result_t mesh_stream_data_tick(mesh_stream_data_t *stream, uint64_t now_ms);

/** True when the receiver delivered total_size bytes or closed. */
int mesh_stream_data_complete(const mesh_stream_data_t *stream);

#ifdef __cplusplus
}
#endif

#endif
