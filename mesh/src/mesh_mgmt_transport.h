#ifndef TURBO_P2P_MESH_MGMT_TRANSPORT_H
#define TURBO_P2P_MESH_MGMT_TRANSPORT_H

#include "mesh_mgmt_codec.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MESH_MGMT_TRANSPORT_OK = 0,
  MESH_MGMT_TRANSPORT_INVALID_ARG = -1,
  MESH_MGMT_TRANSPORT_INVALID_STATE = -2,
  MESH_MGMT_TRANSPORT_INVALID_FRAME = -3,
  MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED = -4,
  MESH_MGMT_TRANSPORT_IO_FAILED = -5,
  MESH_MGMT_TRANSPORT_SECURE_CHANNEL_REQUIRED = -6,
} mesh_mgmt_transport_result_t;

typedef int (*mesh_mgmt_transport_recv_fn)(void *context, uint8_t **out_bytes, size_t *out_len);
typedef void (*mesh_mgmt_transport_release_fn)(void *context, uint8_t *bytes);
typedef int (*mesh_mgmt_transport_send_fn)(void *context, const uint8_t *bytes, size_t len);

typedef struct {
  void *context;
  mesh_mgmt_transport_recv_fn recv;
  mesh_mgmt_transport_release_fn release;
  mesh_mgmt_transport_send_fn send;
} mesh_mgmt_transport_io_v1_t;

/**
 * A complete frame borrowed from the transport's fixed buffer. It remains
 * valid until the matching receipt is committed or the transport is destroyed.
 */
typedef struct {
  const uint8_t *frame;
  size_t frame_len;
  uint64_t generation;
} mesh_mgmt_transport_receipt_v1_t;

/** Single event-loop owner; no internal locking. */
typedef struct {
  mesh_mgmt_transport_io_v1_t io;
  uint8_t frame[MESH_MGMT_FRAME_MAX];
  uint8_t *recv_chunk;
  size_t recv_chunk_len;
  size_t recv_chunk_offset;
  size_t used;
  size_t expected;
  uint64_t generation;
  mesh_mgmt_transport_result_t last_error;
  int initialized;
  int frame_ready;
  int terminal;
} mesh_mgmt_transport_v1_t;

/**
 * Initialize a zero-initialized transport over caller-owned IO. Each recv
 * chunk must be no larger than MESH_MGMT_FRAME_MAX. The IO context must outlive
 * the transport. Production socket adapters must authenticate their secure
 * channel first.
 */
mesh_mgmt_transport_result_t mesh_mgmt_transport_init_v1(mesh_mgmt_transport_v1_t *transport,
                                                         const mesh_mgmt_transport_io_v1_t *io);

/** Release any retained recv chunk. The IO context itself is never destroyed. */
void mesh_mgmt_transport_destroy_v1(mesh_mgmt_transport_v1_t *transport);

/** Receive and structurally validate exactly one MMP frame. */
mesh_mgmt_transport_result_t
mesh_mgmt_transport_receive_v1(mesh_mgmt_transport_v1_t *transport,
                               mesh_mgmt_transport_receipt_v1_t *out_receipt);

/** Commit the exact borrowed receipt after all borrowed dispatcher views are done. */
mesh_mgmt_transport_result_t
mesh_mgmt_transport_commit_v1(mesh_mgmt_transport_v1_t *transport,
                              const mesh_mgmt_transport_receipt_v1_t *receipt);

/** Structurally validate and send one complete MMP frame. */
mesh_mgmt_transport_result_t mesh_mgmt_transport_send_v1(mesh_mgmt_transport_v1_t *transport,
                                                         const uint8_t *frame, size_t frame_len);

#ifdef __cplusplus
}
#endif

#endif
