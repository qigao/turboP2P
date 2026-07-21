#include "mesh_mgmt_transport.h"

#include "mesh_mgmt_wire.h"

#include <limits.h>
#include <string.h>

#define MESH_MGMT_TRANSPORT_INITIAL_GENERATION 1u

static const uint8_t MESH_MGMT_TRANSPORT_MAGIC[4] = {'T', 'M', 'G', 'M'};

static void release_recv_chunk(mesh_mgmt_transport_v1_t *transport) {
  if (transport->recv_chunk) {
    transport->io.release(transport->io.context, transport->recv_chunk);
  }
  transport->recv_chunk = NULL;
  transport->recv_chunk_len = 0u;
  transport->recv_chunk_offset = 0u;
}

static mesh_mgmt_transport_result_t enter_terminal(mesh_mgmt_transport_v1_t *transport,
                                                   mesh_mgmt_transport_result_t error) {
  release_recv_chunk(transport);
  memset(transport->frame, 0, transport->used);
  transport->used = 0u;
  transport->expected = 0u;
  transport->frame_ready = 0;
  transport->terminal = 1;
  transport->last_error = error;
  return error;
}

static mesh_mgmt_transport_result_t determine_expected(mesh_mgmt_transport_v1_t *transport) {
  size_t header_len;
  size_t payload_len;

  if (memcmp(transport->frame, MESH_MGMT_TRANSPORT_MAGIC, sizeof(MESH_MGMT_TRANSPORT_MAGIC)) != 0) {
    return MESH_MGMT_TRANSPORT_INVALID_FRAME;
  }
  header_len = mesh_mgmt_wire_read_u16(transport->frame + 8u);
  payload_len = mesh_mgmt_wire_read_u32(transport->frame + 10u);
  if (header_len > MESH_MGMT_HEADER_MAX ||
      payload_len >
          MESH_MGMT_FRAME_MAX - MESH_MGMT_PREFIX_SIZE - MESH_MGMT_SIGNATURE_SIZE - header_len) {
    return MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED;
  }
  transport->expected = MESH_MGMT_PREFIX_SIZE + header_len + payload_len + MESH_MGMT_SIGNATURE_SIZE;
  return MESH_MGMT_TRANSPORT_OK;
}

static mesh_mgmt_transport_result_t prepare_chunk(mesh_mgmt_transport_v1_t *transport) {
  uint8_t *bytes = NULL;
  size_t length = 0u;
  int recv_result;

  recv_result = transport->io.recv(transport->io.context, &bytes, &length);
  if (recv_result != 0 || !bytes || length == 0u) {
    if (bytes)
      transport->io.release(transport->io.context, bytes);
    return enter_terminal(transport, MESH_MGMT_TRANSPORT_IO_FAILED);
  }
  if (length > MESH_MGMT_FRAME_MAX) {
    transport->io.release(transport->io.context, bytes);
    return enter_terminal(transport, MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED);
  }
  transport->recv_chunk = bytes;
  transport->recv_chunk_len = length;
  transport->recv_chunk_offset = 0u;
  return MESH_MGMT_TRANSPORT_OK;
}

mesh_mgmt_transport_result_t mesh_mgmt_transport_init_v1(mesh_mgmt_transport_v1_t *transport,
                                                         const mesh_mgmt_transport_io_v1_t *io) {
  if (!transport || !io || !io->context || !io->recv || !io->release || !io->send)
    return MESH_MGMT_TRANSPORT_INVALID_ARG;
  if (transport->initialized || transport->recv_chunk || transport->io.context)
    return MESH_MGMT_TRANSPORT_INVALID_STATE;
  memset(transport, 0, sizeof(*transport));
  transport->io = *io;
  transport->generation = MESH_MGMT_TRANSPORT_INITIAL_GENERATION;
  transport->last_error = MESH_MGMT_TRANSPORT_OK;
  transport->initialized = 1;
  return MESH_MGMT_TRANSPORT_OK;
}

void mesh_mgmt_transport_destroy_v1(mesh_mgmt_transport_v1_t *transport) {
  if (!transport)
    return;
  if (transport->recv_chunk && transport->io.release)
    release_recv_chunk(transport);
  memset(transport, 0, sizeof(*transport));
}

mesh_mgmt_transport_result_t
mesh_mgmt_transport_receive_v1(mesh_mgmt_transport_v1_t *transport,
                               mesh_mgmt_transport_receipt_v1_t *out_receipt) {
  mesh_mgmt_frame_view_t view;

  if (!out_receipt)
    return MESH_MGMT_TRANSPORT_INVALID_ARG;
  memset(out_receipt, 0, sizeof(*out_receipt));
  if (!transport || !transport->initialized)
    return MESH_MGMT_TRANSPORT_INVALID_STATE;
  if (transport->terminal)
    return transport->last_error;
  if (transport->frame_ready)
    return MESH_MGMT_TRANSPORT_INVALID_STATE;

  for (;;) {
    size_t target;
    size_t available;
    size_t needed;
    size_t copy_length;
    mesh_mgmt_transport_result_t result;

    if (transport->expected == 0u && transport->used == MESH_MGMT_PREFIX_SIZE) {
      result = determine_expected(transport);
      if (result != MESH_MGMT_TRANSPORT_OK)
        return enter_terminal(transport, result);
    }
    if (transport->expected != 0u && transport->used == transport->expected) {
      mesh_mgmt_codec_result_t codec_result =
          mesh_mgmt_frame_decode(transport->frame, transport->used, &view);
      if (codec_result != MESH_MGMT_CODEC_OK) {
        result = codec_result == MESH_MGMT_CODEC_RESOURCE_EXHAUSTED
                     ? MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED
                     : MESH_MGMT_TRANSPORT_INVALID_FRAME;
        return enter_terminal(transport, result);
      }
      transport->frame_ready = 1;
      out_receipt->frame = transport->frame;
      out_receipt->frame_len = transport->used;
      out_receipt->generation = transport->generation;
      return MESH_MGMT_TRANSPORT_OK;
    }
    if (!transport->recv_chunk) {
      result = prepare_chunk(transport);
      if (result != MESH_MGMT_TRANSPORT_OK)
        return result;
    }

    target = transport->expected != 0u ? transport->expected : MESH_MGMT_PREFIX_SIZE;
    available = transport->recv_chunk_len - transport->recv_chunk_offset;
    needed = target - transport->used;
    copy_length = available < needed ? available : needed;
    memcpy(transport->frame + transport->used, transport->recv_chunk + transport->recv_chunk_offset,
           copy_length);
    transport->used += copy_length;
    transport->recv_chunk_offset += copy_length;
    if (transport->recv_chunk_offset == transport->recv_chunk_len)
      release_recv_chunk(transport);
  }
}

mesh_mgmt_transport_result_t
mesh_mgmt_transport_commit_v1(mesh_mgmt_transport_v1_t *transport,
                              const mesh_mgmt_transport_receipt_v1_t *receipt) {
  if (!transport || !receipt)
    return MESH_MGMT_TRANSPORT_INVALID_ARG;
  if (!transport->initialized || transport->terminal || !transport->frame_ready ||
      receipt->frame != transport->frame || receipt->frame_len != transport->used ||
      receipt->generation != transport->generation) {
    return MESH_MGMT_TRANSPORT_INVALID_STATE;
  }
  if (transport->generation == UINT64_MAX)
    return enter_terminal(transport, MESH_MGMT_TRANSPORT_INVALID_STATE);
  memset(transport->frame, 0, transport->used);
  transport->used = 0u;
  transport->expected = 0u;
  transport->frame_ready = 0;
  transport->generation++;
  return MESH_MGMT_TRANSPORT_OK;
}

mesh_mgmt_transport_result_t mesh_mgmt_transport_send_v1(mesh_mgmt_transport_v1_t *transport,
                                                         const uint8_t *frame, size_t frame_len) {
  mesh_mgmt_frame_view_t view;
  mesh_mgmt_codec_result_t codec_result;

  if (!transport || !frame)
    return MESH_MGMT_TRANSPORT_INVALID_ARG;
  if (!transport->initialized)
    return MESH_MGMT_TRANSPORT_INVALID_STATE;
  if (transport->terminal)
    return transport->last_error;
  codec_result = mesh_mgmt_frame_decode(frame, frame_len, &view);
  if (codec_result == MESH_MGMT_CODEC_RESOURCE_EXHAUSTED)
    return MESH_MGMT_TRANSPORT_RESOURCE_EXHAUSTED;
  if (codec_result != MESH_MGMT_CODEC_OK)
    return MESH_MGMT_TRANSPORT_INVALID_FRAME;
  if (transport->io.send(transport->io.context, frame, frame_len) != 0)
    return enter_terminal(transport, MESH_MGMT_TRANSPORT_IO_FAILED);
  return MESH_MGMT_TRANSPORT_OK;
}
