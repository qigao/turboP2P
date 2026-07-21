#include "mesh_mgmt_coronet_adapter.h"

#include <string.h>

static int coronet_recv(void *context, uint8_t **out_bytes, size_t *out_len) {
  return coro_socket_recv((coro_socket_t *)context, (char **)out_bytes, out_len);
}

static void coronet_release(void *context, uint8_t *bytes) {
  (void)context;
  coro_socket_free_recv(bytes);
}

static int coronet_send(void *context, const uint8_t *bytes, size_t len) {
  return coro_socket_send((coro_socket_t *)context, (const char *)bytes, len);
}

mesh_mgmt_transport_result_t
mesh_mgmt_transport_init_coronet_v1(mesh_mgmt_transport_v1_t *transport, coro_socket_t *socket) {
  mesh_mgmt_transport_io_v1_t io;
  mesh_mgmt_transport_result_t result;

  if (!transport)
    return MESH_MGMT_TRANSPORT_INVALID_ARG;
  result = mesh_mgmt_transport_coronet_io_v1(&io, socket);
  if (result != MESH_MGMT_TRANSPORT_OK)
    return result;
  return mesh_mgmt_transport_init_v1(transport, &io);
}

mesh_mgmt_transport_result_t mesh_mgmt_transport_coronet_io_v1(mesh_mgmt_transport_io_v1_t *out_io,
                                                               coro_socket_t *socket) {
  uint8_t channel_binding[CORO_TLS_CHANNEL_BINDING_SIZE];
  int tls_result;

  if (!out_io || !socket)
    return MESH_MGMT_TRANSPORT_INVALID_ARG;
  memset(out_io, 0, sizeof(*out_io));
  memset(channel_binding, 0, sizeof(channel_binding));
  tls_result = coro_socket_tls_export_channel_binding(socket, channel_binding);
  memset(channel_binding, 0, sizeof(channel_binding));
  if (tls_result != 0)
    return MESH_MGMT_TRANSPORT_SECURE_CHANNEL_REQUIRED;
  out_io->context = socket;
  out_io->recv = coronet_recv;
  out_io->release = coronet_release;
  out_io->send = coronet_send;
  return MESH_MGMT_TRANSPORT_OK;
}
