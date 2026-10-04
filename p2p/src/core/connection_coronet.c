/* Explicit legacy node adapter, removed with the node/executor CNet migration. */
#include "connection.h"
#include "../../include/p2p.h"
#include <CoroNet/turbo_stream.h>
#include <turbo_error.h>
#include <stdlib.h>

static int stream_send(void *handle, const void *data, size_t len) {
    int result = turbo_stream_send(handle, (const char *)data, len);
    return result == 0 ? P2P_OK :
        result == TURBO_ENOBUFS ? P2P_ERR_RESOURCE_EXHAUSTED : P2P_ERR_NETWORK;
}

static void stream_close(void *handle) {
    turbo_stream_t *stream = handle;
    if (!stream) return;
    turbo_stream_set_user_data(stream, NULL);
    turbo_stream_close(stream);
    turbo_stream_destroy(stream);
}

static p2p_connection_t *create_stream(void *handle, p2p_conn_type_t type) {
    p2p_connection_t *connection;
    if (!handle) return NULL;
    connection = calloc(1, sizeof(*connection));
    if (!connection) return NULL;
    connection->type = type;
    connection->ops.handle = handle;
    connection->ops.send = stream_send;
    connection->ops.close = stream_close;
    connection->is_connected = 1;
    return connection;
}

p2p_connection_t *p2p_connection_create_outbound(void *handle) {
    return create_stream(handle, P2P_CONN_OUTBOUND);
}

p2p_connection_t *p2p_connection_create_inbound(void *handle) {
    return create_stream(handle, P2P_CONN_INBOUND);
}
