/**
 * connection.c - Thin P2P ownership wrapper over CNet.
 */
#include "connection.h"

#include <salts_buffer.h>
#include <salts/error_codes.h>

#include <stdlib.h>
#include <string.h>

p2p_connection_t *p2p_connection_create(cnet_client *client,
                                        cnet_connection handle,
                                        p2p_conn_type_t type) {
    p2p_connection_t *conn;
    if (!client || handle.generation == 0u) return NULL;
    conn = (p2p_connection_t *)calloc(1, sizeof(*conn));
    if (!conn) return NULL;
    conn->type = type;
    conn->client = client;
    conn->handle = handle;
    return conn;
}

void p2p_connection_destroy(p2p_connection_t *conn) {
    if (!conn) return;
    (void)p2p_connection_close(conn);
    free(conn);
}

int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len) {
    mem_buffer_t *buffer;
    int status;
    if (!conn || !conn->client || conn->handle.generation == 0u ||
        !data || len == 0u || conn->close_requested) {
        return SALTS_EINVAL;
    }
    buffer = mem_get_buffer(mem_global(), len);
    if (!buffer) return SALTS_ENOMEM;
    memcpy(mem_buffer_data(buffer), data, len);
    mem_set_used(buffer, len);
    status = cnet_send_buffer(conn->client, conn->handle, buffer);
    mem_buffer_release(buffer);
    return status;
}

int p2p_connection_close(p2p_connection_t *conn) {
    int status;
    if (!conn || !conn->client || conn->handle.generation == 0u)
        return SALTS_EINVAL;
    if (conn->close_requested) return SALTS_EALREADY;
    status = cnet_close(conn->client, conn->handle);
    if (status == SALTS_OK || status == SALTS_EALREADY ||
        status == SALTS_ENOENT || status == SALTS_ESHUTDOWN) {
        conn->close_requested = 1;
    }
    return status;
}
