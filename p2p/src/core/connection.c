/**
 * connection.c - typed CNet connection ownership.
 */
#include "connection.h"

#include <salts/error_codes.h>
#include <salts_buffer.h>
#include <stdlib.h>
#include <string.h>

p2p_connection_t *p2p_connection_create(p2p_conn_type_t type,
                                         cnet_client *owner,
                                         cnet_connection handle) {
    p2p_connection_t *conn;
    if (!owner || handle.generation == 0u) return NULL;
    conn = (p2p_connection_t *)calloc(1, sizeof(*conn));
    if (!conn) return NULL;
    conn->type = type;
    conn->owner = owner;
    conn->handle = handle;
    conn->is_connected = 1;
    return conn;
}

int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len) {
    mem_buffer_t *buffer;
    int status;
    if (!conn || !conn->owner || !conn->is_connected || conn->close_requested ||
        !data || len == 0u) {
        return SALTS_EINVAL;
    }
    buffer = mem_get_buffer(mem_global(), len);
    if (!buffer) return SALTS_ENOMEM;
    memcpy(mem_buffer_data(buffer), data, len);
    mem_set_used(buffer, len);
    status = cnet_send_buffer(conn->owner, conn->handle, buffer);
    mem_buffer_release(buffer);
    return status;
}

int p2p_connection_close(p2p_connection_t *conn) {
    int status;
    if (!conn || !conn->owner) return SALTS_EINVAL;
    if (!conn->is_connected || conn->close_requested) return SALTS_EALREADY;
    status = cnet_close(conn->owner, conn->handle);
    if (status == SALTS_OK || status == SALTS_EALREADY || status == SALTS_ENOENT) {
        conn->close_requested = 1;
        if (status == SALTS_ENOENT) conn->is_connected = 0;
    }
    return status;
}

void p2p_connection_destroy(p2p_connection_t *conn) {
    if (!conn) return;
    if (conn->owner && conn->is_connected && !conn->close_requested) {
        (void)p2p_connection_close(conn);
    }
    free(conn);
}
