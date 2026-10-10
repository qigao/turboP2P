#include "connection.h"
#include "../../include/p2p.h"
#include <stdlib.h>

void p2p_connection_destroy(p2p_connection_t *conn) {
    if (!conn) return;
    if (conn->ops.destroy) {
        conn->ops.destroy(conn->ops.handle);
        return;
    }
    p2p_connection_close(conn);
    free(conn);
}

int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len) {
    if (!conn || !conn->is_connected || !conn->ops.send) {
        return P2P_ERR_NETWORK;
    }
    return conn->ops.send(conn->ops.handle, data, len);
}

void p2p_connection_close(p2p_connection_t *conn) {
    if (!conn || !conn->is_connected) return;
    /* Reentrant close must see the closed logical state. */
    conn->is_connected = 0;
    if (conn->ops.close) conn->ops.close(conn->ops.handle);
}

int p2p_connection_pause(p2p_connection_t *conn, int paused) {
    if (!conn || !conn->is_connected) return P2P_ERR_NETWORK;
    if (!conn->ops.pause) return P2P_ERR_INVALID_STATE;
    return conn->ops.pause(conn->ops.handle, paused != 0);
}

int p2p_connection_send_completed(p2p_connection_t *conn, const void *data,
    size_t len, p2p_send_complete_fn complete, void *context) {
    if (!data || !len || !complete) return P2P_ERR_INVALID_ARG;
    if (!conn || !conn->is_connected) return P2P_ERR_NETWORK;
    if (!conn->ops.send_completed) return P2P_ERR_INVALID_STATE;
    return conn->ops.send_completed(conn->ops.handle, data, len, complete, context);
}

int p2p_connection_send_terminal(p2p_connection_t *conn, const void *data,
    size_t len, p2p_send_complete_fn complete, void *context) {
    if (!data || !len || !complete) return P2P_ERR_INVALID_ARG;
    if (!conn || !conn->is_connected) return P2P_ERR_NETWORK;
    if (!conn->ops.send_terminal) return P2P_ERR_INVALID_STATE;
    return conn->ops.send_terminal(conn->ops.handle, data, len, complete, context);
}
