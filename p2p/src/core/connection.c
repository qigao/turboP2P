/**
 * connection.c - Unified connection abstraction implementation
 * Eliminates dual client/conn state with clean polymorphism
 */

#include "connection.h"
#include <CoroNet/turbo_stream.h>
#include <stdlib.h>

/* =============================================================================
 * Outbound Connection Operations
 * ============================================================================= */

static int outbound_send(void *handle, const void *data, size_t len) {
    return turbo_stream_send((turbo_stream_t *)handle, (const char *)data, len);
}

static void outbound_close(void *handle) {
    turbo_stream_t *stream = (turbo_stream_t *)handle;
    if (stream) {
        turbo_stream_set_user_data(stream, NULL);
        turbo_stream_close(stream);
        turbo_stream_destroy(stream);
    }
}

/* =============================================================================
 * Inbound Connection Operations
 * ============================================================================= */

static int inbound_send(void *handle, const void *data, size_t len) {
    return turbo_stream_send((turbo_stream_t *)handle, (const char *)data, len);
}

static void inbound_close(void *handle) {
    turbo_stream_t *stream = (turbo_stream_t *)handle;
    if (stream) {
        turbo_stream_set_user_data(stream, NULL);
        turbo_stream_close(stream);
        turbo_stream_destroy(stream);
    }
}

/* =============================================================================
 * Connection Lifecycle
 * ============================================================================= */

p2p_connection_t *p2p_connection_create_outbound(void *client_handle) {
    if (!client_handle) return NULL;
    
    p2p_connection_t *conn = (p2p_connection_t *)calloc(1, sizeof(p2p_connection_t));
    if (!conn) return NULL;
    
    conn->type = P2P_CONN_OUTBOUND;
    conn->ops.handle = client_handle;
    conn->ops.send = outbound_send;
    conn->ops.close = outbound_close;
    conn->is_connected = 1;
    
    return conn;
}

p2p_connection_t *p2p_connection_create_inbound(void *conn_handle) {
    if (!conn_handle) return NULL;

    p2p_connection_t *conn = (p2p_connection_t *)calloc(1, sizeof(p2p_connection_t));
    if (!conn) return NULL;
    
    conn->type = P2P_CONN_INBOUND;
    conn->ops.handle = conn_handle;
    conn->ops.send = inbound_send;
    conn->ops.close = inbound_close;
    conn->is_connected = 1;
    
    return conn;
}

void p2p_connection_destroy(p2p_connection_t *conn) {
    if (!conn) return;
    
    if (conn->is_connected && conn->ops.close) {
        conn->is_connected = 0;
        conn->ops.close(conn->ops.handle);
    }
    
    free(conn);
}

/* =============================================================================
 * Connection Operations
 * ============================================================================= */

int p2p_connection_send(p2p_connection_t *conn, const void *data, size_t len) {
    if (!conn || !conn->is_connected || !conn->ops.send) {
        return -1;
    }
    
    return conn->ops.send(conn->ops.handle, data, len);
}

void p2p_connection_close(p2p_connection_t *conn) {
    if (!conn || !conn->is_connected) return;
    
    if (conn->ops.close) {
        conn->ops.close(conn->ops.handle);
    }
    
    conn->is_connected = 0;
}
