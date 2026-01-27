/**
 * connection.c - Unified connection abstraction implementation
 * Eliminates dual client/conn state with clean polymorphism
 */

#include "connection.h"
#include <turbo_async_client.h>
#include <turbo_async_server.h>
#include <stdlib.h>

/* Forward declaration for server context */
typedef struct {
    async_server_t *server;
    async_server_connection_t *conn;
} inbound_ctx_t;

/* =============================================================================
 * Outbound Connection Operations
 * ============================================================================= */

static int outbound_send(void *handle, const void *data, size_t len) {
    async_client_t *client = (async_client_t *)handle;
    async_client_status_t status = async_client_send(client, data, len);
    return (status == ASYNC_CLIENT_STATUS_OK) ? 0 : -1;
}

static void outbound_close(void *handle) {
    async_client_t *client = (async_client_t *)handle;
    if (client) {
        /* destroy implies close, stop, and join */
        async_client_destroy(client);
    }
}

/* =============================================================================
 * Inbound Connection Operations
 * ============================================================================= */

static int inbound_send(void *handle, const void *data, size_t len) {
    inbound_ctx_t *ctx = (inbound_ctx_t *)handle;
    async_server_status_t status = async_server_send(ctx->server, ctx->conn, data, len);
    return (status == ASYNC_SERVER_STATUS_OK) ? 0 : -1;
}

static void inbound_close(void *handle) {
    inbound_ctx_t *ctx = (inbound_ctx_t *)handle;
    async_server_connection_set_user_data(ctx->conn, NULL);
    async_server_close_connection(ctx->server, ctx->conn);
    free(ctx);
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

p2p_connection_t *p2p_connection_create_inbound(void *server_handle, void *conn_handle) {
    if (!server_handle || !conn_handle) return NULL;
    
    inbound_ctx_t *ctx = (inbound_ctx_t *)malloc(sizeof(inbound_ctx_t));
    if (!ctx) return NULL;
    
    ctx->server = (async_server_t *)server_handle;
    ctx->conn = (async_server_connection_t *)conn_handle;
    
    p2p_connection_t *conn = (p2p_connection_t *)calloc(1, sizeof(p2p_connection_t));
    if (!conn) {
        free(ctx);
        return NULL;
    }
    
    conn->type = P2P_CONN_INBOUND;
    conn->ops.handle = ctx;
    conn->ops.send = inbound_send;
    conn->ops.close = inbound_close;
    conn->is_connected = 1;
    
    return conn;
}

void p2p_connection_destroy(p2p_connection_t *conn) {
    if (!conn) return;
    
    if (conn->is_connected && conn->ops.close) {
        /* Clear user data to prevent use-after-free in callbacks if peer is destroyed */
        if (conn->type == P2P_CONN_OUTBOUND && conn->ops.handle) {
            async_client_set_user_data((async_client_t *)conn->ops.handle, NULL);
        }

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
