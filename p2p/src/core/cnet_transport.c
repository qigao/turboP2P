#include "cnet_transport.h"

#include <stdlib.h>
#include <string.h>

typedef struct p2p_cnet_connection_s {
    p2p_connection_t base;
    p2p_cnet_owner_t *owner;
    struct p2p_cnet_connection_s *next;
    cnet_connection handle;
    p2p_cnet_callbacks_t callbacks;
    size_t *writes;
    size_t write_head;
    size_t write_count;
    size_t pending_bytes;
    size_t send_hwm;
    mem_buffer_t *paused_buffer;
    size_t paused_offset;
    int ready;
    int paused;
    int receive_pending;
    int close_requested;
    int close_admitted;
    int terminal;
    int detached;
    int error;
} p2p_cnet_connection_t;

struct p2p_cnet_owner_s {
    cnet_client client;
    cnet_listener listener;
    p2p_cnet_config_t config;
    p2p_cnet_connection_t *connections;
    size_t connection_count;
    p2p_cnet_accept_fn accept;
    void *accept_context;
    int busy;
    int stopping;
    int stopped;
};

static int connection_send(void *handle, const void *data, size_t length);
static void connection_close(void *handle);
static void connection_destroy(void *handle);

static int p2p_error(int status) {
    if (status == SALTS_OK) return P2P_OK;
    if (status == SALTS_ENOMEM) return P2P_ERR_NO_MEM;
    if (status == SALTS_ENOBUFS) return P2P_ERR_RESOURCE_EXHAUSTED;
    if (status == SALTS_ETIMEDOUT) return P2P_ERR_TIMEOUT;
    if (status == SALTS_EINVAL) return P2P_ERR_INVALID_ARG;
    if (status == SALTS_EBUSY || status == SALTS_ESHUTDOWN ||
        status == SALTS_EALREADY) return P2P_ERR_INVALID_STATE;
    return P2P_ERR_NETWORK;
}

static p2p_cnet_connection_t *cnet_connection_from_base(const p2p_connection_t *base) {
    if (!base || base->ops.destroy != connection_destroy || !base->ops.handle)
        return NULL;
    return base->ops.handle;
}

static int same_handle(cnet_connection left, cnet_connection right) {
    return left.slot == right.slot && left.generation == right.generation;
}

static int active(const p2p_cnet_connection_t *connection) {
    return !connection->owner->stopping && !connection->close_requested &&
           !connection->terminal && !connection->detached;
}

static void try_close(p2p_cnet_connection_t *connection) {
    int status;
    if (!connection->close_requested || connection->close_admitted ||
        connection->terminal || connection->owner->stopped) return;
    status = cnet_close(&connection->owner->client, connection->handle);
    if (status == SALTS_OK || status == SALTS_EALREADY) {
        connection->close_admitted = 1;
    } else if (status != SALTS_ENOBUFS) {
        if (!connection->error) connection->error = p2p_error(status);
        connection->owner->stopping = 1;
    }
    /* Queue pressure never permits freeing an observer. Retry after progress;
     * completed owner stop is the other path to callback quiescence. */
}

static void connection_close(void *handle) {
    p2p_cnet_connection_t *connection = handle;
    connection->base.is_connected = 0;
    connection->close_requested = 1;
    try_close(connection);
}

static void connection_destroy(void *handle) {
    p2p_cnet_connection_t *connection = handle;
    connection->detached = 1;
    memset(&connection->callbacks, 0, sizeof(connection->callbacks));
    connection_close(connection);
}

static void fail(p2p_cnet_connection_t *connection, int error) {
    if (!connection->error) connection->error = error;
    connection_close(connection);
}

static void free_connection(p2p_cnet_connection_t *connection) {
    if (connection->paused_buffer) mem_buffer_release(connection->paused_buffer);
    free(connection->writes);
    free(connection);
}

static void sweep(p2p_cnet_owner_t *owner) {
    p2p_cnet_connection_t **link = &owner->connections;
    while (*link) {
        p2p_cnet_connection_t *connection = *link;
        if (connection->detached && (connection->terminal || owner->stopped)) {
            *link = connection->next;
            owner->connection_count--;
            free_connection(connection);
        } else {
            link = &connection->next;
        }
    }
}

static int connection_send(void *handle, const void *data, size_t length) {
    p2p_cnet_connection_t *connection = handle;
    mem_buffer_t *buffer;
    int status;
    size_t index;
    if (!data || !length) return P2P_ERR_INVALID_ARG;
    if (!active(connection) || !connection->ready) return P2P_ERR_NETWORK;
    if (length > connection->send_hwm - connection->pending_bytes ||
        length > connection->owner->config.client.max_send_bytes ||
        connection->write_count == connection->owner->config.pending_write_limit)
        return P2P_ERR_RESOURCE_EXHAUSTED;
    buffer = mem_get_buffer(mem_global(), length);
    if (!buffer) return P2P_ERR_NO_MEM;
    memcpy(mem_buffer_data(buffer), data, length);
    mem_set_used(buffer, length);
    status = cnet_send_buffer(&connection->owner->client, connection->handle, buffer);
    mem_buffer_release(buffer);
    if (status != SALTS_OK) return p2p_error(status);
    /* CNet admission never calls the observer inline. */
    index = (connection->write_head + connection->write_count) %
            connection->owner->config.pending_write_limit;
    connection->writes[index] = length;
    connection->write_count++;
    connection->pending_bytes += length;
    return P2P_OK;
}

static void demand(p2p_cnet_connection_t *connection) {
    int status;
    if (!active(connection) || !connection->ready || connection->paused ||
        connection->receive_pending || connection->paused_buffer) return;
    status = cnet_receive(&connection->owner->client, connection->handle, 1);
    if (status != SALTS_OK) {
        fail(connection, p2p_error(status));
        return;
    }
    connection->receive_pending = 1;
}

static size_t deliver(p2p_cnet_connection_t *connection,
                       const uint8_t *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length && active(connection) && !connection->paused) {
        size_t consumed = 0;
        int result;
        if (!connection->callbacks.receive) {
            fail(connection, P2P_ERR_INVALID_STATE);
            break;
        }
        result = connection->callbacks.receive(&connection->base, bytes + offset,
            length - offset, &consumed, connection->callbacks.context);
        if (result != P2P_OK) {
            fail(connection, result);
            break;
        }
        if (consumed > length - offset ||
            (!consumed && active(connection) && !connection->paused)) {
            fail(connection, P2P_ERR_PROTOCOL);
            break;
        }
        offset += consumed;
    }
    return offset;
}

static void on_receive(void *context, cnet_connection handle,
                         const cnet_receive_view *view) {
    p2p_cnet_connection_t *connection = context;
    size_t consumed;
    if (!same_handle(connection->handle, handle)) return;
    connection->receive_pending = 0;
    if (!active(connection)) return;
    if (!view || view->kind != CNET_MESSAGE_BYTES || !view->data || !view->size ||
        view->size > connection->owner->config.client.receive_buffer_bytes ||
        connection->paused_buffer) {
        fail(connection, P2P_ERR_PROTOCOL);
        return;
    }
    consumed = deliver(connection, view->data, view->size);
    if (!active(connection)) return;
    if (consumed < view->size) {
        size_t remaining = view->size - consumed;
        connection->paused_buffer = mem_get_buffer(mem_global(), remaining);
        if (!connection->paused_buffer) {
            fail(connection, P2P_ERR_NO_MEM);
            return;
        }
        memcpy(mem_buffer_data(connection->paused_buffer),
               (const uint8_t *)view->data + consumed, remaining);
        mem_set_used(connection->paused_buffer, remaining);
    }
    demand(connection);
}

static void on_send(void *context, cnet_connection handle, size_t length) {
    p2p_cnet_connection_t *connection = context;
    if (!same_handle(connection->handle, handle) || connection->terminal) return;
    if (!connection->write_count ||
        connection->writes[connection->write_head] != length) {
        fail(connection, P2P_ERR_PROTOCOL);
        return;
    }
    connection->write_head = (connection->write_head + 1) %
                            connection->owner->config.pending_write_limit;
    connection->write_count--;
    connection->pending_bytes -= length;
    if (active(connection) && connection->callbacks.sent)
        connection->callbacks.sent(&connection->base, length,
                                    connection->callbacks.context);
}

static void on_state(void *context, cnet_connection handle,
                       cnet_connection_state state, const cnet_error *error) {
    p2p_cnet_connection_t *connection = context;
    if (!same_handle(connection->handle, handle) || connection->terminal) return;
    if (state == CNET_CONNECTION_CONNECTED) {
        int result = P2P_OK;
        connection->ready = 1;
        if (!active(connection)) {
            connection_close(connection);
            return;
        }
        if (connection->callbacks.connected)
            result = connection->callbacks.connected(&connection->base,
                                                       connection->callbacks.context);
        if (result != P2P_OK) fail(connection, result);
        demand(connection);
    } else if (state == CNET_CONNECTION_CLOSED || state == CNET_CONNECTION_FAILED) {
        connection->terminal = 1;
        connection->base.is_connected = 0;
        connection->ready = 0;
        connection->receive_pending = 0;
        connection->write_count = 0;
        connection->pending_bytes = 0;
        if (!connection->error && error && error->status != SALTS_OK)
            connection->error = p2p_error(error->status);
        if (!connection->error && state == CNET_CONNECTION_FAILED)
            connection->error = P2P_ERR_NETWORK;
        if (!connection->detached && connection->callbacks.closed)
            connection->callbacks.closed(&connection->base, connection->error,
                                           connection->callbacks.context);
    }
}

static p2p_cnet_connection_t *allocate_connection(p2p_cnet_owner_t *owner,
                                                  p2p_conn_type_t type) {
    p2p_cnet_connection_t *connection;
    if (owner->connection_count >= owner->config.client.connection_capacity) return NULL;
    connection = calloc(1, sizeof(*connection));
    if (!connection) return NULL;
    connection->writes = calloc(owner->config.pending_write_limit, sizeof(size_t));
    if (!connection->writes) { free(connection); return NULL; }
    connection->base.type = type;
    connection->base.is_connected = 1;
    connection->base.ops.send = connection_send;
    connection->base.ops.close = connection_close;
    connection->base.ops.handle = connection;
    connection->base.ops.destroy = connection_destroy;
    connection->owner = owner;
    connection->send_hwm = owner->config.send_hwm_bytes;
    return connection;
}

static void publish_connection(p2p_cnet_owner_t *owner,
                                 p2p_cnet_connection_t *connection) {
    connection->next = owner->connections;
    owner->connections = connection;
    owner->connection_count++;
}

static cnet_observer observer(p2p_cnet_connection_t *connection) {
    cnet_observer result = {0};
    result.on_state = on_state;
    result.on_receive = on_receive;
    result.on_send = on_send;
    result.user = connection;
    return result;
}

int p2p_cnet_owner_create(const p2p_cnet_config_t *config,
                          p2p_cnet_owner_t **output) {
    p2p_cnet_owner_t *owner;
    int status;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (!config || !config->send_hwm_bytes || !config->pending_write_limit ||
        config->pending_write_limit > SIZE_MAX / sizeof(size_t) ||
        !config->accept_budget || !config->stop_timeout_ms ||
        config->client.tls_io_buffer_bytes) return P2P_ERR_INVALID_ARG;
    owner = calloc(1, sizeof(*owner));
    if (!owner) return P2P_ERR_NO_MEM;
    owner->config = *config;
    status = cnet_client_init(&owner->client, &config->client);
    if (status != SALTS_OK) { free(owner); return p2p_error(status); }
    *output = owner;
    return P2P_OK;
}

static int close_listener(p2p_cnet_owner_t *owner) {
    int status;
    if (!owner->listener.impl) return SALTS_OK;
    status = cnet_listener_close(&owner->listener);
    if (status != SALTS_OK && status != SALTS_EALREADY) return status;
    return cnet_listener_destroy(&owner->listener);
}

int p2p_cnet_owner_listen(p2p_cnet_owner_t *owner, const char *host,
                          uint16_t port, size_t backlog,
                          p2p_cnet_accept_fn accept, void *context,
                          cnet_stream_peer *local) {
    cnet_listener_config config = {0};
    int status;
    if (!owner || !host || !accept || !local || !backlog) return P2P_ERR_INVALID_ARG;
    if (owner->stopping || owner->listener.impl) return P2P_ERR_INVALID_STATE;
    config.backend = owner->config.client.backend;
    config.host = host;
    config.port = port;
    config.backlog = backlog;
    status = cnet_listener_init(&owner->listener, &config);
    if (status != SALTS_OK) return p2p_error(status);
    status = cnet_listener_local(&owner->listener, local);
    if (status != SALTS_OK) {
        close_listener(owner);
        return p2p_error(status);
    }
    owner->accept = accept;
    owner->accept_context = context;
    return P2P_OK;
}

int p2p_cnet_owner_connect(p2p_cnet_owner_t *owner, const cnet_stream_peer *peer,
                           const p2p_cnet_callbacks_t *callbacks,
                           p2p_connection_t **output) {
    p2p_cnet_connection_t *connection;
    cnet_observer events;
    int status;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (!owner || !peer || !callbacks || !callbacks->receive) return P2P_ERR_INVALID_ARG;
    if (owner->stopping) return P2P_ERR_INVALID_STATE;
    if (owner->connection_count >= owner->config.client.connection_capacity)
        return P2P_ERR_RESOURCE_EXHAUSTED;
    connection = allocate_connection(owner, P2P_CONN_OUTBOUND);
    if (!connection) return P2P_ERR_NO_MEM;
    connection->callbacks = *callbacks;
    events = observer(connection);
    status = cnet_connect_peer(&owner->client, peer, NULL, &events, &connection->handle);
    if (status != SALTS_OK) { free_connection(connection); return p2p_error(status); }
    publish_connection(owner, connection);
    *output = &connection->base;
    return P2P_OK;
}

static int accept_connections(p2p_cnet_owner_t *owner) {
    if (!owner->listener.impl) return P2P_OK;
    for (size_t index = 0; index < owner->config.accept_budget && !owner->stopping; ++index) {
        cnet_accepted_stream accepted = CNET_ACCEPTED_STREAM_INIT;
        p2p_cnet_connection_t *connection;
        cnet_observer events;
        int status = cnet_listener_accept_detached(&owner->listener, &accepted);
        if (status == SALTS_ETIMEDOUT) break;
        if (status != SALTS_OK) return p2p_error(status);
        connection = allocate_connection(owner, P2P_CONN_INBOUND);
        if (!connection) {
            cnet_accepted_stream_close(&accepted);
            return owner->connection_count >= owner->config.client.connection_capacity ?
                P2P_ERR_RESOURCE_EXHAUSTED : P2P_ERR_NO_MEM;
        }
        events = observer(connection);
        status = cnet_client_adopt_accepted(&owner->client, &accepted, &events,
                                            &connection->handle);
        if (status != SALTS_OK) { free_connection(connection); return p2p_error(status); }
        publish_connection(owner, connection);
        status = owner->accept(owner, &connection->base, &accepted.peer,
                                owner->accept_context);
        if (status != P2P_OK || !connection->callbacks.receive) {
            if (status != P2P_OK) connection->error = status;
            connection_destroy(connection);
        }
    }
    return P2P_OK;
}

static void resume_connections(p2p_cnet_owner_t *owner) {
    for (p2p_cnet_connection_t *connection = owner->connections;
         connection; connection = connection->next) {
        if (active(connection) && !connection->paused && connection->paused_buffer) {
            const uint8_t *bytes = mem_buffer_data(connection->paused_buffer);
            size_t length = mem_buffer_used(connection->paused_buffer);
            connection->paused_offset += deliver(connection,
                bytes + connection->paused_offset, length - connection->paused_offset);
            if (connection->paused_offset == length || !active(connection)) {
                mem_buffer_release(connection->paused_buffer);
                connection->paused_buffer = NULL;
                connection->paused_offset = 0;
            }
        }
        try_close(connection);
        demand(connection);
    }
}

int p2p_cnet_owner_poll(p2p_cnet_owner_t *owner) {
    size_t events = 0;
    int result, progress;
    if (!owner) return P2P_ERR_INVALID_ARG;
    if (owner->busy || owner->stopped) return P2P_ERR_INVALID_STATE;
    if (owner->stopping) return p2p_cnet_owner_stop(owner);
    owner->busy = 1;
    result = accept_connections(owner);
    resume_connections(owner);
    progress = cnet_client_poll(&owner->client, 0, &events);
    if (progress != SALTS_OK) owner->stopping = 1;
    if (result == P2P_OK) result = p2p_error(progress);
    /* Closing requests rejected by command pressure get another admission
     * attempt after CNet has consumed commands, without nested polling. */
    for (p2p_cnet_connection_t *connection = owner->connections;
         connection; connection = connection->next) try_close(connection);
    owner->busy = 0;
    sweep(owner);
    if (owner->stopping) {
        int stop_result = p2p_cnet_owner_stop(owner);
        if (result == P2P_OK) result = stop_result;
    }
    return result;
}

int p2p_cnet_owner_stop(p2p_cnet_owner_t *owner) {
    int status, destroyed, listener_status;
    if (!owner) return P2P_ERR_INVALID_ARG;
    owner->stopping = 1;
    if (owner->busy || owner->stopped) return P2P_OK;
    owner->busy = 1;
    listener_status = close_listener(owner);
    status = owner->client.impl ?
        cnet_client_stop(&owner->client, owner->config.stop_timeout_ms) : SALTS_OK;
    destroyed = cnet_client_destroy(&owner->client);
    if (!owner->client.impl && !owner->listener.impl) owner->stopped = 1;
    owner->busy = 0;
    sweep(owner);
    if (listener_status != SALTS_OK) return p2p_error(listener_status);
    return status != SALTS_OK ? p2p_error(status) : p2p_error(destroyed);
}

int p2p_cnet_owner_destroy(p2p_cnet_owner_t *owner) {
    int result;
    if (!owner) return P2P_OK;
    if (owner->busy) return P2P_ERR_INVALID_STATE;
    result = p2p_cnet_owner_stop(owner);
    if (!owner->stopped) return result == P2P_OK ? P2P_ERR_INVALID_STATE : result;
    while (owner->connections) {
        p2p_cnet_connection_t *connection = owner->connections;
        owner->connections = connection->next;
        free_connection(connection);
    }
    free(owner);
    return P2P_OK;
}

size_t p2p_cnet_owner_connection_count(const p2p_cnet_owner_t *owner) {
    return owner ? owner->connection_count : 0;
}

int p2p_cnet_connection_handoff(p2p_connection_t *base,
                                const p2p_cnet_callbacks_t *callbacks) {
    p2p_cnet_connection_t *connection = cnet_connection_from_base(base);
    if (!connection || !callbacks || !callbacks->receive) return P2P_ERR_INVALID_ARG;
    if (!active(connection)) return P2P_ERR_INVALID_STATE;
    connection->callbacks = *callbacks;
    return P2P_OK;
}

int p2p_cnet_connection_pause(p2p_connection_t *base, int paused) {
    p2p_cnet_connection_t *connection = cnet_connection_from_base(base);
    if (!connection) return P2P_ERR_INVALID_ARG;
    if (!active(connection)) return P2P_ERR_INVALID_STATE;
    connection->paused = !!paused;
    return P2P_OK;
}

int p2p_cnet_connection_set_send_hwm(p2p_connection_t *base, size_t bytes) {
    p2p_cnet_connection_t *connection = cnet_connection_from_base(base);
    if (!connection || !bytes) return P2P_ERR_INVALID_ARG;
    if (!active(connection) || bytes < connection->pending_bytes)
        return P2P_ERR_INVALID_STATE;
    if (bytes > connection->owner->config.send_hwm_bytes)
        return P2P_ERR_RESOURCE_EXHAUSTED;
    connection->send_hwm = bytes;
    return P2P_OK;
}

size_t p2p_cnet_connection_pending_bytes(const p2p_connection_t *base) {
    const p2p_cnet_connection_t *connection = cnet_connection_from_base(base);
    return connection ? connection->pending_bytes : 0;
}
