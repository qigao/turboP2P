#include "cnet_transport.h"

#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

typedef struct {
    size_t length;
    p2p_send_complete_fn complete;
    void *context;
} p2p_cnet_write_t;

typedef struct p2p_cnet_connection_s {
    p2p_connection_t base;
    p2p_cnet_owner_t *owner;
    struct p2p_cnet_connection_s *next;
    cnet_connection handle;
    p2p_cnet_callbacks_t callbacks;
    p2p_cnet_write_t *writes;
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
    cnet_handoff *inbound_credit;
    cnet_handoff_ticket inbound_ticket;
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
    native_io_backend *external_backend; /* borrowed under registered SG host lease */
    native_io_sharded_host_lease host_lease; /* immutable SG runtime/shard affinity */
    native_io_sharded_completion *host_batch; /* fixed-capacity scratch */
    p2p_cnet_sg_t *sg_acceptor;
    p2p_cnet_sg_t *sg_final;
    size_t sg_final_index;
};

struct p2p_cnet_sg_s {
    p2p_cnet_owner_t *acceptor;
    p2p_cnet_owner_t *finals[P2P_CNET_SG_MAX_OWNERS];
    cnet_handoff inboxes[P2P_CNET_SG_MAX_OWNERS];
    size_t owner_count;
    size_t explicit_owner;
    cnet_owner_placement_kind placement;
    uint64_t sequence;
    atomic_uint_fast64_t routed;
    atomic_uint_fast64_t denied;
    atomic_bool sealed;
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

/* A TAKEN handoff credit protects the final connection and all application
 * callback context. Release it only after CNet's terminal and peer detach (or
 * a fully completed CNet client stop). Never release from on_state itself. */
static int sweep(p2p_cnet_owner_t *owner) {
    p2p_cnet_connection_t **link = &owner->connections;
    while (*link) {
        p2p_cnet_connection_t *connection = *link;
        if (connection->inbound_credit != NULL &&
            ((connection->detached && connection->terminal) || owner->stopped)) {
            int status = cnet_handoff_release(connection->inbound_credit,
                                              connection->inbound_ticket);
            if (status != SALTS_OK) return p2p_error(status);
            connection->inbound_credit = NULL;
        }
        if (connection->detached && (connection->terminal || owner->stopped)) {
            *link = connection->next;
            owner->connection_count--;
            free_connection(connection);
        } else {
            link = &connection->next;
        }
    }
    return P2P_OK;
}

static int connection_send_completed(void *handle, const void *data, size_t length,
    p2p_send_complete_fn complete, void *context) {
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
    connection->writes[index] = (p2p_cnet_write_t){length, complete, context};
    connection->write_count++;
    connection->pending_bytes += length;
    return P2P_OK;
}

static int connection_send(void *handle, const void *data, size_t length) {
    return connection_send_completed(handle, data, length, NULL, NULL);
}

static int connection_pause(void *handle, int paused) {
    p2p_cnet_connection_t *connection = handle;
    return p2p_cnet_connection_pause(&connection->base, paused);
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
    p2p_cnet_write_t write;
    if (!same_handle(connection->handle, handle) || connection->terminal) return;
    if (!connection->write_count ||
        connection->writes[connection->write_head].length != length) {
        fail(connection, P2P_ERR_PROTOCOL);
        return;
    }
    write = connection->writes[connection->write_head];
    connection->write_head = (connection->write_head + 1) %
                            connection->owner->config.pending_write_limit;
    connection->write_count--;
    connection->pending_bytes -= length;
    if (!connection->detached && write.complete)
        write.complete(write.context, active(connection) ? P2P_OK : P2P_ERR_NETWORK);
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

        if (!connection->error && error && error->status != SALTS_OK)
            connection->error = p2p_error(error->status);
        if (!connection->error && state == CNET_CONNECTION_FAILED)
            connection->error = P2P_ERR_NETWORK;
        /* Detach each entry before invoking it: a terminal may destroy its
         * peer/connection and suppress every remaining borrowed context. */
        while (connection->write_count) {
            p2p_cnet_write_t write = connection->writes[connection->write_head];
            connection->write_head = (connection->write_head + 1) %
                connection->owner->config.pending_write_limit;
            connection->write_count--;
            connection->pending_bytes -= write.length;
            if (!connection->detached && write.complete)
                write.complete(write.context, connection->error ?
                    connection->error : P2P_ERR_NETWORK);
        }
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
    connection->writes = calloc(owner->config.pending_write_limit, sizeof(p2p_cnet_write_t));
    if (!connection->writes) { free(connection); return NULL; }
    connection->base.type = type;
    connection->base.is_connected = 1;
    connection->base.ops.send = connection_send;
    connection->base.ops.close = connection_close;
    connection->base.ops.handle = connection;
    connection->base.ops.destroy = connection_destroy;
    connection->base.ops.pause = connection_pause;
    connection->base.ops.send_completed = connection_send_completed;
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

static int create_owner_impl(const p2p_cnet_config_t *config,
                             native_io_backend *external_backend,
                             native_io_sharded_host_lease host_lease,
                             p2p_cnet_owner_t **output) {
    p2p_cnet_owner_t *owner;
    int status;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (!config || !config->send_hwm_bytes || !config->pending_write_limit ||
        config->pending_write_limit > SIZE_MAX / sizeof(p2p_cnet_write_t) ||
        !config->accept_budget || !config->stop_timeout_ms ||
        config->client.tls_io_buffer_bytes)
        return P2P_ERR_INVALID_ARG;
    if (external_backend &&
        (host_lease.version != NATIVE_IO_SHARDED_HOST_VERSION ||
         !host_lease.owner_identity || !host_lease.generation))
        return P2P_ERR_INVALID_ARG;
    if (external_backend && (!config->client.completion_batch_capacity ||
        config->client.completion_batch_capacity >
            SIZE_MAX / sizeof(native_io_sharded_completion)))
        return P2P_ERR_INVALID_ARG;
    owner = calloc(1, sizeof(*owner));
    if (!owner) return P2P_ERR_NO_MEM;
    owner->config = *config;
    owner->external_backend = external_backend;
    owner->host_lease = host_lease;
    if (external_backend) {
        /* One startup allocation for the complete bounded host-observed batch.
         * No per-shard-turn allocation and no NativeIO observe ownership here. */
        owner->host_batch = calloc(config->client.completion_batch_capacity,
                                    sizeof(*owner->host_batch));
        if (!owner->host_batch) { free(owner); return P2P_ERR_NO_MEM; }
        status = cnet_client_init_external(&owner->client, &config->client,
                                           external_backend);
    } else status = cnet_client_init(&owner->client, &config->client);
    if (status != SALTS_OK) {
        free(owner->host_batch);
        free(owner);
        return p2p_error(status);
    }
    *output = owner;
    return P2P_OK;
}

int p2p_cnet_owner_create(const p2p_cnet_config_t *config,
                          p2p_cnet_owner_t **output) {
    return create_owner_impl(config, NULL, (native_io_sharded_host_lease){0}, output);
}

int p2p_cnet_owner_create_external(const p2p_cnet_config_t *config,
                                   native_io_backend *borrowed_backend,
                                   native_io_sharded_host_lease lease,
                                   p2p_cnet_owner_t **output) {
    if (!borrowed_backend) {
        if (output) *output = NULL;
        return P2P_ERR_INVALID_ARG;
    }
    return create_owner_impl(config, borrowed_backend, lease, output);
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
    if (owner->external_backend) {
        native_io_request accepted = {0};
        status = cnet_listener_attach_external(&owner->listener,
                                               owner->external_backend);
        if (status == SALTS_OK)
            status = cnet_listener_submit_external_accept(&owner->listener,
                                                          &accepted);
        if (status != SALTS_OK) {
            close_listener(owner);
            return p2p_error(status);
        }
    }
    owner->accept = accept;
    owner->accept_context = context;
    return P2P_OK;
}

int p2p_cnet_owner_bind_handoff_accept(p2p_cnet_owner_t *owner,
                                       p2p_cnet_accept_fn accept,
                                       void *context) {
    if (!owner || !accept) return P2P_ERR_INVALID_ARG;
    if (!owner->external_backend || !owner->client.impl ||
        owner->listener.impl || owner->accept ||
        owner->busy || owner->stopping || owner->stopped)
        return P2P_ERR_INVALID_STATE;
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


/* A detached inbound socket belongs to exactly one final CNet Owner. The
 * remote address snapshot is copied before CNet consumes the descriptor.
 * Until final terminal/callback retirement a TAKEN ticket protects storage. */
static int adopt_detached(p2p_cnet_owner_t *owner,
                          cnet_accepted_stream *accepted,
                          cnet_handoff *credit_owner,
                          cnet_handoff_ticket credit) {
    p2p_cnet_connection_t *connection;
    cnet_observer events;
    cnet_stream_peer peer;
    int status;

    if (!owner->accept || owner->stopping || owner->stopped) {
        cnet_accepted_stream_close(accepted);
        if (credit_owner) cnet_handoff_release(credit_owner, credit);
        return P2P_ERR_INVALID_STATE;
    }
    peer = accepted->peer;
    connection = allocate_connection(owner, P2P_CONN_INBOUND);
    if (!connection) {
        cnet_accepted_stream_close(accepted);
        if (credit_owner) cnet_handoff_release(credit_owner, credit);
        return owner->connection_count >= owner->config.client.connection_capacity
            ? P2P_ERR_RESOURCE_EXHAUSTED : P2P_ERR_NO_MEM;
    }
    events = observer(connection);
    status = cnet_client_adopt_accepted(&owner->client, accepted, &events,
                                         &connection->handle);
    if (status != SALTS_OK) {
        if (accepted->internal_active) cnet_accepted_stream_close(accepted);
        free_connection(connection);
        if (credit_owner) cnet_handoff_release(credit_owner, credit);
        return p2p_error(status);
    }
    connection->inbound_credit = credit_owner;
    connection->inbound_ticket = credit;
    publish_connection(owner, connection);
    status = owner->accept(owner, &connection->base, &peer,
                            owner->accept_context);
    if (status != P2P_OK || !connection->callbacks.receive) {
        if (status != P2P_OK) connection->error = status;
        connection_destroy(connection);
    }
    return P2P_OK;
}

/* The SG's inbound placement is decided once at accept, using an immutable
 * owner order and a coherent *advisory* handoff credit snapshot. Full protocol
 * auth (cookie, Noise, MMP) is performed solely on the selected final Owner.
 * In particular TCP source IP is NOT a signed STRICT_KEY identity. */
static int sg_route_accepted(p2p_cnet_owner_t *owner,
                             cnet_accepted_stream *accepted) {
    p2p_cnet_sg_t *sg = owner->sg_acceptor;
    cnet_owner_placement_hint hints[P2P_CNET_SG_MAX_OWNERS] = {{0}};
    cnet_owner_placement_input input = {0};
    cnet_handoff_ticket ticket = {0};
    size_t selected = SIZE_MAX;
    int status;
    if (atomic_load_explicit(&sg->sealed, memory_order_acquire)) {
        cnet_accepted_stream_close(accepted);
        atomic_fetch_add_explicit(&sg->denied, 1u, memory_order_relaxed);
        return P2P_OK;
    }
    for (size_t i = 0u; i < sg->owner_count; ++i) {
        cnet_handoff_snapshot snap = {0};
        if (cnet_handoff_get_snapshot(&sg->inboxes[i], &snap) != SALTS_OK) {
            cnet_accepted_stream_close(accepted);
            return P2P_ERR_INVALID_STATE;
        }
        hints[i].pressure = (uint64_t)(snap.reserved + snap.queued + snap.taken);
        hints[i].eligible = !snap.sealed &&
            hints[i].pressure < snap.connection_capacity;
        if (sg->finals[i] == owner) {
            /* No cross-thread read of another Owner's connection_count. */
            hints[i].pressure += (uint64_t)owner->connection_count;
            hints[i].eligible = hints[i].eligible &&
                owner->connection_count < owner->config.client.connection_capacity;
        }
    }
    if (sg->sequence == UINT64_MAX) {
        cnet_accepted_stream_close(accepted);
        return P2P_ERR_RESOURCE_EXHAUSTED;
    }
    input.size = sizeof(input);
    input.version = CNET_OWNER_PLACEMENT_VERSION;
    input.kind = sg->placement;
    input.owners = hints;
    input.owner_count = sg->owner_count;
    input.explicit_owner = sg->explicit_owner;
    input.sequence = sg->sequence++;
    status = cnet_owner_placement_choose(&input, &selected);
    if (status == SALTS_ENOBUFS) {
        cnet_accepted_stream_close(accepted);
        atomic_fetch_add_explicit(&sg->denied, 1u, memory_order_relaxed);
        return P2P_OK; /* Capacity denial is not a listener runtime failure. */
    }
    if (status != SALTS_OK || selected >= sg->owner_count) {
        cnet_accepted_stream_close(accepted);
        return P2P_ERR_INVALID_STATE;
    }
    if (sg->finals[selected] == owner) {
        status = adopt_detached(owner, accepted, NULL, ticket);
        if (status == P2P_OK) {
            atomic_fetch_add_explicit(&sg->routed, 1u, memory_order_relaxed);
            return P2P_OK;
        }
        if (status == P2P_ERR_RESOURCE_EXHAUSTED) {
            atomic_fetch_add_explicit(&sg->denied, 1u, memory_order_relaxed);
            return P2P_OK;
        }
        return status;
    }
    status = cnet_handoff_reserve(&sg->inboxes[selected], &ticket);
    if (status != SALTS_OK) {
        cnet_accepted_stream_close(accepted);
        if (status == SALTS_ENOBUFS || status == SALTS_ESHUTDOWN) {
            atomic_fetch_add_explicit(&sg->denied, 1u, memory_order_relaxed);
            return P2P_OK; /* No hidden retry onto a different Owner. */
        }
        return p2p_error(status);
    }
    status = cnet_handoff_publish(&sg->inboxes[selected], ticket, accepted);
    if (status != SALTS_OK) {
        if (accepted->internal_active) cnet_accepted_stream_close(accepted);
        if (cnet_handoff_release(&sg->inboxes[selected], ticket) != SALTS_OK)
            return P2P_ERR_INVALID_STATE;
        if (status == SALTS_ENOBUFS || status == SALTS_ESHUTDOWN) {
            atomic_fetch_add_explicit(&sg->denied, 1u, memory_order_relaxed);
            return P2P_OK;
        }
        return p2p_error(status);
    }
    atomic_fetch_add_explicit(&sg->routed, 1u, memory_order_relaxed);
    return P2P_OK; /* Successful publish owns the socket and producer ticket. */
}

/* The final Owner alone takes credits and adopts detached sockets. In stop,
 * seal first and close all queued streams, releasing tickets after close. */
static int sg_take_owner(p2p_cnet_owner_t *owner, int closing) {
    if (!owner->sg_final) return P2P_OK;
    cnet_handoff *inbox =
        &owner->sg_final->inboxes[owner->sg_final_index];
    size_t progress = 0u;
    while (closing || progress < owner->config.accept_budget) {
        cnet_accepted_stream accepted = CNET_ACCEPTED_STREAM_INIT;
        cnet_handoff_ticket ticket = {0};
        int status = cnet_handoff_take(inbox, &ticket, &accepted);
        if (status == SALTS_ENOENT) return P2P_OK;
        if (status != SALTS_OK) return p2p_error(status);
        ++progress;
        if (closing) {
            status = cnet_accepted_stream_close(&accepted);
            if (status != SALTS_OK) return p2p_error(status);
            status = cnet_handoff_release(inbox, ticket);
            if (status != SALTS_OK) return p2p_error(status);
        } else {
            status = adopt_detached(owner, &accepted, inbox, ticket);
            if (status != P2P_OK && status != P2P_ERR_RESOURCE_EXHAUSTED &&
                status != P2P_ERR_NO_MEM)
                return status;
        }
    }
    return P2P_OK;
}

int p2p_cnet_sg_create_v1(const p2p_cnet_sg_config_v1_t *config,
                           p2p_cnet_sg_t **output) {
    p2p_cnet_sg_t *sg;
    int status;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    if (!config || config->size != sizeof(*config) ||
        config->version != P2P_CNET_SG_VERSION || !config->acceptor ||
        !config->acceptor->listener.impl ||
        config->acceptor->sg_acceptor || config->acceptor->busy ||
        config->acceptor->stopping || config->acceptor->stopped ||
        config->final_owner_count == 0u ||
        config->final_owner_count > P2P_CNET_SG_MAX_OWNERS ||
        !config->queue_capacity || !config->connection_capacity ||
        config->queue_capacity > config->connection_capacity ||
        (config->placement != CNET_OWNER_PLACE_EXPLICIT &&
         config->placement != CNET_OWNER_PLACE_ROUND_ROBIN &&
         config->placement != CNET_OWNER_PLACE_LOWEST_PRESSURE) ||
        (config->placement == CNET_OWNER_PLACE_EXPLICIT &&
         config->explicit_owner >= config->final_owner_count) ||
        (config->placement != CNET_OWNER_PLACE_EXPLICIT && config->explicit_owner))
        return P2P_ERR_INVALID_ARG;
    for (size_t i = 0u; i < config->final_owner_count; ++i) {
        p2p_cnet_owner_t *target = config->final_owners[i];
        if (!target || !target->client.impl || !target->accept || target->busy ||
            target->stopping || target->stopped || target->sg_final ||
            config->connection_capacity > target->config.client.connection_capacity ||
            (target != config->acceptor && target->sg_acceptor))
            return P2P_ERR_INVALID_STATE;
        for (size_t j = 0u; j < i; ++j)
            if (target == config->final_owners[j])
                return P2P_ERR_INVALID_ARG;
    }
    sg = calloc(1u, sizeof(*sg));
    if (!sg) return P2P_ERR_NO_MEM;
    sg->acceptor = config->acceptor;
    sg->owner_count = config->final_owner_count;
    sg->placement = config->placement;
    sg->explicit_owner = config->explicit_owner;
    atomic_init(&sg->sealed, false);
    atomic_init(&sg->routed, 0u);
    atomic_init(&sg->denied, 0u);
    for (size_t i = 0u; i < sg->owner_count; ++i) {
        cnet_handoff_config inbox = {sizeof(inbox), CNET_HANDOFF_VERSION,
                                    config->connection_capacity,
                                    config->queue_capacity};
        status = cnet_handoff_init(&sg->inboxes[i], &inbox);
        if (status != SALTS_OK) {
            for (size_t j = 0u; j < i; ++j)
                cnet_handoff_destroy(&sg->inboxes[j]);
            free(sg);
            return p2p_error(status);
        }
        sg->finals[i] = config->final_owners[i];
    }
    config->acceptor->sg_acceptor = sg;
    for (size_t i = 0u; i < sg->owner_count; ++i) {
        sg->finals[i]->sg_final = sg;
        sg->finals[i]->sg_final_index = i;
    }
    *output = sg;
    return P2P_OK;
}

int p2p_cnet_sg_seal_v1(p2p_cnet_sg_t *sg) {
    if (!sg) return P2P_ERR_INVALID_ARG;
    atomic_store_explicit(&sg->sealed, true, memory_order_release);
    for (size_t i = 0u; i < sg->owner_count; ++i) {
        int status = cnet_handoff_seal(&sg->inboxes[i]);
        if (status != SALTS_OK) return p2p_error(status);
    }
    return P2P_OK;
}

int p2p_cnet_sg_snapshot_v1(p2p_cnet_sg_t *sg, size_t index,
                             p2p_cnet_sg_snapshot_v1_t *output) {
    int status;
    if (!output) return P2P_ERR_INVALID_ARG;
    memset(output, 0, sizeof(*output));
    if (!sg || index >= sg->owner_count) return P2P_ERR_INVALID_ARG;
    status = cnet_handoff_get_snapshot(&sg->inboxes[index], &output->handoff);
    if (status != SALTS_OK) return p2p_error(status);
    output->size = sizeof(*output);
    output->version = P2P_CNET_SG_VERSION;
    output->sealed = atomic_load_explicit(&sg->sealed, memory_order_acquire);
    output->routed = atomic_load_explicit(&sg->routed, memory_order_relaxed);
    output->denied = atomic_load_explicit(&sg->denied, memory_order_relaxed);
    return P2P_OK;
}

int p2p_cnet_sg_destroy_v1(p2p_cnet_sg_t *sg) {
    if (!sg) return P2P_ERR_INVALID_ARG;
    if (!atomic_load_explicit(&sg->sealed, memory_order_acquire) ||
        !sg->acceptor->stopped || sg->acceptor->busy)
        return P2P_ERR_INVALID_STATE;
    for (size_t i = 0u; i < sg->owner_count; ++i) {
        cnet_handoff_snapshot snap = {0};
        if (!sg->finals[i]->stopped || sg->finals[i]->busy ||
            cnet_handoff_get_snapshot(&sg->inboxes[i], &snap) != SALTS_OK ||
            !snap.drained)
            return P2P_ERR_INVALID_STATE;
    }
    for (size_t i = 0u; i < sg->owner_count; ++i)
        if (cnet_handoff_destroy(&sg->inboxes[i]) != SALTS_OK)
            return P2P_ERR_INVALID_STATE;
    sg->acceptor->sg_acceptor = NULL;
    for (size_t i = 0u; i < sg->owner_count; ++i) {
        sg->finals[i]->sg_final = NULL;
        sg->finals[i]->sg_final_index = 0u;
    }
    free(sg);
    return P2P_OK;
}

static int accept_connections(p2p_cnet_owner_t *owner) {
    if (!owner->listener.impl) return P2P_OK;
    for (size_t index = 0u; index < owner->config.accept_budget && !owner->stopping; ++index) {
        cnet_accepted_stream accepted = CNET_ACCEPTED_STREAM_INIT;
        int status = cnet_listener_accept_detached(&owner->listener, &accepted);
        if (status == SALTS_ETIMEDOUT) break;
        if (status != SALTS_OK) return p2p_error(status);
        status = owner->sg_acceptor
            ? sg_route_accepted(owner, &accepted)
            : adopt_detached(owner, &accepted, NULL, (cnet_handoff_ticket){0});
        if (status != P2P_OK) return status;
    }
    return P2P_OK;
}

static void resume_connections(p2p_cnet_owner_t *owner) {
    for (p2p_cnet_connection_t *connection = owner->connections;
         connection; connection = connection->next) {
        if (active(connection) && !connection->paused && connection->paused_buffer) {
            const uint8_t *bytes = (const uint8_t *)mem_buffer_data(connection->paused_buffer);
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
    result = sg_take_owner(owner, 0);
    if (result == P2P_OK) result = accept_connections(owner);
    resume_connections(owner);
    progress = cnet_client_poll(&owner->client, 0, &events);
    if (progress != SALTS_OK) owner->stopping = 1;
    if (result == P2P_OK) result = p2p_error(progress);
    /* Closing requests rejected by command pressure get another admission
     * attempt after CNet has consumed commands, without nested polling. */
    for (p2p_cnet_connection_t *connection = owner->connections;
         connection; connection = connection->next) try_close(connection);
    owner->busy = 0;
    int retire_result = sweep(owner);
    if (retire_result != P2P_OK) {
        owner->stopping = 1;
        if (result == P2P_OK) result = retire_result;
    }
    if (owner->stopping) {
        int stop_result = p2p_cnet_owner_stop(owner);
        if (result == P2P_OK) result = stop_result;
    }
    return result;
}

/* SG Host owns the only observer on this shard. This transport borrows the
 * backend under the provided immutable Host lease, so there is no private
 * NativeIO poll, hidden actor task, backend allocation or second observe.
 *
 * The API is intentionally one-transport-per-shard. When multiple CNet
 * consumers share a shard the host must advance/route them in ONE combined
 * cnet_sg_host_routes, not invoke this helper once for each consumer. */
int p2p_cnet_owner_poll_sg_host(p2p_cnet_owner_t *owner,
                                native_io_sharded_context *context,
                                native_io_sharded_host_lease lease,
                                size_t *out_observed,
                                size_t *out_sg_settled) {
    size_t count = 0u, routed_events = 0u;
    size_t accepts = 0u, sharded = 0u;
    cnet_sg_host_routes routes = {0};
    cnet_client *clients[1];
    int result = P2P_OK, status;
    if (out_observed) *out_observed = 0u;
    if (out_sg_settled) *out_sg_settled = 0u;
    if (!owner || !context || !out_observed || !out_sg_settled ||
        !owner->external_backend || !owner->host_batch ||
        owner->busy || owner->stopped ||
        lease.version != NATIVE_IO_SHARDED_HOST_VERSION ||
        owner->host_lease.owner_identity != lease.owner_identity ||
        owner->host_lease.owner_shard != lease.owner_shard ||
        owner->host_lease.generation != lease.generation ||
        native_io_sharded_context_shard(context) != (size_t)lease.owner_shard)
        return P2P_ERR_INVALID_STATE;
    owner->busy = 1;

    if (owner->sg_final) {
        result = sg_take_owner(owner, owner->stopping);
        if (result != P2P_OK) goto done;
    }
    resume_connections(owner);
    status = cnet_client_advance_external(&owner->client, &routed_events);
    if (status != SALTS_OK) { result = p2p_error(status); goto done; }

    status = native_io_sharded_context_observe_host(
        context, lease, owner->host_batch,
        owner->config.client.completion_batch_capacity, 0u, &count);
    if (status != SALTS_OK && status != SALTS_ETIMEDOUT) {
        result = p2p_error(status);
        goto done;
    }
    *out_observed = count;
    clients[0] = &owner->client;
    routes.size = sizeof(routes);
    routes.version = CNET_SG_HOST_ROUTING_VERSION;
    routes.listener = owner->listener.impl ? &owner->listener : NULL;
    routes.clients = clients;
    routes.client_count = 1u;
    status = cnet_sg_host_route_batch(owner->host_batch, count, &routes,
                                       &accepts, &sharded);
    *out_sg_settled = sharded;
    if (status != SALTS_OK) { result = p2p_error(status); goto done; }

    if (accepts != 0u && !owner->stopping) {
        result = accept_connections(owner);
        if (result != P2P_OK) goto done;
        if (owner->listener.impl) {
            native_io_request next = {0};
            status = cnet_listener_submit_external_accept(&owner->listener,
                                                           &next);
            if (status != SALTS_OK) {
                result = p2p_error(status);
                goto done;
            }
        }
    }
    status = cnet_client_advance_external(&owner->client, &routed_events);
    if (status != SALTS_OK) { result = p2p_error(status); goto done; }
    resume_connections(owner);
    for (p2p_cnet_connection_t *connection = owner->connections;
         connection; connection = connection->next)
        try_close(connection);
done:
    owner->busy = 0;
    {
        int retire = sweep(owner);
        if (result == P2P_OK) result = retire;
    }
    return result;
}

int p2p_cnet_owner_stop(p2p_cnet_owner_t *owner) {
    int status, destroyed, listener_status, sg_result = P2P_OK;
    if (!owner) return P2P_ERR_INVALID_ARG;
    owner->stopping = 1;
    if (owner->busy || owner->stopped) return P2P_OK;
    owner->busy = 1;
    if (owner->sg_acceptor)
        sg_result = p2p_cnet_sg_seal_v1(owner->sg_acceptor);
    if (owner->sg_final) {
        cnet_handoff *inbox =
            &owner->sg_final->inboxes[owner->sg_final_index];
        int sealed = cnet_handoff_seal(inbox);
        if (sg_result == P2P_OK && sealed != SALTS_OK)
            sg_result = p2p_error(sealed);
        if (sg_result == P2P_OK)
            sg_result = sg_take_owner(owner, 1);
    }
    if (sg_result != P2P_OK) {
        owner->busy = 0;
        return sg_result; /* Retain all owner + inbox state for retry. */
    }
    listener_status = close_listener(owner);
    status = owner->client.impl
        ? (owner->external_backend
            ? cnet_client_stop_external(&owner->client)
            : cnet_client_stop(&owner->client, owner->config.stop_timeout_ms))
        : SALTS_OK;
    /* An external Owner cannot pump its own backend during stop. Retain all
     * callback/scratch/lease storage until the SG Host routes terminal events. */
    destroyed = (status == SALTS_OK || status == SALTS_EALREADY)
        ? cnet_client_destroy(&owner->client) : status;
    if (!owner->client.impl && !owner->listener.impl) owner->stopped = 1;
    owner->busy = 0;
    sg_result = sweep(owner);
    if (listener_status != SALTS_OK) return p2p_error(listener_status);
    if (status != SALTS_OK) return p2p_error(status);
    if (destroyed != SALTS_OK) return p2p_error(destroyed);
    return sg_result;
}

int p2p_cnet_owner_destroy(p2p_cnet_owner_t *owner) {
    int result;
    if (!owner) return P2P_OK;
    if (owner->busy || owner->sg_acceptor || owner->sg_final)
        return P2P_ERR_INVALID_STATE; /* SG retains live owner storage. */
    result = p2p_cnet_owner_stop(owner);
    if (!owner->stopped) return result == P2P_OK ? P2P_ERR_INVALID_STATE : result;
    while (owner->connections) {
        p2p_cnet_connection_t *connection = owner->connections;
        owner->connections = connection->next;
        free_connection(connection);
    }
    free(owner->host_batch);
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
