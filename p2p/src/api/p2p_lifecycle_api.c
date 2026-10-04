#include "p2p.h"
#include "../core/node_state.h"
#include "../core/node_cnet.h"
#include "../security/p2p_private_key_executor.h"
#include <stdlib.h>
#include <string.h>

struct p2p_runtime_v2_s {
    p2p_node_cnet_t *owner;
    int terminal;
    int in_api;
    int bound;
};

int p2p_runtime_config_v2_init(p2p_runtime_config_v2_t *config) {
    enum { CONNECTIONS = 128, QUEUE_SLOTS = 256, REQUESTS = 512,
        COMPLETION_BATCH = 64, RECEIVE_BYTES = 64 * 1024, PENDING_WRITES = 8,
        ACCEPT_BUDGET = 16, BUFFER_BYTES = 8 * 1024 * 1024, TIMEOUT_MS = 5000 };
    if (!config) return P2P_ERR_INVALID_ARG;
    memset(config, 0, sizeof(*config));
    config->struct_size = sizeof(*config);
    config->connection_capacity = CONNECTIONS;
    config->command_capacity = config->event_capacity = QUEUE_SLOTS;
    config->request_capacity = REQUESTS;
    config->completion_batch_capacity = COMPLETION_BATCH;
    config->send_hwm_bytes = P2P_SECURITY_SEND_HWM_DEFAULT_BYTES;
    config->receive_buffer_bytes = RECEIVE_BYTES;
    config->pending_write_limit = PENDING_WRITES;
    config->accept_budget = ACCEPT_BUDGET;
    config->command_buffer_bytes = config->event_buffer_bytes = BUFFER_BYTES;
    config->connect_timeout_ms = config->write_timeout_ms = config->stop_timeout_ms = TIMEOUT_MS;
    return P2P_OK;
}

int p2p_create_v2(const char *ip, int port, p2p_node_t **output) {
    struct p2p_runtime_v2_s *runtime;
    int result;
    if (!output) return P2P_ERR_INVALID_ARG;
    *output = NULL;
    runtime = calloc(1, sizeof(*runtime));
    if (!runtime) return P2P_ERR_NO_MEM;
    result = p2p_node_state_create_checked(ip, port, output);
    if (result != P2P_OK) { free(runtime); return result; }
    (*output)->runtime_v2 = runtime;
    return P2P_OK;
}

static void transport_config(const p2p_runtime_config_v2_t *config,
    p2p_cnet_config_t *transport) {
    memset(transport, 0, sizeof(*transport));
#ifdef _WIN32
    transport->client.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
    transport->client.backend = NATIVE_IO_BACKEND_EPOLL;
#else
    transport->client.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
    transport->client.connection_capacity = config->connection_capacity;
    transport->client.command_capacity = config->command_capacity;
    transport->client.request_capacity = config->request_capacity;
    transport->client.completion_batch_capacity = config->completion_batch_capacity;
    transport->client.event_capacity = config->event_capacity;
    transport->client.max_send_bytes = config->send_hwm_bytes;
    transport->client.receive_buffer_bytes = config->receive_buffer_bytes;
    transport->client.connect_timeout_ms = config->connect_timeout_ms;
    transport->client.write_timeout_ms = config->write_timeout_ms;
    transport->client.command_buffer_bytes = config->command_buffer_bytes;
    transport->client.event_buffer_bytes = config->event_buffer_bytes;
    transport->send_hwm_bytes = config->send_hwm_bytes;
    transport->pending_write_limit = config->pending_write_limit;
    transport->accept_budget = config->accept_budget;
    transport->stop_timeout_ms = config->stop_timeout_ms;
}

int p2p_start_nonblocking_v2(p2p_node_t *node, const p2p_runtime_config_v2_t *config) {
    struct p2p_runtime_v2_s *runtime;
    p2p_cnet_config_t transport;
    int result;
    if (!node || !config || config->struct_size != sizeof(*config)) return P2P_ERR_INVALID_ARG;
    runtime = node->runtime_v2;
    if (!runtime || runtime->in_api || runtime->terminal || runtime->owner)
        return P2P_ERR_INVALID_STATE;
    runtime->in_api = 1;
    transport_config(config, &transport);
    result = p2p_node_cnet_create(node, &transport, &runtime->owner);
    if (result == P2P_OK) {
        result = p2p_node_cnet_listen(runtime->owner);
        if (result != P2P_OK) {
            int stopped;
            runtime->terminal = 1;
            stopped = p2p_node_cnet_stop(runtime->owner);
            if (stopped != P2P_OK) result = stopped;
        } else {
            runtime->bound = 1;
            p2p_gossip_start(node);
        }
    }
    runtime->in_api = 0;
    return result;
}

int p2p_node_get_listen_address_v2(const p2p_node_t *node,
    char *ip, size_t capacity, int *port) {
    size_t length;
    if (!node || !ip || !capacity || !port) return P2P_ERR_INVALID_ARG;
    if (!node->runtime_v2 || !node->runtime_v2->bound) return P2P_ERR_INVALID_STATE;
    length = strlen(node->ip);
    if (capacity <= length) return P2P_ERR_RESOURCE_EXHAUSTED;
    memcpy(ip, node->ip, length + 1);
    *port = node->port;
    return P2P_OK;
}

int p2p_stop_v2(p2p_node_t *node) {
    struct p2p_runtime_v2_s *runtime;
    int result;
    if (!node) return P2P_ERR_INVALID_ARG;
    runtime = node->runtime_v2;
    if (!runtime || runtime->in_api) return P2P_ERR_INVALID_STATE;
    runtime->in_api = 1;
    runtime->terminal = 1;
    if (runtime->owner) result = p2p_node_cnet_stop(runtime->owner);
    else {
        p2p_private_key_executor_shutdown(node->private_key_executor);
        result = p2p_node_cleanup_transfers(node);
    }
    runtime->in_api = 0;
    return result;
}

int p2p_destroy_v2(p2p_node_t *node) {
    struct p2p_runtime_v2_s *runtime;
    int result;
    if (!node) return P2P_OK;
    runtime = node->runtime_v2;
    if (!runtime || runtime->in_api) return P2P_ERR_INVALID_STATE;
    runtime->in_api = 1;
    result = p2p_node_cnet_destroy(runtime->owner);
    if (result != P2P_OK) { runtime->in_api = 0; return result; }
    runtime->owner = NULL;
    runtime->terminal = 1;
    /* The runtime remains owned until the final state destructor succeeds. */
    node->runtime_v2 = NULL;
    result = p2p_node_state_destroy(node);
    if (result != P2P_OK) {
        node->runtime_v2 = runtime;
        runtime->in_api = 0;
        return result;
    }
    free(runtime);
    return P2P_OK;
}
