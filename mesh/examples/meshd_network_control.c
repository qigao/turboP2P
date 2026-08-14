#include "meshd_network_control.h"

#include "mesh_multi_network_internal.h"

#include <flowmq.h>
#include <turbo_crypto.h>
#include <turbo_thread.h>

#include <string.h>

#define MESHD_NETWORK_CONTROL_HOST "127.0.0.1"
#define MESHD_NETWORK_CONTROL_PATH "/mesh-node-control"
#define MESHD_NETWORK_CONTROL_TOPIC "mesh.node.control"

static int bytes_are_zero(const uint8_t *bytes, size_t size) {
    uint8_t combined = 0u;
    size_t index;
    for (index = 0u; index < size; ++index) {
        combined |= bytes[index];
    }
    return combined == 0u;
}

static int transient_result(mesh_control_result_t result) {
    return result == MESH_CONTROL_OK ||
           result == MESH_CONTROL_PROVIDER_UNAVAILABLE ||
           result == MESH_CONTROL_TIMEOUT ||
           result == MESH_CONTROL_RESOURCE_EXHAUSTED;
}

static void set_timeouts(flowmq_coronet_timeout_config_t *timeouts,
                         uint64_t timeout_ms) {
    memset(timeouts, 0, sizeof(*timeouts));
    timeouts->timeout_ms = timeout_ms;
    timeouts->connect_timeout_ms = timeout_ms;
    timeouts->send_timeout_ms = timeout_ms;
    timeouts->recv_timeout_ms = timeout_ms;
    timeouts->handshake_timeout_ms = timeout_ms;
    timeouts->set_flags = FLOWMQ_TIMEOUT_SET_ALL;
    timeouts->explicit_flags = FLOWMQ_TIMEOUT_SET_ALL;
}

int meshd_network_control_init(
    meshd_network_control_t *runtime,
    const meshd_network_control_config_t *config) {
    flowmq_coronet_tls_server_config_t tls;
    flowmq_router_endpoint_config_t endpoint;
    mesh_fabric_config_v2_t fabric_config;
    mesh_network_issuer_v1_t issuer;
    mesh_node_network_control_service_config_v1_t service_config;
    uint8_t expected_mesh_id[MESH_CONTROL_DIGEST_SIZE];
    int result;

    if (!runtime || runtime->initialized || !config || !config->node ||
        !config->underlay ||
        !mesh_node_config_network_control_enabled(config->node) ||
        !flowmq_coronet_tls_is_tls13_only() ||
        bytes_are_zero(config->mesh_id, sizeof(config->mesh_id)) ||
        bytes_are_zero(config->provider_id, sizeof(config->provider_id)) ||
        bytes_are_zero(config->issuer_id, sizeof(config->issuer_id)) ||
        bytes_are_zero(config->issuer_public_key,
                       sizeof(config->issuer_public_key)) ||
        bytes_are_zero(config->sender_incarnation,
                       sizeof(config->sender_incarnation))) {
        return -1;
    }
    memset(expected_mesh_id, 0, sizeof(expected_mesh_id));
    if (!config->underlay->network_id ||
        turbo_crypto_sha256(config->underlay->network_id,
                            strlen(config->underlay->network_id),
                            expected_mesh_id) != TURBO_CRYPTO_OK ||
        memcmp(expected_mesh_id, config->mesh_id,
               sizeof(expected_mesh_id)) != 0) {
        memset(expected_mesh_id, 0, sizeof(expected_mesh_id));
        return -1;
    }
    memset(expected_mesh_id, 0, sizeof(expected_mesh_id));

    memset(&issuer, 0, sizeof(issuer));
    memcpy(issuer.key_id, config->issuer_id, sizeof(issuer.key_id));
    memcpy(issuer.public_key, config->issuer_public_key,
           sizeof(issuer.public_key));
    mesh_fabric_config_init_v2(&fabric_config);
    fabric_config.underlay = *config->underlay;
    fabric_config.trusted_issuers = &issuer;
    fabric_config.trusted_issuer_count = 1u;
    fabric_config.max_networks = config->node->network_control_network_capacity;

    memset(runtime, 0, sizeof(*runtime));
    result = mesh_fabric_create_v2(&fabric_config, &runtime->fabric);
    if (result != MESH_OK) {
        memset(&issuer, 0, sizeof(issuer));
        return -1;
    }
    runtime->underlay = mesh_internal_fabric_underlay_v2(runtime->fabric);
    if (!runtime->underlay) {
        mesh_fabric_destroy_v2(runtime->fabric);
        memset(runtime, 0, sizeof(*runtime));
        memset(&issuer, 0, sizeof(issuer));
        return -1;
    }

    memset(&tls, 0, sizeof(tls));
    tls.ca_file = config->node->network_control_client_ca_file;
    tls.cert_file = config->node->network_control_certificate_file;
    tls.key_file = config->node->network_control_private_key_file;
    tls.require_client_certificate = 1;
    flowmq_router_endpoint_config_init(&endpoint);
    endpoint.transport = FLOWMQ_TRANSPORT_TLS;
    endpoint.host = MESHD_NETWORK_CONTROL_HOST;
    endpoint.path = MESHD_NETWORK_CONTROL_PATH;
    endpoint.topic = MESHD_NETWORK_CONTROL_TOPIC;
    endpoint.identity = config->node->network_control_identity;
    endpoint.tls = &tls;
    endpoint.port = config->node->network_control_port;
    endpoint.max_frame_size = MESH_NODE_IPC_FLOWMQ_MAX_FRAME_SIZE_V1;
    endpoint.max_connections = 1u;
    endpoint.heartbeat_interval_ms =
        config->node->network_control_heartbeat_interval_ms;
    endpoint.heartbeat_timeout_ms =
        config->node->network_control_heartbeat_timeout_ms;
    set_timeouts(&endpoint.timeouts,
                 config->node->network_control_io_timeout_ms);

    memset(&service_config, 0, sizeof(service_config));
    service_config.fabric = runtime->fabric;
    service_config.bind_endpoint = &endpoint;
    service_config.expected_peer_identity =
        config->node->network_control_expected_peer_identity;
    service_config.expected_peer_certificate_sha256 =
        config->node->network_control_expected_peer_certificate_sha256;
    service_config.expected_peer_certificate_sha256_next =
        config->node->network_control_expected_peer_certificate_sha256_next;
    service_config.identity_policy_generation =
        config->node->network_control_identity_policy_generation;
    memcpy(service_config.mesh_id, config->mesh_id,
           sizeof(service_config.mesh_id));
    memcpy(service_config.provider_id, config->provider_id,
           sizeof(service_config.provider_id));
    memcpy(service_config.sender_incarnation, config->sender_incarnation,
           sizeof(service_config.sender_incarnation));
    service_config.network_capacity =
        config->node->network_control_network_capacity;
    service_config.operation_capacity =
        config->node->network_control_operation_capacity;
    service_config.channel_capacity =
        config->node->network_control_channel_capacity;
    service_config.channel_max_retained_bytes =
        config->node->network_control_channel_max_retained_bytes;
    service_config.command_budget =
        config->node->network_control_command_budget;
    service_config.send_budget = config->node->network_control_send_budget;
    service_config.delete_drain_timeout_ms =
        config->node->network_control_delete_drain_timeout_ms;
    service_config.shutdown_drain_timeout_ms =
        config->node->network_control_shutdown_drain_timeout_ms;
    if (mesh_node_network_control_service_init_v1(
            &runtime->service, &service_config) != MESH_CONTROL_OK) {
        mesh_fabric_destroy_v2(runtime->fabric);
        memset(runtime, 0, sizeof(*runtime));
        memset(&issuer, 0, sizeof(issuer));
        return -1;
    }
    runtime->initialized = 1u;
    memset(&issuer, 0, sizeof(issuer));
    return 0;
}

mesh_network_t *meshd_network_control_borrow_underlay(
    meshd_network_control_t *runtime) {
    return runtime && runtime->initialized ? runtime->underlay : NULL;
}

int meshd_network_control_start(meshd_network_control_t *runtime) {
    if (!runtime || !runtime->initialized || runtime->started) {
        return -1;
    }
    if (mesh_fabric_start_v2(runtime->fabric) != MESH_OK) {
        return -1;
    }
    if (mesh_node_network_control_service_start_v1(&runtime->service) !=
        MESH_CONTROL_OK) {
        mesh_fabric_stop_v2(runtime->fabric);
        return -1;
    }
    runtime->started = 1u;
    return 0;
}

int meshd_network_control_poll(meshd_network_control_t *runtime,
                               int timeout_ms) {
    size_t processed = 0u;
    size_t sent = 0u;
    mesh_control_result_t result;
    if (!runtime || !runtime->initialized || !runtime->started ||
        timeout_ms < 0) {
        return -1;
    }
    if (mesh_fabric_poll_v2(runtime->fabric, timeout_ms) != MESH_OK) {
        return -1;
    }
    result = mesh_node_network_control_service_poll_v1(
        &runtime->service, &processed, &sent);
    return transient_result(result) ? 0 : -1;
}

int meshd_network_control_shutdown(meshd_network_control_t *runtime,
                                   size_t *out_abandoned_operations) {
    uint64_t deadline;
    mesh_control_result_t result;
    int abandoned = 0;
    if (!runtime || !out_abandoned_operations || !runtime->initialized) {
        return -1;
    }
    *out_abandoned_operations = 0u;
    if (!runtime->started) {
        return 0;
    }
    if (mesh_node_network_control_service_begin_drain_v1(
            &runtime->service) != MESH_CONTROL_OK) {
        return -1;
    }
    deadline = turbo_monotonic_ms() +
               runtime->service.shutdown_drain_timeout_ms;
    for (;;) {
        size_t processed = 0u;
        size_t sent = 0u;
        result = mesh_node_network_control_service_stop_v1(&runtime->service);
        if (result == MESH_CONTROL_OK) {
            break;
        }
        if (result != MESH_CONTROL_RESOURCE_EXHAUSTED ||
            turbo_monotonic_ms() >= deadline) {
            if (result != MESH_CONTROL_RESOURCE_EXHAUSTED) {
                return -1;
            }
            result = mesh_node_network_control_service_abort_v1(
                &runtime->service, out_abandoned_operations);
            if (result != MESH_CONTROL_OK) {
                return -1;
            }
            abandoned = 1;
            break;
        }
        result = mesh_node_network_control_service_poll_v1(
            &runtime->service, &processed, &sent);
        if (!transient_result(result)) {
            return -1;
        }
        turbo_sleep_ms(1u);
    }
    if (mesh_node_network_control_service_destroy_v1(&runtime->service) !=
        MESH_CONTROL_OK) {
        return -1;
    }
    mesh_fabric_stop_v2(runtime->fabric);
    runtime->started = 0u;
    return abandoned;
}

void meshd_network_control_destroy(meshd_network_control_t *runtime) {
    size_t abandoned_operations = 0u;
    if (!runtime) {
        return;
    }
    if (runtime->service.lifecycle == MESH_NODE_NETWORK_CONTROL_RUNNING_V1) {
        if (mesh_node_network_control_service_begin_drain_v1(
                &runtime->service) != MESH_CONTROL_OK) {
            return;
        }
    }
    if (runtime->service.lifecycle == MESH_NODE_NETWORK_CONTROL_DRAINING_V1 ||
        runtime->service.lifecycle == MESH_NODE_NETWORK_CONTROL_ABORTING_V1) {
        if (mesh_node_network_control_service_abort_v1(
                &runtime->service, &abandoned_operations) != MESH_CONTROL_OK) {
            return;
        }
    }
    if (runtime->service.lifecycle == MESH_NODE_NETWORK_CONTROL_READY_V1 ||
        runtime->service.lifecycle == MESH_NODE_NETWORK_CONTROL_STOPPED_V1) {
        if (mesh_node_network_control_service_destroy_v1(&runtime->service) !=
            MESH_CONTROL_OK) {
            return;
        }
    }
    if (runtime->fabric) {
        mesh_fabric_destroy_v2(runtime->fabric);
    }
    memset(runtime, 0, sizeof(*runtime));
}
