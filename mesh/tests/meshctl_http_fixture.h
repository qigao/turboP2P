#ifndef MESHCTL_HTTP_FIXTURE_H
#define MESHCTL_HTTP_FIXTURE_H

#include "meshctl_rpc_http.h"
#include <http_server/http.h>

static chttp_server_config meshctl_test_http_server_config(void) {
    chttp_server_config config = {0};
    config.host = "127.0.0.1";
#if defined(_WIN32)
    config.network.backend = NATIVE_IO_BACKEND_IOCP;
#elif defined(__linux__)
    config.network.backend = NATIVE_IO_BACKEND_EPOLL;
#else
    config.network.backend = NATIVE_IO_BACKEND_KQUEUE;
#endif
    config.backlog = 8u;
    config.network.connection_capacity = 2u;
    config.network.command_capacity = 8u;
    config.network.request_capacity = 8u;
    config.network.completion_batch_capacity = 8u;
    config.network.event_capacity = 8u;
    config.network.max_send_bytes = MESHD_CTL_RPC_MAX_RESPONSE_SIZE + 65536u;
    config.network.receive_buffer_bytes = 4096u;
    config.network.connect_timeout_ms = 10000u;
    config.network.read_timeout_ms = 10000u;
    config.network.write_timeout_ms = 10000u;
    config.route_capacity = 8u;
    config.middleware_capacity = 1u;
    config.max_route_middleware_count = 1u;
    config.max_route_param_count = 1u;
    config.max_route_param_bytes = 128u;
    config.max_target_bytes = 512u;
    config.max_header_count = 16u;
    config.max_header_bytes = 1024u;
    config.max_request_body_bytes = 1u;
    config.max_response_header_count = 16u;
    config.max_response_header_bytes = MESHD_CTL_RPC_MAX_HEADER_SIZE + 1024u;
    config.max_response_body_bytes = MESHD_CTL_RPC_MAX_RESPONSE_SIZE + 1u;
    config.poll_slice_ms = 2u;
    return config;
}

#endif
