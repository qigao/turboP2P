# =============================================================================
# Mesh Examples
# =============================================================================

# Mesh demo - P2P mesh networking without TUN device
add_executable(mesh_demo
    mesh_demo.c)

target_link_libraries(mesh_demo
    PRIVATE mesh
    TurboP2P::P2P)

target_compile_definitions(mesh_demo PRIVATE USING_EXAMPLES)

set_target_properties(mesh_demo PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# M3 raft node skeleton (Phase 2b-ii step 1): metadata stack assembly + self-test.
if(TURBOP2P_BUILD_TURBORAFT_M3)
  add_executable(m3_raft_node_main
      m3_raft_node_main.c)
  target_link_libraries(m3_raft_node_main
      PRIVATE m3_raft_node m3_object_manifest)
  target_compile_definitions(m3_raft_node_main PRIVATE TURBO_P2P_M3_RAFT_ENABLED=1)
  set_target_properties(m3_raft_node_main PROPERTIES
      FOLDER "mesh/examples"
      RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()
# M3 store node - data-plane service: authorized PUT/READ + receipts.
add_executable(m3_store_node_main
    m3_store_node_main.c)
target_link_libraries(m3_store_node_main
    PRIVATE m3_store_node m3_chunk_mesh)
set_target_properties(m3_store_node_main PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Live-over-HTTP demo: a producer feeds the sliding-window HLS live playlist
# and a minimal HTTP server serves /live.m3u8 + /live/seg-N.
add_executable(mesh_stream_live_hls_main
    mesh_stream_live_hls_main.c)
target_link_libraries(mesh_stream_live_hls_main
    PRIVATE mesh_stream_live_hls mesh_stream_kcp_adapter mesh_stream_live
            TurboNet::CoroNet TurboUtils::Core)
if(WIN32)
    target_link_libraries(mesh_stream_live_hls_main PRIVATE ws2_32)
endif()
set_target_properties(mesh_stream_live_hls_main PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Live source: produce blocks and send them over KCP to a live HLS relay.
add_executable(mesh_stream_live_source_main
    mesh_stream_live_source_main.c)
target_link_libraries(mesh_stream_live_source_main
    PRIVATE mesh_stream_kcp_adapter mesh_stream_live TurboNet::CoroNet TurboUtils::Core)
if(WIN32)
    target_link_libraries(mesh_stream_live_source_main PRIVATE ws2_32)
endif()
set_target_properties(mesh_stream_live_source_main PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Live failover client: watch a primary live HLS gateway and switch to a
# backup serving the same deterministic session.
add_executable(mesh_stream_live_client_main
    mesh_stream_live_client_main.c)
target_link_libraries(mesh_stream_live_client_main
    PRIVATE TurboNet::CoroNet TurboHttp::HttpClient TurboUtils::Core)
if(WIN32)
    target_link_libraries(mesh_stream_live_client_main PRIVATE ws2_32)
endif()
set_target_properties(mesh_stream_live_client_main PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Mesh-stream media pipeline - publish (manifest + playlists) / range pull.
add_executable(mesh_stream_media_main
    mesh_stream_media_main.c)
target_link_libraries(mesh_stream_media_main
    PRIVATE mesh_stream_media_pull mesh_media_playlist mesh_media_index
            mesh_release m3_object_manifest m3_gateway_sigv4 mesh_mgmt_crypto
            TurboNet::Crypto TurboNet::CoroNet TurboHttp::HttpClient OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(mesh_stream_media_main PRIVATE ws2_32)
endif()
set_target_properties(mesh_stream_media_main PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Mesh-stream cluster node - multi-process discovery + QoS + bandwidth smoke.
add_executable(mesh_stream_node_main
    mesh_stream_node_main.c)
target_link_libraries(mesh_stream_node_main
    PRIVATE mesh_stream_discovery mesh_stream_qos)
set_target_properties(mesh_stream_node_main PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# M3 gateway - Phase 1 single-node S3 gateway over the M3 chunk store.
add_executable(m3_gateway_main
    m3_gateway_main.c)
target_link_libraries(m3_gateway_main
    PRIVATE m3_gateway TurboHttp::Iris)
if(WIN32)
    target_link_libraries(m3_gateway_main PRIVATE ws2_32)
endif()
set_target_properties(m3_gateway_main PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Mesh CLI - minimal developer mesh tool
add_executable(meshctl
    meshctl.c
    mesh_config.c
    mesh_runtime_health.c)

target_link_libraries(meshctl
    PRIVATE mesh
    TurboP2P::P2P
    TurboUtils::Core)

if(WIN32)
    target_link_libraries(meshctl PRIVATE ws2_32)
endif()

target_compile_definitions(meshctl PRIVATE USING_EXAMPLES)

set_target_properties(meshctl PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Mesh VPN - Full P2P VPN with TUN device
add_executable(mesh_vpn
    mesh_vpn.c)

target_link_libraries(mesh_vpn
    PRIVATE mesh tunnel
    TurboP2P::P2P)

target_compile_definitions(mesh_vpn PRIVATE USING_EXAMPLES)

set_target_properties(mesh_vpn PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Meshd - config-driven long-running mesh + tunnel daemon
add_executable(meshd
    meshd.c
    mesh_config.c
    mesh_runtime_health.c)

target_link_libraries(meshd
    PRIVATE mesh tunnel mesh_mgmt_agent_runtime
    mesh_mgmt_execution_rpc_control
    TurboP2P::P2P)

target_compile_definitions(meshd PRIVATE USING_EXAMPLES)

if(TURBO_P2P_ENABLE_NODE_EXECUTION)
    target_sources(meshd PRIVATE meshd_execution_config.c)
    target_link_libraries(meshd PRIVATE mesh_mgmt_execution_node)
    target_compile_definitions(meshd PRIVATE
        TURBO_P2P_ENABLE_NODE_EXECUTION=1)
endif()

set_target_properties(meshd PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
