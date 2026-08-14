# =============================================================================
# Mesh Tests
# =============================================================================

enable_testing()

set(MESH_TEST_SOURCES
    test_mesh.c
    test_mesh_multi_network.c
    test_mesh_faults.c
    test_mesh_multihop.c
    test_mesh_paths.c
    test_mesh_mgmt_codec.c
    test_mesh_mgmt_crypto.c
    test_mesh_mgmt_envelope.c
    test_mesh_mgmt_replay.c
    test_mesh_mgmt_execution.c
    test_mesh_control_primitives.c
    test_mesh_control_outbox.c
    test_mesh_control_durable_outbox.c
    test_mesh_control_durable_outbox_worker.c
    test_mesh_control_agent_sync.c
    test_mesh_control_controller_session.c
    test_mesh_control_controller_identity.c
    test_mesh_control_controller_runtime.c
    test_mesh_control_agent_controller_e2e.c
    test_mesh_control_agent_service.c
    test_mesh_control_agent_runtime.c
    test_mesh_certificate_lifecycle.c
    test_mesh_control_channel.c
    test_mesh_node_ipc.c
    test_mesh_control_mmp.c
    test_mesh_control_document.c
    test_mesh_network_reconciler.c
    test_mesh_control_iris.c
    test_mesh_control_state.c
    test_mesh_control_status.c
    test_mesh_control_policy.c
    test_mesh_control_reconciler.c
    test_mesh_control_owner.c
    test_mesh_control_checkpoint.c
    test_mesh_control_checkpoint_store.c
    test_mesh_control_wal.c
    test_mesh_control_wal_worker.c
    test_mesh_control_agent.c
    test_meshctl_product.c
    test_mesh_product_controller_iris.c
    test_mesh_mgmt_execution_store.c
    test_m3_namespace_local_store.c

    test_m3_gateway_sigv4.c
    test_m3_object_manifest_v2.c
    test_m3_chunk_receipt.c
    test_m3_store_node.c
    test_m3_chunk_mesh.c
    test_m3_gc.c
    test_mesh_stream_data.c
    test_mesh_stream_source_selector.c
    test_mesh_sync_engine.c
    test_mesh_media_index.c
    test_mesh_stream_live.c
    test_mesh_stream_cluster.c
    test_mesh_stream_kcp.c
    test_mesh_stream_media_pull.c
    test_mesh_stream_media_pull_multisource.c
    test_mesh_media_playlist.c
    test_mesh_release.c
    test_mesh_stream_live_hls.c
    test_mesh_flow_ruleset.c
    test_mesh_flow_runtime.c
    test_mesh_flow_ruleset_raft.c
    test_mesh_task_lease.c
    test_mesh_task_lease_raft.c
    test_mesh_task_execution_guard.c
    test_mesh_mgmt_execution_result.c
    test_mesh_mgmt_execution_wire.c
    test_mesh_mgmt_session.c
    test_mesh_mgmt_peer_signer.c
    test_mesh_mgmt_transport.c
    test_mesh_mgmt_p2p_security.c
    test_mesh_mgmt_p2p_adapter.c
    test_mesh_mgmt_endpoint_pool.c
    test_mesh_mgmt_endpoint_record.c
    test_mesh_mgmt_service_record.c
    test_mesh_mgmt_coronet_transport.c
    test_mesh_stream_codec.c
    test_mesh_stream_bind.c
    test_mesh_stream_mgmt_ticket.c
    test_mesh_stream_session.c
    test_mesh_stream_transport.c
    test_mesh_stream_channel.c
    test_mesh_stream_registry.c
    test_mesh_stream_coronet.c
    test_meshctl_rpc.c
    test_meshd_key_file.c
    test_mesh_mgmt_execution_rpc_registry.c
    test_mesh_mgmt_execution_rpc_control.c
    test_mesh_mgmt_execution_disabled_responder.c
    test_meshd_runtime.c)

if(TURBOP2P_ENABLE_FLOWMQ_IPC)
    list(APPEND MESH_TEST_SOURCES test_mesh_node_ipc_flowmq.c)
endif()

if(TURBO_P2P_ENABLE_NODE_EXECUTION)
    set(MESH_MGMT_EXECUTION_TEST_WASM
        "${CMAKE_CURRENT_BINARY_DIR}/mesh_mgmt_execution_test_guest.wasm")
    turbo_add_wasm_application(mesh_mgmt_execution_test_guest
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/data/execution_guest.c
        MAX_MEMORY 262144
        OUTPUT ${MESH_MGMT_EXECUTION_TEST_WASM}
        NO_CHECK)
    set(MESH_MGMT_EXECUTION_TEST_SUCCESS_WASM
        "${CMAKE_CURRENT_BINARY_DIR}/mesh_mgmt_execution_test_success_guest.wasm")
    turbo_add_wasm_application(mesh_mgmt_execution_test_success_guest
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/data/execution_success_guest.c
        MAX_MEMORY 262144
        OUTPUT ${MESH_MGMT_EXECUTION_TEST_SUCCESS_WASM}
        NO_CHECK)
    add_executable(mesh_native_test_worker
        mesh_native_test_worker_main.c)
    set_target_properties(mesh_native_test_worker PROPERTIES
        FOLDER "mesh/tests"
        RUNTIME_OUTPUT_DIRECTORY
            "${CMAKE_BINARY_DIR}/node-execution-test-bin")
    list(APPEND MESH_TEST_SOURCES
        test_mesh_mgmt_execution_runner.c
        test_mesh_mgmt_execution_process.c
        test_mesh_control_execution_provider.c
        test_mesh_mgmt_execution_orchestrator.c
        test_mesh_mgmt_execution_node.c
        test_meshd_execution_config.c)
endif()

if(TURBOP2P_BUILD_TURBORAFT_M3)
  list(APPEND MESH_TEST_SOURCES test_m3_namespace_raft_adapter.c)
  list(APPEND MESH_TEST_SOURCES test_m3_gateway_raft.c)
  list(APPEND MESH_TEST_SOURCES test_m3_raft_cluster.c)
  list(APPEND MESH_TEST_SOURCES test_m3_raft_wirecodec.c)
  list(APPEND MESH_TEST_SOURCES test_m3_raft_coronet_transport.c)
  list(APPEND MESH_TEST_SOURCES test_m3_raft_tls_handshake.c)
  list(APPEND MESH_TEST_SOURCES test_m3_raft_coronet_session.c)
  list(APPEND MESH_TEST_SOURCES test_m3_raft_coronet_node.c)
  list(APPEND MESH_TEST_SOURCES test_m3_gateway_raft_node.c)
  list(APPEND MESH_TEST_SOURCES test_m3_gateway_http.c)
  list(APPEND MESH_TEST_SOURCES test_m3_gateway_datapane.c)
  list(APPEND MESH_TEST_SOURCES test_m3_repair.c)
  list(APPEND MESH_TEST_SOURCES test_mesh_task_lease_raft_adapter.c)
  list(APPEND MESH_TEST_SOURCES test_mesh_flow_ruleset_raft_adapter.c)
  list(APPEND MESH_TEST_SOURCES test_mesh_control_raft.c)
  list(APPEND MESH_TEST_SOURCES test_mesh_control_raft_service.c)
endif()

foreach(test_source ${MESH_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)

    add_executable(${test_name} ${test_source})

    target_include_directories(${test_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                ${CMAKE_CURRENT_SOURCE_DIR}/../src
                ${CMAKE_CURRENT_SOURCE_DIR}/../examples)

    set(extra_test_libs)
    if(test_name STREQUAL "test_mesh")
        list(APPEND extra_test_libs TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_multi_network")
        list(APPEND extra_test_libs TurboNet::Crypto TurboP2P::P2P)
    endif()
    if(test_name STREQUAL "test_mesh_network_reconciler")
        list(APPEND extra_test_libs mesh_network_reconciler
            mesh_node_ipc_network_executor
            TurboNet::Crypto TurboP2P::P2P)
    endif()
    if(test_name STREQUAL "test_mesh_node_ipc_flowmq")
        target_sources(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_config.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/meshd_network_control.c)
        list(APPEND extra_test_libs mesh_node_ipc_flowmq
            mesh_node_control_runtime mesh_node_control_client_runtime
            mesh_node_control_flowmq_provider
            mesh_node_control_flowmq_network_provider
            mesh_node_network_control_service
            TurboNet::Crypto TurboP2P::P2P)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_FLOWMQ_CA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/ca.pem"
            MESH_TEST_FLOWMQ_SERVER_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-current-cert.pem"
            MESH_TEST_FLOWMQ_SERVER_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-current-key.pem"
            MESH_TEST_FLOWMQ_SERVER_NEXT_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-next-cert.pem"
            MESH_TEST_FLOWMQ_SERVER_NEXT_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-next-key.pem"
            MESH_TEST_FLOWMQ_SERVER_CLIENT_AUTH_ONLY_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-client-auth-only-cert.pem"
            MESH_TEST_FLOWMQ_SERVER_CLIENT_AUTH_ONLY_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-client-auth-only-key.pem"
            MESH_TEST_FLOWMQ_CLIENT_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/client-current-cert.pem"
            MESH_TEST_FLOWMQ_CLIENT_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/client-current-key.pem"
            MESH_TEST_FLOWMQ_CLIENT_NEXT_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/client-next-cert.pem"
            MESH_TEST_FLOWMQ_CLIENT_NEXT_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/client-next-key.pem")
        if(WIN32)
            list(APPEND extra_test_libs ws2_32)
        endif()
    endif()
    if(test_name STREQUAL "test_meshd_runtime")
        target_sources(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_config.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_runtime_health.c)
        list(APPEND extra_test_libs tunnel mesh_mgmt_agent_runtime
            meshd_key_file TurboP2P::P2P)
        if(TURBO_P2P_ENABLE_NODE_EXECUTION)
            target_sources(${test_name} PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/../examples/meshd_execution_config.c)
            list(APPEND extra_test_libs mesh_mgmt_execution_node)
            target_compile_definitions(${test_name} PRIVATE
                TURBO_P2P_ENABLE_NODE_EXECUTION=1)
        endif()
    endif()
    if(test_name STREQUAL "test_meshd_key_file")
        list(APPEND extra_test_libs meshd_key_file)
        if(WIN32)
            list(APPEND extra_test_libs advapi32)
        endif()
    endif()
    if(test_name STREQUAL "test_meshctl_rpc")
        target_sources(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_config.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_runtime_health.c)
        list(APPEND extra_test_libs TurboP2P::P2P TurboHttp::TurboHttp)
        if(WIN32)
            list(APPEND extra_test_libs ws2_32)
        endif()
    endif()
    if(test_name STREQUAL "test_meshctl_product")
        list(APPEND extra_test_libs meshctl_product)
    endif()
    if(test_name STREQUAL "test_mesh_product_controller_iris")
        list(APPEND extra_test_libs mesh_product_controller_iris)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_codec")
        list(APPEND extra_test_libs mesh_mgmt_codec)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_crypto")
        list(APPEND extra_test_libs mesh_mgmt_crypto)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_envelope")
        list(APPEND extra_test_libs mesh_mgmt_envelope)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_replay")
        list(APPEND extra_test_libs mesh_mgmt_replay)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution")
        list(APPEND extra_test_libs mesh_mgmt_execution)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution_store")
        list(APPEND extra_test_libs mesh_mgmt_execution_store)
    endif()
    if(test_name STREQUAL "test_m3_namespace_local_store")
        list(APPEND extra_test_libs m3_namespace_local_store)
    endif()
    if(test_name STREQUAL "test_m3_object_manifest_v2")
        list(APPEND extra_test_libs m3_object_manifest OpenSSL::Crypto)
    endif()
    if(test_name STREQUAL "test_m3_chunk_receipt")
        list(APPEND extra_test_libs m3_chunk_receipt)
    endif()
    if(test_name STREQUAL "test_m3_store_node")
        list(APPEND extra_test_libs m3_store_node)
    endif()
    if(test_name STREQUAL "test_m3_chunk_mesh")
        list(APPEND extra_test_libs m3_chunk_mesh m3_store_node TurboP2P::P2P)
    endif()
    if(test_name STREQUAL "test_m3_gc")
        list(APPEND extra_test_libs m3_store_node)
    endif()
    if(test_name STREQUAL "test_mesh_stream_data")
        list(APPEND extra_test_libs mesh_stream_data)
    endif()
    if(test_name STREQUAL "test_mesh_stream_source_selector")
        list(APPEND extra_test_libs mesh_stream_multisource mesh_stream_source_selector TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_sync_engine")
        list(APPEND extra_test_libs mesh_sync_engine m3_object_manifest TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_media_index")
        list(APPEND extra_test_libs mesh_media_index m3_object_manifest TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_stream_live")
        list(APPEND extra_test_libs mesh_stream_live)
    endif()
    if(test_name STREQUAL "test_mesh_stream_cluster")
        list(APPEND extra_test_libs mesh_stream_discovery mesh_stream_qos mesh_mgmt_service_record mesh_flow_ruleset)
    endif()
    if(test_name STREQUAL "test_mesh_stream_kcp")
        list(APPEND extra_test_libs mesh_stream_kcp_adapter mesh_stream_live TurboNet::CoroNet)
        if(WIN32)
            list(APPEND extra_test_libs ws2_32)
        endif()
    endif()
    if(test_name STREQUAL "test_mesh_stream_media_pull")
        list(APPEND extra_test_libs mesh_stream_media_pull mesh_media_index m3_object_manifest TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_stream_media_pull_multisource")
        list(APPEND extra_test_libs mesh_stream_media_pull_multisource mesh_stream_media_pull mesh_stream_multisource mesh_media_index m3_object_manifest TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_media_playlist")
        list(APPEND extra_test_libs mesh_media_playlist mesh_media_index m3_object_manifest TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_release")
        list(APPEND extra_test_libs mesh_release m3_object_manifest TurboNet::Crypto)
    endif()
    if(test_name STREQUAL "test_mesh_stream_live_hls")
        list(APPEND extra_test_libs mesh_stream_live_hls mesh_stream_live)
    endif()
    if(test_name STREQUAL "test_m3_repair")
        list(APPEND extra_test_libs m3_repair m3_namespace_raft_adapter m3_object_manifest m3_store_node)
    endif()
    if(test_name STREQUAL "test_m3_gateway_sigv4")
        list(APPEND extra_test_libs m3_gateway_sigv4)
    elseif(test_name STREQUAL "test_mesh_flow_ruleset")
        list(APPEND extra_test_libs mesh_flow_ruleset)
    elseif(test_name STREQUAL "test_mesh_flow_runtime")
        list(APPEND extra_test_libs mesh_flow_ruleset)
    elseif(test_name STREQUAL "test_mesh_flow_ruleset_raft")
        list(APPEND extra_test_libs mesh_flow_ruleset_raft)
    elseif(test_name STREQUAL "test_mesh_task_lease")
        list(APPEND extra_test_libs mesh_task_lease)
    elseif(test_name STREQUAL "test_mesh_task_lease_raft")
        list(APPEND extra_test_libs mesh_task_lease_raft)
    elseif(test_name STREQUAL "test_mesh_task_execution_guard")
        list(APPEND extra_test_libs mesh_task_execution_guard)
    elseif(test_name STREQUAL "test_m3_namespace_raft_adapter")
        list(APPEND extra_test_libs m3_namespace_raft_adapter)
    elseif(test_name STREQUAL "test_m3_gateway_raft")
        list(APPEND extra_test_libs m3_gateway_raft m3_object_manifest)
    elseif(test_name STREQUAL "test_m3_raft_cluster")
        list(APPEND extra_test_libs m3_namespace_raft_adapter m3_object_manifest TurboRaft::SQLiteStorage)
    elseif(test_name STREQUAL "test_m3_raft_wirecodec")
        list(APPEND extra_test_libs m3_namespace_raft_adapter m3_object_manifest TurboRaft::SQLiteStorage TurboRaft::Core)
    elseif(test_name STREQUAL "test_m3_raft_coronet_transport")
        list(APPEND extra_test_libs TurboRaft::CoroNet TurboRaft::Core)
    elseif(test_name STREQUAL "test_m3_raft_coronet_session")
        list(APPEND extra_test_libs TurboRaft::CoroNet TurboRaft::Core)
    elseif(test_name STREQUAL "test_m3_raft_coronet_node")
        list(APPEND extra_test_libs m3_raft_node m3_object_manifest)
        target_compile_definitions(${test_name} PRIVATE
            M3_TEST_TLS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/m3tls")
    elseif(test_name STREQUAL "test_m3_gateway_raft_node")
        list(APPEND extra_test_libs m3_gateway m3_raft_node m3_object_manifest)
        target_compile_definitions(${test_name} PRIVATE
            M3_TEST_TLS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/m3tls")
    elseif(test_name STREQUAL "test_m3_gateway_http")
        list(APPEND extra_test_libs m3_gateway m3_raft_node m3_object_manifest TurboHttp::Iris TurboHttp::HttpClient)
        target_compile_definitions(${test_name} PRIVATE
            M3_TEST_TLS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/m3tls")
    elseif(test_name STREQUAL "test_m3_gateway_datapane")
        list(APPEND extra_test_libs m3_gateway m3_raft_node m3_object_manifest m3_store_node)
        target_compile_definitions(${test_name} PRIVATE
            M3_TEST_TLS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/m3tls")
    elseif(test_name STREQUAL "test_m3_raft_tls_handshake")
        list(APPEND extra_test_libs TurboRaft::CoroNet TurboRaft::Core TurboNet::CoroNet)
        target_compile_definitions(${test_name} PRIVATE
            M3_TEST_TLS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/m3tls")
    elseif(test_name STREQUAL "test_mesh_task_lease_raft_adapter")
        list(APPEND extra_test_libs mesh_task_lease_raft_adapter)
    elseif(test_name STREQUAL "test_mesh_flow_ruleset_raft_adapter")
        list(APPEND extra_test_libs mesh_flow_ruleset_raft_adapter)
    elseif(test_name STREQUAL "test_mesh_control_raft")
        list(APPEND extra_test_libs mesh_control_raft)
    elseif(test_name STREQUAL "test_mesh_control_raft_service")
        list(APPEND extra_test_libs mesh_control_raft_service)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution_result")
        list(APPEND extra_test_libs mesh_mgmt_execution_result)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution_wire")
        list(APPEND extra_test_libs
            mesh_mgmt_execution_wire
            mesh_mgmt_dispatch
            mesh_mgmt_crypto
            mesh_mgmt_session)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution_runner")
        add_dependencies(${test_name} mesh_mgmt_execution_test_guest)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_EXECUTION_WASM="${MESH_MGMT_EXECUTION_TEST_WASM}")
        list(APPEND extra_test_libs mesh_mgmt_execution_runner)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution_process")
        add_dependencies(${test_name} mesh_mgmt_execution_test_guest
            mesh-execution-worker mesh_native_test_worker)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_EXECUTION_WASM="${MESH_MGMT_EXECUTION_TEST_WASM}"
            MESH_TEST_EXECUTION_WORKER="$<TARGET_FILE:mesh-execution-worker>"
            MESH_TEST_NATIVE_WORKER="$<TARGET_FILE:mesh_native_test_worker>")
        list(APPEND extra_test_libs mesh_mgmt_execution_process)
    endif()
    if(test_name STREQUAL "test_mesh_control_execution_provider")
        add_dependencies(${test_name} mesh_mgmt_execution_test_success_guest
            mesh-execution-worker mesh_native_test_worker)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_EXECUTION_SUCCESS_WASM="${MESH_MGMT_EXECUTION_TEST_SUCCESS_WASM}"
            MESH_TEST_EXECUTION_WORKER="$<TARGET_FILE:mesh-execution-worker>"
            MESH_TEST_NATIVE_WORKER="$<TARGET_FILE:mesh_native_test_worker>")
        list(APPEND extra_test_libs mesh_control_execution_provider)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution_orchestrator")
        add_dependencies(${test_name} mesh_mgmt_execution_test_guest)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_EXECUTION_WASM="${MESH_MGMT_EXECUTION_TEST_WASM}")
      list(APPEND extra_test_libs mesh_mgmt_execution_orchestrator
        mesh_mgmt_execution_service mesh_mgmt_execution_worker
        mesh_mgmt_execution_egress mesh_mgmt_execution_sender)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_execution_node")
        add_dependencies(${test_name} mesh_mgmt_execution_test_guest)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_EXECUTION_WASM="${MESH_MGMT_EXECUTION_TEST_WASM}")
        list(APPEND extra_test_libs mesh_mgmt_execution_node)
    endif()
    if(test_name STREQUAL "test_meshd_execution_config")
        target_sources(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/meshd_execution_config.c)
        list(APPEND extra_test_libs
            mesh_mgmt_execution_node mesh_mgmt_execution_process)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_session")
        list(APPEND extra_test_libs
            mesh_mgmt_peer
            mesh_mgmt_peer_signer
            mesh_mgmt_execution_consumer
            mesh_mgmt_execution_response_consumer)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_peer_signer")
        list(APPEND extra_test_libs mesh_mgmt_peer_signer)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_transport")
        list(APPEND extra_test_libs mesh_mgmt_transport)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_p2p_security")
        list(APPEND extra_test_libs mesh_mgmt_p2p_security)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_p2p_adapter")
        list(APPEND extra_test_libs mesh_mgmt_agent_runtime)
        if(WIN32)
            list(APPEND extra_test_libs ws2_32)
        endif()
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_endpoint_pool")
        list(APPEND extra_test_libs mesh_mgmt_endpoint_pool)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_endpoint_record")
        list(APPEND extra_test_libs mesh_mgmt_agent_runtime)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_service_record")
        list(APPEND extra_test_libs mesh_mgmt_service_record)
    endif()
    if(test_name STREQUAL "test_mesh_mgmt_coronet_transport")
        list(APPEND extra_test_libs mesh_mgmt_coronet_adapter)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_TLS_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/localhost-cert.pem"
            MESH_TEST_TLS_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/localhost-key.pem")
        if(WIN32)
            list(APPEND extra_test_libs ws2_32)
        endif()
    endif()
    if(test_name STREQUAL "test_mesh_stream_codec")
        list(APPEND extra_test_libs mesh_stream_codec)
    endif()
    if(test_name STREQUAL "test_mesh_stream_bind")
        list(APPEND extra_test_libs mesh_stream_bind)
    endif()
    if(test_name STREQUAL "test_mesh_stream_mgmt_ticket")
        list(APPEND extra_test_libs mesh_stream_mgmt_ticket)
    endif()
    if(test_name STREQUAL "test_mesh_stream_session")
        list(APPEND extra_test_libs mesh_stream_session)
    endif()
    if(test_name STREQUAL "test_mesh_stream_transport" OR
       test_name STREQUAL "test_mesh_stream_channel" OR
       test_name STREQUAL "test_mesh_stream_registry")
        list(APPEND extra_test_libs mesh_stream_transport)
    endif()
    if(test_name STREQUAL "test_mesh_stream_coronet")
        list(APPEND extra_test_libs mesh_stream_transport)
        target_compile_definitions(${test_name} PRIVATE
            MESH_TEST_TLS_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/localhost-cert.pem"
            MESH_TEST_TLS_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/localhost-key.pem")
        if(WIN32)
            list(APPEND extra_test_libs ws2_32)
        endif()
    endif()

    target_link_libraries(${test_name}
        PRIVATE mesh
                TurboUtils::TinyTest
                ${extra_test_libs})

    set(test_runtime_output_directory "${CMAKE_BINARY_DIR}/bin")
    if(test_name STREQUAL "test_mesh_mgmt_execution_runner" OR
       test_name STREQUAL "test_mesh_mgmt_execution_orchestrator" OR
       test_name STREQUAL "test_mesh_mgmt_execution_process" OR
       test_name STREQUAL "test_mesh_control_execution_provider")
        set(test_runtime_output_directory
            "${CMAKE_BINARY_DIR}/node-execution-test-bin")
    endif()
    set_target_properties(${test_name} PROPERTIES
        FOLDER "mesh/tests"
        RUNTIME_OUTPUT_DIRECTORY ${test_runtime_output_directory})

    if(WIN32 AND (test_name STREQUAL "test_mesh_mgmt_execution_runner" OR
                  test_name STREQUAL "test_mesh_mgmt_execution_orchestrator" OR
                  test_name STREQUAL "test_mesh_mgmt_execution_process" OR
                  test_name STREQUAL "test_mesh_control_execution_provider"))
        add_custom_command(TARGET ${test_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${_turbo_p2p_runtime_dlls} $<TARGET_FILE_DIR:${test_name}>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:TurboRuntime::Core> $<TARGET_FILE_DIR:${test_name}>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:TurboWasm::Runtime> $<TARGET_FILE_DIR:${test_name}>)
    endif()

    add_test(NAME ${test_name} COMMAND ${test_name})
    if(TARGET turbo_p2p_copy_runtime_dlls)
        add_dependencies(${test_name} turbo_p2p_copy_runtime_dlls)
    endif()
endforeach()

if(TURBOP2P_ENABLE_FLOWMQ_IPC)
    add_executable(test_mesh_node_ipc_flowmq_process
        test_mesh_node_ipc_flowmq_process.c)
    target_include_directories(test_mesh_node_ipc_flowmq_process
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    target_link_libraries(test_mesh_node_ipc_flowmq_process
        PRIVATE mesh_node_ipc_flowmq TurboUtils::Core)
    target_compile_definitions(test_mesh_node_ipc_flowmq_process PRIVATE
        MESH_TEST_FLOWMQ_CA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/ca.pem"
        MESH_TEST_FLOWMQ_SERVER_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-current-cert.pem"
        MESH_TEST_FLOWMQ_SERVER_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/server-current-key.pem"
        MESH_TEST_FLOWMQ_CLIENT_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/client-current-cert.pem"
        MESH_TEST_FLOWMQ_CLIENT_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls/client-current-key.pem")
    if(WIN32)
        target_link_libraries(test_mesh_node_ipc_flowmq_process PRIVATE ws2_32)
    endif()
    set_target_properties(test_mesh_node_ipc_flowmq_process PROPERTIES
        FOLDER "mesh/tests"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    add_test(NAME test_mesh_node_ipc_flowmq_process
        COMMAND test_mesh_node_ipc_flowmq_process)
    set_tests_properties(test_mesh_node_ipc_flowmq_process PROPERTIES
        LABELS "mesh;flowmq;cross-process;security"
        TIMEOUT 20)
    if(TARGET turbo_p2p_copy_runtime_dlls)
        add_dependencies(test_mesh_node_ipc_flowmq_process
            turbo_p2p_copy_runtime_dlls)
    endif()
endif()

target_link_libraries(test_mesh_mgmt_execution_rpc_registry PRIVATE
    mesh_mgmt_execution_rpc_registry
)

target_link_libraries(test_mesh_control_primitives PRIVATE
    mesh_control_primitives
)

target_link_libraries(test_mesh_control_outbox PRIVATE
    mesh_control_outbox
)

target_link_libraries(test_mesh_control_durable_outbox PRIVATE
    mesh_control_durable_outbox
)

target_link_libraries(test_mesh_control_durable_outbox_worker PRIVATE
    mesh_control_durable_outbox_worker
)

target_link_libraries(test_mesh_control_agent_sync PRIVATE
    mesh_control_agent_sync
)

target_link_libraries(test_mesh_control_controller_session PRIVATE
    mesh_control_controller_session mesh_control_mmp mesh_control_status
)

target_link_libraries(test_mesh_control_controller_identity PRIVATE
    mesh_control_controller_identity
)
target_compile_definitions(test_mesh_control_controller_identity PRIVATE
    MESH_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls")

target_link_libraries(test_mesh_control_controller_runtime PRIVATE
    mesh_control_controller_runtime
)
target_compile_definitions(test_mesh_control_controller_runtime PRIVATE
    MESH_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls")

target_link_libraries(test_mesh_control_agent_controller_e2e PRIVATE
    mesh_control_agent_runtime mesh_control_controller_runtime
    mesh_control_document mesh_control_mmp TurboUtils::Core
)
target_compile_definitions(test_mesh_control_agent_controller_e2e PRIVATE
    MESH_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls")
if(WIN32)
    target_link_libraries(test_mesh_control_agent_controller_e2e PRIVATE ws2_32)
endif()

target_link_libraries(test_mesh_control_agent_service PRIVATE
    mesh_control_agent_service mesh_control_status
)

target_link_libraries(test_mesh_control_agent_runtime PRIVATE
    mesh_control_agent_runtime mesh_control_status
)
target_compile_definitions(test_mesh_control_agent_runtime PRIVATE
    MESH_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls")

target_link_libraries(test_mesh_certificate_lifecycle PRIVATE
    mesh_certificate_lifecycle
)
target_compile_definitions(test_mesh_certificate_lifecycle PRIVATE
    MESH_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/flowmq_tls")

target_link_libraries(test_mesh_control_channel PRIVATE
    mesh_control_channel
)

target_link_libraries(test_mesh_node_ipc PRIVATE
    mesh_node_ipc
)

target_link_libraries(test_mesh_control_mmp PRIVATE
    mesh_control_mmp
)

target_link_libraries(test_mesh_control_document PRIVATE
    mesh_control_document
)

target_link_libraries(test_mesh_control_iris PRIVATE
    mesh_control_iris
)

target_link_libraries(test_mesh_control_state PRIVATE
    mesh_control_state
)

target_link_libraries(test_mesh_control_status PRIVATE
    mesh_control_status
)

target_link_libraries(test_mesh_control_policy PRIVATE
    mesh_control_policy
)

target_link_libraries(test_mesh_control_reconciler PRIVATE
    mesh_control_reconciler
)

target_link_libraries(test_mesh_control_owner PRIVATE
    mesh_control_owner mesh_control_mmp
)

target_link_libraries(test_mesh_control_checkpoint PRIVATE
    mesh_control_checkpoint mesh_control_mmp
)

target_link_libraries(test_mesh_control_checkpoint_store PRIVATE
    mesh_control_checkpoint_store
)

target_link_libraries(test_mesh_control_wal PRIVATE
    mesh_control_wal mesh_control_mmp mesh_mgmt_crypto
)

target_link_libraries(test_mesh_control_wal_worker PRIVATE
    mesh_control_wal_worker mesh_control_mmp mesh_mgmt_crypto
)

target_link_libraries(test_mesh_control_agent PRIVATE
    mesh_control_agent TurboHttp::TurboHttp
)
if(WIN32)
    target_link_libraries(test_mesh_control_agent PRIVATE ws2_32)
endif()
target_compile_definitions(test_mesh_control_agent PRIVATE
    MESH_CONTROL_AGENT_TEST_CERT="${CMAKE_CURRENT_SOURCE_DIR}/data/localhost-cert.pem"
    MESH_CONTROL_AGENT_TEST_KEY="${CMAKE_CURRENT_SOURCE_DIR}/data/localhost-key.pem"
)

target_link_libraries(test_mesh_mgmt_execution_rpc_control PRIVATE
    mesh_mgmt_execution_rpc_control
)

target_link_libraries(test_mesh_mgmt_execution_disabled_responder PRIVATE
    mesh_mgmt_execution_disabled_responder
)

target_link_libraries(test_meshd_runtime PRIVATE
    mesh_mgmt_execution_rpc_control
)
