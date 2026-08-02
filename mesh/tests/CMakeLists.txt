# =============================================================================
# Mesh Tests
# =============================================================================

enable_testing()

set(MESH_TEST_SOURCES
    test_mesh.c
    test_mesh_faults.c
    test_mesh_multihop.c
    test_mesh_paths.c
    test_mesh_mgmt_codec.c
    test_mesh_mgmt_crypto.c
    test_mesh_mgmt_envelope.c
    test_mesh_mgmt_replay.c
    test_mesh_mgmt_execution.c
    test_mesh_mgmt_execution_store.c
    test_m3_namespace_local_store.c
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
    test_mesh_mgmt_execution_rpc_registry.c
    test_mesh_mgmt_execution_rpc_control.c
    test_mesh_mgmt_execution_disabled_responder.c
    test_meshd_runtime.c)

if(TURBO_P2P_ENABLE_NODE_EXECUTION)
    set(MESH_MGMT_EXECUTION_TEST_WASM
        "${CMAKE_CURRENT_BINARY_DIR}/mesh_mgmt_execution_test_guest.wasm")
    turbo_add_wasm_application(mesh_mgmt_execution_test_guest
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/data/execution_guest.c
        MAX_MEMORY 262144
        OUTPUT ${MESH_MGMT_EXECUTION_TEST_WASM}
        NO_CHECK)
    list(APPEND MESH_TEST_SOURCES
        test_mesh_mgmt_execution_runner.c
        test_mesh_mgmt_execution_orchestrator.c
        test_mesh_mgmt_execution_node.c
        test_meshd_execution_config.c)
endif()

if(TURBOP2P_BUILD_TURBORAFT_M3)
  list(APPEND MESH_TEST_SOURCES test_m3_namespace_raft_adapter.c)
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
    if(test_name STREQUAL "test_meshd_runtime")
        target_sources(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_config.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_runtime_health.c)
        list(APPEND extra_test_libs tunnel mesh_mgmt_agent_runtime TurboP2P::P2P)
        if(TURBO_P2P_ENABLE_NODE_EXECUTION)
            target_sources(${test_name} PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/../examples/meshd_execution_config.c)
            list(APPEND extra_test_libs mesh_mgmt_execution_node)
            target_compile_definitions(${test_name} PRIVATE
                TURBO_P2P_ENABLE_NODE_EXECUTION=1)
        endif()
    endif()
    if(test_name STREQUAL "test_meshctl_rpc")
        target_sources(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_config.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../examples/mesh_runtime_health.c)
        list(APPEND extra_test_libs TurboP2P::P2P)
        if(WIN32)
            list(APPEND extra_test_libs ws2_32)
        endif()
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
        list(APPEND extra_test_libs mesh_mgmt_execution_node)
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
       test_name STREQUAL "test_mesh_mgmt_execution_orchestrator")
        set(test_runtime_output_directory
            "${CMAKE_BINARY_DIR}/node-execution-test-bin")
    endif()
    set_target_properties(${test_name} PROPERTIES
        FOLDER "mesh/tests"
        RUNTIME_OUTPUT_DIRECTORY ${test_runtime_output_directory})

    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

target_link_libraries(test_mesh_mgmt_execution_rpc_registry PRIVATE
    mesh_mgmt_execution_rpc_registry
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
