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
    test_mesh_mgmt_session.c
    test_mesh_mgmt_peer_signer.c
    test_mesh_mgmt_transport.c
    test_mesh_mgmt_p2p_adapter.c
    test_mesh_mgmt_endpoint_pool.c
    test_mesh_mgmt_endpoint_record.c
    test_mesh_mgmt_coronet_transport.c
    test_mesh_stream_codec.c
    test_mesh_stream_bind.c
    test_mesh_stream_mgmt_ticket.c
    test_mesh_stream_session.c
    test_mesh_stream_transport.c
    test_mesh_stream_channel.c
    test_mesh_stream_registry.c
    test_mesh_stream_coronet.c
    test_meshd_runtime.c)

foreach(test_source ${MESH_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)

    add_executable(${test_name} ${test_source})

    target_include_directories(${test_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                ${CMAKE_CURRENT_SOURCE_DIR}/../src
                ${CMAKE_CURRENT_SOURCE_DIR}/../examples)

    set(extra_test_libs)
    if(test_name STREQUAL "test_meshd_runtime")
        list(APPEND extra_test_libs tunnel TurboP2P::P2P)
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
    if(test_name STREQUAL "test_mesh_mgmt_session")
        list(APPEND extra_test_libs mesh_mgmt_peer mesh_mgmt_peer_signer)
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

    set_target_properties(${test_name} PROPERTIES
        FOLDER "mesh/tests"
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
