# =============================================================================
# Tunnel Tests
# =============================================================================

# Enable testing
enable_testing()

# Test sources
set(TUNNEL_TEST_SOURCES
    test_fake_dns.c
    test_ip_stack.c
    test_nat.c
    test_session.c
    test_tunnel.c
    test_socks5.c)

# Create test executables
foreach(test_source ${TUNNEL_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)

    add_executable(${test_name}
        ${test_source}
        $<TARGET_OBJECTS:tunnel_objs>)

    target_compile_definitions(${test_name} PRIVATE TUNNEL_STATIC)
    target_include_directories(${test_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                ${CMAKE_CURRENT_SOURCE_DIR}/../src)

    target_link_libraries(${test_name}
        PRIVATE Salts::Core
                Salts::Platform Salts::CNet
                Salts::TinyTest)

    if(WIN32)
        target_link_libraries(${test_name} PRIVATE ws2_32)
    endif()

    set_property(TARGET ${test_name} PROPERTY LINKER_LANGUAGE CXX)

    # Set folder for IDE organization
    set_target_properties(${test_name} PROPERTIES
        FOLDER "tunnel/tests"
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

    # Add test
    add_test(NAME ${test_name}
        COMMAND ${test_name})
    if(TARGET turbo_p2p_copy_runtime_dlls)
        add_dependencies(${test_name} turbo_p2p_copy_runtime_dlls)
    endif()
endforeach()

add_executable(test_proxy_cnet test_proxy_cnet.c $<TARGET_OBJECTS:tunnel_objs>)
target_include_directories(test_proxy_cnet PRIVATE ../include ../src)
target_compile_definitions(test_proxy_cnet PRIVATE TUNNEL_STATIC
  TUNNEL_TEST_TLS_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../mesh/tests/data/cnet-server-cert.pem"
  TUNNEL_TEST_TLS_KEY_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../mesh/tests/data/cnet-server-key.pem"
  TUNNEL_TEST_TLS_CA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../mesh/tests/data/cnet-ca-cert.pem")
target_link_libraries(test_proxy_cnet PRIVATE Salts::Core Salts::Platform Salts::CNet Salts::TinyTest)
set_target_properties(test_proxy_cnet PROPERTIES LINKER_LANGUAGE CXX FOLDER "tunnel/tests")
add_test(NAME test_proxy_cnet COMMAND test_proxy_cnet)
set_tests_properties(test_proxy_cnet PROPERTIES TIMEOUT 60)
if(TARGET turbo_p2p_copy_runtime_dlls)
  add_dependencies(test_proxy_cnet turbo_p2p_copy_runtime_dlls)
endif()
