# =============================================================================
# Tunnel Tests (using Unity framework)
# =============================================================================

# Enable testing
enable_testing()

# Test sources
set(TUNNEL_TEST_SOURCES
    test_fake_dns.c
    test_ip_stack.c
    test_nat.c
    test_session.c
    test_socks5.c)

# Create test executables
foreach(test_source ${TUNNEL_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)
    
    add_executable(${test_name}
        ${test_source}
        $<TARGET_OBJECTS:tunnel_objs>)
    
    target_include_directories(${test_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                ${CMAKE_CURRENT_SOURCE_DIR}/../src
                ${CMAKE_SOURCE_DIR}/vendor/unity)
    
    target_link_libraries(${test_name}
        PRIVATE TurboNet::Utils
                TurboNet::Core
                libuv::uv
                unity)  # Link Unity framework if available
    
    # Set folder for IDE organization
    set_target_properties(${test_name} PROPERTIES
        FOLDER "tunnel/tests"
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    
    # Add test
    add_test(NAME ${test_name}
        COMMAND ${test_name})
endforeach()
 