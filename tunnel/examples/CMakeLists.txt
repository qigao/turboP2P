# =============================================================================
# Tunnel Examples
# =============================================================================

# Basic tunnel example
add_executable(tunnel_example
    tunnel_example.c)

target_include_directories(tunnel_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(tunnel_example
    PRIVATE tunnel)

target_compile_definitions(tunnel_example PRIVATE USING_EXAMPLES)

set_target_properties(tunnel_example PROPERTIES
    FOLDER "tunnel/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# SOCKS5 proxy tunnel
add_executable(tunnel_socks5
    tunnel_socks5.c)

target_include_directories(tunnel_socks5 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(tunnel_socks5
    PRIVATE tunnel)

target_compile_definitions(tunnel_socks5 PRIVATE USING_EXAMPLES)

set_target_properties(tunnel_socks5 PROPERTIES
    FOLDER "tunnel/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
