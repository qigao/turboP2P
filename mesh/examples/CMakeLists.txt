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

# Mesh CLI - minimal developer mesh tool
add_executable(meshctl
    meshctl.c
    mesh_config.c
    mesh_runtime_health.c)

target_link_libraries(meshctl
    PRIVATE mesh
    TurboP2P::P2P)

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
    PRIVATE mesh tunnel
    TurboP2P::P2P)

target_compile_definitions(meshd PRIVATE USING_EXAMPLES)

set_target_properties(meshd PROPERTIES
    FOLDER "mesh/examples"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
