project(tunnel C)

# =============================================================================
# Tunnel Library
# =============================================================================

# Core library sources
set(TUNNEL_LIB_SOURCES
    # Core tunnel implementation
    src/core/tunnel.c
    src/core/tunnel_config.c
    src/stb_sprintf.c
    # DNS modules
    src/dns/tunnel_fake_dns.c
    # NAT and session management
    src/nat/tunnel_nat.c
    src/session/tunnel_session.c
    # Proxy protocols
    src/proxy/tunnel_proxy.c
    src/proxy/tunnel_http.c
    src/proxy/tunnel_socks5.c
    # Network stack
    src/stack/tunnel_checksum.c
    src/stack/tunnel_ip_stack.c
    # Platform-specific TUN device
    src/tun/tunnel_tun_linux.c
    src/tun/tunnel_tun_macos.c
    src/tun/tunnel_tun_windows.c
    # Public headers
    include/turbo_tunnel.h)

# Build object library (for internal tests)
add_library(tunnel_objs STATIC ${TUNNEL_LIB_SOURCES})
target_compile_definitions(tunnel_objs PRIVATE SHARED_CXX)
target_include_directories(
  tunnel_objs
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${Stb_INCLUDE_DIR})
target_link_libraries(tunnel_objs PUBLIC  TurboNet::Utils TurboNet::Core)
set_target_properties(
  tunnel_objs
  PROPERTIES VERSION 1.0.0
  FOLDER "tunnel"
             SOVERSION 1 )
# Build as shared library (DLL on Windows)
add_library(tunnel SHARED $<TARGET_OBJECTS:tunnel_objs>)
add_library(TurboP2P::Tunnel ALIAS tunnel)

# Define export macros for DLL
target_compile_definitions(tunnel PRIVATE SHARED_CXX)

# Include directories (must be after add_library) Include directories (must be
# after add_library)
target_include_directories(
  tunnel
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${Stb_INCLUDE_DIR})

# Link libraries
target_link_libraries(tunnel PUBLIC TurboNet::Utils TurboNet::Core)

set_property(TARGET tunnel PROPERTY FOLDER "tunnel")
set_target_properties(
  tunnel
  PROPERTIES VERSION 1.0.0
  FOLDER "tunnel"
             SOVERSION 1
             EXPORT_NAME Tunnel)

# Install
install(
  TARGETS tunnel
  EXPORT TurboP2PTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
  DESTINATION include/
  FILES_MATCHING
  PATTERN "*.h")

# =============================================================================
# Examples
# =============================================================================

add_subdirectory(examples)

# =============================================================================
# Tests
# =============================================================================

add_subdirectory(tests)
