project(mesh C)

# =============================================================================
# Mesh Library
# =============================================================================

# Mesh library sources
set(MESH_LIB_SOURCES src/mesh.c include/turbo_mesh.h)

# Internal MMP structural codec. It has no installed headers and is not linked
# into the data-plane library until the authenticated management agent exists.
add_library(mesh_mgmt_codec STATIC
  src/mesh_mgmt_codec.c
  src/mesh_mgmt_codec.h)
target_include_directories(mesh_mgmt_codec PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_property(TARGET mesh_mgmt_codec PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_crypto STATIC
  src/mesh_mgmt_crypto.c
  src/mesh_mgmt_crypto.h)
target_include_directories(mesh_mgmt_crypto PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_crypto PRIVATE OpenSSL::Crypto monocypher)
set_property(TARGET mesh_mgmt_crypto PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_envelope STATIC
  src/mesh_mgmt_envelope.c
  src/mesh_mgmt_envelope.h)
target_include_directories(mesh_mgmt_envelope PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_envelope PUBLIC
  mesh_mgmt_codec mesh_mgmt_crypto)
set_property(TARGET mesh_mgmt_envelope PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_identity STATIC
  src/mesh_mgmt_identity.c
  src/mesh_mgmt_identity.h
  src/mesh_mgmt_wire.h)
target_include_directories(mesh_mgmt_identity PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_identity PUBLIC
  mesh_mgmt_codec mesh_mgmt_crypto)
set_property(TARGET mesh_mgmt_identity PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_session STATIC
  src/mesh_mgmt_session.c
  src/mesh_mgmt_session.h)
target_include_directories(mesh_mgmt_session PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_session PUBLIC
  mesh_mgmt_envelope mesh_mgmt_identity)
set_property(TARGET mesh_mgmt_session PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_replay STATIC
  src/mesh_mgmt_replay.c
  src/mesh_mgmt_replay.h)
target_include_directories(mesh_mgmt_replay PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_replay PUBLIC
  mesh_mgmt_envelope)
set_property(TARGET mesh_mgmt_replay PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_dispatch STATIC
  src/mesh_mgmt_dispatch.c
  src/mesh_mgmt_dispatch.h)
target_include_directories(mesh_mgmt_dispatch PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_dispatch PUBLIC
  mesh_mgmt_session mesh_mgmt_replay)
set_property(TARGET mesh_mgmt_dispatch PROPERTY FOLDER "mesh/internal")

# Bounded MMP framing over a reliable byte stream. The core preserves
# coalesced recv chunks and uses an explicit borrowed-frame commit lifecycle.
add_library(mesh_mgmt_transport STATIC
  src/mesh_mgmt_transport.c
  src/mesh_mgmt_transport.h)
target_include_directories(mesh_mgmt_transport PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_transport PUBLIC mesh_mgmt_codec)
set_property(TARGET mesh_mgmt_transport PROPERTY FOLDER "mesh/internal")

# Per-socket owner for ordered transport receipt, authenticated dispatch and
# synchronous event acceptance. Socket lifecycle remains at the agent edge.
add_library(mesh_mgmt_connection STATIC
  src/mesh_mgmt_connection.c
  src/mesh_mgmt_connection.h)
target_include_directories(mesh_mgmt_connection PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_connection PUBLIC
  mesh_mgmt_transport mesh_mgmt_dispatch)
set_property(TARGET mesh_mgmt_connection PROPERTY FOLDER "mesh/internal")

# Adjacent peer handshake driver. Signed frame construction is injected so
# private-key ownership remains at the future mesh-agent boundary.
add_library(mesh_mgmt_peer STATIC
  src/mesh_mgmt_peer.c
  src/mesh_mgmt_peer.h)
target_include_directories(mesh_mgmt_peer PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_peer PUBLIC mesh_mgmt_connection)
set_property(TARGET mesh_mgmt_peer PROPERTY FOLDER "mesh/internal")

# Short-lived local signer for HELLO/ACK builders. It uses TurboUtils CSPRNG,
# copies the caller-loaded management seed, and wipes the copy on destroy.
add_library(mesh_mgmt_peer_signer STATIC
  src/mesh_mgmt_peer_signer.c
  src/mesh_mgmt_peer_signer.h)
target_include_directories(mesh_mgmt_peer_signer PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_peer_signer PUBLIC
  mesh_mgmt_peer mesh_mgmt_identity mesh_mgmt_session TurboUtils::Core)
set_property(TARGET mesh_mgmt_peer_signer PROPERTY FOLDER "mesh/internal")

# Thin secure-socket adapter. It accepts only an already-open TLS 1.3 CoroNet
# connection and never takes ownership of the caller's socket.
add_library(mesh_mgmt_coronet_adapter STATIC
  src/mesh_mgmt_coronet_adapter.c
  src/mesh_mgmt_coronet_adapter.h)
target_include_directories(mesh_mgmt_coronet_adapter PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_coronet_adapter PUBLIC
  mesh_mgmt_transport TurboNet::CoroNet)
set_property(TARGET mesh_mgmt_coronet_adapter PROPERTY FOLDER "mesh/internal")

# P2P custom-message adapter. It accepts only peers whose encrypted handshake
# exposed a static public key and never owns the node, peer, or callback bytes.
add_library(mesh_mgmt_p2p_adapter STATIC
  src/mesh_mgmt_p2p_adapter.c
  src/mesh_mgmt_p2p_adapter.h)
target_include_directories(mesh_mgmt_p2p_adapter PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_p2p_adapter PUBLIC
  mesh_mgmt_transport TurboP2P::P2P)
set_property(TARGET mesh_mgmt_p2p_adapter PROPERTY FOLDER "mesh/internal")

# Composition root for one authenticated P2P peer. Listener registration and
# reconnect remain outside this per-connection owner.
add_library(mesh_mgmt_p2p_peer STATIC
  src/mesh_mgmt_p2p_peer.c
  src/mesh_mgmt_p2p_peer.h)
target_include_directories(mesh_mgmt_p2p_peer PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_p2p_peer PUBLIC
  mesh_mgmt_p2p_adapter mesh_mgmt_peer_signer)
set_property(TARGET mesh_mgmt_p2p_peer PROPERTY FOLDER "mesh/internal")

# Bounded agent edge for one P2P node. It owns global callback routing and one
# short-lived MMP runtime per authenticated transport peer, but not the node.
add_library(mesh_mgmt_agent_router STATIC
  src/mesh_mgmt_agent_router.c
  src/mesh_mgmt_agent_router.h)
target_include_directories(mesh_mgmt_agent_router PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_agent_router PUBLIC
  mesh_mgmt_p2p_peer TurboUtils::Core)
set_property(TARGET mesh_mgmt_agent_router PROPERTY FOLDER "mesh/internal")

# Bounded, identity-keyed management endpoint state. Verified discovery input,
# dial attempts, timeouts, backoff and quarantine stay outside P2P internals.
add_library(mesh_mgmt_endpoint_pool STATIC
  src/mesh_mgmt_endpoint_pool.c
  src/mesh_mgmt_endpoint_pool.h)
target_include_directories(mesh_mgmt_endpoint_pool PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_endpoint_pool PUBLIC
  mesh_mgmt_crypto TurboP2P::P2P TurboUtils::Core)
set_property(TARGET mesh_mgmt_endpoint_pool PROPERTY FOLDER "mesh/internal")

# Strict canonical codec and direct-trust verification boundary for signed
# DHT endpoint records. Raw discovery bytes never enter endpoint dial state.
add_library(mesh_mgmt_endpoint_record STATIC
  src/mesh_mgmt_endpoint_record.c
  src/mesh_mgmt_endpoint_record.h)
target_include_directories(mesh_mgmt_endpoint_record PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_endpoint_record PUBLIC
  mesh_mgmt_endpoint_pool mesh_mgmt_envelope mesh_mgmt_identity OpenSSL::Crypto)
set_property(TARGET mesh_mgmt_endpoint_record PROPERTY FOLDER "mesh/internal")

# Validated local endpoint signer and connected-peer DHT push boundary. It
# borrows the P2P node and owns a wiped copy of the management signing seed.
add_library(mesh_mgmt_endpoint_publisher STATIC
  src/mesh_mgmt_endpoint_publisher.c
  src/mesh_mgmt_endpoint_publisher.h)
target_include_directories(mesh_mgmt_endpoint_publisher PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_endpoint_publisher PUBLIC
  mesh_mgmt_endpoint_record mesh_mgmt_peer_signer TurboP2P::P2P TurboUtils::Core)
set_property(TARGET mesh_mgmt_endpoint_publisher PROPERTY FOLDER "mesh/internal")

# Dedicated mesh-agent composition root. It owns a private P2P listener, the
# MMP callback router and bounded endpoint reconnect state on one event loop.
add_library(mesh_mgmt_agent_runtime STATIC
  src/mesh_mgmt_agent_runtime.c
  src/mesh_mgmt_agent_runtime.h)
target_include_directories(mesh_mgmt_agent_runtime PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_agent_runtime PUBLIC
  mesh_mgmt_agent_router mesh_mgmt_endpoint_publisher TurboNet::CoroNet)
set_property(TARGET mesh_mgmt_agent_runtime PROPERTY FOLDER "mesh/internal")

# Length-first framing for future reliable byte-stream transports. This codec
# is internal and transport-agnostic; it is not linked into the mesh data path.
add_library(mesh_stream_codec STATIC
  src/mesh_stream_codec.c
  src/mesh_stream_codec.h)
target_include_directories(mesh_stream_codec PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_property(TARGET mesh_stream_codec PROPERTY FOLDER "mesh/internal")

# One-time, mutually signed identity binding for a dedicated TLS 1.3 data
# connection. The CoroNet adapter below derives its RFC 9266 exporter directly
# from the live socket; callers cannot supply a data-plane binding.
add_library(mesh_stream_bind STATIC
  src/mesh_stream_bind.c
  src/mesh_stream_bind.h)
target_include_directories(mesh_stream_bind PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_bind PUBLIC
  mesh_mgmt_crypto TurboUtils::Core)
set_property(TARGET mesh_stream_bind PROPERTY FOLDER "mesh/internal")

# MMP Stream V1 ticket schemas and the responder-owned issuance command. The
# dispatcher remains observer-only; MMP delivery writes through this boundary.
add_library(mesh_stream_mgmt_ticket STATIC
  src/mesh_stream_mgmt_ticket.c
  src/mesh_stream_mgmt_ticket.h)
target_include_directories(mesh_stream_mgmt_ticket PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_mgmt_ticket PUBLIC
  mesh_mgmt_dispatch mesh_stream_bind)
set_property(TARGET mesh_stream_mgmt_ticket PROPERTY FOLDER "mesh/internal")

# Authorized receiver-side stream state. It is kept transport-agnostic and
# internal until an authenticated CoroNet adapter can own its lifecycle.
add_library(mesh_stream_session STATIC
  src/mesh_stream_session.c
  src/mesh_stream_session.h)
target_include_directories(mesh_stream_session PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_session PUBLIC mesh_stream_codec)
set_property(TARGET mesh_stream_session PROPERTY FOLDER "mesh/internal")

# Bounded receive-window driver, authenticated lifecycle owner, bounded channel
# registry, and thin CoroNet adapter. The target remains internal and is not
# linked into the public mesh data path.
add_library(mesh_stream_transport STATIC
  src/mesh_stream_transport.c
  src/mesh_stream_transport.h
  src/mesh_stream_channel.c
  src/mesh_stream_channel.h
  src/mesh_stream_registry.c
  src/mesh_stream_registry.h
  src/mesh_stream_coronet_adapter.c
  src/mesh_stream_coronet_adapter.h)
target_include_directories(mesh_stream_transport PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_transport PUBLIC
  mesh_stream_bind mesh_stream_session TurboNet::CoroNet)
set_property(TARGET mesh_stream_transport PROPERTY FOLDER "mesh/internal")

# Build as shared library (DLL on Windows)
add_library(mesh SHARED ${MESH_LIB_SOURCES})
add_library(TurboP2P::Mesh ALIAS mesh)

# Define export macros for DLL
target_compile_definitions(mesh PRIVATE SHARED_CXX)

# Include directories
target_include_directories(
  mesh
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Link libraries
target_link_libraries(mesh PUBLIC TurboUtils::Core TurboP2P::P2P)

if(NOT DEFINED TURBOP2P_ICE_TARGET OR "${TURBOP2P_ICE_TARGET}" STREQUAL "" OR
   NOT TARGET ${TURBOP2P_ICE_TARGET})
  message(FATAL_ERROR "mesh requires the TurboNet ICE target")
endif()

target_link_libraries(mesh PRIVATE ${TURBOP2P_ICE_TARGET})
target_compile_definitions(mesh PUBLIC MESH_HAS_TURBO_ICE=1)
target_compile_definitions(mesh PRIVATE MESH_HAS_TURBO_ICE_CLOSE=1)

set_property(TARGET mesh PROPERTY FOLDER "mesh")
set_target_properties(
  mesh
  PROPERTIES VERSION 1.0.0
             SOVERSION 1
             EXPORT_NAME Mesh)

# Install
install(
  TARGETS mesh
  EXPORT TurboP2PTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
  DESTINATION include/turbo/mesh
  FILES_MATCHING
  PATTERN "*.h")

# =============================================================================
# Examples
# =============================================================================

if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(BUILD_TESTS)
  add_subdirectory(tests)
endif()
