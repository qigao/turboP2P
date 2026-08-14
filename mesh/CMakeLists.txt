project(mesh C)
find_package(OpenSSL REQUIRED)
# =============================================================================
# Mesh Library
# =============================================================================

# Mesh library sources
set(MESH_LIB_SOURCES
  src/mesh.c
  src/mesh_multi_network.c
  src/mesh_multi_network_internal.h
  include/turbo_mesh.h
  include/turbo_mesh_multi_network.h)

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
target_link_libraries(mesh_mgmt_crypto PRIVATE OpenSSL::Crypto TurboNet::Crypto)
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

add_library(mesh_mgmt_p2p_security STATIC
  src/mesh_mgmt_p2p_security.c
  src/mesh_mgmt_p2p_security.h)
target_include_directories(mesh_mgmt_p2p_security PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_p2p_security PUBLIC
  mesh_mgmt_identity TurboP2P::P2P
  PRIVATE TurboNet::Crypto)
set_property(TARGET mesh_mgmt_p2p_security PROPERTY FOLDER "mesh/internal")

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

# Pure E0 node-execution schema, authorization intersection and bounded journal
# simulator. It has no transport, filesystem, TurboRuntime or Wasm dependency.
add_library(mesh_mgmt_execution STATIC
  src/mesh_mgmt_execution.c
  src/mesh_mgmt_execution.h)
target_include_directories(mesh_mgmt_execution PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_property(TARGET mesh_mgmt_execution PROPERTY FOLDER "mesh/internal")

# Transport-neutral resource and operation contracts shared by H2, WebSocket
# and MMP adapters. The outbox copies callback-borrowed payloads into a bounded
# single-owner FIFO before any coroutine suspension or worker handoff.
add_library(mesh_control_primitives STATIC
  src/mesh_control_primitives.c
  src/mesh_control_primitives.h)
target_include_directories(mesh_control_primitives PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_property(TARGET mesh_control_primitives PROPERTY FOLDER "mesh/internal")

add_library(meshctl_product STATIC
  src/meshctl_product.c
  src/meshctl_product.h)
target_include_directories(meshctl_product PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
target_link_libraries(meshctl_product PUBLIC
  TurboParser::Parser TurboParser::Selector TurboHttp::TurboHttp
  TurboUtils::Core)
set_property(TARGET meshctl_product PROPERTY FOLDER "mesh/internal")

add_library(mesh_product_controller_iris STATIC
  src/mesh_product_controller_iris.c
  src/mesh_product_controller_iris.h)
target_include_directories(mesh_product_controller_iris PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
target_link_libraries(mesh_product_controller_iris PUBLIC
  mesh_control_primitives TurboHttp::Iris TurboParser::Parser
  TurboParser::Selector TurboUtils::Core
  PRIVATE OpenSSL::Crypto)
set_property(TARGET mesh_product_controller_iris PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_outbox STATIC
  src/mesh_control_outbox.c
  src/mesh_control_outbox.h)
target_include_directories(mesh_control_outbox PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_outbox
  PUBLIC mesh_control_primitives TurboUtils::Core)
set_property(TARGET mesh_control_outbox PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_durable_outbox STATIC
  src/mesh_control_durable_outbox.c
  src/mesh_control_durable_outbox.h)
target_include_directories(mesh_control_durable_outbox PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_durable_outbox
  PUBLIC mesh_control_primitives TurboUtils::Core
  PRIVATE OpenSSL::Crypto)
set_property(TARGET mesh_control_durable_outbox PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_durable_outbox_worker STATIC
  src/mesh_control_durable_outbox_worker.c
  src/mesh_control_durable_outbox_worker.h)
target_include_directories(mesh_control_durable_outbox_worker PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_durable_outbox_worker
  PUBLIC mesh_control_durable_outbox TurboUtils::Core
  PRIVATE OpenSSL::Crypto)
set_property(TARGET mesh_control_durable_outbox_worker
  PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_agent_sync STATIC
  src/mesh_control_agent_sync.c
  src/mesh_control_agent_sync.h)
target_include_directories(mesh_control_agent_sync PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_agent_sync PUBLIC
  mesh_control_primitives mesh_mgmt_crypto mesh_mgmt_identity)
set_property(TARGET mesh_control_agent_sync PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_controller_session STATIC
  src/mesh_control_controller_session.c
  src/mesh_control_controller_session.h)
target_include_directories(mesh_control_controller_session PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_controller_session PUBLIC
  mesh_control_agent_sync mesh_control_durable_outbox_worker
  mesh_control_status mesh_control_mmp mesh_mgmt_envelope)
set_property(TARGET mesh_control_controller_session
  PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_controller_identity STATIC
  src/mesh_control_controller_identity.c
  src/mesh_control_controller_identity.h)
target_include_directories(mesh_control_controller_identity PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_controller_identity PUBLIC
  mesh_control_controller_session mesh_certificate_lifecycle)
set_property(TARGET mesh_control_controller_identity
  PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_controller_iris STATIC
  src/mesh_control_controller_iris.c
  src/mesh_control_controller_iris.h)
target_include_directories(mesh_control_controller_iris PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_controller_iris PUBLIC
  mesh_control_controller_session TurboHttp::Iris TurboNet::CoroNet
  TurboUtils::Core)
set_property(TARGET mesh_control_controller_iris PROPERTY FOLDER "mesh/internal")

add_library(mesh_secure_file STATIC
  src/mesh_secure_file.c
  src/mesh_secure_file.h)
target_include_directories(mesh_secure_file PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(WIN32)
  target_link_libraries(mesh_secure_file PRIVATE advapi32)
endif()
set_property(TARGET mesh_secure_file PROPERTY FOLDER "mesh/internal")

add_library(mesh_certificate_lifecycle STATIC
  src/mesh_certificate_lifecycle.c
  src/mesh_certificate_lifecycle.h)
target_include_directories(mesh_certificate_lifecycle PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_certificate_lifecycle PUBLIC
  mesh_control_primitives TurboUtils::Core
  PRIVATE mesh_mgmt_crypto mesh_secure_file OpenSSL::Crypto)
set_property(TARGET mesh_certificate_lifecycle PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_agent_http_client STATIC
  src/mesh_control_agent_http_client.c
  src/mesh_control_agent_http_client.h)
target_include_directories(mesh_control_agent_http_client PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_agent_http_client PUBLIC
  mesh_control_agent_sync mesh_control_controller_iris
  TurboHttp::TurboHttp TurboNet::CoroNet)
set_property(TARGET mesh_control_agent_http_client PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_channel STATIC
  src/mesh_control_channel.c
  src/mesh_control_channel.h)
target_include_directories(mesh_control_channel PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_channel
  PUBLIC mesh_control_primitives TurboUtils::Core)
set_property(TARGET mesh_control_channel PROPERTY FOLDER "mesh/internal")

# Canonical typed local-control frames and the bounded ownership-transfer
# channel used at the FlowMQ callback/domain-owner boundary. The codec is
# transport-neutral; the optional FlowMQ adapter is layered above it.
add_library(mesh_node_ipc STATIC
  src/mesh_node_ipc.c
  src/mesh_node_ipc.h
  src/mesh_node_ipc_channel.c
  src/mesh_node_ipc_channel.h
  src/mesh_node_ipc_client.c
  src/mesh_node_ipc_client.h
  src/mesh_node_ipc_owner.c
  src/mesh_node_ipc_owner.h)
target_include_directories(mesh_node_ipc PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_node_ipc
  PUBLIC mesh_control_primitives TurboUtils::Core
  PRIVATE TurboNet::Crypto)
set_property(TARGET mesh_node_ipc PROPERTY FOLDER "mesh/internal")

if(TURBOP2P_ENABLE_FLOWMQ_IPC)
  add_library(mesh_node_ipc_flowmq STATIC
    src/mesh_node_ipc_flowmq.c
    src/mesh_node_ipc_flowmq.h)
  target_include_directories(mesh_node_ipc_flowmq PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_node_ipc_flowmq PUBLIC
    mesh_node_ipc FlowMQ::FlowMQ)
  set_property(TARGET mesh_node_ipc_flowmq PROPERTY FOLDER "mesh/internal")

  add_library(mesh_node_control_runtime STATIC
    src/mesh_node_control_runtime.c
    src/mesh_node_control_runtime.h)
  target_include_directories(mesh_node_control_runtime PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_node_control_runtime PUBLIC
    mesh_node_ipc_flowmq mesh_node_ipc)
  set_property(TARGET mesh_node_control_runtime PROPERTY FOLDER "mesh/internal")

  add_library(mesh_node_control_client_runtime STATIC
    src/mesh_node_control_client_runtime.c
    src/mesh_node_control_client_runtime.h)
  target_include_directories(mesh_node_control_client_runtime PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_node_control_client_runtime PUBLIC
    mesh_node_ipc_flowmq mesh_node_ipc)
  set_property(TARGET mesh_node_control_client_runtime PROPERTY FOLDER "mesh/internal")

  add_library(mesh_node_control_flowmq_provider STATIC
    src/mesh_node_control_flowmq_provider.c
    src/mesh_node_control_flowmq_provider.h)
  target_include_directories(mesh_node_control_flowmq_provider PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_node_control_flowmq_provider PUBLIC
    mesh_node_control_client_runtime mesh_control_reconciler
    mesh_control_document
    PRIVATE TurboNet::Crypto)
  set_property(TARGET mesh_node_control_flowmq_provider PROPERTY FOLDER "mesh/internal")

  add_library(mesh_node_control_flowmq_network_provider STATIC
    src/mesh_node_control_flowmq_network_provider.c
    src/mesh_node_control_flowmq_network_provider.h
    src/mesh_control_network_provider.h)
  target_include_directories(mesh_node_control_flowmq_network_provider PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_node_control_flowmq_network_provider PUBLIC
    mesh_node_control_client_runtime mesh_control_document
    PRIVATE TurboNet::Crypto)
  set_property(TARGET mesh_node_control_flowmq_network_provider PROPERTY FOLDER "mesh/internal")
endif()

add_library(mesh_control_mmp STATIC
  src/mesh_control_mmp.c
  src/mesh_control_mmp.h)
target_include_directories(mesh_control_mmp PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_mmp
  PUBLIC mesh_control_primitives mesh_mgmt_envelope)
set_property(TARGET mesh_control_mmp PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_document STATIC
  src/mesh_control_document.c
  src/mesh_control_document.h)
target_include_directories(mesh_control_document PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_document PUBLIC
  mesh_control_mmp mesh_mgmt_codec PRIVATE mesh_mgmt_crypto)
set_property(TARGET mesh_control_document PROPERTY FOLDER "mesh/internal")

add_library(mesh_network_reconciler STATIC
  src/mesh_network_reconciler.c
  src/mesh_network_reconciler.h)
target_include_directories(mesh_network_reconciler PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(mesh_network_reconciler PUBLIC
  mesh_control_document mesh PRIVATE TurboNet::Crypto)
set_property(TARGET mesh_network_reconciler PROPERTY FOLDER "mesh/internal")

add_library(mesh_node_ipc_network_executor STATIC
  src/mesh_node_ipc_network_executor.c
  src/mesh_node_ipc_network_executor.h)
target_include_directories(mesh_node_ipc_network_executor PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_node_ipc_network_executor PUBLIC
  mesh_node_ipc mesh_network_reconciler PRIVATE TurboNet::Crypto)
set_property(TARGET mesh_node_ipc_network_executor PROPERTY FOLDER "mesh/internal")

if(TURBOP2P_ENABLE_FLOWMQ_IPC)
  add_library(mesh_node_network_control_service STATIC
    src/mesh_node_network_control_service.c
    src/mesh_node_network_control_service.h)
  target_include_directories(mesh_node_network_control_service PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_node_network_control_service PUBLIC
    mesh_node_control_runtime mesh_node_ipc_network_executor
    mesh_network_reconciler)
  set_property(TARGET mesh_node_network_control_service
    PROPERTY FOLDER "mesh/internal")
endif()

add_library(mesh_control_iris STATIC
  src/mesh_control_iris.c
  src/mesh_control_iris.h)
target_include_directories(mesh_control_iris PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_iris
  PUBLIC mesh_control_channel mesh_control_mmp TurboHttp::Iris)
set_property(TARGET mesh_control_iris PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_state STATIC
  src/mesh_control_state.c
  src/mesh_control_state.h)
target_include_directories(mesh_control_state PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_state PUBLIC mesh_control_primitives)
set_property(TARGET mesh_control_state PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_status STATIC
  src/mesh_control_status.c
  src/mesh_control_status.h)
target_include_directories(mesh_control_status PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_status PUBLIC
  mesh_control_state mesh_mgmt_codec)
set_property(TARGET mesh_control_status PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_policy STATIC
  src/mesh_control_policy.c
  src/mesh_control_policy.h)
target_include_directories(mesh_control_policy PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_policy PUBLIC
  mesh_control_document mesh_control_primitives)
set_property(TARGET mesh_control_policy PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_reconciler STATIC
  src/mesh_control_reconciler.c
  src/mesh_control_reconciler.h)
target_include_directories(mesh_control_reconciler PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_reconciler PUBLIC
  mesh_control_document mesh_control_state)
set_property(TARGET mesh_control_reconciler PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_owner STATIC
  src/mesh_control_owner.c
  src/mesh_control_owner.h)
target_include_directories(mesh_control_owner PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_owner PUBLIC
  mesh_control_channel mesh_control_document mesh_control_state mesh_mgmt_replay)
set_property(TARGET mesh_control_owner PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_checkpoint STATIC
  src/mesh_control_checkpoint.c
  src/mesh_control_checkpoint.h)
target_include_directories(mesh_control_checkpoint PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_checkpoint
  PUBLIC mesh_control_owner
  PRIVATE OpenSSL::Crypto)
set_property(TARGET mesh_control_checkpoint PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_checkpoint_store STATIC
  src/mesh_control_checkpoint_store.c
  src/mesh_control_checkpoint_store.h)
target_include_directories(mesh_control_checkpoint_store PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_checkpoint_store
  PUBLIC mesh_control_checkpoint TurboUtils::Core
  PRIVATE OpenSSL::Crypto)
set_property(TARGET mesh_control_checkpoint_store PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_wal STATIC
  src/mesh_control_wal.c
  src/mesh_control_wal.h)
target_include_directories(mesh_control_wal PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_wal
  PUBLIC mesh_control_owner mesh_control_mmp
  PRIVATE mesh_mgmt_crypto OpenSSL::Crypto TurboUtils::Core)
set_property(TARGET mesh_control_wal PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_wal_worker STATIC
  src/mesh_control_wal_worker.c
  src/mesh_control_wal_worker.h)
target_include_directories(mesh_control_wal_worker PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_wal_worker
  PUBLIC mesh_control_checkpoint_store mesh_control_wal TurboUtils::Core
  PRIVATE mesh_mgmt_crypto)
set_property(TARGET mesh_control_wal_worker PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_agent STATIC
  src/mesh_control_agent.c
  src/mesh_control_agent.h
  src/mesh_control_network_provider.h)
target_include_directories(mesh_control_agent PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_agent PUBLIC
  mesh_control_iris mesh_control_owner mesh_control_policy
  mesh_control_reconciler mesh_network_reconciler mesh_control_status mesh_control_wal_worker
  TurboNet::CoroNet TurboHttp::Iris)
set_property(TARGET mesh_control_agent PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_agent_service STATIC
  src/mesh_control_agent_service.c
  src/mesh_control_agent_service.h)
target_include_directories(mesh_control_agent_service PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_agent_service PUBLIC
  mesh_control_agent mesh_control_agent_http_client mesh_control_agent_sync
  mesh_certificate_lifecycle TurboUtils::Core)
set_property(TARGET mesh_control_agent_service PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_agent_runtime STATIC
  src/mesh_control_agent_runtime.c
  src/mesh_control_agent_runtime.h)
target_include_directories(mesh_control_agent_runtime PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_agent_runtime PUBLIC
  mesh_control_agent_service mesh_certificate_lifecycle)
set_property(TARGET mesh_control_agent_runtime PROPERTY FOLDER "mesh/internal")

add_library(mesh_control_controller_runtime STATIC
  src/mesh_control_controller_runtime.c
  src/mesh_control_controller_runtime.h)
target_include_directories(mesh_control_controller_runtime PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_control_controller_runtime PUBLIC
  mesh_control_controller_identity mesh_control_controller_iris
  mesh_certificate_lifecycle TurboHttp::Iris TurboNet::CoroNet
  TurboUtils::Core)
set_property(TARGET mesh_control_controller_runtime
  PROPERTY FOLDER "mesh/internal")

# Internal single-store M3 immutable CAS. Namespace, Raft, gateway, transport
# capability and execution authority remain separate layers.
add_library(m3_chunk_store STATIC
  src/m3_chunk_store.c
  src/m3_chunk_store.h)
target_include_directories(m3_chunk_store PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_store
  PUBLIC TurboUtils::Core
  PRIVATE OpenSSL::Crypto)
set_property(TARGET m3_chunk_store PROPERTY FOLDER "mesh/internal")

# Server-side AWS Signature V4 verification for the M3 gateway.
add_library(m3_gateway_sigv4 STATIC
  src/m3_gateway_sigv4.c
  src/m3_gateway_sigv4.h)
target_include_directories(m3_gateway_sigv4 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_gateway_sigv4 PUBLIC TurboNet::Crypto)
set_property(TARGET m3_gateway_sigv4 PROPERTY FOLDER "mesh/internal")

# Authenticated chunk transport over a p2p node: wire codec, capability
# sign/verify, store-side service and gateway-side request/response client.
add_library(m3_chunk_mesh STATIC
  src/m3_chunk_mesh.c
  src/m3_chunk_mesh.h)
target_include_directories(m3_chunk_mesh PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_mesh
  PUBLIC m3_store_node mesh_mgmt_crypto TurboP2P::P2P
  PRIVATE TurboUtils::Core)
set_property(TARGET m3_chunk_mesh PROPERTY FOLDER "mesh/internal")

# Data-plane client used by the metadata leader: issues authorized chunk
# capabilities to registered store nodes, verifies durable receipts and
# encodes the placement into a V2 manifest.
add_library(m3_gateway_datapane STATIC
  src/m3_gateway_datapane.c
  src/m3_gateway_datapane.h)
target_include_directories(m3_gateway_datapane PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_gateway_datapane
  PUBLIC m3_store_node m3_object_manifest m3_chunk_mesh TurboP2P::P2P
  PRIVATE TurboNet::Crypto TurboUtils::Core)
set_property(TARGET m3_gateway_datapane PROPERTY FOLDER "mesh/internal")

# Placement repair: computes per-chunk replica debt, backfills missing
# replicas from healthy sources and produces an updated manifest for
# UPDATE_PLACEMENT commit.
add_library(m3_repair STATIC
  src/m3_repair.c
  src/m3_repair.h)
target_include_directories(m3_repair PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_repair PUBLIC m3_gateway_datapane)
set_property(TARGET m3_repair PROPERTY FOLDER "mesh/internal")

# Phase 1 single-node M3 S3 gateway (Iris routes + chunk/namespace wiring).
add_library(m3_gateway STATIC
  src/m3_gateway.c
  src/m3_gateway.h)
target_include_directories(m3_gateway PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_gateway PUBLIC
  m3_gateway_sigv4 m3_namespace_local_store m3_object_manifest
  m3_gateway_datapane m3_repair mesh_media_playlist mesh_release
  TurboNet::Crypto TurboHttp::Iris)
set_property(TARGET m3_gateway PROPERTY FOLDER "mesh/internal")

# Owner-loop bridge from a content CID to the P2P swarm and immutable local
# M3 CAS. Stable seed files remain outside the CAS filesystem boundary.
add_library(m3_chunk_fetch_service STATIC
  src/m3_chunk_fetch_service.c
  src/m3_chunk_fetch_service.h)
target_include_directories(m3_chunk_fetch_service PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_fetch_service
  PUBLIC m3_chunk_store TurboP2P::P2P
  PRIVATE TurboUtils::Core)
set_property(TARGET m3_chunk_fetch_service PROPERTY FOLDER "mesh/internal")

# Canonical immutable object manifest contract for Raft metadata pages,
# snapshots and download planning. It owns no namespace or transport state.
add_library(m3_object_manifest STATIC
  src/m3_object_manifest.c
  src/m3_object_manifest.h)
target_include_directories(m3_object_manifest PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_object_manifest
  PUBLIC m3_chunk_store
  PRIVATE OpenSSL::Crypto)
set_property(TARGET m3_object_manifest PROPERTY FOLDER "mesh/internal")

# Ordered manifest downloader over the M3 chunk swarm. It assembles into a
# private temporary file and publishes only after whole-object verification.
add_library(m3_object_download_service STATIC
  src/m3_object_download_service.c
  src/m3_object_download_service.h)
target_include_directories(m3_object_download_service PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_object_download_service
  PUBLIC m3_chunk_fetch_service m3_object_manifest
  PRIVATE OpenSSL::Crypto TurboUtils::Core)
set_property(TARGET m3_object_download_service PROPERTY FOLDER "mesh/internal")

# Linearizable namespace-to-data-plane composition. The metadata implementation
# is injected and remains the sole owner of bucket/key and committed versions.
add_library(m3_object_resolver STATIC
  src/m3_object_resolver.c
  src/m3_object_resolver.h)
target_include_directories(m3_object_resolver PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_object_resolver
  PUBLIC m3_object_download_service m3_chunk_capability)
set_property(TARGET m3_object_resolver PROPERTY FOLDER "mesh/internal")

# Explicit single-owner local profile for stage/demo runs. Distributed M3 must
# replace this with a Raft state machine plus quorum ReadIndex adapter.
add_library(m3_namespace_local_store STATIC
  src/m3_namespace_local_store.c
  src/m3_namespace_local_store.h)
target_include_directories(m3_namespace_local_store PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_namespace_local_store
  PUBLIC m3_object_resolver m3_object_manifest)
set_property(TARGET m3_namespace_local_store PROPERTY FOLDER "mesh/internal")

# Deterministic, bounded L3/L4 policy fact source. Publication into the packet
# plane is intentionally separate so static configuration behavior is stable.
add_library(mesh_flow_ruleset STATIC
  src/mesh_flow_ruleset.c
  src/mesh_flow_ruleset.h
  src/mesh_flow_runtime.c
  src/mesh_flow_runtime.h)
target_include_directories(mesh_flow_ruleset PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_property(TARGET mesh_flow_ruleset PROPERTY FOLDER "mesh/internal")

add_library(mesh_flow_ruleset_raft STATIC
  src/mesh_flow_ruleset_raft.c
  src/mesh_flow_ruleset_raft.h)
target_include_directories(mesh_flow_ruleset_raft PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_flow_ruleset_raft PUBLIC mesh_flow_ruleset)
set_property(TARGET mesh_flow_ruleset_raft PROPERTY FOLDER "mesh/internal")

# Cluster scheduling fact source for execution ownership. It is separate from
# the target node's durable command journal and local RPC pending registry.
add_library(mesh_task_lease STATIC
  src/mesh_task_lease.c
  src/mesh_task_lease.h)
target_include_directories(mesh_task_lease PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_task_lease PUBLIC mesh_mgmt_execution)
set_property(TARGET mesh_task_lease PROPERTY FOLDER "mesh/internal")

add_library(mesh_task_lease_raft STATIC
  src/mesh_task_lease_raft.c
  src/mesh_task_lease_raft.h)
target_include_directories(mesh_task_lease_raft PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
target_link_libraries(mesh_task_lease_raft PUBLIC mesh_task_lease)
set_property(TARGET mesh_task_lease_raft PROPERTY FOLDER "mesh/internal")

add_library(mesh_task_execution_guard STATIC
  src/mesh_task_execution_guard.c
  src/mesh_task_execution_guard.h)
target_include_directories(mesh_task_execution_guard PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_task_execution_guard
  PUBLIC mesh_task_lease
  PRIVATE mesh_mgmt_crypto)
set_property(TARGET mesh_task_execution_guard PROPERTY FOLDER "mesh/internal")

if(TURBOP2P_BUILD_TURBORAFT_M3)
  # Dedicated metadata group: immutable chunks remain in the P2P data plane.
  add_library(m3_namespace_raft_adapter STATIC
    src/m3_namespace_raft_adapter.c
    src/m3_namespace_raft_adapter.h)
  target_include_directories(m3_namespace_raft_adapter PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(m3_namespace_raft_adapter PUBLIC
    m3_namespace_local_store TurboRaft::Service)
  set_property(TARGET m3_namespace_raft_adapter PROPERTY FOLDER "mesh/internal")

  add_library(mesh_task_lease_raft_adapter STATIC
    src/mesh_task_lease_raft_adapter.c
    src/mesh_task_lease_raft_adapter.h)
  target_include_directories(mesh_task_lease_raft_adapter PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_task_lease_raft_adapter PUBLIC
    mesh_task_lease_raft TurboRaft::Service)
  set_property(TARGET mesh_task_lease_raft_adapter PROPERTY FOLDER "mesh/internal")

  add_library(mesh_flow_ruleset_raft_adapter STATIC
    src/mesh_flow_ruleset_raft_adapter.c
    src/mesh_flow_ruleset_raft_adapter.h)
  target_include_directories(mesh_flow_ruleset_raft_adapter PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_flow_ruleset_raft_adapter PUBLIC
    mesh_flow_ruleset_raft TurboRaft::Service)
  set_property(TARGET mesh_flow_ruleset_raft_adapter PROPERTY FOLDER "mesh/internal")

  add_library(mesh_control_raft STATIC
    src/mesh_control_raft.c
    src/mesh_control_raft.h)
  target_include_directories(mesh_control_raft PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_control_raft PUBLIC
    mesh_flow_ruleset_raft_adapter mesh_task_lease_raft_adapter
    TurboRaft::Service)
  set_property(TARGET mesh_control_raft PROPERTY FOLDER "mesh/internal")

  add_library(mesh_control_raft_service STATIC
    src/mesh_control_raft_service.c
    src/mesh_control_raft_service.h)
  target_include_directories(mesh_control_raft_service PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_control_raft_service PUBLIC
    mesh_control_raft TurboRaft::SQLiteStorage)
  set_property(TARGET mesh_control_raft_service PROPERTY FOLDER "mesh/internal")

  # Phase 2a: single-voter raft metadata backend for the M3 gateway.
  add_library(m3_gateway_raft STATIC
    src/m3_gateway_raft.c
    src/m3_gateway_raft.h)
  target_include_directories(m3_gateway_raft PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(m3_gateway_raft PUBLIC
    m3_namespace_raft_adapter TurboRaft::Service TurboRaft::SQLiteStorage)
  target_compile_definitions(m3_gateway_raft PUBLIC TURBO_P2P_M3_RAFT_ENABLED=1)
  set_property(TARGET m3_gateway_raft PROPERTY FOLDER "mesh/internal")
  target_link_libraries(m3_gateway PUBLIC m3_gateway_raft)
  target_compile_definitions(m3_gateway PUBLIC TURBO_P2P_M3_RAFT_ENABLED=1)

  # Phase 2b-ii: multi-process CoroNet TLS transport node runtime.
  add_library(m3_raft_node STATIC
    src/m3_raft_node.c
    src/m3_raft_node.h)
  target_include_directories(m3_raft_node PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(m3_raft_node PUBLIC
    m3_gateway_raft TurboRaft::CoroNet TurboNet::CoroNet)
  set_property(TARGET m3_raft_node PROPERTY FOLDER "mesh/internal")

  # Multi-node metadata backend: the gateway embeds an m3_raft_node voter.
  target_link_libraries(m3_gateway PUBLIC m3_raft_node)
endif()

# Pure evaluator for already-verified M3 chunk claims. Signature verification,
# replay journals, transport and filesystem access remain outside this target.
add_library(m3_chunk_capability STATIC
  src/m3_chunk_capability.c
  src/m3_chunk_capability.h)
target_include_directories(m3_chunk_capability PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_capability
  PUBLIC m3_chunk_store
  PRIVATE TurboUtils::Core)
set_property(TARGET m3_chunk_capability PROPERTY FOLDER "mesh/internal")

# Verifiable durable-evidence issued by one store node. Signs the canonical
# receipt body with RFC 8032 Ed25519 and fingerprints the signed receipt for
# manifest placement references.
add_library(m3_chunk_receipt STATIC
  src/m3_chunk_receipt.c
  src/m3_chunk_receipt.h)
target_include_directories(m3_chunk_receipt PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_receipt
  PUBLIC mesh_mgmt_crypto m3_chunk_capability
  PRIVATE OpenSSL::Crypto TurboUtils::Core)
set_property(TARGET m3_chunk_receipt PROPERTY FOLDER "mesh/internal")

# Data-plane service over one immutable local CAS: authorized PUT/READ, quota
# accounting and signed durable receipts consumed by the metadata plane.
add_library(m3_store_node STATIC
  src/m3_store_node.c
  src/m3_store_node.h)
target_include_directories(m3_store_node PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_store_node
  PUBLIC m3_chunk_read_service m3_chunk_receipt
  PRIVATE TurboUtils::Core)
set_property(TARGET m3_store_node PROPERTY FOLDER "mesh/internal")
# The only M3 storage adapter intended for gateway/bulk-stream consumers. It
# accepts authorized access rather than raw network claims or host paths.
add_library(m3_chunk_access_store STATIC
  src/m3_chunk_access_store.c
  src/m3_chunk_access_store.h)
target_include_directories(m3_chunk_access_store PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_access_store
  PUBLIC m3_chunk_capability
  PRIVATE m3_chunk_store)
set_property(TARGET m3_chunk_access_store PROPERTY FOLDER "mesh/internal")

# Bounded owner-loop request journal. UUID reuse is idempotent only when the
# canonical authorized-access digest and terminal result remain identical.
add_library(m3_chunk_replay STATIC
  src/m3_chunk_replay.c
  src/m3_chunk_replay.h)
target_include_directories(m3_chunk_replay PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_replay
  PUBLIC m3_chunk_capability
  PRIVATE OpenSSL::Crypto TurboUtils::Core)
set_property(TARGET m3_chunk_replay PROPERTY FOLDER "mesh/internal")

# Versioned durable snapshot owner for mutation replay bindings. It persists a
# new IN_PROGRESS binding before side effects and terminal results afterward.
add_library(m3_chunk_replay_store STATIC
  src/m3_chunk_replay_store.c
  src/m3_chunk_replay_store.h)
target_include_directories(m3_chunk_replay_store PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_replay_store
  PUBLIC m3_chunk_replay
  PRIVATE OpenSSL::Crypto TurboUtils::Core)
set_property(TARGET m3_chunk_replay_store PROPERTY FOLDER "mesh/internal")

# Read-only M3 composition root. Mutation remains fail-closed until replay
# bindings and terminal results have a durable on-disk format.
add_library(m3_chunk_read_service STATIC
  src/m3_chunk_read_service.c
  src/m3_chunk_read_service.h)
target_include_directories(m3_chunk_read_service PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(m3_chunk_read_service
  PUBLIC m3_chunk_access_store m3_chunk_replay)
set_property(TARGET m3_chunk_read_service PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_execution_store STATIC
  src/mesh_mgmt_execution_store.c
  src/mesh_mgmt_execution_store.h)
target_include_directories(mesh_mgmt_execution_store PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_execution_store
  PUBLIC mesh_mgmt_execution mesh_mgmt_execution_result TurboUtils::Core
  PRIVATE OpenSSL::Crypto)
set_property(TARGET mesh_mgmt_execution_store PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_execution_result STATIC
  src/mesh_mgmt_execution_result.c
  src/mesh_mgmt_execution_result.h)
target_include_directories(mesh_mgmt_execution_result PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_execution_result
  PUBLIC mesh_mgmt_execution
  PRIVATE mesh_mgmt_crypto)
set_property(TARGET mesh_mgmt_execution_result PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_execution_wire STATIC
  src/mesh_mgmt_execution_wire.c
  src/mesh_mgmt_execution_wire.h)
target_include_directories(mesh_mgmt_execution_wire PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_execution_wire
  PUBLIC mesh_mgmt_execution_result
  PRIVATE mesh_mgmt_crypto)
set_property(TARGET mesh_mgmt_execution_wire PROPERTY FOLDER "mesh/internal")

option(TURBO_P2P_ENABLE_NODE_EXECUTION
  "Build the local prestaged TurboRuntime node-execution runner" OFF)
if(TURBO_P2P_ENABLE_NODE_EXECUTION)
  find_package(TurboRuntime CONFIG REQUIRED)
  add_library(mesh_mgmt_execution_runner STATIC
    src/mesh_mgmt_execution_runner.c
    src/mesh_mgmt_execution_runner.h)
  target_include_directories(mesh_mgmt_execution_runner PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_runner
    PUBLIC mesh_mgmt_execution
    PRIVATE OpenSSL::Crypto TurboRuntime::Core TurboUtils::Core)
  set_property(TARGET mesh_mgmt_execution_runner PROPERTY FOLDER "mesh/internal")

  add_library(mesh_mgmt_execution_orchestrator STATIC
    src/mesh_mgmt_execution_orchestrator.c
    src/mesh_mgmt_execution_orchestrator.h)
  target_include_directories(mesh_mgmt_execution_orchestrator PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_orchestrator
    PUBLIC mesh_mgmt_execution_runner mesh_mgmt_execution_store
           mesh_mgmt_execution_result
    PRIVATE mesh_mgmt_crypto OpenSSL::Crypto)
  set_property(TARGET mesh_mgmt_execution_orchestrator
    PROPERTY FOLDER "mesh/internal")

  add_library(mesh_mgmt_execution_process STATIC
    src/mesh_mgmt_execution_process.c
    src/mesh_mgmt_execution_process.h)
  target_include_directories(mesh_mgmt_execution_process PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_process
    PUBLIC mesh_mgmt_execution_orchestrator mesh_mgmt_execution_result
           mesh_mgmt_execution_runner TurboUtils::Core
    PRIVATE mesh_mgmt_crypto OpenSSL::Crypto)
  set_property(TARGET mesh_mgmt_execution_process
    PROPERTY FOLDER "mesh/internal")

  add_library(mesh_control_execution_provider STATIC
    src/mesh_control_execution_provider.c
    src/mesh_control_execution_provider.h)
  target_include_directories(mesh_control_execution_provider PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_control_execution_provider
    PUBLIC mesh_control_reconciler mesh_mgmt_execution_process
    PRIVATE mesh_mgmt_execution_store mesh_mgmt_crypto TurboUtils::Core
            OpenSSL::Crypto)
  set_property(TARGET mesh_control_execution_provider
    PROPERTY FOLDER "mesh/internal")
endif()

add_library(mesh_mgmt_dispatch STATIC
  src/mesh_mgmt_dispatch.c
  src/mesh_mgmt_dispatch.h)
target_include_directories(mesh_mgmt_dispatch PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_dispatch PUBLIC
  mesh_mgmt_session mesh_mgmt_replay
  PRIVATE mesh_mgmt_execution_wire mesh_mgmt_crypto)
set_property(TARGET mesh_mgmt_dispatch PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_execution_consumer STATIC
  src/mesh_mgmt_execution_consumer.c
  src/mesh_mgmt_execution_consumer.h)
target_include_directories(mesh_mgmt_execution_consumer PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_execution_consumer
  PUBLIC mesh_mgmt_dispatch mesh_mgmt_execution_wire
  PRIVATE mesh_mgmt_crypto)
set_property(TARGET mesh_mgmt_execution_consumer PROPERTY FOLDER "mesh/internal")

add_library(mesh_mgmt_execution_response_consumer STATIC
  src/mesh_mgmt_execution_response_consumer.c
  src/mesh_mgmt_execution_response_consumer.h)
target_include_directories(mesh_mgmt_execution_response_consumer PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_execution_response_consumer
  PUBLIC mesh_mgmt_dispatch mesh_mgmt_execution_wire
  PRIVATE mesh_mgmt_crypto)
set_property(TARGET mesh_mgmt_execution_response_consumer
  PROPERTY FOLDER "mesh/internal")

if(TURBO_P2P_ENABLE_NODE_EXECUTION)
  add_library(mesh_mgmt_execution_service STATIC
    src/mesh_mgmt_execution_service.c
    src/mesh_mgmt_execution_service.h)
  target_include_directories(mesh_mgmt_execution_service PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_service
    PUBLIC mesh_mgmt_execution_consumer mesh_mgmt_execution_orchestrator
           mesh_mgmt_execution_wire)
  set_property(TARGET mesh_mgmt_execution_service PROPERTY FOLDER "mesh/internal")

  add_library(mesh_mgmt_execution_worker STATIC
    src/mesh_mgmt_execution_worker.c
    src/mesh_mgmt_execution_worker.h)
  target_include_directories(mesh_mgmt_execution_worker PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_worker
    PUBLIC mesh_mgmt_execution_service TurboUtils::Core)
  set_property(TARGET mesh_mgmt_execution_worker PROPERTY FOLDER "mesh/internal")

  add_library(mesh_mgmt_execution_egress STATIC
    src/mesh_mgmt_execution_egress.c
    src/mesh_mgmt_execution_egress.h)
  target_include_directories(mesh_mgmt_execution_egress PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_egress
    PUBLIC mesh_mgmt_execution_worker TurboUtils::Core)
  set_property(TARGET mesh_mgmt_execution_egress PROPERTY FOLDER "mesh/internal")

  add_library(mesh_mgmt_execution_sender STATIC
    src/mesh_mgmt_execution_sender.c
    src/mesh_mgmt_execution_sender.h)
  target_include_directories(mesh_mgmt_execution_sender PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_sender
    PUBLIC mesh_mgmt_execution_egress mesh_mgmt_peer_signer
           mesh_mgmt_connection mesh_mgmt_agent_runtime
    PRIVATE mesh_mgmt_crypto)
  set_property(TARGET mesh_mgmt_execution_sender PROPERTY FOLDER "mesh/internal")

  add_library(mesh_mgmt_execution_node STATIC
    src/mesh_mgmt_execution_node.c
    src/mesh_mgmt_execution_node.h)
  target_include_directories(mesh_mgmt_execution_node PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_mgmt_execution_node
    PUBLIC mesh_mgmt_execution_runner mesh_mgmt_execution_store
           mesh_mgmt_execution_orchestrator mesh_mgmt_execution_service
           mesh_mgmt_execution_worker mesh_mgmt_execution_egress
           mesh_mgmt_execution_sender mesh_mgmt_agent_runtime
    PRIVATE mesh_mgmt_crypto)
  set_property(TARGET mesh_mgmt_execution_node PROPERTY FOLDER "mesh/internal")
endif()

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

# Bounded agent edge for one P2P node. It supports exclusive callback ownership
# and externally dispatched shared-node mode, and owns one short-lived MMP
# runtime per authenticated transport peer, but not the node.
add_library(mesh_mgmt_agent_router STATIC
  src/mesh_mgmt_agent_router.c
  src/mesh_mgmt_agent_router.h)
target_include_directories(mesh_mgmt_agent_router PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_agent_router PUBLIC
  mesh_mgmt_p2p_peer
  mesh_mgmt_execution_disabled_responder
  mesh_mgmt_execution_response_consumer
  TurboUtils::Core)
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

# Signed virtual-service discovery is deliberately separate from physical
# endpoint records so RPC addresses can never enter transport dial state.
add_library(mesh_mgmt_service_record STATIC
  src/mesh_mgmt_service_record.c
  src/mesh_mgmt_service_record.h)
target_include_directories(mesh_mgmt_service_record PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_service_record PUBLIC
  mesh_mgmt_envelope mesh_mgmt_identity OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(mesh_mgmt_endpoint_record PUBLIC ws2_32)
  target_link_libraries(mesh_mgmt_service_record PUBLIC ws2_32)
endif()
set_property(TARGET mesh_mgmt_service_record PROPERTY FOLDER "mesh/internal")

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

# Validated signer and connected-peer DHT push boundary for RPC virtual service
# records. It owns no transport endpoint state.
add_library(mesh_mgmt_service_publisher STATIC
  src/mesh_mgmt_service_publisher.c
  src/mesh_mgmt_service_publisher.h)
target_include_directories(mesh_mgmt_service_publisher PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_service_publisher PUBLIC
  mesh_mgmt_service_record mesh_mgmt_peer_signer TurboP2P::P2P TurboUtils::Core)
set_property(TARGET mesh_mgmt_service_publisher PROPERTY FOLDER "mesh/internal")

# Dedicated mesh-agent composition root. It owns a private P2P listener, the
# MMP callback router and bounded endpoint reconnect state on one event loop.
add_library(mesh_mgmt_agent_runtime STATIC
  src/mesh_mgmt_agent_runtime.c
  src/mesh_mgmt_agent_runtime.h)
target_include_directories(mesh_mgmt_agent_runtime PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_mgmt_agent_runtime PUBLIC
  mesh_mgmt_agent_router mesh_mgmt_endpoint_publisher mesh_mgmt_p2p_security
  mesh_mgmt_service_publisher
  TurboNet::CoroNet)
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

# Reliable ordered block-stream session (P1): frame protocol, sliding
# window, selective retransmit, backpressure and resume, over a pluggable
# byte transport (mesh_stream_transport / CoroNet TLS adapter later).
add_library(mesh_stream_data STATIC
  src/mesh_stream_data.c
  src/mesh_stream_data.h)
target_include_directories(mesh_stream_data PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_data
  PRIVATE TurboNet::Crypto TurboUtils::Core)
set_property(TARGET mesh_stream_data PROPERTY FOLDER "mesh/internal")

# Per-source health scoring and bad-source elimination for multi-source pulls.
add_library(mesh_stream_source_selector STATIC
  src/mesh_stream_source_selector.c
  src/mesh_stream_source_selector.h)
target_include_directories(mesh_stream_source_selector PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_source_selector PUBLIC mesh_stream_data)
set_property(TARGET mesh_stream_source_selector PROPERTY FOLDER "mesh/internal")

# Parallel multi-source block puller: schedules block fetches across the best
# sources, verifies each block, retries failures/timeouts and delivers in order.
add_library(mesh_stream_multisource STATIC
  src/mesh_stream_multisource.c
  src/mesh_stream_multisource.h)
target_include_directories(mesh_stream_multisource PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_multisource
  PUBLIC mesh_stream_source_selector
  PRIVATE TurboNet::Crypto)
set_property(TARGET mesh_stream_multisource PROPERTY FOLDER "mesh/internal")

# Stream service discovery: mesh-stream/mesh-sync dns-name convention and a
# bounded registry over the mgmt service record (epoch fenced, TTL expired).
add_library(mesh_stream_discovery STATIC
  src/mesh_stream_discovery.c
  src/mesh_stream_discovery.h)
target_include_directories(mesh_stream_discovery PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_discovery PUBLIC mesh_mgmt_service_record)
set_property(TARGET mesh_stream_discovery PROPERTY FOLDER "mesh/internal")

# Multi-source backing for the media range pull: the multisource block puller
# (P2) serves as the fetch io of mesh_stream_media_pull (P8).
add_library(mesh_stream_media_pull_multisource STATIC
  src/mesh_stream_media_pull_multisource.c
  src/mesh_stream_media_pull_multisource.h)
target_include_directories(mesh_stream_media_pull_multisource PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_media_pull_multisource
  PUBLIC mesh_stream_media_pull mesh_stream_multisource)
set_property(TARGET mesh_stream_media_pull_multisource PROPERTY FOLDER "mesh/internal")

# Live-over-HTTP core: sliding-window HLS live playlist over the live session.
add_library(mesh_stream_live_hls STATIC
  src/mesh_stream_live_hls.c
  src/mesh_stream_live_hls.h)
target_include_directories(mesh_stream_live_hls PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_live_hls PRIVATE TurboUtils::Core)
set_property(TARGET mesh_stream_live_hls PROPERTY FOLDER "mesh/internal")

# Multi-file software release manifest: versioned path -> gateway object key +
# object digest, canonical encode/decode + reproducible digest.
add_library(mesh_release STATIC
  src/mesh_release.c
  src/mesh_release.h)
target_include_directories(mesh_release PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_release
  PUBLIC m3_object_manifest
  PRIVATE TurboNet::Crypto TurboUtils::Core)
set_property(TARGET mesh_release PROPERTY FOLDER "mesh/internal")

# HLS-style playlist generation over the media index: media playlist with
# per-segment EXTINF + EXT-X-BYTERANGE (feeding mesh_stream_media_pull) and a
# master playlist over the ABR ladder.
add_library(mesh_media_playlist STATIC
  src/mesh_media_playlist.c
  src/mesh_media_playlist.h)
target_include_directories(mesh_media_playlist PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_media_playlist PUBLIC mesh_media_index)
set_property(TARGET mesh_media_playlist PROPERTY FOLDER "mesh/internal")

# On-demand media range pull: resolve a byte range to its chunk span via the
# media index and fetch/verify/assemble exactly those chunks (Range/206).
add_library(mesh_stream_media_pull STATIC
  src/mesh_stream_media_pull.c
  src/mesh_stream_media_pull.h)
target_include_directories(mesh_stream_media_pull PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_media_pull
  PUBLIC mesh_media_index
  PRIVATE TurboNet::Crypto TurboUtils::Core)
set_property(TARGET mesh_stream_media_pull PROPERTY FOLDER "mesh/internal")

# KCP transport binding for mesh_stream_live: live FEC -> turbo_kcp
# Reed-Solomon FEC config and a coro_socket-backed datagram io bridge.
add_library(mesh_stream_kcp_adapter STATIC
  src/mesh_stream_kcp_adapter.c
  src/mesh_stream_kcp_adapter.h)
target_include_directories(mesh_stream_kcp_adapter PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_kcp_adapter
  PUBLIC mesh_stream_live TurboNet::CoroNet)
set_property(TARGET mesh_stream_kcp_adapter PROPERTY FOLDER "mesh/internal")

# Per-peer stream QoS: flow-ruleset admission + sliding-window bandwidth and
# chunk statistics.
add_library(mesh_stream_qos STATIC
  src/mesh_stream_qos.c
  src/mesh_stream_qos.h)
target_include_directories(mesh_stream_qos PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_qos PUBLIC mesh_flow_ruleset)
set_property(TARGET mesh_stream_qos PROPERTY FOLDER "mesh/internal")

# Live edge streaming session: seq-numbered blocks with a bounded reorder
# window, LIVE_SKIP for blocks that are no longer recoverable, and an XOR
# erasure codec (the testable stand-in for the turbo_kcp Reed-Solomon FEC
# backend that a KCP-bound io adapter would enable).
add_library(mesh_stream_live STATIC
  src/mesh_stream_live.c
  src/mesh_stream_live.h)
target_include_directories(mesh_stream_live PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_stream_live PRIVATE TurboUtils::Core)
set_property(TARGET mesh_stream_live PROPERTY FOLDER "mesh/internal")

# Media segment index + ABR ladder: chunk-aligned segments over an M3
# manifest, byte-range -> chunk-span resolution (HTTP Range/206) and
# bandwidth-driven rendition selection.
add_library(mesh_media_index STATIC
  src/mesh_media_index.c
  src/mesh_media_index.h)
target_include_directories(mesh_media_index PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_media_index
  PUBLIC m3_object_manifest
  PRIVATE TurboNet::Crypto TurboUtils::Core)
set_property(TARGET mesh_media_index PROPERTY FOLDER "mesh/internal")

# File sync engine: manifest diff (fetch only missing chunks), progressive
# temp-file assembly with per-chunk verification, resume from a committed
# offset, and explicit conflict policies (last-writer-wins / keep-both).
add_library(mesh_sync_engine STATIC
  src/mesh_sync_engine.c
  src/mesh_sync_engine.h)
target_include_directories(mesh_sync_engine PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mesh_sync_engine
  PUBLIC m3_object_manifest
  PRIVATE TurboNet::Crypto TurboUtils::Core)
set_property(TARGET mesh_sync_engine PROPERTY FOLDER "mesh/internal")

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
target_link_libraries(mesh
  PUBLIC TurboUtils::Core TurboP2P::P2P
  PRIVATE mesh_mgmt_agent_router mesh_mgmt_crypto mesh_flow_ruleset
          TurboNet::Crypto)


target_link_libraries(mesh PRIVATE  TurboNet::Ice)
target_compile_definitions(mesh PUBLIC MESH_HAS_TURBO_ICE=1)
target_compile_definitions(mesh PRIVATE MESH_HAS_TURBO_ICE_CLOSE=1)

if(TURBOP2P_BUILD_TURBORAFT_M3)
  add_library(mesh_control_raft_mesh_bridge STATIC
    src/mesh_control_raft_mesh_bridge.c
    src/mesh_control_raft_mesh_bridge.h)
  target_include_directories(mesh_control_raft_mesh_bridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(mesh_control_raft_mesh_bridge PUBLIC
    mesh_control_raft mesh)
  set_property(TARGET mesh_control_raft_mesh_bridge
    PROPERTY FOLDER "mesh/internal")
endif()

# Shared-node management mode uses mesh's internal callback bridge while the
# dedicated runtime mode remains available for compatibility.
target_link_libraries(mesh_mgmt_agent_runtime PUBLIC mesh)

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

# Strict private-key file adapter for deployable daemon identities. It is
# available to daemon tests even when example executables are disabled.
add_library(meshd_key_file STATIC
  examples/meshd_key_file.c
  examples/meshd_key_file.h)
target_include_directories(meshd_key_file PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/examples)
target_link_libraries(meshd_key_file PRIVATE mesh_mgmt_crypto)
if(WIN32)
  target_link_libraries(meshd_key_file PRIVATE advapi32)
endif()
set_property(TARGET meshd_key_file PROPERTY FOLDER "mesh/internal")

if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(BUILD_TESTS)
  add_subdirectory(tests)
endif()
add_library(mesh_mgmt_execution_rpc_registry STATIC
    src/mesh_mgmt_execution_rpc_registry.c
)
target_include_directories(mesh_mgmt_execution_rpc_registry PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(mesh_mgmt_execution_rpc_registry PUBLIC
    mesh_mgmt_execution_response_consumer
)

add_library(mesh_mgmt_execution_rpc_control STATIC
    src/mesh_mgmt_execution_rpc_control.c
)
target_include_directories(mesh_mgmt_execution_rpc_control PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(mesh_mgmt_execution_rpc_control PUBLIC
    mesh_mgmt_execution_rpc_registry
    mesh_mgmt_execution_wire
)

add_library(mesh_mgmt_execution_disabled_responder STATIC
    src/mesh_mgmt_execution_disabled_responder.c
)
target_include_directories(mesh_mgmt_execution_disabled_responder PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(mesh_mgmt_execution_disabled_responder
    PUBLIC
        mesh_mgmt_execution_consumer
        mesh_mgmt_peer_signer
        mesh_mgmt_connection
    PRIVATE
        mesh_mgmt_crypto
)
