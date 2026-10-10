cmake_minimum_required(VERSION 3.27)
project(TurboP2PSaltsFoundationTests LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
include(CTest)
get_filename_component(TURBOP2P_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
list(APPEND CMAKE_MODULE_PATH "${TURBOP2P_SOURCE_DIR}/cmake")
include(SaltsDependencies)
find_package(OpenSSL REQUIRED)

# Compile real production sources against installed SDKs without admitting a
# second network runtime. The complete migrated tunnel target is also built below.
set(mesh_src "${TURBOP2P_SOURCE_DIR}/mesh/src")
set(mesh_tests "${TURBOP2P_SOURCE_DIR}/mesh/tests")
add_subdirectory("${TURBOP2P_SOURCE_DIR}/vendor/monocypher" monocypher)
add_library(foundation STATIC
  "${mesh_src}/mesh_mgmt_codec.c"
  "${mesh_src}/mesh_mgmt_envelope.c"
  "${mesh_src}/mesh_mgmt_identity.c"
  "${mesh_src}/mesh_mgmt_session.c"
  "${mesh_src}/mesh_mgmt_replay.c"
  "${mesh_src}/mesh_mgmt_execution_wire.c"
  "${mesh_src}/mesh_mgmt_execution.c"
  "${mesh_src}/mesh_mgmt_execution_result.c"
  "${mesh_src}/mesh_mgmt_dispatch.c"
  "${mesh_src}/mesh_mgmt_execution_consumer.c"
  "${mesh_src}/mesh_mgmt_execution_response_consumer.c"
  "${mesh_src}/mesh_mgmt_transport.c"
  "${mesh_src}/mesh_mgmt_connection.c"
  "${mesh_src}/mesh_mgmt_peer.c"
  "${mesh_src}/mesh_mgmt_peer_signer.c"
  "${mesh_src}/mesh_mgmt_cnet_peer.c"
  "${mesh_src}/mesh_mgmt_crypto.c"
  "${mesh_src}/mesh_stream_bind.c"
  "${mesh_src}/mesh_stream_cnet_adapter.c"
  "${mesh_src}/mesh_control_primitives.c"
  "${mesh_src}/mesh_control_outbox.c"
  "${mesh_src}/mesh_stream_codec.c"
  "${mesh_src}/mesh_stream_session.c"
  "${mesh_src}/mesh_stream_transport.c"
  "${mesh_src}/mesh_stream_channel.c"
  "${mesh_src}/mesh_stream_registry.c"
  "${mesh_src}/mesh_stream_data.c"
  "${mesh_src}/mesh_stream_multisource.c"
  "${mesh_src}/mesh_stream_source_selector.c"
  "${mesh_src}/m3_object_manifest.c"
  "${mesh_src}/mesh_media_index.c"
  "${mesh_src}/mesh_media_playlist.c"
  "${mesh_src}/mesh_release.c"
  "${mesh_src}/mesh_stream_media_pull.c"
  "${mesh_src}/mesh_stream_media_pull_multisource.c")
target_include_directories(foundation PUBLIC "${mesh_src}")
target_link_libraries(foundation PUBLIC
  Salts::CSTL Salts::Platform Salts::Crypto Salts::CNet OpenSSL::Crypto monocypher)

foreach(test_name IN ITEMS
  test_mesh_mgmt_session
  test_mesh_mgmt_transport
  test_mesh_mgmt_peer_signer
  test_mesh_mgmt_crypto
  test_mesh_stream_bind
  test_mesh_stream_channel
  test_mesh_stream_registry
  test_mesh_control_outbox
  test_mesh_stream_transport
  test_mesh_stream_data
  test_mesh_stream_source_selector
  test_mesh_media_index
  test_mesh_media_playlist
  test_mesh_release
  test_mesh_stream_media_pull
  test_mesh_stream_media_pull_multisource)
  add_executable(${test_name} "${mesh_tests}/${test_name}.c")
  set_property(TARGET ${test_name} PROPERTY LINKER_LANGUAGE CXX)
  target_link_libraries(${test_name} PRIVATE foundation Salts::TinyTest)
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

add_executable(test_salts_sha256 test_salts_sha256.c)
set_property(TARGET test_salts_sha256 PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_salts_sha256 PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME test_salts_sha256 COMMAND test_salts_sha256)

foreach(test_name IN ITEMS test_mesh_mgmt_cnet_tls_policy test_mesh_mgmt_cnet_peer test_mesh_stream_cnet test_mesh_stream_cnet_bind test_mesh_stream_cnet_channel test_mesh_stream_cnet_registry)
  add_executable(${test_name} "${mesh_tests}/${test_name}.c")
  set_property(TARGET ${test_name} PROPERTY LINKER_LANGUAGE CXX)
  target_link_libraries(${test_name} PRIVATE foundation Salts::TinyTest Salts::CNet)
  if(NOT test_name STREQUAL "test_mesh_stream_cnet")
    target_link_libraries(${test_name} PRIVATE OpenSSL::SSL)
  endif()
  target_compile_definitions(${test_name} PRIVATE
    MESH_TEST_TLS_CERT_FILE="${mesh_tests}/data/cnet-server-cert.pem"
    MESH_TEST_TLS_CA_FILE="${mesh_tests}/data/cnet-ca-cert.pem"
    MESH_TEST_TLS_KEY_FILE="${mesh_tests}/data/cnet-server-key.pem")
  add_test(NAME ${test_name} COMMAND ${test_name})
  set_tests_properties(${test_name} PROPERTIES TIMEOUT 60)
endforeach()

# Compile the complete tunnel product path, including platform TUN sources.
set(BUILD_TESTS ON)
set(BUILD_EXAMPLES OFF)
add_subdirectory("${TURBOP2P_SOURCE_DIR}/tunnel" tunnel)

# Compile the P2P security production closure before migrating its network owner.
include(NoiseC)
turbo_p2p_configure_noise_c()
target_link_libraries(test_salts_sha256 PRIVATE TurboP2P::NoiseProtocol)
add_library(p2p_security STATIC
  "${TURBOP2P_SOURCE_DIR}/p2p/src/crypto/p2p_crypto.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/security/p2p_cookie.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/security/p2p_key_worker.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/security/p2p_noise_backend.c")
target_include_directories(p2p_security PUBLIC
  "${TURBOP2P_SOURCE_DIR}/p2p/src"
  "${TURBOP2P_SOURCE_DIR}/p2p/include")
target_link_libraries(p2p_security PUBLIC Salts::Core Salts::Platform Salts::Concurrency
  OpenSSL::Crypto monocypher TurboP2P::NoiseProtocol)
if(WIN32)
  target_link_libraries(p2p_security PUBLIC ws2_32)
endif()
add_executable(test_p2p_security
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_security.c")
set_property(TARGET test_p2p_security PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_security PRIVATE p2p_security Salts::TinyTest)
add_test(NAME test_p2p_security COMMAND test_p2p_security)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(test_p2p_security PRIVATE P2P_TEST_WRAP_RANDOM)
  target_link_options(test_p2p_security PRIVATE
    "-Wl,--wrap=cmeta_platform_secure_random")
endif()

add_library(p2p_cnet_transport STATIC
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/connection.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/cnet_transport.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/cnet_sg_ace.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/security/p2p_cnet_admission.c")
target_include_directories(p2p_cnet_transport PUBLIC
  "${TURBOP2P_SOURCE_DIR}/p2p/src" "${TURBOP2P_SOURCE_DIR}/p2p/include")
target_link_libraries(p2p_cnet_transport PUBLIC Salts::CNet Salts::CMeta Salts::Core p2p_security)
# Installed-SDK C11/C++17 conformance for typed CMeta ACE SG admission hints.
add_executable(test_p2p_cnet_ace_placement
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_ace_placement.c")
set_property(TARGET test_p2p_cnet_ace_placement PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_ace_placement PRIVATE
  p2p_cnet_transport Salts::TinyTest)
add_test(NAME test_p2p_cnet_ace_placement COMMAND test_p2p_cnet_ace_placement)
add_executable(test_p2p_cnet_ace_placement_cpp
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_ace_placement_cpp.cpp")
set_property(TARGET test_p2p_cnet_ace_placement_cpp PROPERTY LINKER_LANGUAGE CXX)
target_include_directories(test_p2p_cnet_ace_placement_cpp PRIVATE
  "${TURBOP2P_SOURCE_DIR}/p2p/src")
target_link_libraries(test_p2p_cnet_ace_placement_cpp PRIVATE
  p2p_cnet_transport)
add_test(NAME test_p2p_cnet_ace_placement_cpp COMMAND test_p2p_cnet_ace_placement_cpp)

add_executable(test_p2p_cnet_transport
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_transport.c")
set_property(TARGET test_p2p_cnet_transport PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_transport PRIVATE
  p2p_cnet_transport p2p_security Salts::TinyTest Salts::Platform)
add_test(NAME test_p2p_cnet_transport COMMAND test_p2p_cnet_transport)
set_tests_properties(test_p2p_cnet_transport PROPERTIES TIMEOUT 60)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(test_p2p_cnet_transport PRIVATE P2P_CNET_TEST_WRAP)
  target_link_options(test_p2p_cnet_transport PRIVATE
    "-Wl,--wrap=cnet_connect_peer" "-Wl,--wrap=cnet_close"
    "-Wl,--wrap=cnet_send_buffer" "-Wl,--wrap=cnet_client_stop")
endif()

add_executable(test_p2p_cnet_admission
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_admission.c")
set_property(TARGET test_p2p_cnet_admission PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_admission PRIVATE
  p2p_cnet_transport Salts::TinyTest Salts::Platform)
add_test(NAME test_p2p_cnet_admission COMMAND test_p2p_cnet_admission)
set_tests_properties(test_p2p_cnet_admission PROPERTIES TIMEOUT 60)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(test_p2p_cnet_admission PRIVATE P2P_ADMISSION_TEST_WRAP)
  target_link_options(test_p2p_cnet_admission PRIVATE
    "-Wl,--wrap=cnet_manager_reserve" "-Wl,--wrap=cnet_send_buffer")
endif()

add_executable(test_p2p_key_worker
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_key_worker.c")
set_property(TARGET test_p2p_key_worker PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_key_worker PRIVATE p2p_security Salts::TinyTest)
add_test(NAME test_p2p_key_worker COMMAND test_p2p_key_worker)
set_tests_properties(test_p2p_key_worker PROPERTIES TIMEOUT 60)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(test_p2p_key_worker PRIVATE P2P_KEY_WORKER_TEST_WRAP)
  target_link_options(test_p2p_key_worker PRIVATE
    "-Wl,--wrap=cmeta_threadpool_try_submit_task")
endif()

# Compile the actual peer, codec and node-bound executor with CNet. Test doubles
# provide only node policy/events; no peer, crypto or transport implementation.
add_library(p2p_peer_core STATIC
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/peer.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/peer_cnet.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/protocol/message.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/security/p2p_private_key_executor.c")
target_include_directories(p2p_peer_core PUBLIC "${TURBOP2P_SOURCE_DIR}/vendor/uthash/src")
target_link_libraries(p2p_peer_core PUBLIC p2p_cnet_transport Salts::Concurrency)
add_executable(test_p2p_cnet_peer "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_peer.c")
set_property(TARGET test_p2p_cnet_peer PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_peer PRIVATE p2p_peer_core Salts::TinyTest)
add_test(NAME test_p2p_cnet_peer COMMAND test_p2p_cnet_peer)
set_tests_properties(test_p2p_cnet_peer PROPERTIES TIMEOUT 60)

# Production node network policy, routing handlers and explicit CNet owner.
# Shared node/configuration, public polling and file handlers are real;
# public construction and blocking start still require the legacy runtime.
add_subdirectory("${TURBOP2P_SOURCE_DIR}/vendor/croar" croar)
add_library(p2p_node_core STATIC
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/node_state.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/file.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/api/p2p_file_api.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/api/p2p_dht_api.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/api/p2p_loop_api.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/api/p2p_lifecycle_api.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/api/p2p_security_api.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/api/p2p_peer_api.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/protocol/handlers_transfer.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/transfer/transfer.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/transfer/sender.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/transfer/receiver.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/transfer/bitmap.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/transfer/sha256.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/node_network.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/node_cnet.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/peer_table.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/protocol/handlers.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/dht/kademlia.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/dht/kademlia_rpc.c"
  "${TURBOP2P_SOURCE_DIR}/p2p/src/core/vivaldi.c")
target_link_libraries(p2p_node_core PUBLIC p2p_peer_core roaring PRIVATE Salts::Crypto)
if(NOT WIN32)
  target_link_libraries(p2p_node_core PUBLIC m)
endif()
add_executable(test_p2p_cnet_node "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_node.c")
set_property(TARGET test_p2p_cnet_node PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_node PRIVATE p2p_node_core Salts::TinyTest)
add_test(NAME test_p2p_cnet_node COMMAND test_p2p_cnet_node)
set_tests_properties(test_p2p_cnet_node PROPERTIES TIMEOUT 60)
add_executable(test_p2p_cnet_files "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_files.c")
set_property(TARGET test_p2p_cnet_files PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_files PRIVATE p2p_node_core Salts::TinyTest)
add_test(NAME test_p2p_cnet_files COMMAND test_p2p_cnet_files)
set_tests_properties(test_p2p_cnet_files PROPERTIES TIMEOUT 60)
add_executable(test_p2p_cnet_security_config "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_security_config.c")
set_property(TARGET test_p2p_cnet_security_config PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_security_config PRIVATE p2p_node_core Salts::TinyTest)
add_test(NAME test_p2p_cnet_security_config COMMAND test_p2p_cnet_security_config)
set_tests_properties(test_p2p_cnet_security_config PROPERTIES TIMEOUT 60)
add_executable(test_p2p_cnet_dht "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_dht.c")
set_property(TARGET test_p2p_cnet_dht PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_dht PRIVATE p2p_node_core Salts::TinyTest)
add_test(NAME test_p2p_cnet_dht COMMAND test_p2p_cnet_dht)
set_tests_properties(test_p2p_cnet_dht PROPERTIES TIMEOUT 60)
# Cross-Owner accepted TCP handoff through real CNet queues; the final
# Owner runs actual node cookie + Noise authentication, not just policy ABI.
add_executable(test_p2p_cnet_sg_handoff
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_sg_handoff.c")
set_property(TARGET test_p2p_cnet_sg_handoff PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_sg_handoff PRIVATE
  p2p_node_core Salts::CNet Salts::TinyTest)
add_test(NAME test_p2p_cnet_sg_handoff COMMAND test_p2p_cnet_sg_handoff)
set_tests_properties(test_p2p_cnet_sg_handoff PROPERTIES TIMEOUT 60)

# Real NativeIO SG Host with authoritative completion observe/routing and
# final P2P CNet Owner cookie/Noise, not a second NativeIO backend.
add_executable(test_p2p_cnet_sg_host
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_sg_host.c")
set_property(TARGET test_p2p_cnet_sg_host PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_sg_host PRIVATE
  p2p_node_core Salts::CNet Salts::TinyTest)
add_test(NAME test_p2p_cnet_sg_host COMMAND test_p2p_cnet_sg_host)
set_tests_properties(test_p2p_cnet_sg_host PROPERTIES TIMEOUT 90)

# Four *actual* SG NativeIO workers, three distinct final P2P Owners,
# credited cross-shard TCP, and real Noise identity/data callback affinity.
add_executable(test_p2p_cnet_sg_host_four
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_sg_host_four.c")
set_property(TARGET test_p2p_cnet_sg_host_four PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_sg_host_four PRIVATE
  p2p_node_core Salts::CNet Salts::TinyTest)
add_test(NAME test_p2p_cnet_sg_host_four COMMAND test_p2p_cnet_sg_host_four)
set_tests_properties(test_p2p_cnet_sg_host_four PROPERTIES TIMEOUT 90)

# One native SG Host observes/composes a P2P CNet client + a SECOND real
# independently configured external CNet client on the SAME shard backend.
add_executable(test_p2p_cnet_sg_cohost
  "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_sg_cohost.c")
set_property(TARGET test_p2p_cnet_sg_cohost PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_sg_cohost PRIVATE
  p2p_node_core Salts::CNet Salts::TinyTest)
add_test(NAME test_p2p_cnet_sg_cohost COMMAND test_p2p_cnet_sg_cohost)
set_tests_properties(test_p2p_cnet_sg_cohost PROPERTIES TIMEOUT 90)


# Opt-in signed-MMP READY-gated encrypted data echo: exactly FOUR distinct
# authenticated clients at 1 / 2 / 4 Final SG Owners plus one acceptor.
# All profiles reserve exactly four total Final CNet/Pool connections.
# Benchmarks are NOT Release CTest and do NOT imply raw CNet/MMP RPC latency.
option(P2P_MMP_SG_BUILD_BENCHMARKS "Build equal-load signed SG Pool benchmarks" OFF)
if(P2P_MMP_SG_BUILD_BENCHMARKS)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Signed SG benchmark requires Linux process CPU clock")
  endif()
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_mesh_mmp_sg_${finals}
      "${mesh_tests}/../bench/bench_mesh_mmp_sg_pool.c")
    set_property(TARGET bench_mesh_mmp_sg_${finals} PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_mesh_mmp_sg_${finals}
      PRIVATE BENCH_MMP_FINALS=${finals})
    target_include_directories(bench_mesh_mmp_sg_${finals} PRIVATE
      "${mesh_tests}")
    target_link_libraries(bench_mesh_mmp_sg_${finals} PRIVATE
      mgmt_agent_runtime p2p_node_core Salts::CNet Salts::TinyTest)
  endforeach()
  # Paired independent SG progress against the EXACT same signed identity
  # fixture, payloads, warmup, message counts, and original CNet credit policy.
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_mesh_mmp_sg_${finals}_async
      "${mesh_tests}/../bench/bench_mesh_mmp_sg_pool.c")
    set_property(TARGET bench_mesh_mmp_sg_${finals}_async PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_mesh_mmp_sg_${finals}_async
      PRIVATE BENCH_MMP_FINALS=${finals} BENCH_ASYNC_PROGRESS=1)
    target_include_directories(bench_mesh_mmp_sg_${finals}_async PRIVATE
      "${mesh_tests}")
    target_link_libraries(bench_mesh_mmp_sg_${finals}_async PRIVATE
      mgmt_agent_runtime p2p_node_core Salts::CNet Salts::TinyTest)
  endforeach()
endif()

# Opt-in true raw CNet TCP baseline. Same four accepted physical
# sessions and 1/2/4 final SG workers (+1 acceptor), but deliberately
# no Noise/MMP/ClientPool; do not compare to encrypted RPC blindly.
option(P2P_RAW_CNET_SG_BUILD_BENCHMARKS "Build raw CNet SG TCP baselines" OFF)
if(P2P_RAW_CNET_SG_BUILD_BENCHMARKS)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Raw CNet SG baseline requires Linux CPU clock")
  endif()
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_raw_cnet_sg_${finals}
      "${mesh_tests}/../bench/bench_raw_cnet_sg_echo.c")
    set_property(TARGET bench_raw_cnet_sg_${finals} PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_raw_cnet_sg_${finals}
      PRIVATE BENCH_RAW_FINALS=${finals})
    target_link_libraries(bench_raw_cnet_sg_${finals} PRIVATE
      Salts::CNet Salts::TinyTest)
  endforeach()
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_raw_cnet_sg_${finals}_async
      "${mesh_tests}/../bench/bench_raw_cnet_sg_echo.c")
    set_property(TARGET bench_raw_cnet_sg_${finals}_async PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_raw_cnet_sg_${finals}_async
      PRIVATE BENCH_RAW_FINALS=${finals} BENCH_RAW_ASYNC_PROGRESS=1)
    target_link_libraries(bench_raw_cnet_sg_${finals}_async PRIVATE
      Salts::CNet Salts::TinyTest)
  endforeach()
  # True application session-independent workload, still exactly 4 sessions.
  # Run separately from the batch-barrier fixture; do not conflate the two
  # different offered-load models when claiming SG multicore scaling.
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_raw_cnet_sg_${finals}_sessions
      "${mesh_tests}/../bench/bench_raw_cnet_sg_echo.c")
    set_property(TARGET bench_raw_cnet_sg_${finals}_sessions PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_raw_cnet_sg_${finals}_sessions
      PRIVATE BENCH_RAW_FINALS=${finals} BENCH_APP_INDEPENDENT=1)
    target_link_libraries(bench_raw_cnet_sg_${finals}_sessions PRIVATE
      Salts::CNet Salts::TinyTest)
    add_executable(bench_raw_cnet_sg_${finals}_async_sessions
      "${mesh_tests}/../bench/bench_raw_cnet_sg_echo.c")
    set_property(TARGET bench_raw_cnet_sg_${finals}_async_sessions PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_raw_cnet_sg_${finals}_async_sessions
      PRIVATE BENCH_RAW_FINALS=${finals} BENCH_RAW_ASYNC_PROGRESS=1 BENCH_APP_INDEPENDENT=1)
    target_link_libraries(bench_raw_cnet_sg_${finals}_async_sessions PRIVATE
      Salts::CNet Salts::TinyTest)
  endforeach()
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_mesh_mmp_sg_${finals}_sessions
      "${mesh_tests}/../bench/bench_mesh_mmp_sg_pool.c")
    set_property(TARGET bench_mesh_mmp_sg_${finals}_sessions PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_mesh_mmp_sg_${finals}_sessions PRIVATE
      BENCH_MMP_FINALS=${finals} BENCH_APP_INDEPENDENT=1)
    target_include_directories(bench_mesh_mmp_sg_${finals}_sessions PRIVATE "${mesh_tests}")
    target_link_libraries(bench_mesh_mmp_sg_${finals}_sessions PRIVATE
      mgmt_agent_runtime p2p_node_core Salts::CNet Salts::TinyTest)
    add_executable(bench_mesh_mmp_sg_${finals}_async_sessions
      "${mesh_tests}/../bench/bench_mesh_mmp_sg_pool.c")
    set_property(TARGET bench_mesh_mmp_sg_${finals}_async_sessions PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_mesh_mmp_sg_${finals}_async_sessions PRIVATE
      BENCH_MMP_FINALS=${finals} BENCH_ASYNC_PROGRESS=1 BENCH_APP_INDEPENDENT=1)
    target_include_directories(bench_mesh_mmp_sg_${finals}_async_sessions PRIVATE "${mesh_tests}")
    target_link_libraries(bench_mesh_mmp_sg_${finals}_async_sessions PRIVATE
      mgmt_agent_runtime p2p_node_core Salts::CNet Salts::TinyTest)
  endforeach()
endif()

# Optional pure Noise/P2P echo stage between raw CNet and signed MMP
# (four authenticated transport connections; 1/2/4 SG Final workers).
option(P2P_NOISE_SG_BUILD_BENCHMARKS "Build four-session Noise-only SG echo" OFF)
if(P2P_NOISE_SG_BUILD_BENCHMARKS)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Noise-only SG benchmark requires Linux CPU clock")
  endif()
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_noise_sg_${finals}
      "${mesh_tests}/../bench/bench_noise_sg_echo.c")
    set_property(TARGET bench_noise_sg_${finals} PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_noise_sg_${finals}
      PRIVATE NOISE_BENCH_FINALS=${finals})
    target_link_libraries(bench_noise_sg_${finals}
      PRIVATE p2p_node_core Salts::CNet Salts::TinyTest)
  endforeach()
  foreach(finals IN ITEMS 1 2 4)
    add_executable(bench_noise_sg_${finals}_async
      "${mesh_tests}/../bench/bench_noise_sg_echo.c")
    set_property(TARGET bench_noise_sg_${finals}_async PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_noise_sg_${finals}_async PRIVATE
      NOISE_BENCH_FINALS=${finals} NOISE_ASYNC_PROGRESS=1)
    target_link_libraries(bench_noise_sg_${finals}_async
      PRIVATE p2p_node_core Salts::CNet Salts::TinyTest)
  endforeach()
endif()

# Benchmark-only installed SDK profile, isolated from Release and ASan CTest.
# Topologies 1/2/4 have respectively 1/1/3 authenticated connections; use
# the session column rather than claiming equal-load CPU scaling.
option(P2P_SG_BUILD_BENCHMARKS "Build opt-in SG NativeIO/Noise benchmarks" OFF)
if(P2P_SG_BUILD_BENCHMARKS)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "P2P SG benchmark requires Linux process CPU clock")
  endif()
  foreach(_shards IN ITEMS 1 2 4)
    add_executable(bench_p2p_sg_${_shards}
      "${TURBOP2P_SOURCE_DIR}/p2p/bench/bench_p2p_sg_owner.c")
    set_property(TARGET bench_p2p_sg_${_shards} PROPERTY LINKER_LANGUAGE CXX)
    target_compile_definitions(bench_p2p_sg_${_shards} PRIVATE BENCH_SG_SHARDS=${_shards})
    target_include_directories(bench_p2p_sg_${_shards} PRIVATE
      "${TURBOP2P_SOURCE_DIR}/p2p/tests")
    target_link_libraries(bench_p2p_sg_${_shards}
      PRIVATE p2p_node_core Salts::CNet Salts::TinyTest)
  endforeach()
  # Same one authenticated session as the 1- and 2-shard rows, but with
  # three installed final Owners, two deliberately idle during measurement.
  add_executable(bench_p2p_sg_4_1
    "${TURBOP2P_SOURCE_DIR}/p2p/bench/bench_p2p_sg_owner.c")
  set_property(TARGET bench_p2p_sg_4_1 PROPERTY LINKER_LANGUAGE CXX)
  target_compile_definitions(bench_p2p_sg_4_1
    PRIVATE BENCH_SG_SHARDS=4 BENCH_ACTIVE_SESSIONS=1)
  target_include_directories(bench_p2p_sg_4_1 PRIVATE
    "${TURBOP2P_SOURCE_DIR}/p2p/tests")
  target_link_libraries(bench_p2p_sg_4_1
    PRIVATE p2p_node_core Salts::CNet Salts::TinyTest)
  # Paired hot-path comparison: independent bounded SG tasks, no global wait
  # during measured rounds. The setup/teardown retains safe drain barriers.
  foreach(_profile IN ITEMS 1 2 4 4_1)
    add_executable(bench_p2p_sg_${_profile}_async
      "${TURBOP2P_SOURCE_DIR}/p2p/bench/bench_p2p_sg_owner.c")
    set_property(TARGET bench_p2p_sg_${_profile}_async PROPERTY LINKER_LANGUAGE CXX)
    if(_profile STREQUAL "4_1")
      target_compile_definitions(bench_p2p_sg_${_profile}_async PRIVATE
        BENCH_SG_SHARDS=4 BENCH_ACTIVE_SESSIONS=1 BENCH_ASYNC_PROGRESS=1)
    else()
      target_compile_definitions(bench_p2p_sg_${_profile}_async PRIVATE
        BENCH_SG_SHARDS=${_profile} BENCH_ASYNC_PROGRESS=1)
    endif()
    target_include_directories(bench_p2p_sg_${_profile}_async PRIVATE
      "${TURBOP2P_SOURCE_DIR}/p2p/tests")
    target_link_libraries(bench_p2p_sg_${_profile}_async
      PRIVATE p2p_node_core Salts::CNet Salts::TinyTest)
  endforeach()
endif()

add_executable(test_p2p_cnet_lifecycle "${TURBOP2P_SOURCE_DIR}/p2p/tests/test_p2p_cnet_lifecycle.c")
set_property(TARGET test_p2p_cnet_lifecycle PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_p2p_cnet_lifecycle PRIVATE p2p_node_core Salts::TinyTest)
add_test(NAME test_p2p_cnet_lifecycle COMMAND test_p2p_cnet_lifecycle)
set_tests_properties(test_p2p_cnet_lifecycle PROPERTIES TIMEOUT 60)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(test_p2p_cnet_lifecycle PRIVATE P2P_LIFECYCLE_TEST_WRAP)
  target_link_options(test_p2p_cnet_lifecycle PRIVATE
    "-Wl,--wrap=cnet_client_stop" "-Wl,--wrap=p2p_crypto_generate_identity" "-Wl,--wrap=calloc")
  target_compile_definitions(test_p2p_cnet_dht PRIVATE P2P_DHT_TEST_WRAP)
  target_link_options(test_p2p_cnet_dht PRIVATE "-Wl,--wrap=malloc")
  target_compile_definitions(test_p2p_cnet_node PRIVATE P2P_NODE_TEST_WRAP)
  target_link_options(test_p2p_cnet_node PRIVATE
    "-Wl,--wrap=cnet_client_stop" "-Wl,--wrap=cnet_client_poll")
  target_compile_definitions(test_p2p_cnet_files PRIVATE P2P_FILES_TEST_WRAP)
  target_link_options(test_p2p_cnet_files PRIVATE "-Wl,--wrap=p2p_peer_send")
endif()

# Real dedicated management composition: no legacy mesh or fake bridge symbols.
add_library(mgmt_agent_runtime STATIC
  "${mesh_src}/mesh_mgmt_agent_runtime.c"
  "${mesh_src}/mesh_mgmt_agent_router.c"
  "${mesh_src}/mesh_mgmt_endpoint_pool.c"
  "${mesh_src}/mesh_mgmt_endpoint_record.c"
  "${mesh_src}/mesh_mgmt_endpoint_publisher.c"
  "${mesh_src}/mesh_mgmt_service_record.c"
  "${mesh_src}/mesh_mgmt_service_publisher.c"
  "${mesh_src}/mesh_mgmt_p2p_adapter.c"
  "${mesh_src}/mesh_mgmt_p2p_peer.c"
  "${mesh_src}/mesh_mgmt_p2p_security.c"
  "${mesh_src}/mesh_mgmt_execution_disabled_responder.c")
target_link_libraries(mgmt_agent_runtime PUBLIC foundation p2p_node_core Salts::CNet)

# Strict DataBind Configurator compiles to a fully owned CNet policy before
# any network Owner callback; no JSON runtime in the P2P data path.
add_library(mesh_mgmt_client_config STATIC
  "${mesh_src}/mesh_mgmt_client_config.c")
target_include_directories(mesh_mgmt_client_config PUBLIC "${mesh_src}")
target_link_libraries(mesh_mgmt_client_config PUBLIC mgmt_agent_runtime
  PRIVATE Salts::DataBind)
add_executable(test_mesh_mgmt_client_config
  "${mesh_tests}/test_mesh_mgmt_client_config.c")
set_property(TARGET test_mesh_mgmt_client_config PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_mesh_mgmt_client_config PRIVATE
  mesh_mgmt_client_config Salts::TinyTest)
add_test(NAME test_mesh_mgmt_client_config COMMAND test_mesh_mgmt_client_config)
set_tests_properties(test_mesh_mgmt_client_config PROPERTIES TIMEOUT 60)

# Host ACE typed RPC service Configurator validates against production
# MMP service encoder. Dynamic DataBind ownership never enters P2P receive/send.
add_library(mesh_mgmt_service_config STATIC
  "${mesh_src}/mesh_mgmt_service_config.c")
target_include_directories(mesh_mgmt_service_config PUBLIC "${mesh_src}")
target_link_libraries(mesh_mgmt_service_config PUBLIC mgmt_agent_runtime
  PRIVATE Salts::DataBind)
add_executable(test_mesh_mgmt_service_config
  "${mesh_tests}/test_mesh_mgmt_service_config.c")
set_property(TARGET test_mesh_mgmt_service_config PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_mesh_mgmt_service_config PRIVATE
  mesh_mgmt_service_config Salts::TinyTest)
add_test(NAME test_mesh_mgmt_service_config COMMAND test_mesh_mgmt_service_config)
add_executable(test_mesh_mgmt_service_config_cpp
  "${mesh_tests}/test_mesh_mgmt_service_config_cpp.cpp")
set_property(TARGET test_mesh_mgmt_service_config_cpp PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_mesh_mgmt_service_config_cpp PRIVATE mesh_mgmt_service_config)
add_test(NAME test_mesh_mgmt_service_config_cpp COMMAND test_mesh_mgmt_service_config_cpp)
set_tests_properties(test_mesh_mgmt_service_config_cpp PROPERTIES TIMEOUT 60)

set_tests_properties(test_mesh_mgmt_service_config PROPERTIES TIMEOUT 60)

add_executable(test_mesh_mgmt_destination_policy
  "${mesh_tests}/test_mesh_mgmt_destination_policy.c")
set_property(TARGET test_mesh_mgmt_destination_policy PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_mesh_mgmt_destination_policy PRIVATE
  mgmt_agent_runtime Salts::TinyTest)
add_test(NAME test_mesh_mgmt_destination_policy COMMAND test_mesh_mgmt_destination_policy)
set_tests_properties(test_mesh_mgmt_destination_policy PROPERTIES TIMEOUT 60)
# Exact native SG Host final-owner with a production signed Noise/MMP
# Router + ClientPool Runtime, not a standalone raw P2P Owner or fake READY.
add_executable(test_mesh_mgmt_sg_runtime
  "${mesh_tests}/test_mesh_mgmt_sg_runtime.c")
set_property(TARGET test_mesh_mgmt_sg_runtime PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_mesh_mgmt_sg_runtime PRIVATE
  mgmt_agent_runtime p2p_node_core Salts::CNet Salts::TinyTest)
add_test(NAME test_mesh_mgmt_sg_runtime COMMAND test_mesh_mgmt_sg_runtime)
set_tests_properties(test_mesh_mgmt_sg_runtime PROPERTIES TIMEOUT 90)

# 2 and 4 independent SG final signed MMP ClientPools on 3/5 native
# workers (including one acceptor): exact physical Manager, per-final
# exclusive Lease, wrong-owner denial and checked Stop/Destroy.
add_executable(test_mesh_mgmt_sg_multi_runtime
  "${mesh_tests}/test_mesh_mgmt_sg_multi_runtime.c")
set_property(TARGET test_mesh_mgmt_sg_multi_runtime PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_mesh_mgmt_sg_multi_runtime PRIVATE
  mgmt_agent_runtime p2p_node_core Salts::CNet Salts::TinyTest)
add_test(NAME test_mesh_mgmt_sg_multi_runtime
  COMMAND test_mesh_mgmt_sg_multi_runtime)
set_tests_properties(test_mesh_mgmt_sg_multi_runtime PROPERTIES TIMEOUT 120)

# The compatibility entry point must compile too; linking/running shared mesh
# still requires the complete root build.
add_library(mgmt_mesh_bridge_compile OBJECT "${mesh_src}/mesh_mgmt_agent_runtime_mesh.c")
target_include_directories(mgmt_mesh_bridge_compile PRIVATE "${TURBOP2P_SOURCE_DIR}/mesh/include")
target_link_libraries(mgmt_mesh_bridge_compile PRIVATE mgmt_agent_runtime)
add_executable(test_mesh_mgmt_cnet_runtime "${mesh_tests}/test_mesh_mgmt_cnet_runtime.c")
set_property(TARGET test_mesh_mgmt_cnet_runtime PROPERTY LINKER_LANGUAGE CXX)
target_link_libraries(test_mesh_mgmt_cnet_runtime PRIVATE mgmt_agent_runtime mesh_mgmt_client_config mesh_mgmt_service_config Salts::TinyTest)
add_test(NAME test_mesh_mgmt_cnet_runtime COMMAND test_mesh_mgmt_cnet_runtime)
set_tests_properties(test_mesh_mgmt_cnet_runtime PROPERTIES TIMEOUT 60)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(test_mesh_mgmt_cnet_runtime PRIVATE MESH_MGMT_RUNTIME_TEST_WRAP)
  target_link_options(test_mesh_mgmt_cnet_runtime PRIVATE
    "-Wl,--wrap=cnet_client_stop" "-Wl,--wrap=p2p_destroy_v2")
endif()

# Qualify the installed Salts 2.3 CNet policy ABI and SaltsUtils 4.3
# DataBind/CMeta ABI without requiring the legacy TurboNet root build.
foreach(language IN ITEMS c cpp)
  set(target test_salts_23_contracts)
  if(language STREQUAL "cpp")
    set(target test_salts_23_contracts_cpp)
  endif()
  add_executable(${target} "test_salts_23_contracts.${language}")
  set_property(TARGET ${target} PROPERTY LINKER_LANGUAGE CXX)
  target_link_libraries(${target} PRIVATE Salts::CNet Salts::DataBind Salts::CMeta)
  add_test(NAME ${target} COMMAND ${target})
endforeach()
