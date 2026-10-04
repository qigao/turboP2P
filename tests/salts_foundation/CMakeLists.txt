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

# These two vector owners still call P2P/management adapters. Compile-check
# their new CSTL contracts here; their lifecycle tests require the root build.
add_library(vector_owners OBJECT
  "${mesh_src}/mesh_mgmt_endpoint_pool.c"
  "${mesh_src}/mesh_mgmt_agent_router.c")
target_include_directories(vector_owners PRIVATE
  "${mesh_src}" "${TURBOP2P_SOURCE_DIR}/p2p/include")
target_link_libraries(vector_owners PRIVATE Salts::CSTL Salts::Platform Salts::Core)

foreach(test_name IN ITEMS
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

foreach(test_name IN ITEMS test_mesh_stream_cnet test_mesh_stream_cnet_bind test_mesh_stream_cnet_channel test_mesh_stream_cnet_registry)
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
