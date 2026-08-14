set(SOURCE_FILES)

include(NoiseC)
turbo_p2p_configure_noise_c()

file(GLOB_RECURSE API_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/api/*.c)
file(GLOB_RECURSE CACHE_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/cache/*.c)
file(GLOB_RECURSE CORE_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/core/*.c)
file(GLOB_RECURSE CRYPTO_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/*.c)
file(GLOB_RECURSE DHT_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/dht/*.c)
file(GLOB_RECURSE PROTOCOL_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/*.c)
file(GLOB_RECURSE SECURITY_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/security/*.c)
file(GLOB_RECURSE TRANSFER_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/transfer/*.c)

# Ignore stale source corpses that may exist in dirty worktrees on some hosts.
list(FILTER CORE_SOURCE_FILES EXCLUDE REGEX [[/handlers\.c$]])
list(FILTER API_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(FILTER CACHE_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(FILTER CORE_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(FILTER CRYPTO_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(FILTER DHT_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(FILTER PROTOCOL_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(FILTER SECURITY_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(FILTER SECURITY_SOURCE_FILES EXCLUDE REGEX [[/p2p_noise_c_platform\.c$]])
list(FILTER TRANSFER_SOURCE_FILES EXCLUDE REGEX [[/test_.*\.c$]])
list(REMOVE_ITEM CORE_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/core/test_p2p.c")

list(APPEND SOURCE_FILES
    ${API_SOURCE_FILES}
    ${CACHE_SOURCE_FILES}
    ${CORE_SOURCE_FILES}
    ${CRYPTO_SOURCE_FILES}
    ${DHT_SOURCE_FILES}
    ${PROTOCOL_SOURCE_FILES}
    ${SECURITY_SOURCE_FILES}
    ${TRANSFER_SOURCE_FILES})

file(GLOB_RECURSE HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h*)

# Build as shared library (DLL on Windows)
add_library(p2p SHARED ${SOURCE_FILES} ${HEADER_FILES}
 )
add_library(TurboP2P::P2P ALIAS p2p)
# Define SHARED_CXX when building as shared library (for DLL export/import)
target_compile_definitions(p2p PRIVATE SHARED_CXX)

target_include_directories(
  p2p
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include/p2p>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(
  p2p
  PUBLIC TurboUtils::Core TurboNet::CoroNet TurboParser::Parser
  PRIVATE OpenSSL::Crypto TurboNet::Crypto TurboP2P::NoiseProtocol roaring uthash)
if(NOT WIN32)
  target_link_libraries(p2p PRIVATE m)
else()
  target_link_libraries(p2p PRIVATE ws2_32)
endif()

set_property(TARGET p2p PROPERTY FOLDER "p2p")
set_target_properties(
  p2p
  PROPERTIES VERSION 1.0.0
             SOVERSION 1
             EXPORT_NAME P2P)

if(WIN32)
  set_target_properties(p2p PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Install
install(
  TARGETS p2p
  EXPORT TurboP2PTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
  DESTINATION include/p2p
  FILES_MATCHING
  PATTERN "*.h")

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
        DESTINATION share/turbo-p2p)

if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
# =============================================================================
# Tests
# =============================================================================

if(BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(TURBOP2P_BUILD_FUZZERS)
  target_compile_options(noise_protocol PRIVATE
                         -fsanitize=fuzzer-no-link,address)
  add_subdirectory(fuzz)
endif()
