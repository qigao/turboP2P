file(GLOB_RECURSE SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c*)
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
         $<INSTALL_INTERFACE:include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src   )
target_link_libraries(
  p2p
  PUBLIC TurboNet::Utils TurboNet::Core TurboNet::Parser
  PRIVATE monocypher TurboNet::Ice roaring uthash)

set_property(TARGET p2p PROPERTY FOLDER "p2p")
set_target_properties(
  p2p
  PROPERTIES VERSION 1.0.0
             SOVERSION 1
             EXPORT_NAME P2P)

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

add_subdirectory(examples)
# =============================================================================
# Tests
# =============================================================================

add_subdirectory(tests)
