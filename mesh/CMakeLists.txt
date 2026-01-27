project(mesh C)

# =============================================================================
# Mesh Library
# =============================================================================

# Mesh library sources
set(MESH_LIB_SOURCES src/mesh.c src/stb_sprintf.c include/turbo_mesh.h)

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
target_link_libraries(mesh PUBLIC TurboNet::Utils TurboP2P::P2P)

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

add_subdirectory(examples)
add_subdirectory(tests)
