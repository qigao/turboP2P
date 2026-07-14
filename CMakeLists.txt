cmake_minimum_required(VERSION 3.20)
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 OLD)
endif()
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()

project(
  TurboP2P
  VERSION 1.0.0
  LANGUAGES C CXX)

# Project configuration - output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Project description
set(PROJECT_DESCRIPTION "High-performance networking library")
set(PROJECT_HOMEPAGE_URL "https://github.com/qigao/turboP2P")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
# Language standards - unified approach
set(CMAKE_CXX_STANDARD 17) # C++17 for compatibility
set(CMAKE_C_STANDARD 11) # C17 to ensure C11 atomic support
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  add_compile_options(/experimental:c11atomics)
endif()
# Enable folder organization in IDEs
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "cmake")

# Enable testing
include(CTest)
enable_testing()

include(CMakeOptions.cmake)
include(Sanitizers)

find_package(TurboUtils REQUIRED PATHS ${TURBO_UTILS_ROOT})
find_package(Threads REQUIRED)
find_package(TurboNet REQUIRED PATHS ${TURBO_NET_ROOT})

if(BUILD_EXAMPLES)
  # TurboHttp releases from before the TurboUtils package split still refer to
  # these build-tree target names. Keep the compatibility local to examples;
  # the aliases are not exported by TurboP2P.
  if(NOT TARGET TurboNet::Utils)
    add_library(TurboNet::Utils ALIAS TurboUtils::Core)
  endif()
  if(NOT TARGET TurboNet::Parser)
    add_library(TurboNet::Parser ALIAS TurboUtils::Parser)
  endif()
  find_package(TurboHttp REQUIRED PATHS ${TURBO_HTTP_ROOT})
endif()

if(NOT DEFINED TURBOP2P_ICE_TARGET OR "${TURBOP2P_ICE_TARGET}" STREQUAL "")
  if(TARGET TurboNet::Ice)
    set(TURBOP2P_ICE_TARGET TurboNet::Ice)
  endif()
endif()

# Additional components
add_subdirectory(vendor)

add_subdirectory(p2p)
add_subdirectory(mesh)
add_subdirectory(tunnel)

# Package Configuration
include(CMakePackageConfigHelpers)

# Generate the config file
configure_package_config_file(
  "${CMAKE_SOURCE_DIR}/cmake/TurboP2PConfig.cmake.in"
  "${CMAKE_BINARY_DIR}/TurboP2PConfig.cmake"
  INSTALL_DESTINATION "lib/cmake/TurboP2P")

# Generate the version file
write_basic_package_version_file(
  "${CMAKE_BINARY_DIR}/TurboP2PConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion)

# Install the config files
install(FILES "${CMAKE_BINARY_DIR}/TurboP2PConfig.cmake"
              "${CMAKE_BINARY_DIR}/TurboP2PConfigVersion.cmake"
        DESTINATION "lib/cmake/TurboP2P")

# Install the export set
install(
  EXPORT TurboP2PTargets
  FILE TurboP2PTargets.cmake
  NAMESPACE TurboP2P::
  DESTINATION "lib/cmake/TurboP2P")
