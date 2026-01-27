cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0144 OLD)
cmake_policy(SET CMP0167 OLD)

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
# Enable folder organization in IDEs
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "cmake")

# Enable testing
include(CTest)
enable_testing()

include(CMakeOptions.cmake)
include(Sanitizers)

# Find common dependencies used by multiple libraries
find_package(llhttp CONFIG REQUIRED)
find_package(libuv CONFIG REQUIRED)
find_package(kcp CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(qjs REQUIRED)
find_package(Threads REQUIRED)
find_package(c-ares CONFIG REQUIRED)
find_package(cJSON CONFIG REQUIRED)
find_package(base64 CONFIG REQUIRED)
find_package(TurboNet CONFIG REQUIRED PATHS ${EXTERNAL_ROOT}/turbonet)
find_package(Stb REQUIRED)

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
