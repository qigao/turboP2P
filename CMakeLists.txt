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
 
set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "cmake")

# Enable testing
include(CTest)
enable_testing()

include(CMakeOptions.cmake)
include(Sanitizers)

find_package(TurboUtils REQUIRED PATHS ${TURBO_UTILS_ROOT})
find_package(TurboParser CONFIG REQUIRED PATHS "${TURBOPARSER_ROOT}")
find_package(TurboNet REQUIRED PATHS ${TURBO_NET_ROOT})
find_package(TurboHttp REQUIRED PATHS ${TURBO_HTTP_ROOT})
find_package(OpenSSL REQUIRED)

if(TURBOP2P_ENABLE_FLOWMQ_IPC)
  find_package(FlowMQ CONFIG REQUIRED)
  if(NOT TARGET FlowMQ::FlowMQ)
    message(FATAL_ERROR
            "TURBOP2P_ENABLE_FLOWMQ_IPC requires FlowMQ::FlowMQ")
  endif()
endif()

if(TURBOP2P_BUILD_TURBORAFT_M3)
  find_package(TurboRaft CONFIG REQUIRED COMPONENTS Service SQLiteStorage
               PATHS ${TURBO_RAFT_ROOT})
endif()

# Windows 测试进程需要从可执行文件目录解析依赖 DLL（turbo_utils.dll、CoroNet.dll、
# turbo_ice.dll、ssl.dll）。把它们复制到运行时输出目录，避免同一 ctest 进程
# 批量启动测试时出现 STATUS_DLL_NOT_FOUND (0xc0000135)。
if(WIN32 AND (BUILD_TESTS OR BUILD_EXAMPLES))
  set(_turbo_p2p_runtime_dlls
      $<TARGET_FILE:TurboNet::CoroNet>
      $<TARGET_FILE:TurboNet::Ice>
      $<TARGET_FILE:TurboUtils::Core>)
  if(TARGET TurboHttp::Iris)
    list(APPEND _turbo_p2p_runtime_dlls $<TARGET_FILE:TurboHttp::Iris>)
  endif()
  if(TARGET TurboHttp::HttpClient)
    list(APPEND _turbo_p2p_runtime_dlls $<TARGET_FILE:TurboHttp::HttpClient>)
  endif()
  if(TARGET TurboHttp::TurboHttp)
    list(APPEND _turbo_p2p_runtime_dlls $<TARGET_FILE:TurboHttp::TurboHttp>)
  endif()
  if(TARGET TurboParser::Mustache)
    list(APPEND _turbo_p2p_runtime_dlls $<TARGET_FILE:TurboParser::Mustache>)
  endif()
  if(TARGET TurboParser::Parser)
    list(APPEND _turbo_p2p_runtime_dlls $<TARGET_FILE:TurboParser::Parser>)
  endif()
  if(TARGET TurboParser::DataBind)
    list(APPEND _turbo_p2p_runtime_dlls $<TARGET_FILE:TurboParser::DataBind>)
  endif()
  if(TARGET FlowMQ::FlowMQ)
    list(APPEND _turbo_p2p_runtime_dlls $<TARGET_FILE:FlowMQ::FlowMQ>)
  endif()
  if(DEFINED VCPKG_INSTALLED_DIR AND EXISTS
     "${VCPKG_INSTALLED_DIR}/x64-windows/bin/ssl.dll")
    list(APPEND _turbo_p2p_runtime_dlls
         "${VCPKG_INSTALLED_DIR}/x64-windows/bin/ssl.dll")
  endif()
  # Imported TurboHTTP binaries are Release-only and depend on BoringSSL's
  # release crypto.dll even when the local test executable is a Debug target.
  if(DEFINED VCPKG_INSTALLED_DIR AND EXISTS
     "${VCPKG_INSTALLED_DIR}/x64-windows/bin/crypto.dll")
    list(APPEND _turbo_p2p_runtime_dlls
         "${VCPKG_INSTALLED_DIR}/x64-windows/bin/crypto.dll")
  endif()
  add_custom_target(turbo_p2p_copy_runtime_dlls
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_turbo_p2p_runtime_dlls}
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Copying test runtime DLLs to ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
    VERBATIM)
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
