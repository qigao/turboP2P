cmake_minimum_required(VERSION 3.25)
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

project(TurboP2P VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(PROJECT_DESCRIPTION "Modern Salts-based P2P and mesh runtime")
set(PROJECT_HOMEPAGE_URL "https://github.com/qigao/turboP2P")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  add_compile_options(/experimental:c11atomics)
endif()
set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "cmake")

include(CTest)
include(CMakeOptions.cmake)
include(Sanitizers)

# Same installed-SDK ownership model as CHttp: explicit current roots only.
foreach(_entry IN ITEMS "Salts|SALTS_ROOT" "SaltsUtils|SALTS_UTILS_ROOT" "SaltsNet|SALTS_NET_ROOT" "Chttp|CHTTP_ROOT")
  string(REPLACE "|" ";" _fields "${_entry}")
  list(GET _fields 0 _package)
  list(GET _fields 1 _root_variable)
  if(NOT DEFINED ${_root_variable} OR "${${_root_variable}}" STREQUAL "")
    message(FATAL_ERROR "${_root_variable} must point at the installed ${_package} SDK")
  endif()
  set(_config_dir "${${_root_variable}}/lib/cmake/${_package}")
  if(NOT EXISTS "${_config_dir}/${_package}Config.cmake")
    message(FATAL_ERROR "${_root_variable} does not contain ${_package}Config.cmake: ${${_root_variable}}")
  endif()
  set(${_package}_DIR "${_config_dir}" CACHE PATH "Explicit installed ${_package} SDK" FORCE)
  find_package(${_package} CONFIG REQUIRED PATHS "${_config_dir}"
               NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
endforeach()

foreach(_target IN ITEMS Salts::CNet Salts::CMeta Salts::CFlow Salts::PluginABI
                         Salts::Plugin Salts::Crypto Salts::DataBind SaltsNet::ICE CHttp::Client CHttp::Server)
  if(NOT TARGET ${_target})
    message(FATAL_ERROR "Required current dependency target is missing: ${_target}")
  endif()
endforeach()

find_package(OpenSSL REQUIRED)

if(TURBOP2P_ENABLE_FLOWMQ_IPC)
  find_package(FlowMQ CONFIG REQUIRED)
  if(NOT TARGET FlowMQ::FlowMQ)
    message(FATAL_ERROR "TURBOP2P_ENABLE_FLOWMQ_IPC requires FlowMQ::FlowMQ")
  endif()
endif()

if(TURBOP2P_BUILD_TURBORAFT_M3)
  find_package(TurboRaft CONFIG REQUIRED COMPONENTS Service SQLiteStorage
               PATHS ${TURBO_RAFT_ROOT})
endif()

# Never stage dependency DLLs by hard-coded triplet/name. Executables that need
# shared runtime dependencies must use TARGET_RUNTIME_DLLS.
if(WIN32 AND (BUILD_TESTS OR BUILD_EXAMPLES))
  add_custom_target(turbo_p2p_runtime_contract
    COMMENT "Runtime DLL closure is staged per executable via TARGET_RUNTIME_DLLS")
endif()

add_subdirectory(vendor)
add_subdirectory(p2p)
add_subdirectory(mesh)
add_subdirectory(tunnel)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_SOURCE_DIR}/cmake/TurboP2PConfig.cmake.in"
  "${CMAKE_BINARY_DIR}/TurboP2PConfig.cmake"
  INSTALL_DESTINATION "lib/cmake/TurboP2P")
write_basic_package_version_file(
  "${CMAKE_BINARY_DIR}/TurboP2PConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion)
install(FILES "${CMAKE_BINARY_DIR}/TurboP2PConfig.cmake"
              "${CMAKE_BINARY_DIR}/TurboP2PConfigVersion.cmake"
        DESTINATION "lib/cmake/TurboP2P")
install(EXPORT TurboP2PTargets FILE TurboP2PTargets.cmake
        NAMESPACE TurboP2P:: DESTINATION "lib/cmake/TurboP2P")
