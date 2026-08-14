include(CMakeDependentOption)

set(CMAKE_COLOR_DIAGNOSTICS ON)

# building the tests
option(ENABLE_TESTS "Enable the tests" ON)

# Address Sanitizer - only enabled for Debug builds
cmake_dependent_option(
    ENABLE_ASAN "Enable Address Sanitizer" ON
    "CMAKE_BUILD_TYPE STREQUAL Debug" OFF
)
if(ENABLE_ASAN)
  set(ENABLE_SANITIZER_ADDRESS ON CACHE BOOL "Enable AddressSanitizer" FORCE)
  if(MSVC)
    set(ENABLE_SANITIZER_UNDEFINED OFF CACHE BOOL
        "Enable UndefinedBehaviorSanitizer" FORCE)
    set(ENABLE_SANITIZER_LEAK OFF CACHE BOOL "Enable LeakSanitizer" FORCE)
  else()
    set(ENABLE_SANITIZER_UNDEFINED ON CACHE BOOL
        "Enable UndefinedBehaviorSanitizer" FORCE)
    set(ENABLE_SANITIZER_LEAK ON CACHE BOOL "Enable LeakSanitizer" FORCE)
  endif()
  set(ENABLE_SANITIZER_THREAD OFF CACHE BOOL "Enable ThreadSanitizer" FORCE)
endif()
 
# if(MSVC)
#     add_compile_options(/bigobj)
# endif()

# zlib support
option(ENABLE_ZLIB "Use zlib" ON)

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build test suite" ON)
option(TURBOP2P_BUILD_TURBORAFT_M3
       "Build the TurboRaft-backed M3 namespace adapter" OFF)
option(TURBOP2P_BUILD_FUZZERS
       "Build Clang libFuzzer targets for security parsers" OFF)
option(TURBOP2P_ENABLE_FLOWMQ_IPC
       "Build the standalone FlowMQ ROUTER/DEALER adapter for meshd local control" OFF)

if(TURBOP2P_BUILD_FUZZERS AND
   (NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR MSVC))
  message(FATAL_ERROR
          "TURBOP2P_BUILD_FUZZERS requires Linux/Unix Clang with libFuzzer support; clang-cl compiler-rt is not a supported fuzz runtime")
endif()
if(TURBOP2P_BUILD_FUZZERS AND
   (ENABLE_SANITIZER_THREAD OR ENABLE_SANITIZER_MEMORY))
  message(FATAL_ERROR
          "TURBOP2P_BUILD_FUZZERS uses AddressSanitizer and cannot be combined with ThreadSanitizer or MemorySanitizer")
endif()

  
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

find_package(Threads REQUIRED)
