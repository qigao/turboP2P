include(FetchContent)

set(TURBO_P2P_NOISE_C_COMMIT
    "cfe25410979a87391bb9ac8d4d4bef64e9f268c6")
set(TURBO_P2P_NOISE_C_SOURCE_DIR "" CACHE PATH
    "Optional clean checkout of the pinned Noise-C commit for offline builds")

function(turbo_p2p_configure_noise_c)
  if(TARGET noise_protocol)
    return()
  endif()

  if(TURBO_P2P_NOISE_C_SOURCE_DIR)
    get_filename_component(_noise_source
                           "${TURBO_P2P_NOISE_C_SOURCE_DIR}" ABSOLUTE)
    if(NOT EXISTS "${_noise_source}/include/noise/protocol.h")
      message(FATAL_ERROR
              "TURBO_P2P_NOISE_C_SOURCE_DIR is not a Noise-C source tree")
    endif()
  else()
    FetchContent_Declare(
      turbo_p2p_noise_c
      GIT_REPOSITORY https://github.com/rweather/noise-c.git
      GIT_TAG ${TURBO_P2P_NOISE_C_COMMIT}
      GIT_SHALLOW FALSE
      GIT_PROGRESS TRUE)
    FetchContent_MakeAvailable(turbo_p2p_noise_c)
    set(_noise_source "${turbo_p2p_noise_c_SOURCE_DIR}")
  endif()

  find_package(Git REQUIRED)
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${_noise_source}" rev-parse HEAD
    RESULT_VARIABLE _noise_revision_result
    OUTPUT_VARIABLE _noise_revision
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _noise_revision_result EQUAL 0 OR
     NOT _noise_revision STREQUAL TURBO_P2P_NOISE_C_COMMIT)
    message(FATAL_ERROR
            "Noise-C must be the pinned commit ${TURBO_P2P_NOISE_C_COMMIT}; got '${_noise_revision}'")
  endif()
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${_noise_source}" status --porcelain
            --untracked-files=no
    RESULT_VARIABLE _noise_status_result
    OUTPUT_VARIABLE _noise_status
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _noise_status_result EQUAL 0 OR NOT _noise_status STREQUAL "")
    message(FATAL_ERROR
            "Noise-C tracked files differ from the pinned commit")
  endif()

  set(_noise_protocol_sources
      "${_noise_source}/src/protocol/cipherstate.c"
      "${_noise_source}/src/protocol/dhstate.c"
      "${_noise_source}/src/protocol/errors.c"
      "${_noise_source}/src/protocol/handshakestate.c"
      "${_noise_source}/src/protocol/hashstate.c"
      "${_noise_source}/src/protocol/names.c"
      "${_noise_source}/src/protocol/patterns.c"
      "${_noise_source}/src/protocol/symmetricstate.c"
      "${_noise_source}/src/protocol/util.c"
      "${_noise_source}/src/backend/ref/cipher-chachapoly.c"
      "${_noise_source}/src/backend/ref/hash-blake2s.c"
      "${_noise_source}/src/crypto/blake2/blake2s.c"
      "${_noise_source}/src/crypto/sha2/sha256.c"
      "${_noise_source}/src/crypto/chacha/chacha.c"
      "${_noise_source}/src/crypto/donna/poly1305-donna.c"
      "${CMAKE_CURRENT_SOURCE_DIR}/src/security/p2p_noise_c_platform.c")

  add_library(noise_protocol STATIC ${_noise_protocol_sources})
  add_library(TurboP2P::NoiseProtocol ALIAS noise_protocol)
  target_include_directories(
    noise_protocol
    PUBLIC "${_noise_source}/include"
    PRIVATE "${_noise_source}/src"
            "${_noise_source}/src/protocol")
  target_link_libraries(noise_protocol PRIVATE TurboNet::Crypto)
  target_compile_definitions(noise_protocol PRIVATE
                             TURBO_P2P_NOISE_C_PINNED_COMMIT=\"${TURBO_P2P_NOISE_C_COMMIT}\")
  if(MSVC)
    target_compile_definitions(noise_protocol PRIVATE WIN32)
    target_compile_options(noise_protocol PRIVATE /wd4244 /wd4267)
  endif()
  set_target_properties(noise_protocol PROPERTIES FOLDER "vendor")
endfunction()
