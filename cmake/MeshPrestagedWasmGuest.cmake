include_guard(GLOBAL)

# Build an actual import-free WebAssembly guest for the raw prestaged
# turbo_main() profile. This is NOT the legacy TurboRuntime guest compiler;
# the output runs through the installed TurboWasm::Runtime.
function(turbop2p_add_raw_wasm_guest target)
  cmake_parse_arguments(GUEST "" "SOURCE;OUTPUT" "" ${ARGN})
  if(NOT GUEST_SOURCE OR NOT GUEST_OUTPUT OR GUEST_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR
      "turbop2p_add_raw_wasm_guest requires SOURCE and OUTPUT")
  endif()
  find_program(TURBOP2P_WASM_CLANG NAMES
    clang clang-20 clang-19 clang-18 clang-17 REQUIRED)
  # An explicit export and no start function prevent guest side effects
  # outside the fuel/deadline-controlled TurboWasm invoke boundary.
  add_custom_command(
    OUTPUT "${GUEST_OUTPUT}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory
      "${CMAKE_CURRENT_BINARY_DIR}"
    COMMAND "${TURBOP2P_WASM_CLANG}"
      --target=wasm32-unknown-unknown
      -O2 -nostdlib -fno-stack-protector
      -Wl,--no-entry -Wl,--export=turbo_main
      -Wl,--strip-all -Wl,-z,stack-size=65536
      "${GUEST_SOURCE}" -o "${GUEST_OUTPUT}"
    DEPENDS "${GUEST_SOURCE}"
    VERBATIM)
  add_custom_target(${target} DEPENDS "${GUEST_OUTPUT}")
endfunction()
