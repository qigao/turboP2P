set(_turbo_p2p_fuzz_targets
    fuzz_p2p_cookie
    fuzz_p2p_message
    fuzz_p2p_noise_read)

add_library(p2p_security_fuzz_support STATIC
            ../src/crypto/p2p_crypto.c
            ../src/protocol/message.c
            ../src/security/p2p_cookie.c
            ../src/security/p2p_noise_backend.c)
target_compile_options(p2p_security_fuzz_support PRIVATE
                       -fsanitize=fuzzer-no-link,address)
target_include_directories(
  p2p_security_fuzz_support PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(
  p2p_security_fuzz_support PUBLIC
  TurboUtils::Core TurboNet::Crypto TurboP2P::NoiseProtocol uthash)
if(WIN32)
  target_link_libraries(p2p_security_fuzz_support PUBLIC ws2_32)
endif()
set_property(TARGET p2p_security_fuzz_support PROPERTY FOLDER "p2p/fuzz")

foreach(_target IN LISTS _turbo_p2p_fuzz_targets)
  add_executable(${_target} ${_target}.c)
  target_compile_options(${_target} PRIVATE
                         -fsanitize=fuzzer-no-link,address)
  target_include_directories(
    ${_target} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
  target_link_libraries(
    ${_target} PRIVATE p2p_security_fuzz_support)
  target_link_options(${_target} PRIVATE -fsanitize=fuzzer,address)
  set_target_properties(
    ${_target} PROPERTIES
    FOLDER "p2p/fuzz"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
  if(TARGET turbo_p2p_copy_runtime_dlls)
    add_dependencies(${_target} turbo_p2p_copy_runtime_dlls)
  endif()
endforeach()

unset(_turbo_p2p_fuzz_targets)
