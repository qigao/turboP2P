# =============================================================================
# P2P Tests (Good Taste Design)
# =============================================================================

enable_testing()
set(folder_name p2p/tests)

# Define test files
set(P2P_TESTS test_p2p)

# Common test configuration
foreach(test_name ${P2P_TESTS})
  add_executable(${test_name} ${test_name}.c)

  target_link_libraries(${test_name} PRIVATE p2p TurboUtils::Core
                                             TurboNet::CoroNet TurboUtils::TinyTest
                                             TurboP2P::NoiseProtocol monocypher uthash)

  target_include_directories(
    ${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                         ${CMAKE_CURRENT_SOURCE_DIR}/../src)

  set_target_properties(
    ${test_name} PROPERTIES FOLDER ${folder_name} RUNTIME_OUTPUT_DIRECTORY
                                                  ${CMAKE_BINARY_DIR}/bin)

  # Add as CTest
  add_test(NAME ${test_name} COMMAND ${test_name})
  if(TARGET turbo_p2p_copy_runtime_dlls)
    add_dependencies(${test_name} turbo_p2p_copy_runtime_dlls)
  endif()
endforeach()

add_executable(test_p2p_security test_p2p_security.c)
set_property(TARGET test_p2p_security PROPERTY LINKER_LANGUAGE CXX)
target_include_directories(test_p2p_security PRIVATE ../src ../include)
target_link_libraries(test_p2p_security PRIVATE
  p2p TurboP2P::NoiseProtocol monocypher Salts::TinyTest)
add_test(NAME test_p2p_security COMMAND test_p2p_security)
if(TARGET turbo_p2p_copy_runtime_dlls)
  add_dependencies(test_p2p_security turbo_p2p_copy_runtime_dlls)
endif()

add_executable(test_p2p_cnet_transport test_p2p_cnet_transport.c)
set_property(TARGET test_p2p_cnet_transport PROPERTY LINKER_LANGUAGE CXX)
target_include_directories(test_p2p_cnet_transport PRIVATE ../src ../include)
target_link_libraries(test_p2p_cnet_transport PRIVATE
  p2p Salts::CNet Salts::Core Salts::Platform Salts::TinyTest)
add_test(NAME test_p2p_cnet_transport COMMAND test_p2p_cnet_transport)
set_tests_properties(test_p2p_cnet_transport PROPERTIES TIMEOUT 60)
if(TARGET turbo_p2p_copy_runtime_dlls)
  add_dependencies(test_p2p_cnet_transport turbo_p2p_copy_runtime_dlls)
endif()
