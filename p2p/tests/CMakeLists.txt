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
                                              uthash)

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
