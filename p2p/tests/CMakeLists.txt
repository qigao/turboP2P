# =============================================================================
# P2P Tests (Good Taste Design)
# =============================================================================

enable_testing()
set(folder_name p2p/tests)

# Define test files
set(P2P_TESTS test_p2p)

# Common test configuration for legacy tests
foreach(test_name ${P2P_TESTS})
  add_executable(${test_name} ${test_name}.c)

  target_link_libraries(${test_name} PRIVATE p2p unity TurboNet::Utils
                                             TurboNet::Core libuv::uv uthash)

  target_include_directories(
    ${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                         ${CMAKE_CURRENT_SOURCE_DIR}/../src)

  set_target_properties(
    ${test_name} PROPERTIES FOLDER ${folder_name} RUNTIME_OUTPUT_DIRECTORY
                                                  ${CMAKE_BINARY_DIR}/bin)

  # Add as CTest
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
