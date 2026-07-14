# =============================================================================
# Mesh Tests
# =============================================================================

enable_testing()

set(MESH_TEST_SOURCES
    test_mesh.c
    test_mesh_faults.c
    test_mesh_multihop.c
    test_mesh_paths.c
    test_meshd_runtime.c)

foreach(test_source ${MESH_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)

    add_executable(${test_name} ${test_source})

    target_include_directories(${test_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                ${CMAKE_CURRENT_SOURCE_DIR}/../src
                ${CMAKE_CURRENT_SOURCE_DIR}/../examples)

    set(extra_test_libs)
    if(test_name STREQUAL "test_meshd_runtime")
        list(APPEND extra_test_libs tunnel TurboP2P::P2P)
    endif()

    target_link_libraries(${test_name}
        PRIVATE mesh
                TurboUtils::TinyTest
                ${extra_test_libs})

    set_target_properties(${test_name} PROPERTIES
        FOLDER "mesh/tests"
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
