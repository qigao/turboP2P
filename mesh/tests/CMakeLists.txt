# =============================================================================
# Mesh Tests
# =============================================================================

enable_testing()

set(MESH_TEST_SOURCES
    test_mesh.c)

foreach(test_source ${MESH_TEST_SOURCES})
    get_filename_component(test_name ${test_source} NAME_WE)

    add_executable(${test_name} ${test_source})

    target_include_directories(${test_name}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
                ${CMAKE_CURRENT_SOURCE_DIR}/../src
                ${CMAKE_SOURCE_DIR}/vendor/unity)

    target_link_libraries(${test_name}
        PRIVATE mesh
                unity)

    set_target_properties(${test_name} PROPERTIES
        FOLDER "mesh/tests"
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/test)

    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
