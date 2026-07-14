#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "nanobench::nanobench" for configuration "Release"
set_property(TARGET nanobench::nanobench APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(nanobench::nanobench PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/nanobench.lib"
  )

list(APPEND _cmake_import_check_targets nanobench::nanobench )
list(APPEND _cmake_import_check_files_for_nanobench::nanobench "${_IMPORT_PREFIX}/lib/nanobench.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
