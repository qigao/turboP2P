#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "nanobench::nanobench" for configuration "Debug"
set_property(TARGET nanobench::nanobench APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(nanobench::nanobench PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/nanobench.lib"
  )

list(APPEND _cmake_import_check_targets nanobench::nanobench )
list(APPEND _cmake_import_check_files_for_nanobench::nanobench "${_IMPORT_PREFIX}/debug/lib/nanobench.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
