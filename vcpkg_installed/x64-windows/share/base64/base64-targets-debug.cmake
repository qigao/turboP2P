#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "aklomp::base64" for configuration "Debug"
set_property(TARGET aklomp::base64 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(aklomp::base64 PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/debug/lib/base64.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/bin/base64.dll"
  )

list(APPEND _cmake_import_check_targets aklomp::base64 )
list(APPEND _cmake_import_check_files_for_aklomp::base64 "${_IMPORT_PREFIX}/debug/lib/base64.lib" "${_IMPORT_PREFIX}/debug/bin/base64.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
