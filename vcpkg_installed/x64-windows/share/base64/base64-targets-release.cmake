#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "aklomp::base64" for configuration "Release"
set_property(TARGET aklomp::base64 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(aklomp::base64 PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/base64.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/base64.dll"
  )

list(APPEND _cmake_import_check_targets aklomp::base64 )
list(APPEND _cmake_import_check_files_for_aklomp::base64 "${_IMPORT_PREFIX}/lib/base64.lib" "${_IMPORT_PREFIX}/bin/base64.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
