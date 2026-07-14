#----------------------------------------------------------------
# Generated CMake target import file for configuration "RELEASE".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "llhttp::llhttp_static" for configuration "RELEASE"
set_property(TARGET llhttp::llhttp_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(llhttp::llhttp_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/llhttp.lib"
  )

list(APPEND _cmake_import_check_targets llhttp::llhttp_static )
list(APPEND _cmake_import_check_files_for_llhttp::llhttp_static "${_IMPORT_PREFIX}/lib/llhttp.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
