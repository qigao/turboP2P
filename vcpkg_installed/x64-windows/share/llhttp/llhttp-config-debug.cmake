#----------------------------------------------------------------
# Generated CMake target import file for configuration "DEBUG".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "llhttp::llhttp_static" for configuration "DEBUG"
set_property(TARGET llhttp::llhttp_static APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(llhttp::llhttp_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "C"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/llhttp.lib"
  )

list(APPEND _cmake_import_check_targets llhttp::llhttp_static )
list(APPEND _cmake_import_check_files_for_llhttp::llhttp_static "${_IMPORT_PREFIX}/debug/lib/llhttp.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
