# Monocypher - A high-quality cryptographic library
# https://monocypher.org/

add_library(monocypher STATIC
    monocypher.c
    monocypher.h
)

target_include_directories(monocypher PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

install(TARGETS monocypher
  EXPORT TurboP2PTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  OPTIONAL)

# Disable warnings for third-party code
if(MSVC)
    target_compile_options(monocypher PRIVATE /W0)
else()
    target_compile_options(monocypher PRIVATE -w)
endif()
set_target_properties( monocypher PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    FOLDER "vendor" 
)