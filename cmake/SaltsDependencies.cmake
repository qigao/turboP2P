# Use one explicitly selected, matching pair of installed SDK profiles.
foreach(_root IN ITEMS SALTS_ROOT SALTS_UTILS_ROOT)
  if(NOT DEFINED ENV{${_root}} OR "$ENV{${_root}}" STREQUAL "")
    message(FATAL_ERROR "${_root} must name the installed SDK profile")
  endif()
  if(NOT IS_DIRECTORY "$ENV{${_root}}")
    message(FATAL_ERROR "${_root} is not a directory: $ENV{${_root}}")
  endif()
  file(TO_CMAKE_PATH "$ENV{${_root}}" _${_root}_PATH)
endforeach()

unset(Salts_DIR CACHE)
unset(Salts_DIR)
unset(SaltsUtils_DIR CACHE)
unset(SaltsUtils_DIR)
# Current latest SaltsUtils native SDK links Salts::Crypto against the
# REAL canonical GmSSL provider. Import its exported target before consuming
# SaltsUtilsTargets; no fake alias, optional fallback or older RC pin.
find_package(GmSSL CONFIG REQUIRED)
if(NOT TARGET GmSSL::GmSSL)
  message(FATAL_ERROR "Canonical GmSSL provider did not export GmSSL::GmSSL")
endif()
find_package(Salts CONFIG REQUIRED PATHS "${_SALTS_ROOT_PATH}"
             NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
find_package(SaltsUtils CONFIG REQUIRED PATHS "${_SALTS_UTILS_ROOT_PATH}"
             NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)
foreach(_target IN ITEMS
    Salts::Core Salts::Platform Salts::Concurrency Salts::CSTL Salts::Crypto
    Salts::CMeta Salts::CFlow Salts::CNet Salts::Plugin Salts::TinyTest
    Salts::DataBind)
  if(NOT TARGET ${_target})
    message(FATAL_ERROR "Installed Salts profile is missing ${_target}")
  endif()
endforeach()
unset(_root)
unset(_target)
unset(_SALTS_ROOT_PATH)
unset(_SALTS_UTILS_ROOT_PATH)
