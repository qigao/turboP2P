# One schema feeds both the generated native/CMeta representation and the
# embedded startup codec. No schema file or compiler is needed at runtime.
salts_idl_target(
  TARGET mesh_rpc_service_config_contract
  IDL "${CMAKE_CURRENT_SOURCE_DIR}/rpc_service_config.schema"
  ARTIFACTS TYPES
  FOLDER "mesh/contracts")

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/rpc_service_config.schema")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/rpc_service_config.schema" rpc_config_schema)
string(REPLACE "\\" "\\\\" rpc_config_schema "${rpc_config_schema}")
string(REPLACE "\"" "\\\"" rpc_config_schema "${rpc_config_schema}")
string(REPLACE "\r" "" rpc_config_schema "${rpc_config_schema}")
string(REPLACE "\n" "\\n\"\n\"" rpc_config_schema "${rpc_config_schema}")
configure_file(rpc_service_config_schema.h.in rpc_service_config_schema.h @ONLY)
target_include_directories(mesh_rpc_service_config_contract_types INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}")
