#define DATABIND_NATIVE_ENABLE_CMETA
#define DATABIND_NATIVE_ENABLE_DATABIND
#include "mesh_rpc_service_config_contract_native.h"

/* Separate C11 producer TU: C and C++ consumers borrow its descriptor through
 * the C ABI. Generated NativeSourceIR remains private C11 implementation data. */
const cmeta_data_desc *mesh_test_service_config_native_data(void) {
  static MeshRpcServiceConfig_native_cmeta_binding metadata;
  if (MeshRpcServiceConfig_native_cmeta_value_bind(&metadata) != 0)
    return NULL;
  return &metadata.data;
}
