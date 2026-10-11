#include "mesh_mgmt_service_component.h"

extern "C" const cmeta_interface_desc *mesh_test_service_cpp_interface(void) {
  return mesh_mgmt_service_provider_v1_interface();
}
extern "C" const cmeta_data_desc *mesh_test_service_cpp_data(void) {
  return cmeta_reflected_data(mesh_mgmt_service_config_v1_t);
}
