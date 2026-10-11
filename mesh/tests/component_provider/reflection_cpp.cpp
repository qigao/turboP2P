#include "mesh_control_component_provider.h"

extern "C" const cmeta_interface_desc *mesh_test_provider_cpp_interface(void) {
  return mesh_control_component_provider_v1_interface();
}
extern "C" const cmeta_data_desc *mesh_test_provider_cpp_data(void) {
  return cmeta_reflected_data(mesh_control_provider_v1_t);
}
