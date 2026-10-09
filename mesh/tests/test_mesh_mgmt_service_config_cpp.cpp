#include "mesh_mgmt_service_config.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

static_assert(std::is_standard_layout<mesh_mgmt_service_config_v1_t>::value,
              "Typed service config must retain public C11/C++17 layout");
static_assert(std::is_standard_layout<mesh_mgmt_service_publish_v1_t>::value,
              "MMP service publish view must retain C-compatible layout");

int main() {
  static constexpr char json[] =
      "{\"schema_version\":1,\"address_family\":4,\"octet0\":100,"
      "\"octet1\":64,\"octet2\":0,\"octet3\":2,\"port\":7878,"
      "\"dns_name\":\"node-b.mesh\"}";
  mesh_mgmt_service_config_v1_t owned{};
  mesh_mgmt_service_publish_v1_t view{};
  if (mesh_mgmt_service_config_from_json_v1(
          json, sizeof(json) - 1u, &owned) != MESH_MGMT_SERVICE_CONFIG_OK)
    return 1;
  if (mesh_mgmt_service_config_publish_view_v1(&owned, &view) !=
      MESH_MGMT_SERVICE_CONFIG_OK)
    return 2;
  if (view.dns_name != owned.dns_name ||
      std::strcmp(view.dns_name, "node-b.mesh") != 0 ||
      view.virtual_address[0] != 100u || view.virtual_address[3] != 2u ||
      view.port != 7878u)
    return 3;
  return 0;
}
