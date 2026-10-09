#include <cnet/owner_placement.h>
#include <cnet/destination_policy.h>
#include <cnet/recovery_policy.h>
#include <cnet/manager.h>
#include <cnet/client_pool.h>
#include <data_bind.h>
#include <data_bind_validation_plan.h>
#include <salts/error_codes.h>

#include <cstdint>
#include <type_traits>

static_assert(std::is_standard_layout<cnet_destination_selection>::value,
              "CNet policy must have a C11/C++17 ABI layout");
static_assert(std::is_standard_layout<cnet_owner_placement_input>::value,
              "CNet owner placement must be C11/C++17 interoperable");
static_assert(std::is_standard_layout<DataBindService>::value,
              "DataBind service ABI must be C11/C++17 interoperable");

int main() {
  const cnet_destination_hint endpoints[] = {{7u, 1u, 0u, true}};
  cnet_destination_selection choice{};
  cnet_destination_result out{};
  DataBindService service = DATA_BIND_SERVICE_INIT;
  choice.size = sizeof(choice);
  choice.version = CNET_DESTINATION_POLICY_VERSION;
  choice.kind = CNET_DESTINATION_EXPLICIT;
  choice.endpoints = endpoints;
  choice.endpoint_count = 1u;
  choice.snapshot_generation = 1u;
  choice.expires_at_ms = UINT64_MAX;
  choice.explicit_endpoint_id = 7u;
  if (cnet_destination_choose(&choice, &out) != SALTS_OK ||
      out.endpoint_id != 7u) return 1;
  return data_bind_service_at(nullptr, 0u, &service) == 0 ? 0 : 2;
}
