#include "core/cnet_sg_ace.h"
#include <salts/error_codes.h>
#include <type_traits>
#include <cstdint>

static_assert(std::is_same<decltype(&p2p_sg_ace_hint_evaluate),
  int (*)(p2p_sg_ace_hint *, const cnet_handoff_snapshot *,
          uint64_t, cnet_owner_placement_hint *)>::value,
  "CMeta ACE Interface requires exact native C++17 dispatch");

int main() {
    p2p_sg_ace_capacity capacity = {3};
    p2p_sg_ace_hint policy = p2p_sg_ace_capacity_strategy(&capacity);
    cnet_handoff_snapshot s = {};
    s.connection_capacity = 2;
    s.queue_capacity = 1;
    cnet_owner_placement_hint hint = {};
    if (!p2p_sg_ace_hint_valid(&policy)) return 1;
    if (!cmeta_interface_desc_valid(p2p_sg_ace_hint_interface())) return 2;
    if (p2p_sg_ace_hint_evaluate(&policy, &s, 1u, &hint) != SALTS_OK) return 3;
    if (!hint.eligible || hint.pressure != 1u) return 4;
    return 0;
}
