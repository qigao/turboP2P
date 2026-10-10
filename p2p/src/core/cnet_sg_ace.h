#ifndef P2P_CNET_SG_ACE_H
#define P2P_CNET_SG_ACE_H

#include <cmeta/interface.h>
#include <cnet/handoff.h>
#include <cnet/owner_placement.h>

/* CMeta ACE Strategy is a borrowed typed Interface for application admission
 * hint composition, NOT a duplicate CNet placement algorithm. CNet owns
 * selection and credited Handoff. This is never called on the packet path. */
#define P2P_SG_ACE_HINT_METHODS(X, I) \
    X(I, R4, int, evaluate, \
      const cnet_handoff_snapshot *, credits, \
      uint64_t, published_live_connections, \
      uint64_t, published_credited_connections, \
      cnet_owner_placement_hint *, out_hint)

CMETA_INTERFACE(p2p_sg_ace_hint, P2P_SG_ACE_HINT_METHODS);

typedef struct p2p_sg_ace_capacity {
    uint64_t client_connection_capacity;
    uint64_t cohost_occupied_slots;
    uint64_t shared_host_connection_capacity; /* zero = unmanaged host */
} p2p_sg_ace_capacity;

/* Exact borrowed view. Caller retains state for the synchronous invocation.
 * P2P occupancy = (live P2P - already adopted TAKEN) +
 *                  TAKEN + RESERVED + QUEUED
 * Host pressure = P2P occupancy + other CNet physical slots.
 * Eligibility separately checks Handoff credit, P2P client capacity, and
 * (when published) overall shared Host capacity. No other-client private
 * CNet structures are read; source data are explicitly Host-owned.
 * The final resource reservation is still performed by upstream CNet. */
#ifdef __cplusplus
extern "C" {
#endif
p2p_sg_ace_hint p2p_sg_ace_capacity_strategy(p2p_sg_ace_capacity *state);
#ifdef __cplusplus
}
#endif

#endif
