#include "cnet_sg_ace.h"

#include <salts/error_codes.h>

static int p2p_sg_ace_capacity_evaluate(
    void *self, const cnet_handoff_snapshot *credits,
    uint64_t published_live_connections, cnet_owner_placement_hint *out_hint) {
    p2p_sg_ace_capacity *state = (p2p_sg_ace_capacity *)self;
    uint64_t reserved, queued, taken, pending, credit_total, occupied;
    if (out_hint) *out_hint = (cnet_owner_placement_hint){0};
    if (!state || !credits || !out_hint ||
        !state->client_connection_capacity || !credits->connection_capacity ||
        !credits->queue_capacity ||
        credits->queue_capacity > credits->connection_capacity)
        return SALTS_EINVAL;
    reserved = (uint64_t)credits->reserved;
    queued = (uint64_t)credits->queued;
    taken = (uint64_t)credits->taken;
    if (reserved > credits->connection_capacity ||
        queued > (uint64_t)credits->connection_capacity - reserved ||
        taken > (uint64_t)credits->connection_capacity - reserved - queued)
        return SALTS_EINVAL;
    pending = reserved + queued;
    credit_total = pending + taken;
    /* TAKEN streams appear in live P2P connections once adopted; max avoids
     * double counting. TAKEN pending-adopt streams are still accounted for. */
    occupied = published_live_connections > taken
        ? published_live_connections : taken;
    if (occupied > UINT64_MAX - pending)
        return SALTS_EINVAL;
    out_hint->pressure = occupied + pending;
    out_hint->eligible =
        !credits->sealed &&
        credit_total < credits->connection_capacity &&
        out_hint->pressure < state->client_connection_capacity;
    return SALTS_OK;
}

CMETA_IMPLEMENTS(p2p_sg_ace_hint, p2p_sg_ace_capacity_impl, 0u,
    .evaluate = p2p_sg_ace_capacity_evaluate);

p2p_sg_ace_hint p2p_sg_ace_capacity_strategy(p2p_sg_ace_capacity *state) {
    return p2p_sg_ace_capacity_impl_as_p2p_sg_ace_hint(state);
}
