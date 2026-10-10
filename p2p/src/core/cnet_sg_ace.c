#include "cnet_sg_ace.h"

#include <salts/error_codes.h>

static int p2p_sg_ace_capacity_evaluate(
    void *self, const cnet_handoff_snapshot *credits,
    uint64_t published_live_connections, uint64_t published_credited_connections,
    cnet_owner_placement_hint *out_hint) {
    const p2p_sg_ace_capacity *state = (const p2p_sg_ace_capacity *)self;
    uint64_t reserved, queued, taken, credit_total, uncredited, p2p_occupancy;
    if (out_hint) *out_hint = (cnet_owner_placement_hint){0};
    if (!state || !credits || !out_hint ||
        !state->client_connection_capacity || !credits->connection_capacity ||
        !credits->queue_capacity ||
        credits->queue_capacity > credits->connection_capacity ||
        (state->shared_host_connection_capacity == 0u &&
         state->cohost_occupied_slots != 0u) ||
        state->cohost_occupied_slots > state->shared_host_connection_capacity)
        return SALTS_EINVAL;

    reserved = (uint64_t)credits->reserved;
    queued = (uint64_t)credits->queued;
    taken = (uint64_t)credits->taken;
    if (reserved > credits->connection_capacity ||
        queued > (uint64_t)credits->connection_capacity - reserved ||
        taken > (uint64_t)credits->connection_capacity - reserved - queued ||
        published_credited_connections > published_live_connections ||
        published_credited_connections > taken)
        return SALTS_EINVAL;
    credit_total = reserved + queued + taken;
    /* Credited/adopted streams are present in BOTH the CNet physical list
     * and Handoff's TAKEN tickets; remove only that proven intersection.
     * Unadopted TAKEN is still counted. Cross-shard stale/coherency mismatch
     * fails closed; reservation remains authoritative, not this hint. */
    uncredited = published_live_connections - published_credited_connections;
    if (uncredited > UINT64_MAX - credit_total)
        return SALTS_EINVAL;
    p2p_occupancy = uncredited + credit_total;
    if (p2p_occupancy > UINT64_MAX - state->cohost_occupied_slots)
        return SALTS_EINVAL;
    out_hint->pressure = p2p_occupancy + state->cohost_occupied_slots;
    out_hint->eligible =
        !credits->sealed &&
        credit_total < credits->connection_capacity &&
        p2p_occupancy < state->client_connection_capacity &&
        (!state->shared_host_connection_capacity ||
         out_hint->pressure < state->shared_host_connection_capacity);
    return SALTS_OK;
}

CMETA_IMPLEMENTS(p2p_sg_ace_hint, p2p_sg_ace_capacity_impl, 0u,
    .evaluate = p2p_sg_ace_capacity_evaluate);

p2p_sg_ace_hint p2p_sg_ace_capacity_strategy(p2p_sg_ace_capacity *state) {
    return p2p_sg_ace_capacity_impl_as_p2p_sg_ace_hint(state);
}
