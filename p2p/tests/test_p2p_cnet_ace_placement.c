#include <tinytest.h>
#include "core/cnet_sg_ace.h"
#include <salts/error_codes.h>
#include <stdint.h>

static cnet_handoff_snapshot snapshot(size_t limit, size_t reserved,
                                      size_t queued, size_t taken) {
    cnet_handoff_snapshot s = {0};
    s.connection_capacity = limit;
    s.queue_capacity = limit;
    s.reserved = reserved;
    s.queued = queued;
    s.taken = taken;
    return s;
}

spec("CMeta ACE admission policy composes actual CNet SG pressure") {
    it("is a valid canonical CMeta Interface and admits available credit") {
        p2p_sg_ace_capacity cap = {4};
        p2p_sg_ace_hint strategy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(4, 0, 0, 0);
        cnet_owner_placement_hint hint = {0};
        check_true(p2p_sg_ace_hint_valid(&strategy));
        check_true(cmeta_interface_desc_valid(p2p_sg_ace_hint_interface()));
        check_equal((size_t)1u, p2p_sg_ace_hint_interface()->method_count);
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 0u, 0u, &hint));
        check_true(hint.eligible);
        check_equal((uint64_t)0u, hint.pressure);
    }
    it("does not double-count a CNet TAKEN credit already adopted by P2P") {
        p2p_sg_ace_capacity cap = {4};
        p2p_sg_ace_hint strategy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(4, 0, 0, 2);
        cnet_owner_placement_hint hint = {0};
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 2u, 2u, &hint));
        check_equal((uint64_t)2u, hint.pressure);
        check_true(hint.eligible);
        s.reserved = 1u;
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 2u, 2u, &hint));
        check_equal((uint64_t)3u, hint.pressure);
        check_true(hint.eligible);
    }
    it("rejects occupied final Owner without trying another pinned one") {
        p2p_sg_ace_capacity cap = {4};
        p2p_sg_ace_hint strategy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(4, 0, 0, 0);
        cnet_owner_placement_hint hints[2] = {{0}};
        cnet_owner_placement_input input = {0};
        size_t selected = SIZE_MAX;
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 4u, 0u, &hints[0]));
        check_false(hints[0].eligible);
        check_equal((uint64_t)4u, hints[0].pressure);
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 1u, 0u, &hints[1]));
        input.size = sizeof(input);
        input.version = CNET_OWNER_PLACEMENT_VERSION;
        input.kind = CNET_OWNER_PLACE_LOWEST_PRESSURE;
        input.owners = hints;
        input.owner_count = 2u;
        check_equal(SALTS_OK, cnet_owner_placement_choose(&input, &selected));
        check_equal((size_t)1u, selected);
        input.kind = CNET_OWNER_PLACE_EXPLICIT;
        input.explicit_owner = 0u;
        selected = SIZE_MAX;
        check_equal(SALTS_ENOBUFS, cnet_owner_placement_choose(&input, &selected));
        check_equal(SIZE_MAX, selected);
    }
    it("checks independent CNet client capacity and Handoff credit capacity") {
        p2p_sg_ace_capacity cap = {16};
        p2p_sg_ace_hint strategy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(1, 0, 0, 1);
        cnet_owner_placement_hint hint = {0};
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 1u, 1u, &hint));
        check_false(hint.eligible);
        s = snapshot(3, 1, 1, 0);
        cap.client_connection_capacity = 3u;
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 2u, 0u, &hint));
        check_equal((uint64_t)4u, hint.pressure);
        check_false(hint.eligible);
        s = snapshot(3, 0, 0, 0);
        s.sealed = true;
        check_equal(SALTS_OK, p2p_sg_ace_hint_evaluate(&strategy, &s, 0u, 0u, &hint));
        check_false(hint.eligible);
    }

    it("deduplicates directly adopted RESERVED credit on the same CNet Owner") {
        p2p_sg_ace_capacity cap = {2};
        p2p_sg_ace_hint policy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot credits = snapshot(2, 1u, 0u, 0u);
        cnet_owner_placement_hint hint = {0};
        /* The live P2P connection retains the *same RESERVED* credit used
         * for direct local admission; count one physical stream, not two. */
        check_equal(SALTS_OK,
            p2p_sg_ace_hint_evaluate(&policy, &credits, 1u, 1u, &hint));
        check_equal((uint64_t)1u, hint.pressure);
        check_true(hint.eligible);
        /* The independent cohost has the remaining RESERVED credit. */
        credits.reserved = 2u;
        check_equal(SALTS_OK,
            p2p_sg_ace_hint_evaluate(&policy, &credits, 1u, 1u, &hint));
        check_equal((uint64_t)2u, hint.pressure);
        check_false(hint.eligible);
    }
    it("counts unadopted TAKEN alongside other live P2P connections") {
        p2p_sg_ace_capacity cap = {6};
        p2p_sg_ace_hint strategy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(6, 1u, 0u, 2u);
        cnet_owner_placement_hint hint = {0};
        /* One of two TAKEN tickets has been adopted; the other is pending.
         * Existing max(3,2)+1 undercounted by one physical slot. */
        check_equal(SALTS_OK,
            p2p_sg_ace_hint_evaluate(&strategy, &s, 3u, 1u, &hint));
        check_equal((uint64_t)5u, hint.pressure);
        check_true(hint.eligible);
        cap.client_connection_capacity = 5u;
        check_equal(SALTS_OK,
            p2p_sg_ace_hint_evaluate(&strategy, &s, 3u, 1u, &hint));
        check_false(hint.eligible);
    }
    it("adds cohosted CNet pressure without conflating P2P client capacity") {
        p2p_sg_ace_capacity cap = {4, 2, 5};
        p2p_sg_ace_hint policy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(4, 0u, 0u, 1u);
        cnet_owner_placement_hint hints[2] = {{0}};
        cnet_owner_placement_input input = {0};
        size_t selected = SIZE_MAX;
        check_equal(SALTS_OK,
            p2p_sg_ace_hint_evaluate(&policy, &s, 1u, 1u, &hints[0]));
        check_equal((uint64_t)3u, hints[0].pressure);
        check_true(hints[0].eligible);
        cap.cohost_occupied_slots = 0u;
        check_equal(SALTS_OK,
            p2p_sg_ace_hint_evaluate(&policy, &s, 1u, 1u, &hints[1]));
        check_equal((uint64_t)1u, hints[1].pressure);
        input.size = sizeof(input);
        input.version = CNET_OWNER_PLACEMENT_VERSION;
        input.kind = CNET_OWNER_PLACE_LOWEST_PRESSURE;
        input.owners = hints;
        input.owner_count = 2u;
        check_equal(SALTS_OK, cnet_owner_placement_choose(&input, &selected));
        check_equal((size_t)1u, selected);
        /* Host budget full while private P2P client capacity remains free. */
        cap.cohost_occupied_slots = 4u;
        check_equal(SALTS_OK,
            p2p_sg_ace_hint_evaluate(&policy, &s, 1u, 1u, &hints[0]));
        check_false(hints[0].eligible);
        cap.shared_host_connection_capacity = 0u;
        check_equal(SALTS_EINVAL,
            p2p_sg_ace_hint_evaluate(&policy, &s, 1u, 1u, &hints[0]));
        check_false(hints[0].eligible);
    }
    it("fails closed on inconsistent adopted-credit snapshots") {
        p2p_sg_ace_capacity cap = {4};
        p2p_sg_ace_hint policy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(4, 0u, 0u, 1u);
        cnet_owner_placement_hint hint = {true, 77u};
        check_equal(SALTS_EINVAL,
            p2p_sg_ace_hint_evaluate(&policy, &s, 1u, 2u, &hint));
        check_false(hint.eligible);
        check_equal((uint64_t)0u, hint.pressure);
        /* Cross-owner TAKEN and published-Owner counts can race during
         * release. Treat that one candidate as unavailable, not a fatal
         * listener failure or inaccurate zero-pressure admission. */
        hint = (cnet_owner_placement_hint){true, 88u};
        check_equal(SALTS_ENOBUFS,
            p2p_sg_ace_hint_evaluate(&policy, &s, 2u, 2u, &hint));
        check_false(hint.eligible);
        check_equal((uint64_t)0u, hint.pressure);
    }
    it("fails fast on impossible credits, missing state or output") {
        p2p_sg_ace_capacity cap = {4};
        p2p_sg_ace_hint strategy = p2p_sg_ace_capacity_strategy(&cap);
        cnet_handoff_snapshot s = snapshot(2, 1, 1, 1);
        cnet_owner_placement_hint hint = {true, 99u};
        check_equal(SALTS_EINVAL, p2p_sg_ace_hint_evaluate(&strategy, &s, 2u, 0u, &hint));
        check_false(hint.eligible);
        check_equal((uint64_t)0u, hint.pressure);
        check_equal(SALTS_EINVAL, p2p_sg_ace_hint_evaluate(&strategy, NULL, 0u, 0u, &hint));
        check_equal(SALTS_EINVAL, p2p_sg_ace_hint_evaluate(&strategy, &s, 0u, 0u, NULL));
        cap.client_connection_capacity = 0u;
        check_equal(SALTS_EINVAL, p2p_sg_ace_hint_evaluate(&strategy, &s, 0u, 0u, &hint));
    }
}
