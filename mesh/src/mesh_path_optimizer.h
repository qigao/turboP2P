#ifndef TURBO_MESH_PATH_OPTIMIZER_H
#define TURBO_MESH_PATH_OPTIMIZER_H

#include <stddef.h>
#include <stdint.h>

#define MESH_PATH_METRIC_MAX_HOPS 15u
#define MESH_PATH_METRIC_MAX_RTT_MS 60000u
#define MESH_PATH_METRIC_MAX_LOSS_PPM 1000000u
#define MESH_PATH_METRIC_INFINITY UINT32_MAX
#define MESH_PATH_METRIC_MAX_FINITE (UINT32_MAX - 1u)

#define MESH_PATH_METRIC_AVAILABLE_RTT (1u << 0)
#define MESH_PATH_METRIC_AVAILABLE_LOSS (1u << 1)
#define MESH_PATH_METRIC_AVAILABLE_QUEUE (1u << 2)
#define MESH_PATH_METRIC_AVAILABLE_ALL \
    (MESH_PATH_METRIC_AVAILABLE_RTT | MESH_PATH_METRIC_AVAILABLE_LOSS | \
     MESH_PATH_METRIC_AVAILABLE_QUEUE)

#define MESH_PATH_METRIC_PROVENANCE_AUTHENTICATED_STREAM (1u << 0)

#define MESH_PATH_METRIC_DIRECT_BASE 100u
#define MESH_PATH_METRIC_LEARNED_BASE 500u
#define MESH_PATH_METRIC_UNKNOWN_PENALTY 100000u
#define MESH_PATH_METRIC_HOP_WEIGHT 100u
#define MESH_PATH_METRIC_SRTT_WEIGHT 8u
#define MESH_PATH_METRIC_RTTVAR_WEIGHT 4u
#define MESH_PATH_METRIC_QUEUE_WEIGHT 8u
#define MESH_PATH_METRIC_LOSS_DIVISOR 100u

#ifndef MESH_PATH_HYSTERESIS_MIN_IMPROVEMENT
#define MESH_PATH_HYSTERESIS_MIN_IMPROVEMENT 200u
#endif
#ifndef MESH_PATH_HYSTERESIS_MIN_IMPROVEMENT_PPM
#define MESH_PATH_HYSTERESIS_MIN_IMPROVEMENT_PPM 100000u
#endif
#ifndef MESH_PATH_HYSTERESIS_WINDOW_MS
#define MESH_PATH_HYSTERESIS_WINDOW_MS 5000u
#endif
#ifndef MESH_PATH_OBSERVER_LIMIT
#define MESH_PATH_OBSERVER_LIMIT 64u
#endif
#ifndef MESH_PATH_OBSERVER_NEXT_HOP_LIMIT
#define MESH_PATH_OBSERVER_NEXT_HOP_LIMIT 4u
#endif
#ifndef MESH_PATH_TRACE_LIMIT
#define MESH_PATH_TRACE_LIMIT 256u
#endif
#if MESH_PATH_TRACE_LIMIT == 0
#error "MESH_PATH_TRACE_LIMIT must be greater than zero"
#endif
#define MESH_PATH_METRIC_CANDIDATE_LIMIT \
    (MESH_PATH_OBSERVER_NEXT_HOP_LIMIT + 3u)

typedef enum {
    MESH_PATH_METRIC_KIND_NONE = 0,
    MESH_PATH_METRIC_KIND_POLICY,
    MESH_PATH_METRIC_KIND_DIRECT,
    MESH_PATH_METRIC_KIND_LEARNED
} mesh_path_metric_kind_t;

typedef struct {
    mesh_path_metric_kind_t kind;
    int eligible;
    uint32_t available_metrics;
    uint32_t srtt_ms;
    uint32_t rttvar_ms;
    uint32_t loss_ppm;
    uint32_t queue_delay_ms;
    uint32_t instability_penalty;
    uint32_t hop_count;
    uint32_t tie_break;
    uint32_t identity;
    uint32_t metric_provenance;
} mesh_path_metric_candidate_t;

typedef struct {
    mesh_path_metric_kind_t current_kind;
    mesh_path_metric_kind_t recommended_kind;
    uint32_t current_identity;
    uint32_t recommended_identity;
    uint32_t current_cost;
    uint32_t recommended_cost;
    uint32_t current_metric_provenance;
    uint32_t recommended_metric_provenance;
    int recommended_available;
    int policy_forced;
    int differs;
} mesh_path_metric_observation_t;

typedef enum {
    MESH_PATH_HYSTERESIS_STABLE = 0,
    MESH_PATH_HYSTERESIS_POLICY,
    MESH_PATH_HYSTERESIS_UNAVAILABLE,
    MESH_PATH_HYSTERESIS_INSUFFICIENT_GAIN,
    MESH_PATH_HYSTERESIS_WINDOW,
    MESH_PATH_HYSTERESIS_READY,
    MESH_PATH_HYSTERESIS_HARD_FAIL
} mesh_path_hysteresis_reason_t;

typedef struct {
    mesh_path_metric_kind_t pending_current_kind;
    mesh_path_metric_kind_t pending_kind;
    uint32_t pending_current_identity;
    uint32_t pending_identity;
    uint64_t pending_since_ms;
    int pending;
} mesh_path_hysteresis_state_t;

typedef struct {
    mesh_path_hysteresis_reason_t reason;
    int suppressed;
    int switch_ready;
    int hard_fail;
} mesh_path_hysteresis_result_t;

typedef struct {
    uint32_t next_hop_ip;
    uint32_t hop_count;
    uint64_t updated_at_ms;
    uint64_t expires_at_ms;
    int in_use;
} mesh_path_observer_candidate_t;

typedef struct {
    mesh_path_metric_kind_t current_kind;
    mesh_path_metric_kind_t recommended_kind;
    uint32_t current_identity;
    uint32_t recommended_identity;
    uint32_t current_cost;
    uint32_t recommended_cost;
    uint32_t current_metric_provenance;
    uint32_t recommended_metric_provenance;
    uint32_t candidate_count;
    uint64_t observed_at_ms;
    mesh_path_hysteresis_reason_t hysteresis_reason;
    int recommended_available;
    int policy_forced;
    int differs;
    int switch_ready;
    int hard_fail;
    int valid;
} mesh_path_observer_diagnostic_t;

typedef struct {
    uint32_t dest_ip;
    mesh_path_observer_candidate_t
        candidates[MESH_PATH_OBSERVER_NEXT_HOP_LIMIT];
    size_t candidate_count;
    mesh_path_hysteresis_state_t hysteresis;
    mesh_path_observer_diagnostic_t diagnostic;
    mesh_path_observer_diagnostic_t trace_baseline;
    int in_use;
} mesh_path_observer_entry_t;

typedef struct {
    mesh_path_observer_entry_t entries[MESH_PATH_OBSERVER_LIMIT];
    size_t count;
    size_t candidate_count;
    uint64_t updates;
    uint64_t capacity_drops;
    uint64_t per_destination_drops;
    uint64_t expirations;
} mesh_path_observer_store_t;

typedef struct {
    uint64_t sequence;
    uint32_t dest_ip;
    mesh_path_observer_diagnostic_t diagnostic;
} mesh_path_trace_record_t;

typedef struct {
    mesh_path_trace_record_t records[MESH_PATH_TRACE_LIMIT];
    size_t start;
    size_t count;
    uint64_t next_sequence;
    uint64_t overwrites;
} mesh_path_trace_store_t;

typedef struct {
    size_t returned_count;
    uint64_t oldest_sequence;
    uint64_t latest_sequence;
    uint64_t next_after_sequence;
    uint64_t overwrites;
    int has_more;
    int gap_detected;
} mesh_path_trace_page_t;

typedef enum {
    MESH_PATH_OBSERVER_INVALID = -2,
    MESH_PATH_OBSERVER_FULL = -1,
    MESH_PATH_OBSERVER_IGNORED = 0,
    MESH_PATH_OBSERVER_INSERTED = 1,
    MESH_PATH_OBSERVER_REFRESHED = 2,
    MESH_PATH_OBSERVER_REPLACED = 3
} mesh_path_observer_update_t;

static inline uint32_t mesh_path_metric_saturating_add(uint32_t lhs, uint32_t rhs) {
    if (lhs >= MESH_PATH_METRIC_MAX_FINITE ||
        rhs > MESH_PATH_METRIC_MAX_FINITE - lhs) {
        return MESH_PATH_METRIC_MAX_FINITE;
    }
    return lhs + rhs;
}

static inline uint32_t mesh_path_metric_saturating_mul(uint32_t lhs, uint32_t rhs) {
    if (lhs != 0u && rhs > MESH_PATH_METRIC_MAX_FINITE / lhs) {
        return MESH_PATH_METRIC_MAX_FINITE;
    }
    return lhs * rhs;
}

static inline int mesh_path_metric_candidate_cost(
    const mesh_path_metric_candidate_t *candidate,
    uint32_t *cost_out) {
    uint32_t cost = 0;

    if (!candidate || !cost_out || !candidate->eligible ||
        candidate->hop_count > MESH_PATH_METRIC_MAX_HOPS) {
        return 0;
    }

    switch (candidate->kind) {
        case MESH_PATH_METRIC_KIND_POLICY:
            cost = 0;
            break;
        case MESH_PATH_METRIC_KIND_DIRECT:
            cost = MESH_PATH_METRIC_DIRECT_BASE;
            break;
        case MESH_PATH_METRIC_KIND_LEARNED:
            cost = MESH_PATH_METRIC_LEARNED_BASE;
            break;
        default:
            return 0;
    }

    cost = mesh_path_metric_saturating_add(
        cost,
        mesh_path_metric_saturating_mul(candidate->hop_count,
                                        MESH_PATH_METRIC_HOP_WEIGHT));

    if ((candidate->available_metrics & MESH_PATH_METRIC_AVAILABLE_RTT) == 0u) {
        cost = mesh_path_metric_saturating_add(
            cost, MESH_PATH_METRIC_UNKNOWN_PENALTY);
        *cost_out =
            mesh_path_metric_saturating_add(cost, candidate->instability_penalty);
        return 1;
    }

    if (candidate->srtt_ms > MESH_PATH_METRIC_MAX_RTT_MS ||
        candidate->rttvar_ms > MESH_PATH_METRIC_MAX_RTT_MS ||
        ((candidate->available_metrics & MESH_PATH_METRIC_AVAILABLE_QUEUE) != 0u &&
         candidate->queue_delay_ms > MESH_PATH_METRIC_MAX_RTT_MS) ||
        ((candidate->available_metrics & MESH_PATH_METRIC_AVAILABLE_LOSS) != 0u &&
         candidate->loss_ppm > MESH_PATH_METRIC_MAX_LOSS_PPM)) {
        return 0;
    }

    cost = mesh_path_metric_saturating_add(
        cost,
        mesh_path_metric_saturating_mul(candidate->srtt_ms,
                                        MESH_PATH_METRIC_SRTT_WEIGHT));
    cost = mesh_path_metric_saturating_add(
        cost,
        mesh_path_metric_saturating_mul(candidate->rttvar_ms,
                                        MESH_PATH_METRIC_RTTVAR_WEIGHT));
    if ((candidate->available_metrics & MESH_PATH_METRIC_AVAILABLE_QUEUE) != 0u) {
        cost = mesh_path_metric_saturating_add(
            cost,
            mesh_path_metric_saturating_mul(candidate->queue_delay_ms,
                                            MESH_PATH_METRIC_QUEUE_WEIGHT));
    }
    if ((candidate->available_metrics & MESH_PATH_METRIC_AVAILABLE_LOSS) != 0u) {
        cost = mesh_path_metric_saturating_add(
            cost, candidate->loss_ppm / MESH_PATH_METRIC_LOSS_DIVISOR);
    }
    cost = mesh_path_metric_saturating_add(cost, candidate->instability_penalty);
    *cost_out = cost;
    return 1;
}

/**
 * Enumerates a bounded candidate snapshot without sorting.
 * Time complexity: O(K). Space complexity: O(1).
 */
static inline mesh_path_metric_observation_t mesh_path_metric_observe(
    const mesh_path_metric_candidate_t *candidates,
    size_t candidate_count,
    mesh_path_metric_kind_t current_kind,
    uint32_t current_identity) {
    mesh_path_metric_observation_t observation;
    uint32_t best_tie_break = UINT32_MAX;
    size_t i = 0;

    observation.current_kind = current_kind;
    observation.recommended_kind = MESH_PATH_METRIC_KIND_NONE;
    observation.current_identity = current_identity;
    observation.recommended_identity = 0;
    observation.current_cost = MESH_PATH_METRIC_INFINITY;
    observation.recommended_cost = MESH_PATH_METRIC_INFINITY;
    observation.current_metric_provenance = 0u;
    observation.recommended_metric_provenance = 0u;
    observation.recommended_available = 0;
    observation.policy_forced = 0;
    observation.differs = 0;

    if ((!candidates && candidate_count != 0u) ||
        candidate_count > MESH_PATH_METRIC_CANDIDATE_LIMIT) {
        return observation;
    }

    for (i = 0; i < candidate_count; i++) {
        const mesh_path_metric_candidate_t *candidate = &candidates[i];
        uint32_t cost = MESH_PATH_METRIC_INFINITY;
        int valid = mesh_path_metric_candidate_cost(candidate, &cost);

        if (candidate->kind == current_kind &&
            candidate->identity == current_identity && valid) {
            observation.current_cost = cost;
            observation.current_metric_provenance =
                candidate->metric_provenance;
        }

        if (candidate->kind == MESH_PATH_METRIC_KIND_POLICY) {
            observation.recommended_kind = MESH_PATH_METRIC_KIND_POLICY;
            observation.recommended_identity = candidate->identity;
            observation.recommended_cost = valid ? cost : MESH_PATH_METRIC_INFINITY;
            observation.recommended_metric_provenance =
                candidate->metric_provenance;
            observation.recommended_available = valid;
            observation.policy_forced = 1;
            observation.differs =
                current_kind != MESH_PATH_METRIC_KIND_POLICY ||
                current_identity != candidate->identity;
            return observation;
        }

        if (!valid) {
            continue;
        }

        if (!observation.recommended_available ||
            cost < observation.recommended_cost ||
            (cost == observation.recommended_cost &&
             candidate->tie_break < best_tie_break)) {
            observation.recommended_kind = candidate->kind;
            observation.recommended_identity = candidate->identity;
            observation.recommended_cost = cost;
            observation.recommended_metric_provenance =
                candidate->metric_provenance;
            observation.recommended_available = 1;
            best_tie_break = candidate->tie_break;
        }
    }

    observation.differs =
        observation.recommended_available &&
        (observation.recommended_kind != current_kind ||
         observation.recommended_identity != current_identity);
    return observation;
}

static inline void mesh_path_hysteresis_reset(
    mesh_path_hysteresis_state_t *state) {
    if (!state) {
        return;
    }
    state->pending_current_kind = MESH_PATH_METRIC_KIND_NONE;
    state->pending_kind = MESH_PATH_METRIC_KIND_NONE;
    state->pending_current_identity = 0;
    state->pending_identity = 0;
    state->pending_since_ms = 0;
    state->pending = 0;
}

/**
 * Qualifies an optimization recommendation without changing the selected path.
 * Time complexity: O(1). Space complexity: O(1).
 */
static inline mesh_path_hysteresis_result_t mesh_path_hysteresis_observe(
    mesh_path_hysteresis_state_t *state,
    const mesh_path_metric_observation_t *observation,
    uint64_t now_ms) {
    mesh_path_hysteresis_result_t result;
    uint32_t improvement = 0;
    uint64_t improvement_ppm = 0;

    result.reason = MESH_PATH_HYSTERESIS_UNAVAILABLE;
    result.suppressed = 0;
    result.switch_ready = 0;
    result.hard_fail = 0;

    if (!state || !observation) {
        return result;
    }

    if (observation->policy_forced) {
        mesh_path_hysteresis_reset(state);
        result.reason = MESH_PATH_HYSTERESIS_POLICY;
        return result;
    }

    if (!observation->recommended_available ||
        observation->recommended_kind == MESH_PATH_METRIC_KIND_NONE ||
        observation->recommended_cost == MESH_PATH_METRIC_INFINITY) {
        mesh_path_hysteresis_reset(state);
        return result;
    }

    if (!observation->differs) {
        mesh_path_hysteresis_reset(state);
        result.reason = MESH_PATH_HYSTERESIS_STABLE;
        return result;
    }

    if (observation->current_cost == MESH_PATH_METRIC_INFINITY) {
        mesh_path_hysteresis_reset(state);
        result.reason = MESH_PATH_HYSTERESIS_HARD_FAIL;
        result.switch_ready = 1;
        result.hard_fail = 1;
        return result;
    }

    if (observation->current_cost == 0u ||
        observation->recommended_cost >= observation->current_cost) {
        mesh_path_hysteresis_reset(state);
        result.reason = MESH_PATH_HYSTERESIS_INSUFFICIENT_GAIN;
        result.suppressed = 1;
        return result;
    }

    improvement = observation->current_cost - observation->recommended_cost;
    improvement_ppm = ((uint64_t)improvement * 1000000u) /
                      observation->current_cost;
    if (improvement < MESH_PATH_HYSTERESIS_MIN_IMPROVEMENT ||
        improvement_ppm < MESH_PATH_HYSTERESIS_MIN_IMPROVEMENT_PPM) {
        mesh_path_hysteresis_reset(state);
        result.reason = MESH_PATH_HYSTERESIS_INSUFFICIENT_GAIN;
        result.suppressed = 1;
        return result;
    }

    if (!state->pending ||
        state->pending_current_kind != observation->current_kind ||
        state->pending_kind != observation->recommended_kind ||
        state->pending_current_identity != observation->current_identity ||
        state->pending_identity != observation->recommended_identity ||
        now_ms < state->pending_since_ms) {
        state->pending_current_kind = observation->current_kind;
        state->pending_kind = observation->recommended_kind;
        state->pending_current_identity = observation->current_identity;
        state->pending_identity = observation->recommended_identity;
        state->pending_since_ms = now_ms;
        state->pending = 1;
        result.reason = MESH_PATH_HYSTERESIS_WINDOW;
        result.suppressed = 1;
        return result;
    }

    if (now_ms - state->pending_since_ms < MESH_PATH_HYSTERESIS_WINDOW_MS) {
        result.reason = MESH_PATH_HYSTERESIS_WINDOW;
        result.suppressed = 1;
        return result;
    }

    result.reason = MESH_PATH_HYSTERESIS_READY;
    result.switch_ready = 1;
    return result;
}

static inline uint64_t mesh_path_observer_expiry(uint64_t now_ms,
                                                 uint64_t ttl_ms) {
    return ttl_ms > UINT64_MAX - now_ms ? UINT64_MAX : now_ms + ttl_ms;
}

static inline void mesh_path_observer_counter_increment(uint64_t *counter) {
    if (counter && *counter < UINT64_MAX) {
        (*counter)++;
    }
}

static inline mesh_path_observer_entry_t *mesh_path_observer_find(
    mesh_path_observer_store_t *store,
    uint32_t dest_ip) {
    size_t i = 0;

    if (!store || dest_ip == 0u) {
        return NULL;
    }
    for (i = 0; i < MESH_PATH_OBSERVER_LIMIT; i++) {
        if (store->entries[i].in_use &&
            store->entries[i].dest_ip == dest_ip) {
            return &store->entries[i];
        }
    }
    return NULL;
}

/**
 * Expires learned candidates and removes empty destination buckets. Time
 * complexity: O(D*C), space: O(1), with D <= 64 and C <= 4.
 */
static inline size_t mesh_path_observer_expire(
    mesh_path_observer_store_t *store,
    uint64_t now_ms) {
    size_t expired = 0;
    size_t entry_index = 0;

    if (!store) {
        return 0;
    }

    for (entry_index = 0; entry_index < MESH_PATH_OBSERVER_LIMIT;
         entry_index++) {
        mesh_path_observer_entry_t *entry = &store->entries[entry_index];
        size_t candidate_index = 0;

        if (!entry->in_use) {
            continue;
        }
        for (candidate_index = 0;
             candidate_index < MESH_PATH_OBSERVER_NEXT_HOP_LIMIT;
             candidate_index++) {
            mesh_path_observer_candidate_t *candidate =
                &entry->candidates[candidate_index];

            if (!candidate->in_use || now_ms < candidate->expires_at_ms) {
                continue;
            }
            *candidate = (mesh_path_observer_candidate_t){0};
            if (entry->candidate_count > 0) {
                entry->candidate_count--;
            }
            if (store->candidate_count > 0) {
                store->candidate_count--;
            }
            mesh_path_observer_counter_increment(&store->expirations);
            expired++;
            entry->diagnostic.valid = 0;
            mesh_path_hysteresis_reset(&entry->hysteresis);
        }
        if (entry->candidate_count == 0) {
            *entry = (mesh_path_observer_entry_t){0};
            if (store->count > 0) {
                store->count--;
            }
        }
    }
    return expired;
}

/**
 * Stores up to four learned next-hop identities per destination. When a
 * destination bucket is full, only a strictly shorter candidate replaces the
 * deterministic worst entry; equal-hop input cannot cause churn.
 * Time complexity: O(D+C), space: O(1), with D <= 64 and C <= 4.
 */
static inline mesh_path_observer_update_t mesh_path_observer_upsert(
    mesh_path_observer_store_t *store,
    uint32_t dest_ip,
    uint32_t next_hop_ip,
    uint32_t hop_count,
    uint64_t now_ms,
    uint64_t ttl_ms) {
    mesh_path_observer_entry_t *entry = NULL;
    mesh_path_observer_entry_t *free_entry = NULL;
    mesh_path_observer_candidate_t *free_candidate = NULL;
    mesh_path_observer_candidate_t *worst_candidate = NULL;
    size_t entry_index = 0;
    size_t candidate_index = 0;

    if (!store || dest_ip == 0u || next_hop_ip == 0u ||
        dest_ip == next_hop_ip || hop_count == 0u ||
        hop_count > MESH_PATH_METRIC_MAX_HOPS || ttl_ms == 0u) {
        return MESH_PATH_OBSERVER_INVALID;
    }

    (void)mesh_path_observer_expire(store, now_ms);
    for (entry_index = 0; entry_index < MESH_PATH_OBSERVER_LIMIT;
         entry_index++) {
        mesh_path_observer_entry_t *candidate_entry =
            &store->entries[entry_index];

        if (!candidate_entry->in_use) {
            if (!free_entry) {
                free_entry = candidate_entry;
            }
            continue;
        }
        if (candidate_entry->dest_ip == dest_ip) {
            entry = candidate_entry;
            break;
        }
    }

    if (!entry) {
        if (!free_entry) {
            mesh_path_observer_counter_increment(&store->capacity_drops);
            return MESH_PATH_OBSERVER_FULL;
        }
        entry = free_entry;
        entry->dest_ip = dest_ip;
        entry->in_use = 1;
        store->count++;
    }

    for (candidate_index = 0;
         candidate_index < MESH_PATH_OBSERVER_NEXT_HOP_LIMIT;
         candidate_index++) {
        mesh_path_observer_candidate_t *candidate =
            &entry->candidates[candidate_index];

        if (!candidate->in_use) {
            if (!free_candidate) {
                free_candidate = candidate;
            }
            continue;
        }
        if (!worst_candidate ||
            candidate->hop_count > worst_candidate->hop_count ||
            (candidate->hop_count == worst_candidate->hop_count &&
             candidate->updated_at_ms < worst_candidate->updated_at_ms) ||
            (candidate->hop_count == worst_candidate->hop_count &&
             candidate->updated_at_ms == worst_candidate->updated_at_ms &&
             candidate->next_hop_ip > worst_candidate->next_hop_ip)) {
            worst_candidate = candidate;
        }
        if (candidate->next_hop_ip == next_hop_ip) {
            if (hop_count > candidate->hop_count) {
                return MESH_PATH_OBSERVER_IGNORED;
            }
            if (hop_count < candidate->hop_count) {
                mesh_path_hysteresis_reset(&entry->hysteresis);
            }
            candidate->hop_count = hop_count;
            candidate->updated_at_ms = now_ms;
            candidate->expires_at_ms =
                mesh_path_observer_expiry(now_ms, ttl_ms);
            entry->diagnostic.valid = 0;
            mesh_path_observer_counter_increment(&store->updates);
            return MESH_PATH_OBSERVER_REFRESHED;
        }
    }

    if (free_candidate) {
        free_candidate->next_hop_ip = next_hop_ip;
        free_candidate->hop_count = hop_count;
        free_candidate->updated_at_ms = now_ms;
        free_candidate->expires_at_ms =
            mesh_path_observer_expiry(now_ms, ttl_ms);
        free_candidate->in_use = 1;
        entry->candidate_count++;
        store->candidate_count++;
        entry->diagnostic.valid = 0;
        mesh_path_observer_counter_increment(&store->updates);
        return MESH_PATH_OBSERVER_INSERTED;
    }

    if (!worst_candidate || hop_count >= worst_candidate->hop_count) {
        mesh_path_observer_counter_increment(&store->capacity_drops);
        mesh_path_observer_counter_increment(&store->per_destination_drops);
        return MESH_PATH_OBSERVER_FULL;
    }

    worst_candidate->next_hop_ip = next_hop_ip;
    worst_candidate->hop_count = hop_count;
    worst_candidate->updated_at_ms = now_ms;
    worst_candidate->expires_at_ms =
        mesh_path_observer_expiry(now_ms, ttl_ms);
    mesh_path_hysteresis_reset(&entry->hysteresis);
    entry->diagnostic.valid = 0;
    mesh_path_observer_counter_increment(&store->updates);
    return MESH_PATH_OBSERVER_REPLACED;
}

static inline void mesh_path_observer_record_diagnostic(
    mesh_path_observer_entry_t *entry,
    const mesh_path_metric_observation_t *observation,
    const mesh_path_hysteresis_result_t *hysteresis,
    size_t candidate_count,
    uint64_t observed_at_ms) {
    mesh_path_observer_diagnostic_t *diagnostic = NULL;

    if (!entry || !observation || !hysteresis || !entry->in_use ||
        candidate_count > MESH_PATH_METRIC_CANDIDATE_LIMIT) {
        return;
    }
    diagnostic = &entry->diagnostic;
    diagnostic->current_kind = observation->current_kind;
    diagnostic->recommended_kind = observation->recommended_kind;
    diagnostic->current_identity = observation->current_identity;
    diagnostic->recommended_identity = observation->recommended_identity;
    diagnostic->current_cost = observation->current_cost;
    diagnostic->recommended_cost = observation->recommended_cost;
    diagnostic->current_metric_provenance =
        observation->current_metric_provenance;
    diagnostic->recommended_metric_provenance =
        observation->recommended_metric_provenance;
    diagnostic->candidate_count = (uint32_t)candidate_count;
    diagnostic->observed_at_ms = observed_at_ms;
    diagnostic->hysteresis_reason = hysteresis->reason;
    diagnostic->recommended_available = observation->recommended_available;
    diagnostic->policy_forced = observation->policy_forced;
    diagnostic->differs = observation->differs;
    diagnostic->switch_ready = hysteresis->switch_ready;
    diagnostic->hard_fail = hysteresis->hard_fail;
    diagnostic->valid = 1;
}

static inline int mesh_path_observer_diagnostic_equal(
    const mesh_path_observer_diagnostic_t *lhs,
    const mesh_path_observer_diagnostic_t *rhs) {
    if (!lhs || !rhs || !lhs->valid || !rhs->valid) {
        return 0;
    }
    return lhs->current_kind == rhs->current_kind &&
           lhs->recommended_kind == rhs->recommended_kind &&
           lhs->current_identity == rhs->current_identity &&
           lhs->recommended_identity == rhs->recommended_identity &&
           lhs->current_cost == rhs->current_cost &&
           lhs->recommended_cost == rhs->recommended_cost &&
           lhs->current_metric_provenance == rhs->current_metric_provenance &&
           lhs->recommended_metric_provenance ==
               rhs->recommended_metric_provenance &&
           lhs->candidate_count == rhs->candidate_count &&
           lhs->hysteresis_reason == rhs->hysteresis_reason &&
           lhs->recommended_available == rhs->recommended_available &&
           lhs->policy_forced == rhs->policy_forced &&
           lhs->differs == rhs->differs &&
           lhs->switch_ready == rhs->switch_ready &&
           lhs->hard_fail == rhs->hard_fail;
}

/**
 * Appends only semantic path changes. The fixed ring overwrites its oldest
 * record when full. Time and space complexity are O(1).
 */
static inline int mesh_path_trace_append_if_changed(
    mesh_path_trace_store_t *store,
    uint32_t dest_ip,
    const mesh_path_observer_diagnostic_t *diagnostic,
    mesh_path_observer_diagnostic_t *baseline) {
    mesh_path_trace_record_t *record = NULL;
    const mesh_path_trace_record_t *latest = NULL;
    size_t index = 0;

    if (!store || dest_ip == 0u || !diagnostic || !diagnostic->valid ||
        !baseline ||
        mesh_path_observer_diagnostic_equal(baseline, diagnostic)) {
        return 0;
    }

    if (store->count > 0u && store->next_sequence == UINT64_MAX) {
        latest = &store->records[(store->start + store->count - 1u) %
                                 MESH_PATH_TRACE_LIMIT];
        if (latest->sequence == UINT64_MAX) {
            return 0;
        }
    }

    if (store->count < MESH_PATH_TRACE_LIMIT) {
        index = (store->start + store->count) % MESH_PATH_TRACE_LIMIT;
        store->count++;
    } else {
        index = store->start;
        store->start = (store->start + 1u) % MESH_PATH_TRACE_LIMIT;
        mesh_path_observer_counter_increment(&store->overwrites);
    }

    if (store->next_sequence == 0u) {
        store->next_sequence = 1u;
    }
    record = &store->records[index];
    record->sequence = store->next_sequence;
    record->dest_ip = dest_ip;
    record->diagnostic = *diagnostic;
    if (store->next_sequence < UINT64_MAX) {
        store->next_sequence++;
    }
    *baseline = *diagnostic;
    return 1;
}

/**
 * Copies the newest available window in chronological order without mutating
 * the owner-loop store. Time complexity is O(N), N <= output capacity.
 */
static inline size_t mesh_path_trace_snapshot(
    const mesh_path_trace_store_t *store,
    mesh_path_trace_record_t *out,
    size_t capacity) {
    size_t copy_count = 0;
    size_t first = 0;
    size_t i = 0;

    if (!store || !out || capacity == 0u || store->count == 0u) {
        return 0;
    }
    copy_count = store->count < capacity ? store->count : capacity;
    first = (store->start + store->count - copy_count) %
            MESH_PATH_TRACE_LIMIT;
    for (i = 0; i < copy_count; i++) {
        out[i] = store->records[(first + i) % MESH_PATH_TRACE_LIMIT];
    }
    return copy_count;
}

/**
 * Copies the oldest retained records after an exclusive sequence cursor.
 * A cursor older than retained history reports a gap and resumes at the
 * oldest record. Time complexity is O(R), R <= 256; space is O(1).
 */
static inline size_t mesh_path_trace_snapshot_after(
    const mesh_path_trace_store_t *store,
    uint64_t after_sequence,
    mesh_path_trace_record_t *out,
    size_t capacity,
    mesh_path_trace_page_t *page) {
    size_t first_offset = 0;
    size_t available_count = 0;
    size_t copy_count = 0;
    size_t i = 0;

    if (!page || (!out && capacity != 0u)) {
        return 0;
    }
    *page = (mesh_path_trace_page_t){0};
    page->next_after_sequence = after_sequence;
    if (!store || store->count == 0u) {
        return 0;
    }

    page->oldest_sequence = store->records[store->start].sequence;
    page->latest_sequence =
        store->records[(store->start + store->count - 1u) %
                       MESH_PATH_TRACE_LIMIT].sequence;
    page->overwrites = store->overwrites;
    if (after_sequence != 0u &&
        after_sequence < page->oldest_sequence &&
        page->oldest_sequence - after_sequence > 1u) {
        page->gap_detected = 1;
    }

    if (after_sequence >= page->oldest_sequence) {
        for (first_offset = 0; first_offset < store->count; first_offset++) {
            const mesh_path_trace_record_t *record =
                &store->records[(store->start + first_offset) %
                                MESH_PATH_TRACE_LIMIT];
            if (record->sequence > after_sequence) {
                break;
            }
        }
    }

    available_count = store->count - first_offset;
    copy_count = available_count < capacity ? available_count : capacity;
    for (i = 0; i < copy_count; i++) {
        out[i] = store->records[(store->start + first_offset + i) %
                                MESH_PATH_TRACE_LIMIT];
    }
    page->returned_count = copy_count;
    page->has_more = available_count > copy_count;
    if (copy_count > 0u) {
        page->next_after_sequence = out[copy_count - 1u].sequence;
    }
    return copy_count;
}

/**
 * Copies the latest owner-loop diagnostic without advancing observer state.
 * Time complexity: O(D), space: O(1), with D <= 64.
 */
static inline int mesh_path_observer_diagnostic_snapshot(
    const mesh_path_observer_store_t *store,
    uint32_t dest_ip,
    mesh_path_observer_diagnostic_t *out) {
    size_t entry_index = 0;

    if (!out) {
        return 0;
    }
    *out = (mesh_path_observer_diagnostic_t){0};
    if (!store || dest_ip == 0u) {
        return 0;
    }
    for (entry_index = 0; entry_index < MESH_PATH_OBSERVER_LIMIT;
         entry_index++) {
        const mesh_path_observer_entry_t *entry =
            &store->entries[entry_index];

        if (!entry->in_use || entry->dest_ip != dest_ip ||
            !entry->diagnostic.valid) {
            continue;
        }
        *out = entry->diagnostic;
        return 1;
    }
    return 0;
}

#endif
