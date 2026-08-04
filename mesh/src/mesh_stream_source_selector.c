#include "mesh_stream_source_selector.h"

#include <string.h>

static int bytes_are_nonzero(const uint8_t *bytes, size_t size) {
  uint8_t aggregate = 0u;

  if (!bytes)
    return 0;
  for (size_t i = 0u; i < size; i++)
    aggregate |= bytes[i];
  return aggregate != 0u;
}

mesh_stream_source_selector_result_t mesh_stream_source_selector_init(
    mesh_stream_source_selector_v1_t *selector, uint64_t fail_threshold,
    uint64_t rtt_alpha) {
  if (!selector)
    return MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG;
  memset(selector, 0, sizeof(*selector));
  selector->fail_threshold =
      fail_threshold == 0u ? MESH_STREAM_SOURCE_DEFAULT_FAIL_THRESHOLD
                           : fail_threshold;
  selector->rtt_alpha = rtt_alpha == 0u ? 4u : rtt_alpha;
  return MESH_STREAM_SOURCE_SELECTOR_OK;
}

mesh_stream_source_selector_result_t mesh_stream_source_selector_register(
    mesh_stream_source_selector_v1_t *selector,
    const uint8_t source_id[MESH_STREAM_SOURCE_ID_SIZE]) {
  if (!selector || !source_id ||
      !bytes_are_nonzero(source_id, MESH_STREAM_SOURCE_ID_SIZE)) {
    return MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG;
  }
  for (size_t i = 0u; i < selector->count; i++) {
    if (memcmp(selector->sources[i].id, source_id,
               MESH_STREAM_SOURCE_ID_SIZE) == 0) {
      return MESH_STREAM_SOURCE_SELECTOR_OK;
    }
  }
  if (selector->count >= MESH_STREAM_SOURCE_MAX)
    return MESH_STREAM_SOURCE_SELECTOR_RESOURCE_EXHAUSTED;
  memcpy(selector->sources[selector->count].id, source_id,
         MESH_STREAM_SOURCE_ID_SIZE);
  selector->sources[selector->count].enabled = 1u;
  selector->sources[selector->count].smoothed_rtt_ms = 0u;
  selector->count++;
  return MESH_STREAM_SOURCE_SELECTOR_OK;
}

mesh_stream_source_selector_result_t mesh_stream_source_selector_report_success(
    mesh_stream_source_selector_v1_t *selector, size_t source_index,
    uint64_t rtt_ms, uint64_t now_ms) {
  mesh_stream_source_metric_v1_t *source;

  if (!selector || source_index >= selector->count)
    return MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG;
  source = &selector->sources[source_index];
  source->enabled = 1u;
  source->consecutive_failures = 0u;
  source->total_successes++;
  source->last_rtt_ms = rtt_ms;
  source->smoothed_rtt_ms =
      source->smoothed_rtt_ms == 0u
          ? rtt_ms
          : source->smoothed_rtt_ms +
                (rtt_ms - source->smoothed_rtt_ms) / selector->rtt_alpha;
  source->last_activity_ms = now_ms;
  return MESH_STREAM_SOURCE_SELECTOR_OK;
}

mesh_stream_source_selector_result_t mesh_stream_source_selector_report_failure(
    mesh_stream_source_selector_v1_t *selector, size_t source_index,
    uint64_t now_ms) {
  mesh_stream_source_metric_v1_t *source;

  if (!selector || source_index >= selector->count)
    return MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG;
  source = &selector->sources[source_index];
  source->consecutive_failures++;
  source->total_failures++;
  source->last_activity_ms = now_ms;
  if (source->consecutive_failures >= selector->fail_threshold)
    source->enabled = 0u;
  return MESH_STREAM_SOURCE_SELECTOR_OK;
}

static uint64_t effective_rtt(const mesh_stream_source_metric_v1_t *source) {
  /* Unknown RTT (no sample yet) compares as worst so learned sources win. */
  return source->smoothed_rtt_ms == 0u ? UINT64_MAX : source->smoothed_rtt_ms;
}

static int source_is_better(const mesh_stream_source_metric_v1_t *candidate,
                            const mesh_stream_source_metric_v1_t *best) {
  uint64_t candidate_rtt = effective_rtt(candidate);
  uint64_t best_rtt = effective_rtt(best);

  if (candidate->consecutive_failures != best->consecutive_failures)
    return candidate->consecutive_failures < best->consecutive_failures;
  if (candidate_rtt != best_rtt)
    return candidate_rtt < best_rtt;
  return candidate->total_failures < best->total_failures;
}

mesh_stream_source_selector_result_t mesh_stream_source_selector_pick(
    const mesh_stream_source_selector_v1_t *selector, int prefer_spread,
    const size_t *in_flight, size_t in_flight_count, size_t *out_source_index) {
  size_t best = SIZE_MAX;
  size_t best_in_flight = SIZE_MAX;

  if (out_source_index)
    *out_source_index = SIZE_MAX;
  if (!selector || !out_source_index ||
      (prefer_spread && !in_flight) ||
      (prefer_spread && in_flight_count != selector->count)) {
    return MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG;
  }
  for (size_t i = 0u; i < selector->count; i++) {
    const mesh_stream_source_metric_v1_t *candidate = &selector->sources[i];

    if (!candidate->enabled)
      continue;
    if (best == SIZE_MAX) {
      best = i;
      best_in_flight = prefer_spread ? in_flight[i] : 0u;
      continue;
    }
    if (prefer_spread) {
      if (in_flight[i] < best_in_flight ||
          (in_flight[i] == best_in_flight &&
           source_is_better(candidate, &selector->sources[best]))) {
        best = i;
        best_in_flight = in_flight[i];
      }
    } else if (source_is_better(candidate, &selector->sources[best])) {
      best = i;
    }
  }
  if (best == SIZE_MAX)
    return MESH_STREAM_SOURCE_SELECTOR_NO_SOURCE;
  *out_source_index = best;
  return MESH_STREAM_SOURCE_SELECTOR_OK;
}

mesh_stream_source_selector_result_t mesh_stream_source_selector_enable(
    mesh_stream_source_selector_v1_t *selector, size_t source_index) {
  if (!selector || source_index >= selector->count)
    return MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG;
  selector->sources[source_index].enabled = 1u;
  return MESH_STREAM_SOURCE_SELECTOR_OK;
}
