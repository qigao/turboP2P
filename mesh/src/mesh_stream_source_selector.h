#ifndef TURBO_P2P_MESH_STREAM_SOURCE_SELECTOR_H
#define TURBO_P2P_MESH_STREAM_SOURCE_SELECTOR_H

#include "mesh_stream_data.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_STREAM_SOURCE_ID_SIZE 16u
#define MESH_STREAM_SOURCE_MAX 8u
#define MESH_STREAM_SOURCE_DEFAULT_FAIL_THRESHOLD 3u

typedef enum {
  MESH_STREAM_SOURCE_SELECTOR_OK = 0,
  MESH_STREAM_SOURCE_SELECTOR_INVALID_ARG = -1,
  MESH_STREAM_SOURCE_SELECTOR_RESOURCE_EXHAUSTED = -2,
  MESH_STREAM_SOURCE_SELECTOR_NOT_FOUND = -3,
  MESH_STREAM_SOURCE_SELECTOR_NO_SOURCE = -4,
} mesh_stream_source_selector_result_t;

/**
 * Per-source health. A source is disabled once its consecutive failure count
 * reaches fail_threshold; report_success re-enables it. RTT is an EWMA so a
 * flaky source stays deprioritized for a while after recovery.
 */
typedef struct {
  uint8_t id[MESH_STREAM_SOURCE_ID_SIZE];
  uint8_t enabled;
  uint64_t consecutive_failures;
  uint64_t total_failures;
  uint64_t total_successes;
  uint64_t last_rtt_ms;
  uint64_t smoothed_rtt_ms;
  uint64_t last_activity_ms;
} mesh_stream_source_metric_v1_t;

typedef struct {
  mesh_stream_source_metric_v1_t sources[MESH_STREAM_SOURCE_MAX];
  size_t count;
  uint64_t fail_threshold;
  uint64_t rtt_alpha; /* EWMA divisor: smoothed += (rtt - smoothed) / alpha */
} mesh_stream_source_selector_v1_t;

/** Zero-initialize before first use; threshold defaults to 3, alpha to 4. */
mesh_stream_source_selector_result_t mesh_stream_source_selector_init(
    mesh_stream_source_selector_v1_t *selector, uint64_t fail_threshold,
    uint64_t rtt_alpha);

mesh_stream_source_selector_result_t mesh_stream_source_selector_register(
    mesh_stream_source_selector_v1_t *selector,
    const uint8_t source_id[MESH_STREAM_SOURCE_ID_SIZE]);

/** Record one successful fetch; rtt_ms resets failures and updates the EWMA. */
mesh_stream_source_selector_result_t mesh_stream_source_selector_report_success(
    mesh_stream_source_selector_v1_t *selector, size_t source_index,
    uint64_t rtt_ms, uint64_t now_ms);

/** Record one failed fetch; disables the source at the failure threshold. */
mesh_stream_source_selector_result_t mesh_stream_source_selector_report_failure(
    mesh_stream_source_selector_v1_t *selector, size_t source_index,
    uint64_t now_ms);

/**
 * Pick the best enabled source. With prefer_spread, the candidate with the
 * fewest in-flight requests wins first (ties broken by lower failures, then
 * lower smoothed RTT); otherwise lower failures then lower RTT win.
 */
mesh_stream_source_selector_result_t mesh_stream_source_selector_pick(
    const mesh_stream_source_selector_v1_t *selector, int prefer_spread,
    const size_t *in_flight, size_t in_flight_count, size_t *out_source_index);

/** Explicitly re-enable a disabled source (e.g., after a grace period). */
mesh_stream_source_selector_result_t mesh_stream_source_selector_enable(
    mesh_stream_source_selector_v1_t *selector, size_t source_index);

#ifdef __cplusplus
}
#endif

#endif
