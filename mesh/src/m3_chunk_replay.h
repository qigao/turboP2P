#ifndef M3_CHUNK_REPLAY_H
#define M3_CHUNK_REPLAY_H

#include "m3_chunk_capability.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_CHUNK_REPLAY_DIGEST_SIZE 32u
#define M3_CHUNK_REPLAY_MAX_ENTRIES 4096u

typedef enum {
  M3_CHUNK_REPLAY_OK = 0,
  M3_CHUNK_REPLAY_INVALID_ARG = -1,
  M3_CHUNK_REPLAY_INVALID_ACCESS = -2,
  M3_CHUNK_REPLAY_EXPIRED = -3,
  M3_CHUNK_REPLAY_CONFLICT = -4,
  M3_CHUNK_REPLAY_NOT_FOUND = -5,
  M3_CHUNK_REPLAY_RESOURCE_EXHAUSTED = -6,
  M3_CHUNK_REPLAY_CRYPTO_FAILED = -7,
} m3_chunk_replay_result_t;

typedef enum {
  M3_CHUNK_REPLAY_ENTRY_FREE = 0,
  M3_CHUNK_REPLAY_ENTRY_IN_PROGRESS = 1,
  M3_CHUNK_REPLAY_ENTRY_COMPLETED = 2,
} m3_chunk_replay_entry_state_t;

typedef enum {
  M3_CHUNK_REPLAY_BEGIN_NEW = 1,
  M3_CHUNK_REPLAY_BEGIN_IN_PROGRESS = 2,
  M3_CHUNK_REPLAY_BEGIN_COMPLETED = 3,
} m3_chunk_replay_begin_kind_t;

typedef struct {
  turbo_uuid_t request_id;
  uint8_t access_digest[M3_CHUNK_REPLAY_DIGEST_SIZE];
  uint64_t expires_at_ms;
  m3_chunk_replay_entry_state_t state;
  int32_t result_code;
} m3_chunk_replay_entry_v1_t;

/**
 * Owner-loop state. Calls are not thread-safe and must be serialized.
 */
typedef struct {
  m3_chunk_replay_entry_v1_t *entries;
  size_t capacity;
  uint64_t max_ttl_ms;
} m3_chunk_replay_journal_v1_t;

typedef struct {
  m3_chunk_replay_begin_kind_t kind;
  int32_t result_code;
} m3_chunk_replay_begin_v1_t;

m3_chunk_replay_result_t m3_chunk_replay_journal_init_v1(
    m3_chunk_replay_journal_v1_t *journal, size_t capacity,
    uint64_t max_ttl_ms);

void m3_chunk_replay_journal_destroy_v1(
    m3_chunk_replay_journal_v1_t *journal);

/**
 * Remove expired entries. Live entries are never evicted for capacity.
 */
size_t m3_chunk_replay_journal_sweep_v1(
    m3_chunk_replay_journal_v1_t *journal, uint64_t now_ms);

/**
 * Bind a request UUID to the canonical authorized-access digest.
 *
 * A new binding becomes IN_PROGRESS. An exact retry reports the existing
 * state/result. Reusing the UUID for different access returns CONFLICT.
 */
m3_chunk_replay_result_t m3_chunk_replay_begin_request_v1(
    m3_chunk_replay_journal_v1_t *journal,
    const m3_chunk_authorized_access_v1_t *access, uint64_t now_ms,
    m3_chunk_replay_begin_v1_t *out_begin);

/**
 * Persist the first terminal adapter result in memory.
 *
 * Repeating the same completion is idempotent. A different second result is a
 * conflict and cannot change the terminal fact.
 */
m3_chunk_replay_result_t m3_chunk_replay_complete_request_v1(
    m3_chunk_replay_journal_v1_t *journal,
    const m3_chunk_authorized_access_v1_t *access, int32_t result_code);

#ifdef __cplusplus
}
#endif

#endif
