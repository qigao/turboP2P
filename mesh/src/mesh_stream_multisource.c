#include "mesh_stream_multisource.h"

#include <turbo_crypto.h>

#include <stdlib.h>
#include <string.h>

#define SLOT_FREE 0u
#define SLOT_IN_FLIGHT 1u
#define SLOT_DONE 2u

typedef struct {
  uint64_t seq;
  size_t source_index;
  void *handle;
  uint8_t *buffer;
  size_t len;
  uint64_t started_at_ms;
  uint8_t state;
} mesh_stream_multisource_fetch_v1_t;

struct mesh_stream_multisource_s {
  mesh_stream_source_selector_v1_t *selector;
  mesh_stream_multisource_io_v1_t io;
  uint8_t *block_digests;
  size_t block_count;
  uint64_t block_size;
  size_t max_pending;
  uint64_t fetch_timeout_ms;
  size_t max_retries;
  uint8_t *block_done;
  uint8_t *block_retries;
  size_t *source_in_flight;
  mesh_stream_multisource_fetch_v1_t *fetches;
  uint8_t *slot_pool;
  uint64_t next_expected;
  size_t done_count;
  uint8_t complete;
  uint8_t failed;
};

mesh_stream_multisource_t *mesh_stream_multisource_create(
    mesh_stream_source_selector_v1_t *selector,
    const mesh_stream_multisource_io_v1_t *io,
    const uint8_t block_digests[MESH_STREAM_DATA_HASH_SIZE], size_t block_count,
    uint64_t block_size, size_t max_pending, uint64_t fetch_timeout_ms,
    size_t max_retries) {
  mesh_stream_multisource_t *ms;

  if (!selector || !io || !io->start || !io->poll || !io->cancel ||
      !block_digests || block_count == 0u || block_size == 0u ||
      block_size > 1024u * 1024u || max_pending == 0u ||
      max_pending > MESH_STREAM_SOURCE_MAX || selector->count == 0u) {
    return NULL;
  }
  ms = (mesh_stream_multisource_t *)calloc(1, sizeof(*ms));
  if (!ms)
    return NULL;
  ms->selector = selector;
  ms->io = *io;
  ms->block_count = block_count;
  ms->block_size = block_size;
  ms->max_pending = max_pending;
  ms->fetch_timeout_ms = fetch_timeout_ms;
  ms->max_retries = max_retries;
  ms->block_digests = (uint8_t *)malloc(block_count * MESH_STREAM_DATA_HASH_SIZE);
  ms->block_done = (uint8_t *)calloc(block_count, 1u);
  ms->block_retries = (uint8_t *)calloc(block_count, 1u);
  ms->source_in_flight =
      (size_t *)calloc(selector->count, sizeof(*ms->source_in_flight));
  ms->fetches = (mesh_stream_multisource_fetch_v1_t *)calloc(
      max_pending, sizeof(*ms->fetches));
  ms->slot_pool = (uint8_t *)malloc(max_pending * (size_t)block_size);
  if (!ms->block_digests || !ms->block_done || !ms->block_retries ||
      !ms->source_in_flight || !ms->fetches || !ms->slot_pool) {
    mesh_stream_multisource_destroy(ms);
    return NULL;
  }
  memcpy(ms->block_digests, block_digests,
         block_count * MESH_STREAM_DATA_HASH_SIZE);
  for (size_t i = 0u; i < max_pending; i++)
    ms->fetches[i].buffer = ms->slot_pool + i * (size_t)block_size;
  return ms;
}

void mesh_stream_multisource_destroy(mesh_stream_multisource_t *ms) {
  if (!ms)
    return;
  for (size_t i = 0u; i < ms->max_pending; i++) {
    if (ms->fetches && ms->fetches[i].state == SLOT_IN_FLIGHT &&
        ms->fetches[i].handle && ms->io.cancel) {
      ms->io.cancel(ms->io.context, ms->fetches[i].handle);
    }
  }
  free(ms->block_digests);
  free(ms->block_done);
  free(ms->block_retries);
  free(ms->source_in_flight);
  free(ms->fetches);
  free(ms->slot_pool);
  free(ms);
}

static int block_in_flight(const mesh_stream_multisource_t *ms, uint64_t seq) {
  for (size_t i = 0u; i < ms->max_pending; i++) {
    /* A DONE slot still holds verified data that recv will deliver in order;
     * re-starting it would discard the completed fetch and delay delivery. */
    if ((ms->fetches[i].state == SLOT_IN_FLIGHT ||
         ms->fetches[i].state == SLOT_DONE) &&
        ms->fetches[i].seq == seq) {
      return 1;
    }
  }
  return 0;
}

static int verify_block(const mesh_stream_multisource_t *ms, uint64_t seq,
                        const uint8_t *bytes, size_t len) {
  uint8_t digest[MESH_STREAM_DATA_HASH_SIZE];

  if (len > ms->block_size)
    return 0;
  if (turbo_crypto_sha256(bytes, len, digest) != TURBO_CRYPTO_OK)
    return 0;
  return memcmp(digest, ms->block_digests + seq * MESH_STREAM_DATA_HASH_SIZE,
                MESH_STREAM_DATA_HASH_SIZE) == 0;
}

static void release_slot(mesh_stream_multisource_t *ms,
                         mesh_stream_multisource_fetch_v1_t *slot) {
  if (slot->state == SLOT_IN_FLIGHT && ms->source_in_flight)
    ms->source_in_flight[slot->source_index]--;
  slot->state = SLOT_FREE;
  slot->handle = NULL;
  slot->seq = 0u;
  slot->len = 0u;
}

mesh_stream_multisource_result_t mesh_stream_multisource_tick(
    mesh_stream_multisource_t *ms, uint64_t now_ms) {
  size_t source_index;
  mesh_stream_source_selector_result_t pick_result;

  if (!ms)
    return MESH_STREAM_MULTISOURCE_INVALID_ARG;
  if (ms->complete || ms->failed)
    return MESH_STREAM_MULTISOURCE_OK;

  /* 1) Poll in-flight fetches. */
  for (size_t i = 0u; i < ms->max_pending; i++) {
    mesh_stream_multisource_fetch_v1_t *slot = &ms->fetches[i];
    size_t len = 0u;
    int poll_result;

    if (slot->state != SLOT_IN_FLIGHT)
      continue;
    poll_result = ms->io.poll(ms->io.context, slot->handle, &len);
    if (poll_result == 0) {
      if (verify_block(ms, slot->seq, slot->buffer, len)) {
        slot->len = len;
        slot->state = SLOT_DONE;
        (void)mesh_stream_source_selector_report_success(
            ms->selector, slot->source_index,
            now_ms > slot->started_at_ms ? now_ms - slot->started_at_ms : 0u,
            now_ms);
        if (ms->source_in_flight)
          ms->source_in_flight[slot->source_index]--;
      } else {
        /* Corrupt or wrong-size block: drop and retry elsewhere. */
        (void)mesh_stream_source_selector_report_failure(
            ms->selector, slot->source_index, now_ms);
        if (ms->source_in_flight)
          ms->source_in_flight[slot->source_index]--;
        release_slot(ms, slot);
        if (++ms->block_retries[slot->seq] > ms->max_retries) {
          ms->failed = 1u;
          return MESH_STREAM_MULTISOURCE_FAILED;
        }
      }
    } else if (poll_result < 0 ||
               (ms->fetch_timeout_ms > 0u &&
                now_ms > slot->started_at_ms &&
                now_ms - slot->started_at_ms >= ms->fetch_timeout_ms)) {
      uint64_t seq = slot->seq;

      (void)mesh_stream_source_selector_report_failure(ms->selector,
                                                       slot->source_index,
                                                       now_ms);
      ms->io.cancel(ms->io.context, slot->handle);
      release_slot(ms, slot);
      if (++ms->block_retries[seq] > ms->max_retries) {
        ms->failed = 1u;
        return MESH_STREAM_MULTISOURCE_FAILED;
      }
    }
  }

  /* 2) Start fetches for the lowest undone blocks on the best sources. */
  pick_result = mesh_stream_source_selector_pick(
      ms->selector, 1, ms->source_in_flight, ms->selector->count,
      &source_index);
  while (pick_result == MESH_STREAM_SOURCE_SELECTOR_OK) {
    size_t free_slot = SIZE_MAX;

    for (size_t i = 0u; i < ms->max_pending; i++) {
      if (ms->fetches[i].state == SLOT_FREE) {
        free_slot = i;
        break;
      }
    }
    if (free_slot == SIZE_MAX)
      break;
    {
      mesh_stream_multisource_fetch_v1_t *slot = &ms->fetches[free_slot];
      uint64_t seq = SIZE_MAX;

      for (uint64_t s = 0u; s < ms->block_count; s++) {
        if (!ms->block_done[s] && !block_in_flight(ms, s)) {
          seq = s;
          break;
        }
      }
      if (seq == SIZE_MAX)
        break;
      {
        void *handle = NULL;

        if (ms->io.start(ms->io.context, source_index, seq, slot->buffer,
                         (size_t)ms->block_size, &handle) == 0 && handle) {
          slot->state = SLOT_IN_FLIGHT;
          slot->seq = seq;
          slot->source_index = source_index;
          slot->handle = handle;
          slot->started_at_ms = now_ms;
          ms->source_in_flight[source_index]++;
        } else {
          (void)mesh_stream_source_selector_report_failure(
              ms->selector, source_index, now_ms);
          if (++ms->block_retries[seq] > ms->max_retries) {
            ms->failed = 1u;
            return MESH_STREAM_MULTISOURCE_FAILED;
          }
        }
      }
    }
    pick_result = mesh_stream_source_selector_pick(
        ms->selector, 1, ms->source_in_flight, ms->selector->count,
        &source_index);
  }
  return MESH_STREAM_MULTISOURCE_OK;
}

mesh_stream_multisource_result_t mesh_stream_multisource_recv(
    mesh_stream_multisource_t *ms, uint8_t *out, size_t cap, size_t *out_len) {
  if (out_len)
    *out_len = 0u;
  if (!ms || !out_len || (!out && cap > 0u))
    return MESH_STREAM_MULTISOURCE_INVALID_ARG;
  if (ms->failed)
    return MESH_STREAM_MULTISOURCE_FAILED;
  if (ms->complete)
    return MESH_STREAM_MULTISOURCE_END;
  for (size_t i = 0u; i < ms->max_pending; i++) {
    mesh_stream_multisource_fetch_v1_t *slot = &ms->fetches[i];

    if (slot->state == SLOT_DONE && slot->seq == ms->next_expected) {
      if (slot->len > cap)
        return MESH_STREAM_MULTISOURCE_RESOURCE_EXHAUSTED;
      memcpy(out, slot->buffer, slot->len);
      *out_len = slot->len;
      ms->block_done[slot->seq] = 1u;
      ms->next_expected++;
      ms->done_count++;
      release_slot(ms, slot);
      if (ms->done_count == ms->block_count) {
        ms->complete = 1u;
        return MESH_STREAM_MULTISOURCE_OK;
      }
      return MESH_STREAM_MULTISOURCE_OK;
    }
  }
  return MESH_STREAM_MULTISOURCE_AGAIN;
}

int mesh_stream_multisource_complete(const mesh_stream_multisource_t *ms) {
  return ms && ms->complete;
}
