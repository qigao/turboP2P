#ifndef M3_CHUNK_CID_H
#define M3_CHUNK_CID_H

#include <stdint.h>

#define M3_CHUNK_CID_DIGEST_SIZE 32u
#define M3_CHUNK_STORE_HASH_ALGORITHM_SHA256 1u

typedef struct {
  uint8_t hash_algorithm;
  uint64_t size;
  uint8_t digest[M3_CHUNK_CID_DIGEST_SIZE];
} m3_chunk_cid_v1_t;

#endif
