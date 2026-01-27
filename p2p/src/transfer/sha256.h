/**
 * P2P SHA-256 Implementation
 */
#ifndef P2P_SHA256_H
#define P2P_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define P2P_SHA256_DIGEST_SIZE 32
#define P2P_SHA256_BLOCK_SIZE  64

/* Incremental hashing context */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[P2P_SHA256_BLOCK_SIZE];
} p2p_sha256_ctx_t;

/**
 * Initialize hash context
 */
void p2p_sha256_init(p2p_sha256_ctx_t *ctx);

/**
 * Update hash with data
 */
void p2p_sha256_update(p2p_sha256_ctx_t *ctx, const void *data, size_t len);

/**
 * Finalize and get hash
 */
void p2p_sha256_final(p2p_sha256_ctx_t *ctx, uint8_t digest[P2P_SHA256_DIGEST_SIZE]);

/**
 * One-shot hash
 */
void p2p_sha256(const void *data, size_t len, uint8_t digest[P2P_SHA256_DIGEST_SIZE]);

#endif /* P2P_SHA256_H */
