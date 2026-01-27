/**
 * P2P Bitmap - Roaring Bitmap implementation
 */
#ifndef P2P_BITMAP_H
#define P2P_BITMAP_H

#include <stdint.h>
#include <stddef.h>

/* Forward declaration of roaring_bitmap_t */
struct roaring_bitmap_s;
typedef struct roaring_bitmap_s roaring_bitmap_t;

/**
 * Create a new bitmap
 */
roaring_bitmap_t* p2p_bitmap_create(void);

/**
 * Free bitmap
 */
void p2p_bitmap_free(roaring_bitmap_t *bitmap);

/**
 * Set bit at index
 */
void p2p_bitmap_set(roaring_bitmap_t *bitmap, uint32_t index);

/**
 * Clear bit at index
 */
void p2p_bitmap_clear(roaring_bitmap_t *bitmap, uint32_t index);

/**
 * Get bit value at index (returns 0 or 1)
 */
int p2p_bitmap_get(const roaring_bitmap_t *bitmap, uint32_t index);

/**
 * Count number of set bits
 */
uint32_t p2p_bitmap_count_set(const roaring_bitmap_t *bitmap);

/**
 * Find first zero bit, returns total if all bits are set
 */
uint32_t p2p_bitmap_find_first_zero(const roaring_bitmap_t *bitmap, uint32_t total);

/**
 * Check if all bits up to total are set
 */
int p2p_bitmap_is_complete(const roaring_bitmap_t *bitmap, uint32_t total);

#endif /* P2P_BITMAP_H */

