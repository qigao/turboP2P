#include "bitmap.h"
#include <roaring.h>
#include <stdlib.h>

roaring_bitmap_t* p2p_bitmap_create(void) {
    return roaring_bitmap_create();
}

void p2p_bitmap_free(roaring_bitmap_t *bitmap) {
    if (bitmap) {
        roaring_bitmap_free(bitmap);
    }
}

void p2p_bitmap_set(roaring_bitmap_t *bitmap, uint32_t index) {
    if (bitmap) {
        roaring_bitmap_add(bitmap, index);
    }
}

void p2p_bitmap_clear(roaring_bitmap_t *bitmap, uint32_t index) {
    if (bitmap) {
        roaring_bitmap_remove(bitmap, index);
    }
}

int p2p_bitmap_get(const roaring_bitmap_t *bitmap, uint32_t index) {
    if (!bitmap) return 0;
    return roaring_bitmap_contains(bitmap, index) ? 1 : 0;
}

uint32_t p2p_bitmap_count_set(const roaring_bitmap_t *bitmap) {
    if (!bitmap) return 0;
    return (uint32_t)roaring_bitmap_get_cardinality(bitmap);
}

uint32_t p2p_bitmap_find_first_zero(const roaring_bitmap_t *bitmap, uint32_t total) {
    if (!bitmap) return 0;
    
    /* Roaring doesn't have a direct "find first zero" but we can iterate or check ranges */
    /* For small 'total', we can just loop. For large, we might need a better way. */
    /* Given the current usage, a simple loop is probably fine as a start, 
       but Roaring's contains is fast. */
    for (uint32_t i = 0; i < total; i++) {
        if (!roaring_bitmap_contains(bitmap, i)) {
            return i;
        }
    }
    return total;
}

int p2p_bitmap_is_complete(const roaring_bitmap_t *bitmap, uint32_t total) {
    if (!bitmap) return total == 0;
    if (total == 0) return 1;
    return roaring_bitmap_contains_range(bitmap, 0, (uint64_t)total) ? 1 : 0;
}

