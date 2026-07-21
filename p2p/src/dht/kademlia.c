/**
 * kademlia.c - Professional Kademlia DHT Implementation
 * Industry-standard P2P routing (used by BitTorrent, IPFS, Ethereum)
 */

#include "kademlia.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/sha.h>

/* =============================================================================
 * ID Operations
 * ============================================================================= */

void kad_id_from_data(const void *data, size_t len, kad_id_t *out) {
    if (!data || !out) return;
    SHA1((const unsigned char *)data, len, out->bytes);
}

/* XOR distance between two IDs */
static void kad_id_xor(const kad_id_t *a, const kad_id_t *b, kad_id_t *result) {
    for (int i = 0; i < KADEMLIA_ID_BYTES; i++) {
        result->bytes[i] = a->bytes[i] ^ b->bytes[i];
    }
}

/* Compare distances: returns -1 if a closer, 1 if b closer, 0 if equal */
int kad_id_distance_cmp(const kad_id_t *target, const kad_id_t *a, const kad_id_t *b) {
    kad_id_t dist_a, dist_b;
    kad_id_xor(target, a, &dist_a);
    kad_id_xor(target, b, &dist_b);
    
    return memcmp(dist_a.bytes, dist_b.bytes, KADEMLIA_ID_BYTES);
}

/* Count matching prefix bits (for bucket index) */
int kad_id_prefix_len(const kad_id_t *a, const kad_id_t *b) {
    int prefix = 0;
    for (int i = 0; i < KADEMLIA_ID_BYTES; i++) {
        uint8_t diff = a->bytes[i] ^ b->bytes[i];
        if (diff == 0) {
            prefix += 8;
        } else {
            /* Count leading zeros in XOR byte */
            for (int bit = 7; bit >= 0; bit--) {
                if (diff & (1 << bit)) break;
                prefix++;
            }
            break;
        }
    }
    return prefix;
}

/* =============================================================================
 * K-Bucket Operations
 * ============================================================================= */

static int bucket_index(const kad_id_t *local_id, const kad_id_t *node_id) {
    int prefix = kad_id_prefix_len(local_id, node_id);
    int idx = KADEMLIA_ID_BITS - prefix - 1;
    return (idx < 0) ? 0 : (idx >= KADEMLIA_ID_BITS ? KADEMLIA_ID_BITS - 1 : idx);
}

static kad_node_t *kad_node_create(const kad_id_t *id, const char *ip, uint16_t port) {
    kad_node_t *node = (kad_node_t *)calloc(1, sizeof(kad_node_t));
    if (!node) return NULL;
    
    memcpy(&node->id, id, sizeof(kad_id_t));
    strncpy(node->ip, ip, sizeof(node->ip) - 1);
    node->port = port;
    node->last_seen = (uint64_t)time(NULL);
    node->next = NULL;
    
    return node;
}

/* =============================================================================
 * Routing Table Operations
 * ============================================================================= */

kad_routing_table_t *kad_routing_create(const kad_id_t *local_id) {
    if (!local_id) return NULL;
    
    kad_routing_table_t *rt = (kad_routing_table_t *)calloc(1, sizeof(kad_routing_table_t));
    if (!rt) return NULL;
    
    memcpy(&rt->local_id, local_id, sizeof(kad_id_t));
    
    /* Initialize all buckets */
    for (int i = 0; i < KADEMLIA_ID_BITS; i++) {
        rt->buckets[i].head = NULL;
        rt->buckets[i].count = 0;
        rt->buckets[i].last_updated = 0;
    }
    
    return rt;
}

void kad_routing_destroy(kad_routing_table_t *rt) {
    if (!rt) return;
    
    for (int i = 0; i < KADEMLIA_ID_BITS; i++) {
        kad_node_t *node = rt->buckets[i].head;
        while (node) {
            kad_node_t *next = node->next;
            free(node);
            node = next;
        }
    }
    
    free(rt);
}

int kad_routing_add_node(kad_routing_table_t *rt, const kad_node_t *node) {
    if (!rt || !node) return -1;
    
    int idx = bucket_index(&rt->local_id, &node->id);
    kad_bucket_t *bucket = &rt->buckets[idx];
    
    /* Check if node already exists */
    kad_node_t **pp = &bucket->head;
    while (*pp) {
        if (memcmp(&(*pp)->id, &node->id, sizeof(kad_id_t)) == 0) {
            /* Update last_seen and move to head (MRU) */
            kad_node_t *found = *pp;
            *pp = found->next;
            found->last_seen = (uint64_t)time(NULL);
            found->next = bucket->head;
            bucket->head = found;
            return 0;
        }
        pp = &(*pp)->next;
    }
    
    /* Bucket full? */
    if (bucket->count >= KADEMLIA_K) {
        /* Evict the tail (oldest node) - simple LRU policy */
        kad_node_t **tail_p = &bucket->head;
        while ((*tail_p)->next) {
            tail_p = &(*tail_p)->next;
        }
        kad_node_t *oldest = *tail_p;
        *tail_p = NULL;
        free(oldest);
        bucket->count--;
    }
    
    /* Add new node to head */
    kad_node_t *new_node = kad_node_create(&node->id, node->ip, node->port);
    if (!new_node) return -1;
    
    new_node->next = bucket->head;
    bucket->head = new_node;
    bucket->count++;
    bucket->last_updated = (uint64_t)time(NULL);
    
    return 0;
}

void kad_routing_remove_node(kad_routing_table_t *rt, const kad_id_t *id) {
    if (!rt || !id) return;
    
    int idx = bucket_index(&rt->local_id, id);
    kad_bucket_t *bucket = &rt->buckets[idx];
    
    kad_node_t **pp = &bucket->head;
    while (*pp) {
        if (memcmp(&(*pp)->id, id, sizeof(kad_id_t)) == 0) {
            kad_node_t *to_remove = *pp;
            *pp = to_remove->next;
            free(to_remove);
            bucket->count--;
            return;
        }
        pp = &(*pp)->next;
    }
}

kad_node_t **kad_routing_find_closest(kad_routing_table_t *rt, const kad_id_t *target, int count) {
    if (!rt || !target || count <= 0) return NULL;
    
    kad_node_t **results = (kad_node_t **)calloc(count, sizeof(kad_node_t *));
    if (!results) return NULL;
    
    int found = 0;
    
    /* Start from target's bucket and expand outward */
    int target_idx = bucket_index(&rt->local_id, target);
    
    for (int offset = 0; offset < KADEMLIA_ID_BITS && found < count; offset++) {
        /* Check bucket at target_idx + offset */
        if (target_idx + offset < KADEMLIA_ID_BITS) {
            kad_node_t *node = rt->buckets[target_idx + offset].head;
            while (node && found < count) {
                results[found++] = node;
                node = node->next;
            }
        }
        
        /* Check bucket at target_idx - offset */
        if (offset > 0 && target_idx - offset >= 0) {
            kad_node_t *node = rt->buckets[target_idx - offset].head;
            while (node && found < count) {
                results[found++] = node;
                node = node->next;
            }
        }
    }
    
    /* Sort results by XOR distance to target */
    for (int i = 0; i < found - 1; i++) {
        for (int j = i + 1; j < found; j++) {
            if (kad_id_distance_cmp(target, &results[i]->id, &results[j]->id) > 0) {
                kad_node_t *tmp = results[i];
                results[i] = results[j];
                results[j] = tmp;
            }
        }
    }
    
    return results;
}

/* =============================================================================
 * DHT Lifecycle
 * ============================================================================= */

kademlia_dht_t *kademlia_create(const char *ip, uint16_t port) {
    if (!ip) return NULL;
    
    kademlia_dht_t *dht = (kademlia_dht_t *)calloc(1, sizeof(kademlia_dht_t));
    if (!dht) return NULL;
    
    /* Generate node ID from IP:port */
    char id_data[64];
    snprintf(id_data, sizeof(id_data), "%s:%u", ip, port);
    
    kad_id_t local_id;
    kad_id_from_data(id_data, strlen(id_data), &local_id);
    
    dht->routing = kad_routing_create(&local_id);
    if (!dht->routing) {
        free(dht);
        return NULL;
    }
    
    dht->storage = NULL;
    
    return dht;
}

void kademlia_destroy(kademlia_dht_t *dht) {
    if (!dht) return;
    
    kad_routing_destroy(dht->routing);
    
    /* Free storage */
    kad_value_t *val = dht->storage;
    while (val) {
        kad_value_t *next = val->next;
        free(val->data);
        free(val);
        val = next;
    }
    
    free(dht);
}

/* =============================================================================
 * DHT Operations
 * ============================================================================= */

int kademlia_store(kademlia_dht_t *dht, const kad_id_t *key, const void *data, size_t len) {
    if (!dht || !key || !data || len == 0) return -1;
    
    /* Check if key already exists */
    kad_value_t *val = dht->storage;
    while (val) {
        if (memcmp(&val->key, key, sizeof(kad_id_t)) == 0) {
            /* Update existing value */
            free(val->data);
            val->data = malloc(len);
            if (!val->data) return -1;
            memcpy(val->data, data, len);
            val->len = len;
            val->expires = (uint64_t)time(NULL) + 3600;  /* 1 hour TTL */
            return 0;
        }
        val = val->next;
    }
    
    /* Create new value */
    kad_value_t *new_val = (kad_value_t *)calloc(1, sizeof(kad_value_t));
    if (!new_val) return -1;
    
    memcpy(&new_val->key, key, sizeof(kad_id_t));
    new_val->data = malloc(len);
    if (!new_val->data) {
        free(new_val);
        return -1;
    }
    memcpy(new_val->data, data, len);
    new_val->len = len;
    new_val->expires = (uint64_t)time(NULL) + 3600;
    
    new_val->next = dht->storage;
    dht->storage = new_val;
    
    return 0;
}

int kademlia_find_value(kademlia_dht_t *dht, const kad_id_t *key, void *buf, size_t *buf_len) {
    if (!dht || !key || !buf || !buf_len) return -1;
    
    kad_value_t *val = dht->storage;
    while (val) {
        if (memcmp(&val->key, key, sizeof(kad_id_t)) == 0) {
            /* Check expiration */
            if (val->expires < (uint64_t)time(NULL)) {
                return -1;  /* Expired */
            }
            
            if (*buf_len < val->len) {
                *buf_len = val->len;
                return -1;  /* Buffer too small */
            }
            
            memcpy(buf, val->data, val->len);
            *buf_len = val->len;
            return 0;
        }
        val = val->next;
    }
    
    return -1;  /* Not found */
}

kad_node_t **kademlia_find_node(kademlia_dht_t *dht, const kad_id_t *target, int count) {
    if (!dht || !target) return NULL;
    return kad_routing_find_closest(dht->routing, target, count);
}

size_t kademlia_storage_count(kademlia_dht_t *dht) {
    size_t count = 0;
    kad_value_t *val = NULL;

    if (!dht) {
        return 0;
    }

    val = dht->storage;
    while (val) {
        count++;
        val = val->next;
    }

    return count;
}
