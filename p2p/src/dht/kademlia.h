/**
 * kademlia.h - Professional Kademlia DHT Implementation
 * 
 * Features:
 * - 160-bit ID space (SHA-1)
 * - K-buckets with k=20
 * - XOR distance metric
 * - Iterative FIND_NODE/FIND_VALUE
 */

#ifndef P2P_KADEMLIA_H
#define P2P_KADEMLIA_H

#include <stdint.h>
#include <stddef.h>

/* Kademlia constants */
#define KADEMLIA_ID_BITS 160
#define KADEMLIA_ID_BYTES (KADEMLIA_ID_BITS / 8)  /* 20 bytes */
#define KADEMLIA_K 20          /* Bucket size */
#define KADEMLIA_ALPHA 3       /* Parallel lookups */
#define KADEMLIA_B 5           /* Bits per hop */

/* 160-bit node ID */
typedef struct {
    uint8_t bytes[KADEMLIA_ID_BYTES];
} kad_id_t;

/* Node contact info */
typedef struct kad_node_s {
    kad_id_t id;
    char ip[46];  /* IPv6-ready */
    uint16_t port;
    uint64_t last_seen;
    
    /* For k-bucket linked list */
    struct kad_node_s *next;
} kad_node_t;

/* K-bucket (holds up to k nodes) */
typedef struct {
    kad_node_t *head;
    int count;
    uint64_t last_updated;
} kad_bucket_t;

/* Routing table (160 k-buckets) */
typedef struct {
    kad_id_t local_id;
    kad_bucket_t buckets[KADEMLIA_ID_BITS];
} kad_routing_table_t;

/* DHT value storage */
typedef struct kad_value_s {
    kad_id_t key;
    void *data;
    size_t len;
    uint64_t expires;
    
    struct kad_value_s *next;
} kad_value_t;

/* Main Kademlia DHT */
typedef struct {
    kad_routing_table_t *routing;
    kad_value_t *storage;  /* Local key-value store */
} kademlia_dht_t;

/* Lifecycle */
kademlia_dht_t *kademlia_create(const char *ip, uint16_t port);
void kademlia_destroy(kademlia_dht_t *dht);

/* ID operations */
void kad_id_from_data(const void *data, size_t len, kad_id_t *out);
void kad_id_random(kad_id_t *out);
int kad_id_distance_cmp(const kad_id_t *target, const kad_id_t *a, const kad_id_t *b);
int kad_id_prefix_len(const kad_id_t *a, const kad_id_t *b);

/* Routing table operations */
kad_routing_table_t *kad_routing_create(const kad_id_t *local_id);
void kad_routing_destroy(kad_routing_table_t *rt);
int kad_routing_add_node(kad_routing_table_t *rt, const kad_node_t *node);
void kad_routing_remove_node(kad_routing_table_t *rt, const kad_id_t *id);
kad_node_t **kad_routing_find_closest(kad_routing_table_t *rt, const kad_id_t *target, int count);

/* DHT operations */
int kademlia_store(kademlia_dht_t *dht, const kad_id_t *key, const void *data, size_t len);
int kademlia_find_value(kademlia_dht_t *dht, const kad_id_t *key, void *buf, size_t *buf_len);
kad_node_t **kademlia_find_node(kademlia_dht_t *dht, const kad_id_t *target, int count);
size_t kademlia_storage_count(kademlia_dht_t *dht);

#endif /* P2P_KADEMLIA_H */
