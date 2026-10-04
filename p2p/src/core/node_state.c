#include "node_state.h"
#include "../transfer/transfer.h"
#include "../protocol/handlers.h"
#include "../security/p2p_private_key_executor.h"
#include <stdlib.h>
#include <string.h>

static p2p_private_key_executor_t *create_polled_executor(p2p_node_t *node,
    const p2p_blocking_private_key_provider_v4_t *provider) {
    return p2p_private_key_executor_create_with_notify(node, provider, NULL);
}

void p2p_node_saved_cookie_status_locked(const p2p_node_t *node,
    p2p_node_cookie_status_t *status) {
    status->active = node->active_cookie_gates;
    status->challenges_issued = node->cookie_challenges_issued;
    status->verifications_succeeded = node->cookie_verifications_succeeded;
}

p2p_node_t *p2p_node_state_create(const char *ip, int port) {
    p2p_node_t *node;
    if (!ip || strlen(ip) >= P2P_MAX_IP || port < 0 || port > UINT16_MAX)
        return NULL;
    node = calloc(1, sizeof(*node));
    if (!node) return NULL;
    strcpy(node->ip, ip);
    node->port = port;
    vivaldi_init(&node->coord);
    salts_mutex_init(&node->mutex);
    if (!node->mutex) { free(node); return NULL; }
    node->kad_dht = kademlia_create(ip, (uint16_t)port);
    if (!node->kad_dht) goto fail;
    memcpy(node->id, node->kad_dht->routing->local_id.bytes, KADEMLIA_ID_BYTES);
    if (p2p_crypto_generate_identity(&node->crypto.identity) != P2P_OK) goto fail;
    node->transfers = calloc(1, sizeof(*node->transfers));
    if (!node->transfers) goto fail;
    p2p_transfer_manager_init(node->transfers);
    if (!node->transfers->mutex) { free(node->transfers); node->transfers = NULL; goto fail; }
    node->file_message_handler = p2p_handlers_dispatch_transfer;
    node->create_private_key_executor = create_polled_executor;
    node->query_cookie_status_locked = p2p_node_saved_cookie_status_locked;
    return node;
fail:
    (void)p2p_node_state_destroy(node);
    return NULL;
}

void p2p_node_add_file(p2p_node_t *node, p2p_file_t *file) {
    if (!node || !file) return;

    salts_mutex_lock(&node->mutex);
    file->next_file = node->local_files;
    node->local_files = file;
    salts_mutex_unlock(&node->mutex);
}

void p2p_node_remove_file(p2p_node_t *node, const char *key) {
    if (!node || !key) return;

    salts_mutex_lock(&node->mutex);
    p2p_file_t **curr = &node->local_files;
    while (*curr) {
        if (strcmp((*curr)->hash, key) == 0) {
            p2p_file_t *to_remove = *curr;
            *curr = (*curr)->next_file;
            p2p_file_free(to_remove);
            salts_mutex_unlock(&node->mutex);
            return;
        }
        curr = &(*curr)->next_file;
    }
    salts_mutex_unlock(&node->mutex);
}

p2p_file_t *p2p_node_find_local_file_by_id(p2p_node_t *node, const uint8_t *id) {
    p2p_file_t *file = NULL;

    if (!node || !id) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    file = p2p_node_find_local_file_by_id_locked(node, id);
    salts_mutex_unlock(&node->mutex);
    return file;
}

p2p_file_t *p2p_node_find_local_file_by_id_locked(p2p_node_t *node, const uint8_t *id) {
    p2p_file_t *file = NULL;

    if (!node || !id) {
        return NULL;
    }

    file = node->local_files;
    while (file) {
        if (memcmp(file->id, id, P2P_HASH_SIZE) == 0) {
            return file;
        }
        file = file->next_file;
    }
    return NULL;
}

p2p_file_t *p2p_node_detach_local_files(p2p_node_t *node) {
    p2p_file_t *files = NULL;

    if (!node) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    files = node->local_files;
    node->local_files = NULL;
    salts_mutex_unlock(&node->mutex);

    return files;
}

p2p_download_t *p2p_node_detach_downloads(p2p_node_t *node) {
    p2p_download_t *downloads = NULL;

    if (!node) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    downloads = node->downloads;
    node->downloads = NULL;
    salts_mutex_unlock(&node->mutex);

    return downloads;
}

static p2p_topic_t *node_find_topic_locked(p2p_node_t *node, const char *name) {
    p2p_topic_t *curr = NULL;

    if (!node || !name) {
        return NULL;
    }

    curr = node->topics;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            return curr;
        }
        curr = curr->next_topic;
    }

    return NULL;
}

static p2p_topic_t *node_find_or_create_topic_locked(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) {
        return NULL;
    }

    topic = node_find_topic_locked(node, name);
    if (topic) {
        return topic;
    }

    topic = (p2p_topic_t *)calloc(1, sizeof(p2p_topic_t));
    if (!topic) {
        return NULL;
    }

    strncpy(topic->name, name, sizeof(topic->name) - 1);
    topic->next_topic = node->topics;
    node->topics = topic;

    return topic;
}

void p2p_topic_destroy(p2p_topic_t *topic) {
    if (!topic) return;
    if (topic->subscribers) free(topic->subscribers);
    free(topic);
}

p2p_topic_t *p2p_topic_find(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) return NULL;

    salts_mutex_lock(&node->mutex);
    topic = node_find_topic_locked(node, name);
    salts_mutex_unlock(&node->mutex);

    return topic;
}

p2p_topic_t *p2p_topic_find_or_create(p2p_node_t *node, const char *name) {
    p2p_topic_t *topic = NULL;

    if (!node || !name) return NULL;

    salts_mutex_lock(&node->mutex);
    topic = node_find_or_create_topic_locked(node, name);
    salts_mutex_unlock(&node->mutex);

    return topic;
}

int p2p_topic_exists(p2p_node_t *node, const char *name) {
    int exists = 0;

    if (!node || !name) {
        return 0;
    }

    salts_mutex_lock(&node->mutex);
    exists = node_find_topic_locked(node, name) != NULL;
    salts_mutex_unlock(&node->mutex);

    return exists;
}

int p2p_node_remove_topic(p2p_node_t *node, const char *name) {
    if (!node || !name) return P2P_ERR_INVALID_ARG;

    salts_mutex_lock(&node->mutex);
    p2p_topic_t **curr = &node->topics;
    while (*curr) {
        if (strcmp((*curr)->name, name) == 0) {
            p2p_topic_t *to_remove = *curr;
            *curr = (*curr)->next_topic;
            salts_mutex_unlock(&node->mutex);
            p2p_topic_destroy(to_remove);
            return P2P_OK;
        }
        curr = &(*curr)->next_topic;
    }
    salts_mutex_unlock(&node->mutex);
    return P2P_ERR_NOT_FOUND;
}

p2p_topic_t *p2p_node_detach_topics(p2p_node_t *node) {
    p2p_topic_t *topics = NULL;

    if (!node) {
        return NULL;
    }

    salts_mutex_lock(&node->mutex);
    topics = node->topics;
    node->topics = NULL;
    salts_mutex_unlock(&node->mutex);

    return topics;
}

void p2p_cleanup_peers(p2p_node_t *node) {
    if (!node || !node->peers_table) return;

    /* Detach table from node first to prevent re-entry from callbacks */
    salts_mutex_lock(&node->mutex);
    p2p_peer_entry_t *table = node->peers_table;
    node->peers_table = NULL;
    node->peer_count = 0;
    salts_mutex_unlock(&node->mutex);

    p2p_peer_entry_t *curr, *tmp;
    HASH_ITER(hh, table, curr, tmp) {
        /* Disconnect and free peer through professional lifecycle */
        if (curr->peer) {
            p2p_peer_destroy(curr->peer);
        }
        /* Remove from table entry and free the wrapper */
        HASH_DEL(table, curr);
        free(curr);
    }
}

void p2p_cleanup_topics(p2p_node_t *node) {
    p2p_topic_t *topic = NULL;

    if (!node) return;

    topic = p2p_node_detach_topics(node);

    while (topic) {
        p2p_topic_t *next = topic->next_topic;
        p2p_topic_destroy(topic);
        topic = next;
    }
}

void p2p_cleanup_files(p2p_node_t *node) {
    p2p_file_t *file = NULL;

    if (!node) return;

    /* 1. Clear DHT files first (some may be local aliases) */
    file = p2p_node_detach_dht_files(node);
    while (file) {
        p2p_file_t *next = file->next;
        /* Only free if it's not a local file (local files are freed below) */
        if (!file->is_local) {
            p2p_file_free(file);
        }
        file = next;
    }

    /* 2. Free all local files */
    file = p2p_node_detach_local_files(node);
    while (file) {
        p2p_file_t *next = file->next_file;
        p2p_file_free(file);
        file = next;
    }
}

void p2p_cleanup_downloads(p2p_node_t *node) {
    p2p_download_t *download = NULL;

    if (!node) return;

    download = p2p_node_detach_downloads(node);
    while (download) {
        p2p_download_t *next = download->next;

        if (download->fp) {
            fclose(download->fp);
        }

        free(download);
        download = next;
    }
}

void p2p_cleanup_lookup(p2p_node_t *node) {
    p2p_dht_lookup_t *lookup = NULL;
    p2p_dht_lookup_t *tmp = NULL;

    if (!node || !node->dht_lookups) return;

    HASH_ITER(hh, node->dht_lookups, lookup, tmp) {
        HASH_DEL(node->dht_lookups, lookup);
        if (lookup->cleanup && lookup->user_data) {
            lookup->cleanup(lookup->user_data);
        }
        free(lookup);
    }
    node->dht_lookups = NULL;
}

void p2p_cleanup_dht(p2p_node_t *node) {
    if (!node || !node->kad_dht) return;

    /* Professional Kademlia cleanup */
    kademlia_destroy(node->kad_dht);
    node->kad_dht = NULL;
}

static void p2p_cleanup_connect_suppressions(p2p_node_t *node) {
    p2p_connect_suppression_t *suppression = NULL;
    p2p_connect_suppression_t *tmp = NULL;

    if (!node || !node->connect_suppressions) {
        return;
    }

    HASH_ITER(hh, node->connect_suppressions, suppression, tmp) {
        HASH_DEL(node->connect_suppressions, suppression);
        free(suppression);
    }
    node->connect_suppressions = NULL;
}

int p2p_node_cleanup_transfers(p2p_node_t *node) {
    int result;
    if (!node || !node->transfers) return P2P_OK;
    result = p2p_transfer_manager_destroy(node->transfers);
    if (result != P2P_OK) return result;
    free(node->transfers);
    node->transfers = NULL;
    return P2P_OK;
}

int p2p_node_state_destroy(p2p_node_t *node) {
    int result;
    if (!node) return P2P_OK;
    if (node->ctx || node->server || node->gossip_timer || node->network_context)
        return P2P_ERR_INVALID_STATE;
    result = p2p_node_cleanup_transfers(node);
    if (result != P2P_OK) return result;
    node->on_message = NULL;
    node->on_peer_connected = node->on_peer_disconnected = NULL;
    node->network_ops = NULL;
    p2p_private_key_executor_shutdown(node->private_key_executor);
    p2p_cleanup_peers(node);
    p2p_cleanup_topics(node);
    p2p_cleanup_files(node);
    p2p_cleanup_downloads(node);
    p2p_cleanup_lookup(node);
    p2p_cleanup_connect_suppressions(node);
    p2p_cleanup_dht(node);
    p2p_private_key_executor_destroy(node->private_key_executor);
    if (node->pinned_trusted_keys) {
        p2p_crypto_wipe(node->pinned_trusted_keys, node->pinned_trusted_key_count * P2P_KEY_SIZE);
        free(node->pinned_trusted_keys);
    }
    salts_mutex_destroy(&node->mutex);
    p2p_crypto_wipe(node, sizeof(*node));
    free(node);
    return P2P_OK;
}
