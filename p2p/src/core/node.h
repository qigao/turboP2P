#ifndef P2P_NODE_H
#define P2P_NODE_H

#include "types.h"
 
/* Node functions */
p2p_node_t *p2p_node_create(const char *ip, int port);
void p2p_node_destroy(p2p_node_t *node);

/* File management */
void p2p_node_add_file(p2p_node_t *node, p2p_file_t *file);
void p2p_node_remove_file(p2p_node_t *node, const char *key);
p2p_file_t *p2p_node_find_local_file_by_id(p2p_node_t *node, const p2p_id_t id);

/* Network */
void p2p_node_broadcast(p2p_node_t *node, p2p_message_t *msg);
int p2p_dht_join_ring(p2p_node_t *node, const char *bootstrap_ip, int bootstrap_port);
void p2p_dht_create_ring(p2p_node_t *node);

/* File functions */
p2p_file_t *p2p_file_create(const char *key, const char *filepath);
p2p_file_t *p2p_file_find(p2p_node_t *node, const char *key);
int p2p_file_download(p2p_node_t *node, p2p_file_t *file, const char *output_path);
void p2p_file_free(p2p_file_t *file);
p2p_file_t *p2p_file_find_by_id(p2p_file_t *list, const p2p_id_t id);
p2p_file_t *p2p_file_find_by_path(p2p_file_t *list, const char *filepath);
int p2p_file_list_add(p2p_file_t **list, p2p_file_t *file);
int p2p_file_list_remove(p2p_file_t **list, const p2p_id_t id);
void p2p_file_list_destroy(p2p_file_t *list);

/* Message */
void p2p_message_init(p2p_message_t *msg, p2p_msg_type_t type);

#endif /* P2P_NODE_H */
