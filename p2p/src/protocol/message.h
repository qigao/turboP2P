/**
 * P2P Message Serialization
 */
#ifndef P2P_MESSAGE_H
#define P2P_MESSAGE_H

#include "../core/types.h"

/**
 * Initialize a message with a specific type
 */
void p2p_message_init(p2p_message_t *msg, p2p_msg_type_t type);

/**
 * Serialize a message using the canonical application wire schema. Native
 * struct padding and host byte order are never serialized.
 * @param msg Message to serialize
 * @param out Output buffer (allocated by function, caller frees)
 * @param out_len Output length
 * @return P2P_OK on success
 */
int p2p_message_serialize(const p2p_message_t *msg, uint8_t **out, size_t *out_len);

/**
 * Deserialize a message from network data
 * @param data Input buffer
 * @param len Input length
 * @param msg Output message
 * @param consumed Bytes consumed from input
 * @return P2P_OK on success, P2P_ERR_PROTOCOL for malformed or incomplete
 * input, or P2P_ERR_INVALID_ARG for invalid API arguments
 */
int p2p_message_deserialize(const uint8_t *data, size_t len,
                             p2p_message_t *msg, size_t *consumed);

/**
 * Get human-readable name for message type
 */
const char* p2p_message_type_name(p2p_msg_type_t type);

/**
 * Convert node ID to hex string
 */
void p2p_id_to_hex(const p2p_id_t id, char *buf, size_t buf_len);

/**
 * Generate a unique request ID
 */
uint32_t p2p_generate_request_id(void);

#endif /* P2P_MESSAGE_H */
