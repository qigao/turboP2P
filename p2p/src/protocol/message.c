/**
 * message.c - Canonical application message codec
 *
 * The in-memory payload structs are convenience views only.  No native
 * padding, integer representation, or host byte order is placed on the wire.
 */

#include "message.h"
#include "../../src/internal.h"

#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

enum {
    P2P_WIRE_HEADER_SIZE = 8,
    P2P_WIRE_IP_FAMILY_SIZE = 1,
    P2P_WIRE_CONTACT_FIXED_SIZE = P2P_DHT_KEY_SIZE +
                                  P2P_WIRE_IP_FAMILY_SIZE + 2,
    P2P_WIRE_PING_FIXED_SIZE = P2P_DHT_KEY_SIZE +
                               P2P_WIRE_IP_FAMILY_SIZE + 2 + 8 + 6 * 8,
    P2P_WIRE_DHT_RESPONSE_FIXED_SIZE = 1 + 1 + 2,
    P2P_WIRE_FILE_RESPONSE_SIZE = P2P_DHT_KEY_SIZE + 8 + 4 +
                                  P2P_SHA256_SIZE,
    P2P_WIRE_CHUNK_REQUEST_SIZE = 8,
    P2P_WIRE_CHUNK_DATA_FIXED_SIZE = 4 + 4 + 2 + P2P_SHA256_SIZE,
    P2P_WIRE_FILE_ACK_SIZE = 5,
};

static const double P2P_WIRE_COORD_ABS_MAX = 1000000000.0;

_Static_assert(sizeof(double) == 8,
               "application protocol v2 requires IEEE-754 binary64 storage");
_Static_assert(FLT_RADIX == 2 && DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024,
               "application protocol v2 requires IEEE-754 binary64 values");
_Static_assert(VIVALDI_DIMENSIONS == 4,
               "application protocol v2 fixes the coordinate dimension at four");

typedef struct {
    uint8_t *bytes;
    size_t capacity;
    size_t offset;
} p2p_wire_writer_t;

typedef struct {
    const uint8_t *bytes;
    size_t length;
    size_t offset;
} p2p_wire_reader_t;

static uint16_t read_u16_be(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_u32_be(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t read_u64_be(const uint8_t *bytes) {
    return ((uint64_t)read_u32_be(bytes) << 32) |
           read_u32_be(bytes + 4);
}

static void write_u16_be(uint8_t *bytes, uint16_t value) {
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_u32_be(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_u64_be(uint8_t *bytes, uint64_t value) {
    write_u32_be(bytes, (uint32_t)(value >> 32));
    write_u32_be(bytes + 4, (uint32_t)value);
}

static int wire_writer_put(p2p_wire_writer_t *writer, const void *data,
                           size_t length) {
    if (!writer || (!data && length != 0) ||
        writer->offset > writer->capacity ||
        length > writer->capacity - writer->offset) {
        return P2P_ERR_PROTOCOL;
    }
    if (length != 0) {
        memcpy(writer->bytes + writer->offset, data, length);
    }
    writer->offset += length;
    return P2P_OK;
}

static int wire_writer_u8(p2p_wire_writer_t *writer, uint8_t value) {
    return wire_writer_put(writer, &value, sizeof(value));
}

static int wire_writer_u16(p2p_wire_writer_t *writer, uint16_t value) {
    uint8_t bytes[2];
    write_u16_be(bytes, value);
    return wire_writer_put(writer, bytes, sizeof(bytes));
}

static int wire_writer_u32(p2p_wire_writer_t *writer, uint32_t value) {
    uint8_t bytes[4];
    write_u32_be(bytes, value);
    return wire_writer_put(writer, bytes, sizeof(bytes));
}

static int wire_writer_u64(p2p_wire_writer_t *writer, uint64_t value) {
    uint8_t bytes[8];
    write_u64_be(bytes, value);
    return wire_writer_put(writer, bytes, sizeof(bytes));
}

static int wire_writer_double(p2p_wire_writer_t *writer, double value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return wire_writer_u64(writer, bits);
}

static int wire_reader_get(p2p_wire_reader_t *reader, void *output,
                           size_t length) {
    if (!reader || (!output && length != 0) ||
        reader->offset > reader->length ||
        length > reader->length - reader->offset) {
        return P2P_ERR_PROTOCOL;
    }
    if (length != 0) {
        memcpy(output, reader->bytes + reader->offset, length);
    }
    reader->offset += length;
    return P2P_OK;
}

static int wire_reader_u8(p2p_wire_reader_t *reader, uint8_t *value) {
    return wire_reader_get(reader, value, sizeof(*value));
}

static int wire_reader_u16(p2p_wire_reader_t *reader, uint16_t *value) {
    uint8_t bytes[2];
    if (wire_reader_get(reader, bytes, sizeof(bytes)) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    *value = read_u16_be(bytes);
    return P2P_OK;
}

static int wire_reader_u32(p2p_wire_reader_t *reader, uint32_t *value) {
    uint8_t bytes[4];
    if (wire_reader_get(reader, bytes, sizeof(bytes)) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    *value = read_u32_be(bytes);
    return P2P_OK;
}

static int wire_reader_u64(p2p_wire_reader_t *reader, uint64_t *value) {
    uint8_t bytes[8];
    if (wire_reader_get(reader, bytes, sizeof(bytes)) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    *value = read_u64_be(bytes);
    return P2P_OK;
}

static int wire_reader_double(p2p_wire_reader_t *reader, double *value) {
    uint64_t bits;
    if (wire_reader_u64(reader, &bits) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    memcpy(value, &bits, sizeof(bits));
    return P2P_OK;
}

static int wire_text_length(const char text[P2P_MAX_IP], size_t *length) {
    size_t index;
    if (!text || !length) {
        return P2P_ERR_INVALID_ARG;
    }
    for (index = 0; index < P2P_MAX_IP; ++index) {
        if (text[index] == '\0') {
            *length = index;
            return P2P_OK;
        }
    }
    return P2P_ERR_PROTOCOL;
}

static int wire_ip_parse(const char ip[P2P_MAX_IP], int allow_empty,
                         uint8_t *family, uint8_t address[16],
                         size_t *address_length) {
    size_t text_length;
    struct in_addr address4;
    struct in6_addr address6;

    if (!ip || !family || !address || !address_length ||
        wire_text_length(ip, &text_length) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    memset(address, 0, 16);
    if (text_length == 0) {
        if (!allow_empty) {
            return P2P_ERR_PROTOCOL;
        }
        *family = 0;
        *address_length = 0;
        return P2P_OK;
    }
    if (inet_pton(AF_INET, ip, &address4) == 1) {
        *family = 4;
        *address_length = 4;
        memcpy(address, &address4, *address_length);
        return P2P_OK;
    }
    if (inet_pton(AF_INET6, ip, &address6) == 1) {
        *family = 6;
        *address_length = 16;
        memcpy(address, &address6, *address_length);
        return P2P_OK;
    }
    return P2P_ERR_PROTOCOL;
}

static int wire_ping_values_are_valid(const p2p_ping_payload_t *ping) {
    size_t index;
    if (!ping || !isfinite(ping->height) || ping->height < 0.0 ||
        ping->height > P2P_WIRE_COORD_ABS_MAX ||
        !isfinite(ping->error) || ping->error < 0.0 ||
        ping->error > 1.0) {
        return 0;
    }
    for (index = 0; index < VIVALDI_DIMENSIONS; ++index) {
        if (!isfinite(ping->coords[index]) ||
            fabs(ping->coords[index]) > P2P_WIRE_COORD_ABS_MAX) {
            return 0;
        }
    }
    return 1;
}

static int wire_is_raw_type(p2p_msg_type_t type) {
    return type == P2P_MSG_FILE_DATA || type == P2P_MSG_PUBSUB_SUB ||
           type == P2P_MSG_PUBSUB_UNSUB ||
           type == P2P_MSG_PUBSUB_PUBLISH || type == P2P_MSG_GOSSIP ||
           type == P2P_MSG_CUSTOM;
}

static int wire_contact_size(const p2p_kad_contact_t *contact,
                             size_t *wire_size) {
    uint8_t family;
    uint8_t address[16];
    size_t address_length;
    if (!contact || !wire_size || contact->port == 0 ||
        wire_ip_parse(contact->ip, 0, &family, address,
                      &address_length) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    *wire_size = P2P_WIRE_CONTACT_FIXED_SIZE + address_length;
    return P2P_OK;
}

static int message_payload_wire_size(const p2p_message_t *msg,
                                     size_t *wire_size) {
    p2p_msg_type_t type;
    uint8_t ip_family = 0;
    uint8_t ip_address[16];
    size_t ip_address_length = 0;
    size_t size = 0;
    size_t index;

    if (!msg || !wire_size || msg->header.flags != 0) {
        return P2P_ERR_INVALID_ARG;
    }
    type = (p2p_msg_type_t)msg->header.type;
    if (wire_is_raw_type(type)) {
        *wire_size = msg->header.payload_len;
        return P2P_OK;
    }
    switch (type) {
        case P2P_MSG_PING:
        case P2P_MSG_PONG:
            if (msg->header.payload_len != sizeof(p2p_ping_payload_t) ||
                wire_ip_parse(msg->payload.ping.ip, 1, &ip_family,
                              ip_address, &ip_address_length) != P2P_OK ||
                !wire_ping_values_are_valid(&msg->payload.ping)) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_WIRE_PING_FIXED_SIZE + ip_address_length;
            break;
        case P2P_MSG_FILE_GET:
            if (msg->header.payload_len != P2P_DHT_KEY_SIZE) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_DHT_KEY_SIZE;
            break;
        case P2P_MSG_DHT_GET:
        case P2P_MSG_DHT_FIND_NODE:
            if (msg->header.payload_len !=
                sizeof(p2p_dht_find_node_payload_t)) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_DHT_KEY_SIZE;
            break;
        case P2P_MSG_DHT_PUT:
            if (msg->payload.dht_store.data_len >
                    sizeof(msg->payload.dht_store.data) ||
                msg->header.payload_len !=
                    offsetof(p2p_dht_store_payload_t, data) +
                        msg->payload.dht_store.data_len) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_DHT_KEY_SIZE + 2 + msg->payload.dht_store.data_len;
            break;
        case P2P_MSG_DHT_RESPONSE:
            if (msg->payload.dht_response.found > 1 ||
                msg->payload.dht_response.node_count > KADEMLIA_K ||
                msg->payload.dht_response.data_len >
                    sizeof(msg->payload.dht_response.data) ||
                msg->header.payload_len !=
                    offsetof(p2p_dht_response_payload_t, data) +
                        msg->payload.dht_response.data_len ||
                (msg->payload.dht_response.found &&
                 msg->payload.dht_response.node_count != 0) ||
                (!msg->payload.dht_response.found &&
                 msg->payload.dht_response.data_len != 0)) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_WIRE_DHT_RESPONSE_FIXED_SIZE +
                   msg->payload.dht_response.data_len;
            for (index = 0;
                 index < msg->payload.dht_response.node_count; ++index) {
                size_t contact_size;
                if (wire_contact_size(&msg->payload.dht_response.nodes[index],
                                      &contact_size) != P2P_OK) {
                    return P2P_ERR_PROTOCOL;
                }
                size += contact_size;
            }
            break;
        case P2P_MSG_FILE_PUT:
            if (msg->header.payload_len !=
                sizeof(p2p_file_response_payload_t)) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_WIRE_FILE_RESPONSE_SIZE;
            break;
        case P2P_MSG_CHUNK_REQUEST:
            if (msg->header.payload_len !=
                sizeof(p2p_chunk_request_payload_t)) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_WIRE_CHUNK_REQUEST_SIZE;
            break;
        case P2P_MSG_CHUNK_DATA:
            if (msg->payload.chunk_data.data_len >
                    sizeof(msg->payload.chunk_data.data) ||
                msg->header.payload_len !=
                    offsetof(p2p_chunk_data_payload_t, data) +
                        msg->payload.chunk_data.data_len) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_WIRE_CHUNK_DATA_FIXED_SIZE +
                   msg->payload.chunk_data.data_len;
            break;
        case P2P_MSG_FILE_ACK:
            if (msg->header.payload_len != sizeof(p2p_file_ack_payload_t) ||
                (msg->payload.file_ack.success != 0 &&
                 msg->payload.file_ack.success != 1)) {
                return P2P_ERR_PROTOCOL;
            }
            size = P2P_WIRE_FILE_ACK_SIZE;
            break;
        case P2P_MSG_RESERVED_LEGACY_HANDSHAKE:
        default:
            return P2P_ERR_PROTOCOL;
    }
    if (size > UINT16_MAX) {
        return P2P_ERR_PROTOCOL;
    }
    *wire_size = size;
    return P2P_OK;
}

static int wire_write_ip(p2p_wire_writer_t *writer,
                         const char ip[P2P_MAX_IP], int allow_empty) {
    uint8_t family;
    uint8_t address[16];
    size_t address_length;
    if (wire_ip_parse(ip, allow_empty, &family, address,
                      &address_length) != P2P_OK ||
        wire_writer_u8(writer, family) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    return wire_writer_put(writer, address, address_length);
}

static int message_payload_encode(const p2p_message_t *msg,
                                  p2p_wire_writer_t *writer) {
    const p2p_ping_payload_t *ping = &msg->payload.ping;
    p2p_msg_type_t type = (p2p_msg_type_t)msg->header.type;
    size_t index;

    if (wire_is_raw_type(type)) {
        return wire_writer_put(writer, msg->payload.raw,
                               msg->header.payload_len);
    }
    switch (type) {
        case P2P_MSG_PING:
        case P2P_MSG_PONG:
            if (wire_writer_put(writer, ping->node_id, P2P_DHT_KEY_SIZE) !=
                    P2P_OK ||
                wire_write_ip(writer, ping->ip, 1) != P2P_OK ||
                wire_writer_u16(writer, ping->port) != P2P_OK ||
                wire_writer_u64(writer, ping->timestamp) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            for (index = 0; index < VIVALDI_DIMENSIONS; ++index) {
                if (wire_writer_double(writer, ping->coords[index]) !=
                    P2P_OK) {
                    return P2P_ERR_PROTOCOL;
                }
            }
            return wire_writer_double(writer, ping->height) == P2P_OK &&
                           wire_writer_double(writer, ping->error) == P2P_OK
                       ? P2P_OK
                       : P2P_ERR_PROTOCOL;
        case P2P_MSG_FILE_GET:
            return wire_writer_put(writer,
                                   msg->payload.file_response.file_id,
                                   P2P_DHT_KEY_SIZE);
        case P2P_MSG_DHT_GET:
        case P2P_MSG_DHT_FIND_NODE:
            return wire_writer_put(writer,
                                   msg->payload.dht_find_node.target_id,
                                   P2P_DHT_KEY_SIZE);
        case P2P_MSG_DHT_PUT:
            if (wire_writer_put(writer, msg->payload.dht_store.key,
                                P2P_DHT_KEY_SIZE) != P2P_OK ||
                wire_writer_u16(writer,
                                msg->payload.dht_store.data_len) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            return wire_writer_put(writer, msg->payload.dht_store.data,
                                   msg->payload.dht_store.data_len);
        case P2P_MSG_DHT_RESPONSE:
            if (wire_writer_u8(writer,
                               msg->payload.dht_response.found) != P2P_OK ||
                wire_writer_u8(writer,
                               msg->payload.dht_response.node_count) !=
                    P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            for (index = 0;
                 index < msg->payload.dht_response.node_count; ++index) {
                const p2p_kad_contact_t *contact =
                    &msg->payload.dht_response.nodes[index];
                if (wire_writer_put(writer, contact->id,
                                    P2P_DHT_KEY_SIZE) != P2P_OK ||
                    wire_write_ip(writer, contact->ip, 0) != P2P_OK ||
                    wire_writer_u16(writer, contact->port) != P2P_OK) {
                    return P2P_ERR_PROTOCOL;
                }
            }
            if (wire_writer_u16(writer,
                                msg->payload.dht_response.data_len) !=
                P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            return wire_writer_put(writer, msg->payload.dht_response.data,
                                   msg->payload.dht_response.data_len);
        case P2P_MSG_FILE_PUT:
            if (wire_writer_put(writer, msg->payload.file_response.file_id,
                                P2P_DHT_KEY_SIZE) != P2P_OK ||
                wire_writer_u64(writer,
                                msg->payload.file_response.file_size) !=
                    P2P_OK ||
                wire_writer_u32(writer,
                                msg->payload.file_response.total_chunks) !=
                    P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            return wire_writer_put(writer,
                                   msg->payload.file_response.file_hash,
                                   P2P_SHA256_SIZE);
        case P2P_MSG_CHUNK_REQUEST:
            return wire_writer_u32(
                       writer, msg->payload.chunk_request.transfer_id) ==
                               P2P_OK &&
                           wire_writer_u32(
                               writer,
                               msg->payload.chunk_request.chunk_index) ==
                               P2P_OK
                       ? P2P_OK
                       : P2P_ERR_PROTOCOL;
        case P2P_MSG_CHUNK_DATA:
            if (wire_writer_u32(writer,
                                msg->payload.chunk_data.transfer_id) !=
                    P2P_OK ||
                wire_writer_u32(writer,
                                msg->payload.chunk_data.chunk_index) !=
                    P2P_OK ||
                wire_writer_u16(writer,
                                msg->payload.chunk_data.data_len) != P2P_OK ||
                wire_writer_put(writer, msg->payload.chunk_data.chunk_hash,
                                P2P_SHA256_SIZE) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            return wire_writer_put(writer, msg->payload.chunk_data.data,
                                   msg->payload.chunk_data.data_len);
        case P2P_MSG_FILE_ACK:
            return wire_writer_u32(writer,
                                   msg->payload.file_ack.transfer_id) ==
                               P2P_OK &&
                           wire_writer_u8(
                               writer,
                               (uint8_t)msg->payload.file_ack.success) ==
                               P2P_OK
                       ? P2P_OK
                       : P2P_ERR_PROTOCOL;
        default:
            return P2P_ERR_PROTOCOL;
    }
}

static int wire_read_ip(p2p_wire_reader_t *reader,
                        char output[P2P_MAX_IP], int allow_empty) {
    uint8_t family;
    uint8_t address[16];
    size_t address_length;
    int address_family;

    if (wire_reader_u8(reader, &family) != P2P_OK) {
        return P2P_ERR_PROTOCOL;
    }
    if (family == 0) {
        if (!allow_empty) {
            return P2P_ERR_PROTOCOL;
        }
        output[0] = '\0';
        return P2P_OK;
    }
    if (family == 4) {
        address_length = 4;
        address_family = AF_INET;
    } else if (family == 6) {
        address_length = 16;
        address_family = AF_INET6;
    } else {
        return P2P_ERR_PROTOCOL;
    }
    if (wire_reader_get(reader, address, address_length) != P2P_OK ||
        !inet_ntop(address_family, address, output, P2P_MAX_IP)) {
        return P2P_ERR_PROTOCOL;
    }
    return P2P_OK;
}

static int message_payload_decode(p2p_msg_type_t type,
                                  p2p_wire_reader_t *reader,
                                  p2p_message_t *msg) {
    p2p_ping_payload_t *ping = &msg->payload.ping;
    size_t index;

    if (wire_is_raw_type(type)) {
        if (reader->length > sizeof(msg->payload.raw) ||
            wire_reader_get(reader, msg->payload.raw,
                            reader->length) != P2P_OK) {
            return P2P_ERR_PROTOCOL;
        }
        msg->header.payload_len = (uint16_t)reader->length;
        return P2P_OK;
    }
    switch (type) {
        case P2P_MSG_PING:
        case P2P_MSG_PONG:
            if (wire_reader_get(reader, ping->node_id,
                                P2P_DHT_KEY_SIZE) != P2P_OK ||
                wire_read_ip(reader, ping->ip, 1) != P2P_OK ||
                wire_reader_u16(reader, &ping->port) != P2P_OK ||
                wire_reader_u64(reader, &ping->timestamp) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            for (index = 0; index < VIVALDI_DIMENSIONS; ++index) {
                if (wire_reader_double(reader, &ping->coords[index]) !=
                    P2P_OK) {
                    return P2P_ERR_PROTOCOL;
                }
            }
            if (wire_reader_double(reader, &ping->height) != P2P_OK ||
                wire_reader_double(reader, &ping->error) != P2P_OK ||
                !wire_ping_values_are_valid(ping)) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len = sizeof(*ping);
            break;
        case P2P_MSG_FILE_GET:
            if (wire_reader_get(reader,
                                msg->payload.file_response.file_id,
                                P2P_DHT_KEY_SIZE) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len = P2P_DHT_KEY_SIZE;
            break;
        case P2P_MSG_DHT_GET:
        case P2P_MSG_DHT_FIND_NODE:
            if (wire_reader_get(reader,
                                msg->payload.dht_find_node.target_id,
                                P2P_DHT_KEY_SIZE) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len =
                sizeof(p2p_dht_find_node_payload_t);
            break;
        case P2P_MSG_DHT_PUT:
            if (wire_reader_get(reader, msg->payload.dht_store.key,
                                P2P_DHT_KEY_SIZE) != P2P_OK ||
                wire_reader_u16(reader,
                                &msg->payload.dht_store.data_len) != P2P_OK ||
                msg->payload.dht_store.data_len >
                    sizeof(msg->payload.dht_store.data) ||
                wire_reader_get(reader, msg->payload.dht_store.data,
                                msg->payload.dht_store.data_len) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len =
                (uint16_t)(offsetof(p2p_dht_store_payload_t, data) +
                           msg->payload.dht_store.data_len);
            break;
        case P2P_MSG_DHT_RESPONSE:
            if (wire_reader_u8(reader,
                               &msg->payload.dht_response.found) != P2P_OK ||
                wire_reader_u8(
                    reader, &msg->payload.dht_response.node_count) != P2P_OK ||
                msg->payload.dht_response.found > 1 ||
                msg->payload.dht_response.node_count > KADEMLIA_K ||
                (msg->payload.dht_response.found &&
                 msg->payload.dht_response.node_count != 0)) {
                return P2P_ERR_PROTOCOL;
            }
            for (index = 0;
                 index < msg->payload.dht_response.node_count; ++index) {
                p2p_kad_contact_t *contact =
                    &msg->payload.dht_response.nodes[index];
                if (wire_reader_get(reader, contact->id,
                                    P2P_DHT_KEY_SIZE) != P2P_OK ||
                    wire_read_ip(reader, contact->ip, 0) != P2P_OK ||
                    wire_reader_u16(reader, &contact->port) != P2P_OK ||
                    contact->port == 0) {
                    return P2P_ERR_PROTOCOL;
                }
            }
            if (wire_reader_u16(
                    reader, &msg->payload.dht_response.data_len) != P2P_OK ||
                msg->payload.dht_response.data_len >
                    sizeof(msg->payload.dht_response.data) ||
                (!msg->payload.dht_response.found &&
                 msg->payload.dht_response.data_len != 0) ||
                wire_reader_get(reader, msg->payload.dht_response.data,
                                msg->payload.dht_response.data_len) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len =
                (uint16_t)(offsetof(p2p_dht_response_payload_t, data) +
                           msg->payload.dht_response.data_len);
            break;
        case P2P_MSG_FILE_PUT:
            if (wire_reader_get(reader,
                                msg->payload.file_response.file_id,
                                P2P_DHT_KEY_SIZE) != P2P_OK ||
                wire_reader_u64(
                    reader, &msg->payload.file_response.file_size) != P2P_OK ||
                wire_reader_u32(
                    reader, &msg->payload.file_response.total_chunks) !=
                    P2P_OK ||
                wire_reader_get(reader,
                                msg->payload.file_response.file_hash,
                                P2P_SHA256_SIZE) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len =
                sizeof(p2p_file_response_payload_t);
            break;
        case P2P_MSG_CHUNK_REQUEST:
            if (wire_reader_u32(
                    reader, &msg->payload.chunk_request.transfer_id) !=
                    P2P_OK ||
                wire_reader_u32(
                    reader, &msg->payload.chunk_request.chunk_index) !=
                    P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len =
                sizeof(p2p_chunk_request_payload_t);
            break;
        case P2P_MSG_CHUNK_DATA:
            if (wire_reader_u32(
                    reader, &msg->payload.chunk_data.transfer_id) != P2P_OK ||
                wire_reader_u32(
                    reader, &msg->payload.chunk_data.chunk_index) != P2P_OK ||
                wire_reader_u16(
                    reader, &msg->payload.chunk_data.data_len) != P2P_OK ||
                msg->payload.chunk_data.data_len >
                    sizeof(msg->payload.chunk_data.data) ||
                wire_reader_get(reader, msg->payload.chunk_data.chunk_hash,
                                P2P_SHA256_SIZE) != P2P_OK ||
                wire_reader_get(reader, msg->payload.chunk_data.data,
                                msg->payload.chunk_data.data_len) != P2P_OK) {
                return P2P_ERR_PROTOCOL;
            }
            msg->header.payload_len =
                (uint16_t)(offsetof(p2p_chunk_data_payload_t, data) +
                           msg->payload.chunk_data.data_len);
            break;
        case P2P_MSG_FILE_ACK: {
            uint8_t success;
            if (wire_reader_u32(reader,
                                &msg->payload.file_ack.transfer_id) != P2P_OK ||
                wire_reader_u8(reader, &success) != P2P_OK || success > 1) {
                return P2P_ERR_PROTOCOL;
            }
            msg->payload.file_ack.success = success;
            msg->header.payload_len = sizeof(p2p_file_ack_payload_t);
            break;
        }
        default:
            return P2P_ERR_PROTOCOL;
    }
    return reader->offset == reader->length ? P2P_OK : P2P_ERR_PROTOCOL;
}

void p2p_message_init(p2p_message_t *msg, p2p_msg_type_t type) {
    if (!msg) {
        return;
    }
    memset(msg, 0, sizeof(*msg));
    msg->header.type = (uint8_t)type;
}

uint32_t p2p_generate_request_id(void) {
    static uint32_t g_rid = 1;
    return g_rid++;
}

int p2p_message_serialize(const p2p_message_t *msg, uint8_t **out,
                          size_t *out_len) {
    p2p_wire_writer_t writer;
    size_t payload_wire_size;
    size_t total_length;
    uint8_t *bytes;
    int ret;

    if (!msg || !out || !out_len) {
        return P2P_ERR_INVALID_ARG;
    }
    *out = NULL;
    *out_len = 0;
    ret = message_payload_wire_size(msg, &payload_wire_size);
    if (ret != P2P_OK) {
        return ret;
    }
    total_length = P2P_WIRE_HEADER_SIZE + payload_wire_size;
    if (total_length > P2P_NOISE_MAX_PLAINTEXT_SIZE) {
        return P2P_ERR_PROTOCOL;
    }
    bytes = (uint8_t *)malloc(total_length);
    if (!bytes) {
        return P2P_ERR_NO_MEM;
    }
    bytes[0] = msg->header.type;
    bytes[1] = 0;
    write_u16_be(bytes + 2, (uint16_t)payload_wire_size);
    write_u32_be(bytes + 4, msg->header.request_id);
    writer.bytes = bytes + P2P_WIRE_HEADER_SIZE;
    writer.capacity = payload_wire_size;
    writer.offset = 0;
    ret = message_payload_encode(msg, &writer);
    if (ret != P2P_OK || writer.offset != payload_wire_size) {
        free(bytes);
        return ret == P2P_OK ? P2P_ERR_PROTOCOL : ret;
    }
    *out = bytes;
    *out_len = total_length;
    return P2P_OK;
}

int p2p_message_deserialize(const uint8_t *data, size_t len,
                            p2p_message_t *msg, size_t *consumed) {
    p2p_wire_reader_t reader;
    p2p_msg_type_t type;
    uint16_t payload_wire_size;
    size_t total_length;
    int ret;

    if (!data || !msg || !consumed) {
        return P2P_ERR_INVALID_ARG;
    }
    *consumed = 0;
    if (len < P2P_WIRE_HEADER_SIZE) {
        return P2P_ERR_PROTOCOL;
    }
    payload_wire_size = read_u16_be(data + 2);
    total_length = P2P_WIRE_HEADER_SIZE + (size_t)payload_wire_size;
    if (total_length > P2P_NOISE_MAX_PLAINTEXT_SIZE ||
        len < total_length || data[1] != 0) {
        return P2P_ERR_PROTOCOL;
    }
    memset(msg, 0, sizeof(*msg));
    type = (p2p_msg_type_t)data[0];
    msg->header.type = data[0];
    msg->header.request_id = read_u32_be(data + 4);
    reader.bytes = data + P2P_WIRE_HEADER_SIZE;
    reader.length = payload_wire_size;
    reader.offset = 0;
    ret = message_payload_decode(type, &reader, msg);
    if (ret != P2P_OK || reader.offset != reader.length) {
        memset(msg, 0, sizeof(*msg));
        return ret == P2P_OK ? P2P_ERR_PROTOCOL : ret;
    }
    *consumed = total_length;
    return P2P_OK;
}

const char *p2p_message_type_name(p2p_msg_type_t type) {
    switch (type) {
        case P2P_MSG_PING:
            return "PING";
        case P2P_MSG_PONG:
            return "PONG";
        default:
            return "UNKNOWN";
    }
}

void p2p_id_to_hex(const p2p_id_t id, char *buf, size_t buf_len) {
    int index;
    if (!id || !buf || buf_len < 41) {
        return;
    }
    for (index = 0; index < 20; ++index) {
        snprintf(buf + (index * 2), buf_len - (size_t)(index * 2),
                 "%02x", id[index]);
    }
    buf[40] = '\0';
}
