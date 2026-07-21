#ifndef TURBO_P2P_MESH_MGMT_WIRE_H
#define TURBO_P2P_MESH_MGMT_WIRE_H

#include "mesh_mgmt_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint16_t mesh_mgmt_wire_read_u16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static inline uint32_t mesh_mgmt_wire_read_u32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) | bytes[3];
}

static inline uint64_t mesh_mgmt_wire_read_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    size_t index = 0;

    for (index = 0; index < sizeof(value); index++) {
        value = (value << 8u) | bytes[index];
    }
    return value;
}

static inline void mesh_mgmt_wire_write_u16(uint8_t *bytes,
                                             uint16_t value) {
    bytes[0] = (uint8_t)(value >> 8u);
    bytes[1] = (uint8_t)value;
}

static inline void mesh_mgmt_wire_write_u32(uint8_t *bytes,
                                             uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
}

static inline void mesh_mgmt_wire_write_u64(uint8_t *bytes,
                                             uint64_t value) {
    size_t index = 0;

    for (index = 0; index < sizeof(value); index++) {
        bytes[index] = (uint8_t)(value >> (56u - index * 8u));
    }
}

static inline size_t mesh_mgmt_wire_write_tlv(uint8_t *output,
                                               uint16_t field_id,
                                               const uint8_t *value,
                                               size_t value_len) {
    mesh_mgmt_wire_write_u16(output, field_id);
    mesh_mgmt_wire_write_u16(output + sizeof(uint16_t), (uint16_t)value_len);
    memcpy(output + MESH_MGMT_TLV_PREFIX_SIZE, value, value_len);
    return MESH_MGMT_TLV_PREFIX_SIZE + value_len;
}

static inline int mesh_mgmt_wire_read_field(mesh_mgmt_tlv_reader_t *reader,
                                             uint16_t expected_id,
                                             size_t expected_length,
                                             mesh_mgmt_tlv_view_t *field) {
    return mesh_mgmt_tlv_reader_next(reader, field) == 1 &&
           field->field_id == expected_id &&
           field->value_len == expected_length;
}

#endif
