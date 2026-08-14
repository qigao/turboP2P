#ifndef TURBO_P2P_EXAMPLE_SECURITY_H
#define TURBO_P2P_EXAMPLE_SECURITY_H

#include <p2p.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static int p2p_example_hex_nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int p2p_example_parse_hex_32(const char *hex,
                                    uint8_t output[P2P_KEY_SIZE]) {
    size_t index;

    if (!hex || !output || strlen(hex) != P2P_KEY_SIZE * 2u) {
        return 0;
    }
    for (index = 0; index < P2P_KEY_SIZE; ++index) {
        int high = p2p_example_hex_nibble(hex[index * 2u]);
        int low = p2p_example_hex_nibble(hex[index * 2u + 1u]);
        if (high < 0 || low < 0) {
            memset(output, 0, P2P_KEY_SIZE);
            return 0;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static int p2p_example_configure_pinned_peer(
    p2p_node_t *node,
    const char *network_id_hex,
    const char *secret_key_hex,
    const char *trusted_public_key_hex) {
    uint8_t network_id[P2P_SECURITY_ID_SIZE] = {0};
    uint8_t secret_key[P2P_KEY_SIZE] = {0};
    uint8_t trusted_key[P2P_KEY_SIZE] = {0};
    int result = P2P_ERR_INVALID_ARG;

    if (!node ||
        !p2p_example_parse_hex_32(network_id_hex, network_id) ||
        !p2p_example_parse_hex_32(secret_key_hex, secret_key) ||
        !p2p_example_parse_hex_32(trusted_public_key_hex, trusted_key)) {
        goto cleanup;
    }
    result = p2p_node_set_private_key(node, secret_key);
    if (result == P2P_OK) {
        result = p2p_node_configure_pinned_security_v2(
            node, network_id, trusted_key, 1u);
    }

cleanup:
    memset(network_id, 0, sizeof(network_id));
    memset(secret_key, 0, sizeof(secret_key));
    memset(trusted_key, 0, sizeof(trusted_key));
    return result;
}

#endif
