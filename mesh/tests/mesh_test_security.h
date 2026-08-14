#ifndef TURBO_P2P_MESH_TEST_SECURITY_H
#define TURBO_P2P_MESH_TEST_SECURITY_H

#include <p2p.h>
#include <turbo_mesh.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum { MESH_TEST_SECURITY_IDENTITY_COUNT = 4 };

static const char *const mesh_test_security_secrets[
    MESH_TEST_SECURITY_IDENTITY_COUNT] = {
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444",
};
static char mesh_test_security_public_hex[
    MESH_TEST_SECURITY_IDENTITY_COUNT][65];
static const char *mesh_test_security_trusted_ids[
    MESH_TEST_SECURITY_IDENTITY_COUNT];
static int mesh_test_security_ready;

static int mesh_test_security_initialize(void) {
    static const char hex[] = "0123456789abcdef";
    uint8_t secret[P2P_KEY_SIZE];
    uint8_t public_key[P2P_KEY_SIZE];
    size_t identity_index;

    if (mesh_test_security_ready) {
        return 1;
    }

    for (identity_index = 0;
         identity_index < MESH_TEST_SECURITY_IDENTITY_COUNT;
         ++identity_index) {
        size_t byte_index;
        memset(secret, (int)((identity_index + 1u) * 0x11u), sizeof(secret));
        if (p2p_public_key_from_private_key(secret, public_key) != P2P_OK) {
            memset(secret, 0, sizeof(secret));
            memset(public_key, 0, sizeof(public_key));
            return 0;
        }
        for (byte_index = 0; byte_index < sizeof(public_key); ++byte_index) {
            mesh_test_security_public_hex[identity_index][byte_index * 2u] =
                hex[public_key[byte_index] >> 4u];
            mesh_test_security_public_hex[identity_index][byte_index * 2u + 1u] =
                hex[public_key[byte_index] & 0x0fu];
        }
        mesh_test_security_public_hex[identity_index][64] = '\0';
        mesh_test_security_trusted_ids[identity_index] =
            mesh_test_security_public_hex[identity_index];
    }

    memset(secret, 0, sizeof(secret));
    memset(public_key, 0, sizeof(public_key));
    mesh_test_security_ready = 1;
    return 1;
}

static int mesh_test_security_configure(mesh_config_t *config,
                                        size_t identity_index) {
    if (!config || identity_index >= MESH_TEST_SECURITY_IDENTITY_COUNT ||
        !mesh_test_security_initialize()) {
        return 0;
    }

    config->identity_secret_hex = mesh_test_security_secrets[identity_index];
    config->peer_allow_node_ids = mesh_test_security_trusted_ids;
    config->peer_allow_node_id_count = MESH_TEST_SECURITY_IDENTITY_COUNT;
    return 1;
}

#endif
