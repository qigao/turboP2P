#include "protocol/message.h"
#include "security/p2p_noise_backend.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    p2p_message_t message = {0};
    uint8_t *canonical = NULL;
    size_t canonical_length = 0;
    size_t consumed = 0;

    if ((!data && size != 0) || size > P2P_NOISE_MAX_PLAINTEXT_SIZE) {
        return 0;
    }
    if (p2p_message_deserialize(data, size, &message, &consumed) != P2P_OK) {
        return 0;
    }
    if (p2p_message_serialize(&message, &canonical, &canonical_length) !=
            P2P_OK ||
        canonical_length != consumed ||
        memcmp(canonical, data, consumed) != 0) {
        free(canonical);
        abort();
    }
    free(canonical);
    return 0;
}
