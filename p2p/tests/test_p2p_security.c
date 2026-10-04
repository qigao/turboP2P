#include <tinytest.h>
#include <noise/protocol.h>
#include "security/p2p_cookie.h"
#include "security/p2p_noise_c_platform.h"
#include "p2p_security_fixture.h"
#include <limits.h>

void test_p2p_crypto_random_uses_checked_csprng(void) {
    uint8_t random_bytes[P2P_KEY_SIZE] = {0};
    uint8_t zero[P2P_KEY_SIZE] = {0};

    check_equal(P2P_OK, p2p_crypto_random(random_bytes, sizeof(random_bytes)));
    check_true(memcmp(random_bytes, zero, sizeof(random_bytes)) != 0);
    check_equal(P2P_OK, p2p_crypto_random(NULL, 0));
    check_equal(P2P_ERR_INVALID_ARG, p2p_crypto_random(NULL, 1));
}

static void test_p2p_cookie_codec_matches_vector_and_binds_source(void) {
    static const uint8_t expected_packet[P2P_COOKIE_PACKET_SIZE] = {
        0x54, 0x50, 0x43, 0x32, 0x00, 0x02, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39,
        0x31, 0xce, 0x75, 0x47, 0x63, 0x49, 0xb4, 0x2a,
        0xbf, 0x95, 0x4d, 0x08, 0x32, 0x63, 0x94, 0x89,
        0x77, 0x99, 0x06, 0x93, 0x3d, 0x1a, 0x64, 0x28,
        0x0f, 0xd4, 0x0c, 0x62, 0x29, 0x0e, 0x95, 0xb9,
    };
    uint8_t secret[P2P_COOKIE_SECRET_SIZE];
    uint8_t network_id[P2P_SECURITY_ID_SIZE];
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t altered_preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t challenge[P2P_COOKIE_PACKET_SIZE];
    uint8_t response[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];

    for (size_t index = 0; index < sizeof(secret); ++index) {
        secret[index] = (uint8_t)index;
    }
    for (size_t index = 0; index < sizeof(network_id); ++index) {
        network_id[index] = (uint8_t)(index + 32U);
    }
    p2p_secure_preface_build(network_id, preface);
    check_equal(P2P_OK,
                 p2p_secure_preface_validate(network_id, preface));
    check_equal(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "192.0.2.10", preface, UINT64_C(123456789),
                     10000U, 300000U, challenge));
    check_equal(expected_packet, challenge, sizeof(challenge));
    check_equal(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_equal(P2P_OK,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.10", preface, UINT64_C(123456789),
                     10000U, 300000U, response, binding));
    check_equal(P2P_ERR_CRYPTO,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.11", preface, UINT64_C(123456789),
                     10000U, 300000U, response, binding));
    memcpy(altered_preface, preface, sizeof(altered_preface));
    altered_preface[12] ^= 1U;
    check_equal(P2P_ERR_CRYPTO,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.10", altered_preface,
                     UINT64_C(123456789), 10000U, 300000U, response,
                     binding));
    response[47] ^= 1U;
    check_equal(P2P_ERR_CRYPTO,
                 p2p_cookie_verify_response(
                     secret, "192.0.2.10", preface, UINT64_C(123456789),
                     10000U, 300000U, response, binding));
}

static void test_p2p_cookie_codec_bounds_time_and_rotation(void) {
    uint8_t secret[P2P_COOKIE_SECRET_SIZE] = {7};
    uint8_t network_id[P2P_SECURITY_ID_SIZE] = {9};
    uint8_t preface[P2P_SECURE_PREFACE_SIZE];
    uint8_t challenge[P2P_COOKIE_PACKET_SIZE];
    uint8_t response[P2P_COOKIE_PACKET_SIZE];
    uint8_t binding[P2P_COOKIE_BINDING_SIZE];
    const uint64_t now_ms = UINT64_C(123456789);

    p2p_secure_preface_build(network_id, preface);
    check_equal(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, now_ms - 10000U,
                     10000U, 300000U, challenge));
    check_equal(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_equal(P2P_OK,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, now_ms, 10000U,
                     300000U, response, binding));

    check_equal(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, now_ms - 20000U,
                     10000U, 300000U, challenge));
    check_equal(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_equal(P2P_ERR_TIMEOUT,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, now_ms, 10000U,
                     300000U, response, binding));

    check_equal(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, now_ms + 10000U,
                     10000U, 300000U, challenge));
    check_equal(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_equal(P2P_ERR_TIMEOUT,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, now_ms, 10000U,
                     300000U, response, binding));

    /* Bucket 29 uses the previous derived key epoch while bucket 30 uses the
     * current epoch; the previous bucket remains valid across rotation. */
    check_equal(P2P_OK,
                 p2p_cookie_build_challenge(
                     secret, "2001:db8::1", preface, UINT64_C(299999),
                     10000U, 300000U, challenge));
    check_equal(P2P_OK,
                 p2p_cookie_build_response(challenge, response, binding));
    check_equal(P2P_OK,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, UINT64_C(300000),
                     10000U, 300000U, response, binding));
    response[7] = 1U;
    check_equal(P2P_ERR_PROTOCOL,
                 p2p_cookie_verify_response(
                     secret, "2001:db8::1", preface, UINT64_C(300000),
                     10000U, 300000U, response, binding));
}

static int p2p_test_hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int p2p_test_decode_hex(const char *hex,
                               uint8_t *output,
                               size_t output_capacity,
                               size_t *output_len) {
    size_t hex_len;
    size_t index;

    if (!hex || !output || !output_len) {
        return 0;
    }

    hex_len = strlen(hex);
    if ((hex_len & 1U) != 0 || (hex_len / 2U) > output_capacity) {
        return 0;
    }

    for (index = 0; index < hex_len / 2U; ++index) {
        int high = p2p_test_hex_nibble(hex[index * 2U]);
        int low = p2p_test_hex_nibble(hex[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return 0;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }

    *output_len = hex_len / 2U;
    return 1;
}

void test_p2p_noise_xx_matches_upstream_vector(void) {
    /* Source: noise-c/tests/vector/noise-c-basic.txt at revision
     * cfe25410979a87391bb9ac8d4d4bef64e9f268c6.  Keep this copy independent of the fetched file so
     * a dependency update cannot silently update both code and expectation. */
    static const char *const protocol_name =
        "Noise_XX_25519_ChaChaPoly_BLAKE2s";
    static const char *const prologue_hex = "50726f6c6f677565313233";
    static const char *const initiator_static_hex =
        "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
    static const char *const initiator_ephemeral_hex =
        "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
    static const char *const responder_static_hex =
        "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
    static const char *const responder_ephemeral_hex =
        "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
    static const char *const handshake_hash_hex =
        "ff2542ab6833ab2243a6a19599fde5e2b2ac5a6dc4f34a9be3046233fd790d41";
    static const struct {
        const char *payload_hex;
        const char *ciphertext_hex;
    } messages[] = {
        {
            "4c756477696720766f6e204d69736573",
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"
            "4c756477696720766f6e204d69736573",
        },
        {
            "4d757272617920526f746862617264",
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
            "7c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec5a"
            "11745edbea05ef4097ca82afe861d8aa196a6cead1e11b2bb13e336fa13614136"
            "f53e3d34be699da5983876f700ff",
        },
        {
            "462e20412e20486179656b",
            "46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d41"
            "76a11f5a0f70968037b0e0bedf68d18d802efa4220cff733e7b566970e749fef0"
            "6ea55e598cdb819d0a33e",
        },
    };
    NoiseHandshakeState *initiator = NULL;
    NoiseHandshakeState *responder = NULL;
    NoiseHandshakeState *sender;
    NoiseHandshakeState *receiver;
    NoiseDHState *dh;
    NoiseBuffer message_buffer;
    NoiseBuffer payload_buffer;
    uint8_t key[32] = {0};
    uint8_t prologue[32] = {0};
    uint8_t message[256] = {0};
    uint8_t plaintext[256] = {0};
    uint8_t expected_payload[256] = {0};
    uint8_t expected_ciphertext[256] = {0};
    uint8_t actual_hash[32] = {0};
    uint8_t expected_hash[32] = {0};
    size_t key_len = 0;
    size_t prologue_len = 0;
    size_t expected_payload_len = 0;
    size_t expected_ciphertext_len = 0;
    size_t expected_hash_len = 0;
    size_t index;
    int result;

    result = noise_handshakestate_new_by_name(
        &initiator, protocol_name, NOISE_ROLE_INITIATOR);
    check_equal(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_new_by_name(
        &responder, protocol_name, NOISE_ROLE_RESPONDER);
    check_equal(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }

#define SET_NOISE_PRIVATE_KEY(state, accessor, hex_value)                       \
    do {                                                                        \
        check_true(p2p_test_decode_hex((hex_value), key, sizeof(key), &key_len));     \
        dh = accessor((state));                                                  \
        check_not_null(dh);                                                      \
        if (!dh || key_len != sizeof(key)) {                                     \
            goto cleanup;                                                        \
        }                                                                        \
        result = noise_dhstate_set_keypair_private(dh, key, key_len);            \
        check_equal(NOISE_ERROR_NONE, result);                                  \
        if (result != NOISE_ERROR_NONE) {                                        \
            goto cleanup;                                                        \
        }                                                                        \
    } while (0)

    SET_NOISE_PRIVATE_KEY(initiator,
                          noise_handshakestate_get_local_keypair_dh,
                          initiator_static_hex);
    SET_NOISE_PRIVATE_KEY(initiator,
                          noise_handshakestate_get_fixed_ephemeral_dh,
                          initiator_ephemeral_hex);
    SET_NOISE_PRIVATE_KEY(responder,
                          noise_handshakestate_get_local_keypair_dh,
                          responder_static_hex);
    SET_NOISE_PRIVATE_KEY(responder,
                          noise_handshakestate_get_fixed_ephemeral_dh,
                          responder_ephemeral_hex);
#undef SET_NOISE_PRIVATE_KEY

    check_true(p2p_test_decode_hex(prologue_hex, prologue, sizeof(prologue),
                              &prologue_len));
    result = noise_handshakestate_set_prologue(
        initiator, prologue, prologue_len);
    check_equal(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_set_prologue(
        responder, prologue, prologue_len);
    check_equal(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_start(initiator);
    check_equal(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }
    result = noise_handshakestate_start(responder);
    check_equal(NOISE_ERROR_NONE, result);
    if (result != NOISE_ERROR_NONE) {
        goto cleanup;
    }

    for (index = 0; index < sizeof(messages) / sizeof(messages[0]); ++index) {
        sender = (index == 1U) ? responder : initiator;
        receiver = (index == 1U) ? initiator : responder;
        check_equal(NOISE_ACTION_WRITE_MESSAGE,
                     noise_handshakestate_get_action(sender));
        check_equal(NOISE_ACTION_READ_MESSAGE,
                     noise_handshakestate_get_action(receiver));
        check_true(p2p_test_decode_hex(messages[index].payload_hex,
                                  expected_payload,
                                  sizeof(expected_payload),
                                  &expected_payload_len));
        check_true(p2p_test_decode_hex(messages[index].ciphertext_hex,
                                  expected_ciphertext,
                                  sizeof(expected_ciphertext),
                                  &expected_ciphertext_len));

        noise_buffer_set_output(message_buffer, message, sizeof(message));
        noise_buffer_set_input(payload_buffer,
                               expected_payload,
                               expected_payload_len);
        result = noise_handshakestate_write_message(
            sender, &message_buffer, &payload_buffer);
        check_equal(NOISE_ERROR_NONE, result);
        if (result != NOISE_ERROR_NONE) {
            goto cleanup;
        }
        check_equal((int)expected_ciphertext_len, (int)message_buffer.size);
        check_true(memcmp(message, expected_ciphertext, expected_ciphertext_len) == 0);

        noise_buffer_set_input(message_buffer, message, message_buffer.size);
        noise_buffer_set_output(payload_buffer, plaintext, sizeof(plaintext));
        result = noise_handshakestate_read_message(
            receiver, &message_buffer, &payload_buffer);
        check_equal(NOISE_ERROR_NONE, result);
        if (result != NOISE_ERROR_NONE) {
            goto cleanup;
        }
        check_equal((int)expected_payload_len, (int)payload_buffer.size);
        check_true(memcmp(plaintext, expected_payload, expected_payload_len) == 0);
    }

    check_equal(NOISE_ACTION_SPLIT,
                 noise_handshakestate_get_action(initiator));
    check_equal(NOISE_ACTION_SPLIT,
                 noise_handshakestate_get_action(responder));
    check_true(p2p_test_decode_hex(handshake_hash_hex,
                              expected_hash,
                              sizeof(expected_hash),
                              &expected_hash_len));
    check_equal((int)sizeof(actual_hash), (int)expected_hash_len);
    result = noise_handshakestate_get_handshake_hash(
        initiator, actual_hash, sizeof(actual_hash));
    check_equal(NOISE_ERROR_NONE, result);
    check_true(memcmp(actual_hash, expected_hash, sizeof(actual_hash)) == 0);
    result = noise_handshakestate_get_handshake_hash(
        responder, actual_hash, sizeof(actual_hash));
    check_equal(NOISE_ERROR_NONE, result);
    check_true(memcmp(actual_hash, expected_hash, sizeof(actual_hash)) == 0);

cleanup:
    if (initiator) {
        (void)noise_handshakestate_free(initiator);
    }
    if (responder) {
        (void)noise_handshakestate_free(responder);
    }
    p2p_crypto_wipe(key, sizeof(key));
    p2p_crypto_wipe(message, sizeof(message));
    p2p_crypto_wipe(plaintext, sizeof(plaintext));
}

void test_p2p_crypto_rejects_replayed_ciphertext(void) {
    const uint8_t plaintext[] = "mesh-replay-test";
    uint8_t ciphertext[sizeof(plaintext) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(ciphertext)] = {0};
    size_t ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    check_equal(P2P_OK, p2p_test_crypto_sessions(&sender, &receiver));
    check_equal(P2P_OK,
                 p2p_crypto_encrypt(&sender, plaintext, sizeof(plaintext),
                                    ciphertext, &ciphertext_len));
    check_equal(P2P_OK,
                 p2p_crypto_decrypt(&receiver, ciphertext, ciphertext_len,
                                    output, sizeof(output), &output_len));
    check_equal((int)sizeof(plaintext), (int)output_len);
    check_true(memcmp(plaintext, output, sizeof(plaintext)) == 0);
    check_equal(P2P_ERR_CRYPTO,
                 p2p_crypto_decrypt(&receiver, ciphertext, ciphertext_len,
                                    output, sizeof(output), &output_len));
    check_equal(1, (int)receiver.received_frames);
    p2p_crypto_session_destroy(&sender);
    p2p_crypto_session_destroy(&receiver);
}

void test_p2p_crypto_rejects_out_of_order_without_advancing(void) {
    const uint8_t first[] = "first";
    const uint8_t second[] = "second";
    uint8_t first_ciphertext[sizeof(first) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t second_ciphertext[sizeof(second) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(second_ciphertext)] = {0};
    size_t first_ciphertext_len = 0;
    size_t second_ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    check_equal(P2P_OK, p2p_test_crypto_sessions(&sender, &receiver));
    check_equal(P2P_OK,
                 p2p_crypto_encrypt(&sender, first, sizeof(first),
                                    first_ciphertext, &first_ciphertext_len));
    check_equal(P2P_OK,
                 p2p_crypto_encrypt(&sender, second, sizeof(second),
                                    second_ciphertext, &second_ciphertext_len));

    check_equal(P2P_ERR_CRYPTO,
                 p2p_crypto_decrypt(&receiver, second_ciphertext,
                                    second_ciphertext_len, output,
                                    sizeof(output), &output_len));
    check_equal(0, (int)receiver.received_frames);
    check_equal(P2P_OK,
                 p2p_crypto_decrypt(&receiver, first_ciphertext,
                                    first_ciphertext_len, output,
                                    sizeof(output), &output_len));
    check_equal((int)sizeof(first), (int)output_len);
    check_true(memcmp(first, output, sizeof(first)) == 0);
    check_equal(P2P_OK,
                 p2p_crypto_decrypt(&receiver, second_ciphertext,
                                    second_ciphertext_len, output,
                                    sizeof(output), &output_len));
    check_equal((int)sizeof(second), (int)output_len);
    check_true(memcmp(second, output, sizeof(second)) == 0);
    p2p_crypto_session_destroy(&sender);
    p2p_crypto_session_destroy(&receiver);
}

void test_p2p_crypto_rejects_counter_exhaustion(void) {
    const uint8_t plaintext[] = "counter";
    uint8_t ciphertext[sizeof(plaintext) + P2P_TEST_AEAD_FRAME_OVERHEAD] = {0};
    uint8_t output[sizeof(ciphertext)] = {0};
    size_t ciphertext_len = 0;
    size_t output_len = 0;
    p2p_crypto_session_t sender;
    p2p_crypto_session_t receiver;

    check_equal(P2P_OK, p2p_test_crypto_sessions(&sender, &receiver));
    sender.sent_frames = P2P_NOISE_SESSION_FRAME_LIMIT;
    receiver.received_frames = P2P_NOISE_SESSION_FRAME_LIMIT;
    check_equal(P2P_ERR_KEY_EXHAUSTED,
                 p2p_crypto_encrypt(&sender, plaintext, sizeof(plaintext),
                                    ciphertext, &ciphertext_len));
    check_equal(P2P_ERR_KEY_EXHAUSTED,
                 p2p_crypto_decrypt(&receiver, ciphertext, sizeof(ciphertext),
                                    output, sizeof(output), &output_len));
    check_true(sender.sent_frames == P2P_NOISE_SESSION_FRAME_LIMIT);
    check_true(receiver.received_frames == P2P_NOISE_SESSION_FRAME_LIMIT);
    p2p_crypto_session_destroy(&sender);
    p2p_crypto_session_destroy(&receiver);
}

static void check_hex(const char *hex, const uint8_t *actual, size_t length) {
    uint8_t expected[64];
    size_t decoded = 0;
    check_true(p2p_test_decode_hex(hex, expected, sizeof(expected), &decoded));
    check_equal(length, decoded);
    check_equal(expected, actual, length);
}

static void test_primitive_vectors(void) {
    uint8_t key[131];
    uint8_t digest[32];
    uint8_t secret[32];
    size_t length = 0;
    p2p_identity_t identity = {0};
    const uint8_t long_message[] =
        "Test Using Larger Than Block-Size Key - Hash Key First";

    /* RFC 4231 cases 1 and 6, including HMAC's oversized-key reduction. */
    memset(key, 0x0b, 20);
    check_equal(P2P_OK, p2p_crypto_hmac_sha256(
        key, 20, (const uint8_t *)"Hi There", 8, digest));
    check_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
              digest, sizeof(digest));
    memset(key, 0xaa, sizeof(key));
    check_equal(P2P_OK, p2p_crypto_hmac_sha256(
        key, sizeof(key), long_message, sizeof(long_message) - 1, digest));
    check_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
              digest, sizeof(digest));
    check_equal(P2P_OK, p2p_crypto_hmac_sha256(NULL, 0, NULL, 0, digest));
    check_hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
              digest, sizeof(digest));
    check_equal(P2P_ERR_INVALID_ARG,
                p2p_crypto_hmac_sha256(NULL, 1, NULL, 0, digest));
    check_equal(P2P_ERR_INVALID_ARG,
                p2p_crypto_hmac_sha256(key, (size_t)INT_MAX + 1, NULL, 0, digest));
    p2p_crypto_sha256(NULL, 0, digest);
    check_hex("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
              digest, sizeof(digest));

    /* RFC 7748 Alice static key; an aliased reload must preserve the key. */
    check_true(p2p_test_decode_hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        secret, sizeof(secret), &length));
    check_equal(P2P_OK, p2p_crypto_identity_from_secret(&identity, secret));
    check_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
              identity.public_key, sizeof(identity.public_key));
    check_equal(P2P_OK, p2p_crypto_identity_from_secret(&identity, identity.secret_key));
    check_equal(secret, identity.secret_key, sizeof(secret));
    check_equal(P2P_ERR_INVALID_ARG, p2p_crypto_identity_from_secret(&identity, NULL));
    check_equal(secret, identity.secret_key, sizeof(secret));
    p2p_crypto_wipe(&identity, sizeof(identity));
}

static void test_arbitrary_length_verify(void) {
    uint8_t first[79];
    uint8_t second[79];
    memset(first, 0xa5, sizeof(first));
    memcpy(second, first, sizeof(first));
    check_true(p2p_crypto_verify(NULL, NULL, 0));
    check_false(p2p_crypto_verify(NULL, second, 1));
    for (size_t length = 1; length <= sizeof(first); ++length) {
        check_true(p2p_crypto_verify(first, second, length));
        second[length - 1] ^= 1;
        check_false(p2p_crypto_verify(first, second, length));
        second[length - 1] ^= 1;
    }
    p2p_crypto_wipe(first, sizeof(first));
    memset(second, 0, sizeof(second));
    check_equal(first, second, sizeof(first));
}

typedef struct {
    uint8_t secret[32];
    uint8_t public_key[32];
    int error;
    int zero_shared;
    unsigned calls;
    uint64_t seen_deadline;
    const p2p_private_key_cancel_v4_t *seen_cancel;
} provider_fixture_t;

static int provider_public(void *context, uint8_t output[32]) {
    provider_fixture_t *provider = context;
    memcpy(output, provider->public_key, 32);
    return P2P_OK;
}

static int provider_calculate(void *context, const uint8_t remote[32],
                              uint8_t output[32]) {
    provider_fixture_t *provider = context;
    provider->calls++;
    memset(output, provider->zero_shared ? 0 : 0xa5, 32);
    if (provider->error || provider->zero_shared) {
        return provider->error;
    }
    return p2p_test_x25519(output, provider->secret, remote);
}

static int provider_blocking(void *context, const uint8_t remote[32],
                             uint64_t deadline,
                             const p2p_private_key_cancel_v4_t *cancel,
                             uint8_t output[32]) {
    provider_fixture_t *provider = context;
    provider->seen_deadline = deadline;
    provider->seen_cancel = cancel;
    if (cancel->is_cancelled(cancel->context)) {
        return P2P_ERR_TIMEOUT;
    }
    return provider_calculate(context, remote, output);
}

static int is_cancelled(void *context) {
    return *(int *)context;
}

static void test_provider_handshake(int blocking, int cancelled, int error) {
    provider_fixture_t provider = {{7}, {0}, error, 0, 0, 0, NULL};
    p2p_private_key_provider_v3_t synchronous = {0};
    p2p_blocking_private_key_provider_v4_t asynchronous = {0};
    p2p_private_key_cancel_v4_t cancel = {0};
    p2p_identity_t first = {0}, second = {0};
    p2p_noise_handshake_t initiator = {0}, responder = {0};
    p2p_crypto_session_t send = {0}, receive = {0};
    uint8_t message[256], output[256];
    uint8_t zero[32] = {0};
    size_t length = 0, plaintext_length = 0;
    const uint8_t payload[] = "provider roundtrip";
    int result;

    crypto_x25519_public_key(provider.public_key, provider.secret);
    synchronous.struct_size = sizeof(synchronous);
    synchronous.context = &provider;
    synchronous.get_public_key = provider_public;
    synchronous.calculate_x25519 = provider_calculate;
    asynchronous.struct_size = sizeof(asynchronous);
    asynchronous.context = &provider;
    asynchronous.get_public_key = provider_public;
    asynchronous.calculate_x25519 = provider_blocking;
    cancel.struct_size = sizeof(cancel);
    cancel.context = &cancelled;
    cancel.is_cancelled = is_cancelled;
    result = blocking ? p2p_crypto_identity_from_blocking_provider(
        &first, &asynchronous, provider.public_key) :
        p2p_crypto_identity_from_provider(&first, &synchronous, provider.public_key);
    check_equal(P2P_OK, result);
    check_equal(zero, first.secret_key, sizeof(zero));
    check_equal(P2P_OK, p2p_crypto_generate_identity(&second));
    check_equal(P2P_OK, p2p_noise_init_initiator(&initiator, &first, NULL));
    check_equal(P2P_OK, p2p_noise_init_responder(&responder, &second));
    check_equal(P2P_OK, p2p_noise_write_message(&initiator, message, &length, sizeof(message)));
    check_equal(P2P_OK, p2p_noise_read_message(&responder, message, length));
    check_equal(P2P_OK, p2p_noise_write_message(&responder, message, &length, sizeof(message)));
    check_equal(P2P_OK, p2p_noise_read_message(&initiator, message, length));
    result = blocking ? p2p_noise_write_message_with_payload_blocking(
        &initiator, NULL, 0, 12345, &cancel, message, &length, sizeof(message)) :
        p2p_noise_write_message(&initiator, message, &length, sizeof(message));
    if (blocking) {
        check_equal(UINT64_C(12345), provider.seen_deadline);
        check_true(provider.seen_cancel == &cancel);
        check_true(initiator.blocking_cancel == NULL);
        check_equal(UINT64_C(0), initiator.blocking_deadline_ms);
    }
    if (cancelled || error) {
        check_equal(cancelled ? P2P_ERR_TIMEOUT : error, result);
        check_false(p2p_noise_is_complete(&initiator));
        goto cleanup;
    }
    check_equal(P2P_OK, result);
    check_equal(1U, provider.calls);
    check_equal(P2P_OK, p2p_noise_read_message(&responder, message, length));
    check_equal(P2P_OK, p2p_noise_split(&initiator, &send));
    check_equal(P2P_OK, p2p_noise_split(&responder, &receive));
    check_equal(provider.public_key, responder.remote_static_public, 32);
    check_equal(initiator.handshake_hash, responder.handshake_hash, 32);
    check_equal(P2P_OK, p2p_crypto_encrypt(&send, payload, sizeof(payload), message, &length));
    check_equal(P2P_OK, p2p_crypto_decrypt(&receive, message, length, output, sizeof(output), &plaintext_length));
    check_equal(sizeof(payload), plaintext_length);
    check_equal(payload, output, plaintext_length);
cleanup:
    p2p_noise_handshake_destroy(&initiator);
    p2p_noise_handshake_destroy(&responder);
    p2p_crypto_session_destroy(&send);
    p2p_crypto_session_destroy(&receive);
    p2p_crypto_wipe(&first, sizeof(first));
    p2p_crypto_wipe(&second, sizeof(second));
    p2p_crypto_wipe(&provider, sizeof(provider));
}

static void test_dh_rejects_low_order_and_failed_providers(void) {
    NoiseDHState *local = NULL, *remote = NULL;
    uint8_t secret[32] = {7}, low_order[32] = {1};
    uint8_t output[32], zero[32] = {0};
    provider_fixture_t provider = {{7}, {0}, P2P_ERR_TIMEOUT, 0, 0, 0, NULL};
    check_equal(NOISE_ERROR_NONE, noise_dhstate_new_by_name(&local, "25519"));
    check_equal(NOISE_ERROR_NONE, noise_dhstate_new_by_name(&remote, "25519"));
    check_not_null(local);
    check_not_null(remote);
    if (!local || !remote) goto cleanup;
    check_equal(NOISE_ERROR_NONE, noise_dhstate_set_keypair_private(local, secret, 32));
    check_equal(NOISE_ERROR_NONE, noise_dhstate_set_public_key(remote, low_order, 32));
    memset(output, 0xa5, sizeof(output));
    check_equal(NOISE_ERROR_INVALID_PUBLIC_KEY, noise_dhstate_calculate(local, remote, output, 32));
    check_equal(zero, output, 32);
    crypto_x25519_public_key(provider.public_key, provider.secret);
    check_equal(NOISE_ERROR_NONE, noise_dhstate_set_public_key(remote, provider.public_key, 32));
    check_equal(NOISE_ERROR_NONE, p2p_noise_curve25519_set_provider(
        local, provider.public_key, provider_calculate, &provider));
    check_equal(NOISE_ERROR_SYSTEM, noise_dhstate_calculate(local, remote, output, 32));
    check_equal(zero, output, 32);
    check_equal(P2P_ERR_TIMEOUT, p2p_noise_curve25519_take_provider_error(local));
    check_equal(0, p2p_noise_curve25519_take_provider_error(local));
    provider.error = 0;
    provider.zero_shared = 1;
    check_equal(NOISE_ERROR_INVALID_PUBLIC_KEY, noise_dhstate_calculate(local, remote, output, 32));
    check_equal(zero, output, 32);
    check_equal(2U, provider.calls);
cleanup:
    if (local) noise_dhstate_free(local);
    if (remote) noise_dhstate_free(remote);
}

#ifdef P2P_TEST_WRAP_RANDOM
static int fail_random;
int __real_salts_platform_secure_random(void *buffer, size_t length);
int __wrap_salts_platform_secure_random(void *buffer, size_t length) {
    if (!fail_random) {
        return __real_salts_platform_secure_random(buffer, length);
    }
    /* Model an OS failure after partially filling the caller's storage. */
    if (buffer && length) memset(buffer, 0xa5, length / 2);
    return -1;
}

static void test_random_failure_is_terminal(void) {
    uint8_t secret[32] = {7}, output[32], public_key[32], zero[32] = {0};
    p2p_identity_t identity = {0}, previous;
    NoiseDHState *dh = NULL;
    check_equal(P2P_OK, p2p_crypto_identity_from_secret(&identity, secret));
    previous = identity;
    check_equal(NOISE_ERROR_NONE, noise_dhstate_new_by_name(&dh, "25519"));
    if (!dh) return;
    check_equal(NOISE_ERROR_NONE, noise_dhstate_set_keypair_private(dh, secret, 32));
    fail_random = 1;
    memset(output, 0xff, sizeof(output));
    int random_result = p2p_crypto_random(output, sizeof(output));
    int identity_result = p2p_crypto_generate_identity(&identity);
    int dh_result = noise_dhstate_generate_keypair(dh);
    fail_random = 0;
    check_equal(P2P_ERR_CRYPTO, random_result);
    check_equal(zero, output, sizeof(output));
    check_equal(P2P_ERR_CRYPTO, identity_result);
    check_equal(&previous, &identity, sizeof(identity));
    check_equal(NOISE_ERROR_SYSTEM, dh_result);
    check_equal(NOISE_ERROR_NONE, noise_dhstate_get_keypair(
        dh, output, sizeof(output), public_key, sizeof(public_key)));
    check_equal(zero, output, sizeof(output));
    check_equal(zero, public_key, sizeof(public_key));
    noise_dhstate_free(dh);
    p2p_crypto_wipe(&identity, sizeof(identity));
    p2p_crypto_wipe(&previous, sizeof(previous));
}
#endif

spec("P2P security on Salts") {
#ifdef P2P_TEST_WRAP_RANDOM
    it("clears partial RNG output and retains the previous identity on failure") { test_random_failure_is_terminal(); }
#endif
    it("uses the operating system CSPRNG") { test_p2p_crypto_random_uses_checked_csprng(); }
    it("preserves the cookie wire vector and source binding") { test_p2p_cookie_codec_matches_vector_and_binds_source(); }
    it("bounds cookie lifetime and rotation") { test_p2p_cookie_codec_bounds_time_and_rotation(); }
    it("preserves the independent Noise XX upstream vector") { test_p2p_noise_xx_matches_upstream_vector(); }
    it("rejects replay") { test_p2p_crypto_rejects_replayed_ciphertext(); }
    it("preserves receive nonce after out of order ciphertext") { test_p2p_crypto_rejects_out_of_order_without_advancing(); }
    it("rejects exhausted counters") { test_p2p_crypto_rejects_counter_exhaustion(); }
    it("matches HMAC, X25519 and historical BLAKE2b vectors") { test_primitive_vectors(); }
    it("compares arbitrary authenticated lengths and wipes") { test_arbitrary_length_verify(); }
    it("supports an opaque synchronous static key") { test_provider_handshake(0, 0, 0); }
    it("propagates an opaque provider failure") { test_provider_handshake(0, 0, P2P_ERR_IO); }
    it("passes scoped deadline and cancellation to a blocking provider") { test_provider_handshake(1, 0, 0); }
    it("propagates cancellation without establishing a session") { test_provider_handshake(1, 1, 0); }
    it("rejects low order keys and wipes provider failures") { test_dh_rejects_low_order_and_failed_providers(); }
}
