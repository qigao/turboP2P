#include <salts/crypto.h>
#include <tinytest.h>

static const uint8_t abc_digest[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
static const uint8_t empty_digest[32] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

spec("SaltsUtils SHA-256 migration") {
  uint8_t digest[SALTS_CRYPTO_SHA256_DIGEST_SIZE];
  salts_crypto_sha256_ctx_t context;

  it("preserves standard one-shot digests and the empty credential digest") {
    check_equal(salts_crypto_sha256("abc", 3u, digest), SALTS_CRYPTO_OK);
    check_equal(digest, abc_digest, sizeof(digest));
    check_equal(salts_crypto_sha256(NULL, 0u, digest), SALTS_CRYPTO_OK);
    check_equal(digest, empty_digest, sizeof(digest));
  }
  it("preserves incremental hashing across domain and payload boundaries") {
    check_equal(salts_crypto_sha256_init(&context), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sha256_update(&context, "a", 1u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sha256_update(&context, NULL, 0u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sha256_update(&context, "bc", 2u), SALTS_CRYPTO_OK);
    check_equal(salts_crypto_sha256_final(&context, digest), SALTS_CRYPTO_OK);
    check_equal(digest, abc_digest, sizeof(digest));
    check_equal(salts_crypto_sha256_update(&context, "a", 1u), SALTS_CRYPTO_ESTATE);
    check_equal(salts_crypto_sha256_final(&context, digest), SALTS_CRYPTO_ESTATE);
  }
  it("rejects invalid buffers without silently computing a different digest") {
    check_equal(salts_crypto_sha256(NULL, 1u, digest), SALTS_CRYPTO_EINVAL);
    check_equal(salts_crypto_sha256("abc", 3u, NULL), SALTS_CRYPTO_EINVAL);
  }
}
