#include <tinytest.h>

#include "m3_gateway_sigv4.h"

#include <turbo_crypto.h>

#include <stdio.h>
#include <string.h>

/* Test-side independent SigV4 client signing helper. It shares only the
 * cryptographic primitives (turbo_crypto) with the implementation under test,
 * not the canonicalization code, so a symmetric mistake is not masked. */

static void to_hex(const uint8_t *in, size_t len, char *out) {
  static const char HEX[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < len; i++) {
    out[i * 2] = HEX[in[i] >> 4];
    out[i * 2 + 1] = HEX[in[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

static void client_sign(const char *method, const char *uri, const char *query, const char *amzdate,
                        const char *payload_hash, const uint8_t secret[32], const char *access_key,
                        const char *region, const char *service, const char *host,
                        char *authorization_out, size_t cap) {
  char canonical_request[2048];
  char string_to_sign[2048];
  char scope[128];
  uint8_t cr_digest[32];
  char cr_hex[65];
  uint8_t k1[32], k2[32], k3[32], k4[32];
  uint8_t sig[32];
  char sig_hex[65];
  char date[9];

  memcpy(date, amzdate, 8);
  date[8] = '\0';

  snprintf(canonical_request, sizeof(canonical_request),
           "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n"
           "host;x-amz-content-sha256;x-amz-date\n%s",
           method, uri, query ? query : "", host, payload_hash, amzdate, payload_hash);
  turbo_crypto_sha256(canonical_request, strlen(canonical_request), cr_digest);
  to_hex(cr_digest, sizeof(cr_digest), cr_hex);

  snprintf(scope, sizeof(scope), "%s/%s/%s/aws4_request", date, region, service);
  snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", amzdate, scope,
           cr_hex);

  {
    uint8_t buf[36];
    memcpy(buf, "AWS4", 4);
    memcpy(buf + 4, secret, 32);
    turbo_crypto_hmac_sha256(buf, sizeof(buf), date, 8, k1);
    turbo_crypto_hmac_sha256(k1, 32, region, strlen(region), k2);
    turbo_crypto_hmac_sha256(k2, 32, service, strlen(service), k3);
    turbo_crypto_hmac_sha256(k3, 32, "aws4_request", 12, k4);
  }
  turbo_crypto_hmac_sha256(k4, 32, string_to_sign, strlen(string_to_sign), sig);
  to_hex(sig, sizeof(sig), sig_hex);

  snprintf(authorization_out, cap,
           "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;"
           "x-amz-content-sha256;x-amz-date, Signature=%s",
           access_key, scope, sig_hex);
}

/* Test-side presigned URL signer: independent canonicalization (own encode and
 * sort) so a symmetric bug in the implementation is not masked. */
typedef struct {
  char name[64];
  char value[256];
} presign_pair_t;

static int presign_pair_cmp(const void *a, const void *b) {
  const presign_pair_t *l = (const presign_pair_t *)a;
  const presign_pair_t *r = (const presign_pair_t *)b;
  int c = strcmp(l->name, r->name);
  if (c != 0)
    return c;
  return strcmp(l->value, r->value);
}

static void t_uri_encode(const char *in, int encode_slash, char *out, size_t cap) {
  static const char HEX[] = "0123456789ABCDEF";
  size_t o = 0u;
  const unsigned char *p = (const unsigned char *)in;

  for (; *p && o + 1u < cap; p++) {
    unsigned char c = *p;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
        c == '_' || c == '.' || c == '~' || (c == '/' && !encode_slash)) {
      out[o++] = (char)c;
    } else {
      if (o + 3u >= cap)
        break;
      out[o++] = '%';
      out[o++] = HEX[c >> 4u];
      out[o++] = HEX[c & 0x0Fu];
    }
  }
  out[o] = '\0';
}

/* Build a presigned URL query (X-Amz-* + business params; X-Amz-Signature is
 * appended last). business_query is plain name=value&name=value text. */
static void client_sign_presigned(const char *method, const char *uri, const char *business_query,
                                  const char *amzdate, long expires, const uint8_t secret[32],
                                  const char *access_key, const char *region, const char *service,
                                  const char *host, char *url_out, size_t cap) {
  presign_pair_t pairs[32];
  size_t n = 0u;
  size_t i;
  char canonical_query[2048];
  size_t o = 0u;
  char canonical_request[4096];
  char string_to_sign[4096];
  char scope[128];
  char cred_value[256];
  char date[9];
  uint8_t cr_digest[32];
  char cr_hex[65];
  uint8_t k1[32], k2[32], k3[32], k4[32];
  uint8_t sig[32];
  char sig_hex[65];
  const char *p;

  memcpy(date, amzdate, 8);
  date[8] = '\0';

  p = business_query;
  while (p && *p && n + 6u < 32u) {
    const char *amp = strchr(p, '&');
    size_t seg = amp ? (size_t)(amp - p) : strlen(p);
    const char *eq = NULL;
    size_t k;
    for (k = 0u; k < seg; k++) {
      if (p[k] == '=') {
        eq = p + k;
        break;
      }
    }
    {
      size_t name_len = eq ? (size_t)(eq - p) : seg;
      size_t value_len = eq ? seg - name_len - 1u : 0u;
      if (name_len == 0u || name_len >= sizeof(pairs[n].name) ||
          value_len >= sizeof(pairs[n].value)) {
        break;
      }
      memcpy(pairs[n].name, p, name_len);
      pairs[n].name[name_len] = '\0';
      memcpy(pairs[n].value, eq ? eq + 1u : p + seg, value_len);
      pairs[n].value[value_len] = '\0';
      n++;
    }
    if (!amp)
      break;
    p = amp + 1u;
  }

  snprintf(cred_value, sizeof(cred_value), "%s/%s/%s/%s/aws4_request", access_key, date, region,
           service);

  strcpy(pairs[n].name, "X-Amz-Algorithm");
  strcpy(pairs[n].value, "AWS4-HMAC-SHA256");
  n++;
  strcpy(pairs[n].name, "X-Amz-Credential");
  strcpy(pairs[n].value, cred_value);
  n++;
  strcpy(pairs[n].name, "X-Amz-Date");
  strcpy(pairs[n].value, amzdate);
  n++;
  strcpy(pairs[n].name, "X-Amz-Expires");
  snprintf(pairs[n].value, sizeof(pairs[n].value), "%ld", expires);
  n++;
  strcpy(pairs[n].name, "X-Amz-SignedHeaders");
  strcpy(pairs[n].value, "host");
  n++;

  qsort(pairs, n, sizeof(pairs[0]), presign_pair_cmp);

  o = 0u;
  canonical_query[0] = '\0';
  for (i = 0u; i < n; i++) {
    char enc_name[128];
    char enc_value[512];
    size_t name_len;
    size_t value_len;

    t_uri_encode(pairs[i].name, 1, enc_name, sizeof(enc_name));
    t_uri_encode(pairs[i].value, 1, enc_value, sizeof(enc_value));
    name_len = strlen(enc_name);
    value_len = strlen(enc_value);
    if (i > 0u) {
      if (o + 1u >= sizeof(canonical_query))
        break;
      canonical_query[o++] = '&';
    }
    if (o + name_len + 1u + value_len + 1u >= sizeof(canonical_query))
      break;
    memcpy(canonical_query + o, enc_name, name_len);
    o += name_len;
    canonical_query[o++] = '=';
    memcpy(canonical_query + o, enc_value, value_len);
    o += value_len;
  }
  canonical_query[o] = '\0';

  snprintf(canonical_request, sizeof(canonical_request),
           "%s\n%s\n%s\nhost:%s\nhost\nUNSIGNED-PAYLOAD", method, uri, canonical_query, host);
  turbo_crypto_sha256(canonical_request, strlen(canonical_request), cr_digest);
  to_hex(cr_digest, sizeof(cr_digest), cr_hex);

  snprintf(scope, sizeof(scope), "%s/%s/%s/aws4_request", date, region, service);
  snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", amzdate, scope,
           cr_hex);

  {
    uint8_t buf[36];
    memcpy(buf, "AWS4", 4);
    memcpy(buf + 4, secret, 32);
    turbo_crypto_hmac_sha256(buf, sizeof(buf), date, 8, k1);
    turbo_crypto_hmac_sha256(k1, 32, region, strlen(region), k2);
    turbo_crypto_hmac_sha256(k2, 32, service, strlen(service), k3);
    turbo_crypto_hmac_sha256(k3, 32, "aws4_request", 12, k4);
  }
  turbo_crypto_hmac_sha256(k4, 32, string_to_sign, strlen(string_to_sign), sig);
  to_hex(sig, sizeof(sig), sig_hex);

  snprintf(url_out, cap, "%s&X-Amz-Signature=%s", canonical_query, sig_hex);
}

static const uint8_t TEST_SECRET[32] = {
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34};
#define TEST_ACCESS_KEY "AKIDEXAMPLE"
#define TEST_REGION "us-east-1"
#define TEST_SERVICE "s3"
#define TEST_AMZDATE "20260804T120000Z"
#define TEST_HOST "127.0.0.1:8080"
#define TEST_PAYLOAD_HASH "44a7cf26a94a0ba6d69c8c19f0c0c5e0b7f4a4a4e5f6a7b8c9d0e1f2a3b4c5d6"

typedef struct {
  const char *host;
  const char *x_amz_content_sha256;
  const char *x_amz_date;
} test_headers_t;

static const char *test_header_lookup(void *ctx, const char *name) {
  const test_headers_t *h = (const test_headers_t *)ctx;

  if (strcmp(name, "host") == 0)
    return h->host;
  if (strcmp(name, "x-amz-content-sha256") == 0)
    return h->x_amz_content_sha256;
  if (strcmp(name, "x-amz-date") == 0)
    return h->x_amz_date;
  return NULL;
}

static const uint8_t SECRET_ONE[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t SECRET_TWO[32] = {
    0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

typedef struct {
  const char *access_key;
  const uint8_t *secret;
} resolver_entry_t;

static const resolver_entry_t TEST_RESOLVER_ENTRIES[] = {
    {"AKIDONE", SECRET_ONE},
    {"AKIDTWO", SECRET_TWO},
};

/* Multi-credential resolver: keyed by access key; returns secret + scope. */
static int test_credential_resolver(void *context, const char *access_key,
                                    m3_sigv4_credential_v1_t *out) {
  size_t i;
  (void)context;
  for (i = 0u; i < sizeof(TEST_RESOLVER_ENTRIES) / sizeof(TEST_RESOLVER_ENTRIES[0]); i++) {
    if (strcmp(access_key, TEST_RESOLVER_ENTRIES[i].access_key) == 0) {
      memset(out, 0, sizeof(*out));
      strcpy(out->access_key, TEST_RESOLVER_ENTRIES[i].access_key);
      memcpy(out->secret_key, TEST_RESOLVER_ENTRIES[i].secret, sizeof(out->secret_key));
      out->region = TEST_REGION;
      out->service = TEST_SERVICE;
      out->clock_skew_seconds = 900;
      return 0;
    }
  }
  return -1;
}

static void test_valid_request_passes(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign("PUT", "/demo-bucket/hello.txt", NULL, TEST_AMZDATE, TEST_PAYLOAD_HASH, TEST_SECRET,
              TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));

  check_int_eq(M3_SIGV4_OK,
               m3_sigv4_verify_request_v1(&cred, "PUT", "/demo-bucket/hello.txt", NULL,
                                          authorization, TEST_AMZDATE, NULL, test_header_lookup,
                                          &headers, 1785844800 /* == 2026-08-04T12:00:00Z */));
}

static void test_tampered_payload_hash_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign("PUT", "/demo-bucket/hello.txt", NULL, TEST_AMZDATE, TEST_PAYLOAD_HASH, TEST_SECRET,
              TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));

  /* Attacker changes the payload hash header after signing. */
  headers.x_amz_content_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
  check_int_eq(M3_SIGV4_BAD_SIGNATURE,
               m3_sigv4_verify_request_v1(&cred, "PUT", "/demo-bucket/hello.txt", NULL,
                                          authorization, TEST_AMZDATE, NULL, test_header_lookup,
                                          &headers, 1785844800));
}

static void test_tampered_query_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign("GET", "/demo-bucket/hello.txt", "uploadId=abc", TEST_AMZDATE, TEST_PAYLOAD_HASH,
              TEST_SECRET, TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));

  /* Verify against a different query than the one signed. */
  check_int_eq(M3_SIGV4_BAD_SIGNATURE,
               m3_sigv4_verify_request_v1(&cred, "GET", "/demo-bucket/hello.txt", "uploadId=def",
                                          authorization, TEST_AMZDATE, NULL, test_header_lookup,
                                          &headers, 1785844800));
}

static void test_expired_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign("PUT", "/demo-bucket/hello.txt", NULL, TEST_AMZDATE, TEST_PAYLOAD_HASH, TEST_SECRET,
              TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));

  /* now_seconds is 2 hours after the signed timestamp. */
  check_int_eq(M3_SIGV4_EXPIRED,
               m3_sigv4_verify_request_v1(&cred, "PUT", "/demo-bucket/hello.txt", NULL,
                                          authorization, TEST_AMZDATE, NULL, test_header_lookup,
                                          &headers, 1785844800 + 7200));
}

static void test_wrong_access_key_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  strcpy(cred.access_key, "OTHERKEY");
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign("PUT", "/demo-bucket/hello.txt", NULL, TEST_AMZDATE, TEST_PAYLOAD_HASH, TEST_SECRET,
              TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));

  check_int_eq(M3_SIGV4_UNKNOWN_ACCESS_KEY,
               m3_sigv4_verify_request_v1(&cred, "PUT", "/demo-bucket/hello.txt", NULL,
                                          authorization, TEST_AMZDATE, NULL, test_header_lookup,
                                          &headers, 1785844800));
}

static void test_malformed_authorization_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  check_int_eq(M3_SIGV4_MALFORMED_AUTH,
               m3_sigv4_verify_request_v1(&cred, "PUT", "/demo-bucket/hello.txt", NULL,
                                          "not-an-authorization", TEST_AMZDATE, NULL,
                                          test_header_lookup, &headers, 1785844800));
  check_int_eq(M3_SIGV4_UNSUPPORTED_ALGORITHM,
               m3_sigv4_verify_request_v1(&cred, "PUT", "/demo-bucket/hello.txt", NULL,
                                          "HMAC-SHA256 Credential=x/y/z/a/aws4_request, "
                                          "SignedHeaders=host, Signature=00",
                                          TEST_AMZDATE, NULL, test_header_lookup, &headers,
                                          1785844800));
}

static void test_presigned_valid_passes(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, NULL, NULL};
  char url[4096];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign_presigned("GET", "/demo-bucket/hello.txt", "uploadId=abc", TEST_AMZDATE, 300,
                        TEST_SECRET, TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, url,
                        sizeof(url));
  check_int_eq(M3_SIGV4_OK,
               m3_sigv4_verify_presigned_v1(&cred, NULL, NULL, "GET", "/demo-bucket/hello.txt", url,
                                            test_header_lookup, &headers, 1785844800));
}

static void test_presigned_tampered_signature_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, NULL, NULL};
  char url[4096];
  size_t len;

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign_presigned("GET", "/demo-bucket/hello.txt", "uploadId=abc", TEST_AMZDATE, 300,
                        TEST_SECRET, TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, url,
                        sizeof(url));
  /* Flip the final X-Amz-Signature hex digit to a different valid hex digit. */
  len = strlen(url);
  url[len - 1u] = (url[len - 1u] == '0') ? '1' : '0';
  check_int_eq(M3_SIGV4_BAD_SIGNATURE,
               m3_sigv4_verify_presigned_v1(&cred, NULL, NULL, "GET", "/demo-bucket/hello.txt", url,
                                            test_header_lookup, &headers, 1785844800));
}

static void test_presigned_expired_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, NULL, NULL};
  char url[4096];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign_presigned("GET", "/demo-bucket/hello.txt", "uploadId=abc", TEST_AMZDATE, 300,
                        TEST_SECRET, TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, url,
                        sizeof(url));
  /* now is 301s after X-Amz-Date: past the 300s expiry. */
  check_int_eq(M3_SIGV4_EXPIRED,
               m3_sigv4_verify_presigned_v1(&cred, NULL, NULL, "GET", "/demo-bucket/hello.txt", url,
                                            test_header_lookup, &headers, 1785844800 + 301));
  /* now is 901s before X-Amz-Date: outside the 900s skew window. */
  check_int_eq(M3_SIGV4_EXPIRED,
               m3_sigv4_verify_presigned_v1(&cred, NULL, NULL, "GET", "/demo-bucket/hello.txt", url,
                                            test_header_lookup, &headers, 1785844800 - 901));
}

static void test_presigned_wrong_method_rejected(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, NULL, NULL};
  char url[4096];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  client_sign_presigned("GET", "/demo-bucket/hello.txt", "uploadId=abc", TEST_AMZDATE, 300,
                        TEST_SECRET, TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST, url,
                        sizeof(url));
  check_int_eq(M3_SIGV4_BAD_SIGNATURE,
               m3_sigv4_verify_presigned_v1(&cred, NULL, NULL, "PUT", "/demo-bucket/hello.txt", url,
                                            test_header_lookup, &headers, 1785844800));
}

static void test_presigned_resolver_passes(void) {
  test_headers_t headers = {TEST_HOST, NULL, NULL};
  char url[4096];

  client_sign_presigned("GET", "/demo-bucket/hello.txt", "uploadId=abc", TEST_AMZDATE, 300,
                        SECRET_ONE, "AKIDONE", TEST_REGION, TEST_SERVICE, TEST_HOST, url,
                        sizeof(url));
  check_int_eq(M3_SIGV4_OK, m3_sigv4_verify_presigned_v1(NULL, test_credential_resolver, NULL,
                                                         "GET", "/demo-bucket/hello.txt", url,
                                                         test_header_lookup, &headers, 1785844800));
}

static void test_resolver_multi_credential_ok(void) {
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  client_sign("PUT", "/demo-bucket/hello.txt", NULL, TEST_AMZDATE, TEST_PAYLOAD_HASH, SECRET_ONE,
              "AKIDONE", TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));
  check_int_eq(M3_SIGV4_OK,
               m3_sigv4_verify_request_ex_v1(
                   NULL, test_credential_resolver, NULL, "PUT", "/demo-bucket/hello.txt", NULL,
                   authorization, TEST_AMZDATE, NULL, test_header_lookup, &headers, 1785844800));

  client_sign("PUT", "/demo-bucket/hello.txt", NULL, TEST_AMZDATE, TEST_PAYLOAD_HASH, SECRET_TWO,
              "AKIDTWO", TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));
  check_int_eq(M3_SIGV4_OK,
               m3_sigv4_verify_request_ex_v1(
                   NULL, test_credential_resolver, NULL, "PUT", "/demo-bucket/hello.txt", NULL,
                   authorization, TEST_AMZDATE, NULL, test_header_lookup, &headers, 1785844800));
}

static void test_resolver_unknown_key_rejected(void) {
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  client_sign("PUT", "/demo-bucket/hello.txt", NULL, TEST_AMZDATE, TEST_PAYLOAD_HASH, TEST_SECRET,
              "AKIDUNKNOWN", TEST_REGION, TEST_SERVICE, TEST_HOST, authorization,
              sizeof(authorization));
  check_int_eq(M3_SIGV4_UNKNOWN_ACCESS_KEY,
               m3_sigv4_verify_request_ex_v1(
                   NULL, test_credential_resolver, NULL, "PUT", "/demo-bucket/hello.txt", NULL,
                   authorization, TEST_AMZDATE, NULL, test_header_lookup, &headers, 1785844800));
}

static void test_public_signer_round_trip(void) {
  m3_sigv4_credential_v1_t cred = {0};
  test_headers_t headers = {TEST_HOST, TEST_PAYLOAD_HASH, TEST_AMZDATE};
  char authorization[512];

  strcpy(cred.access_key, TEST_ACCESS_KEY);
  memcpy(cred.secret_key, TEST_SECRET, sizeof(cred.secret_key));
  cred.region = TEST_REGION;
  cred.service = TEST_SERVICE;
  cred.clock_skew_seconds = 900;

  /* The public signer must produce what the verifier accepts. */
  check_int_eq(M3_SIGV4_OK,
               m3_sigv4_sign_request_v1("PUT", "/demo-bucket/hello.txt", NULL,
                                        TEST_PAYLOAD_HASH, TEST_SECRET, TEST_ACCESS_KEY,
                                        TEST_REGION, TEST_SERVICE, TEST_HOST, TEST_AMZDATE,
                                        authorization, sizeof(authorization)));
  check_int_eq(M3_SIGV4_OK,
               m3_sigv4_verify_request_v1(&cred, "PUT", "/demo-bucket/hello.txt", NULL,
                                          authorization, TEST_AMZDATE, NULL, test_header_lookup,
                                          &headers, 1785844800));

  /* The same signature fails under a different method (tamper). */
  check_int_eq(M3_SIGV4_BAD_SIGNATURE,
               m3_sigv4_verify_request_v1(&cred, "GET", "/demo-bucket/hello.txt", NULL,
                                          authorization, TEST_AMZDATE, NULL, test_header_lookup,
                                          &headers, 1785844800));

  check_int_eq(M3_SIGV4_INVALID_ARG,
               m3_sigv4_sign_request_v1(NULL, "/x", NULL, TEST_PAYLOAD_HASH, TEST_SECRET,
                                        TEST_ACCESS_KEY, TEST_REGION, TEST_SERVICE, TEST_HOST,
                                        TEST_AMZDATE, authorization, sizeof(authorization)));
}
spec("m3 gateway sigv4") {
  describe("server-side AWS SigV4 verification") {
    it("accepts a valid signed PUT") { test_valid_request_passes(); }
    it("rejects a tampered payload hash") { test_tampered_payload_hash_rejected(); }
    it("rejects a query mismatch") { test_tampered_query_rejected(); }
    it("rejects an expired timestamp") { test_expired_rejected(); }
    it("rejects an unknown access key") { test_wrong_access_key_rejected(); }
    it("rejects malformed or unsupported authorization") {
      test_malformed_authorization_rejected();
    }
  }
  describe("client-side signing") {
    it("signs a request the verifier accepts") { test_public_signer_round_trip(); }
  }
  describe("presigned URL verification") {
    it("accepts a valid presigned URL") { test_presigned_valid_passes(); }
    it("rejects a tampered presigned signature") { test_presigned_tampered_signature_rejected(); }
    it("rejects an expired presigned URL") { test_presigned_expired_rejected(); }
    it("rejects a presigned URL used with a different method") {
      test_presigned_wrong_method_rejected();
    }
    it("accepts a presigned URL via credential resolver") { test_presigned_resolver_passes(); }
  }
  describe("multi-credential resolver") {
    it("accepts requests signed with either resolver key") { test_resolver_multi_credential_ok(); }
    it("rejects an unknown resolver access key") { test_resolver_unknown_key_rejected(); }
  }
}
