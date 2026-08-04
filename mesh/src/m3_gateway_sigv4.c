#include "m3_gateway_sigv4.h"

#include <turbo_crypto.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Server-side AWS Signature Version 4 verification (Phase 1).
 *
 * Scope: single configured credential, AWS4-HMAC-SHA256, x-amz-date required,
 * x-amz-content-sha256 required. Query keys are canonicalized with RFC 3986
 * encoding (encode-slash on) and sorted; canonical URI preserves '/'.
 */

static const char M3_SIGV4_ALGORITHM[] = "AWS4-HMAC-SHA256";
static const char M3_SIGV4_TERMINATOR[] = "aws4_request";
/* AWS presigned URL validity ceiling; also bounds the expiry arithmetic. */
#define M3_SIGV4_EXPIRES_MAX_SECONDS 604800

static const char HEX_LOWER[] = "0123456789abcdef";
static const char HEX_UPPER[] = "0123456789ABCDEF";

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int hex_decode(const char *in, size_t len, uint8_t *out, size_t out_cap) {
  size_t i;

  if (len % 2u != 0u || len / 2u > out_cap)
    return -1;
  for (i = 0u; i < len; i += 2u) {
    int hi = hex_value(in[i]);
    int lo = hex_value(in[i + 1u]);
    if (hi < 0 || lo < 0)
      return -1;
    out[i / 2u] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static void hex_encode(const uint8_t *in, size_t len, char *out) {
  size_t i;

  for (i = 0u; i < len; i++) {
    out[i * 2u] = HEX_LOWER[in[i] >> 4u];
    out[i * 2u + 1u] = HEX_LOWER[in[i] & 0x0Fu];
  }
  out[len * 2u] = '\0';
}

/* RFC 3986 unreserved plus optional '/'. */
static int uri_encode(const char *in, int encode_slash, char *out, size_t cap) {
  size_t o = 0u;
  const unsigned char *p = (const unsigned char *)in;

  for (; *p; p++) {
    unsigned char c = *p;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
        c == '_' || c == '.' || c == '~' || (c == '/' && !encode_slash)) {
      if (o + 1u >= cap)
        return -1;
      out[o++] = (char)c;
    } else {
      if (o + 3u >= cap)
        return -1;
      out[o++] = '%';
      out[o++] = HEX_UPPER[c >> 4u];
      out[o++] = HEX_UPPER[c & 0x0Fu];
    }
  }
  out[o] = '\0';
  return 0;
}

static int percent_decode(const char *in, size_t len, char *out, size_t cap) {
  size_t i;
  size_t o = 0u;

  for (i = 0u; i < len;) {
    if (in[i] == '%' && i + 2u < len) {
      int hi = hex_value(in[i + 1u]);
      int lo = hex_value(in[i + 2u]);
      if (hi < 0 || lo < 0)
        return -1;
      if (o + 1u >= cap)
        return -1;
      out[o++] = (char)((hi << 4) | lo);
      i += 3u;
    } else {
      if (o + 1u >= cap)
        return -1;
      out[o++] = in[i++];
    }
  }
  out[o] = '\0';
  return 0;
}

typedef struct {
  const char *name;
  const char *value;
} query_pair_t;

typedef struct {
  query_pair_t *pairs;
  size_t count;
} query_list_t;

static int query_parse(const char *raw, char *buf, size_t buf_cap, query_pair_t *pairs,
                       size_t max_pairs, size_t *out_count) {
  size_t count = 0u;
  size_t o = 0u;
  const char *p = raw;

  while (p && *p) {
    const char *amp = strchr(p, '&');
    size_t seg_len = amp ? (size_t)(amp - p) : strlen(p);
    const char *eq = NULL;
    size_t i;

    for (i = 0u; i < seg_len; i++) {
      if (p[i] == '=') {
        eq = p + i;
        break;
      }
    }
    {
      size_t name_len = eq ? (size_t)(eq - p) : seg_len;
      const char *value = eq ? eq + 1u : p + seg_len;
      size_t value_len = eq ? (size_t)((p + seg_len) - (eq + 1u)) : 0u;
      char *name_out;
      char *value_out;

      if (count >= max_pairs)
        return -1;
      name_out = buf + o;
      if (percent_decode(p, name_len, name_out, buf_cap - o) != 0)
        return -1;
      o += strlen(name_out) + 1u;
      if (o >= buf_cap)
        return -1;
      value_out = buf + o;
      if (percent_decode(value, value_len, value_out, buf_cap - o) != 0)
        return -1;
      o += strlen(value_out) + 1u;
      if (o >= buf_cap)
        return -1;
      pairs[count].name = name_out;
      pairs[count].value = value_out;
      count++;
    }
    if (!amp)
      break;
    p = amp + 1u;
  }
  *out_count = count;
  return 0;
}

static int query_pair_cmp(const void *a, const void *b) {
  const query_pair_t *l = (const query_pair_t *)a;
  const query_pair_t *r = (const query_pair_t *)b;
  int c = strcmp(l->name, r->name);
  if (c != 0)
    return c;
  return strcmp(l->value, r->value);
}

/* Build the canonical query string (sorted, RFC 3986 encoded, encode-slash on).
 * exclude_name skips one query parameter (presigned X-Amz-Signature); pass NULL
 * to include every parameter. */
static int canonical_query_build(const char *raw, const char *exclude_name, char *out, size_t cap) {
  query_pair_t pairs[64];
  char buf[2048];
  size_t count = 0u;
  size_t i;
  size_t emitted = 0u;
  size_t o = 0u;

  if (!raw || raw[0] == '\0') {
    out[0] = '\0';
    return 0;
  }
  if (query_parse(raw, buf, sizeof(buf), pairs, 64u, &count) != 0)
    return -1;
  qsort(pairs, count, sizeof(pairs[0]), query_pair_cmp);
  for (i = 0u; i < count; i++) {
    if (exclude_name && strcmp(pairs[i].name, exclude_name) == 0)
      continue;
    if (emitted > 0u) {
      if (o + 1u >= cap)
        return -1;
      out[o++] = '&';
    }
    if (uri_encode(pairs[i].name, 1, out + o, cap - o) != 0)
      return -1;
    o += strlen(out + o);
    if (o + 1u >= cap)
      return -1;
    out[o++] = '=';
    if (uri_encode(pairs[i].value, 1, out + o, cap - o) != 0)
      return -1;
    o += strlen(out + o);
    emitted++;
  }
  out[o] = '\0';
  return 0;
}

/* Trim whitespace and collapse internal runs of spaces/tabs to one space. */
static size_t header_value_normalize(const char *in, char *out, size_t cap) {
  size_t o = 0u;
  int pending_space = 0;

  while (*in && isspace((unsigned char)*in))
    in++;
  for (; *in; in++) {
    if (isspace((unsigned char)*in)) {
      pending_space = 1;
    } else {
      if (pending_space && o > 0u) {
        if (o + 1u >= cap)
          return 0u;
        out[o++] = ' ';
      }
      pending_space = 0;
      if (o + 1u >= cap)
        return 0u;
      out[o++] = *in;
    }
  }
  out[o] = '\0';
  return o;
}

typedef struct {
  char algorithm[32];
  char credential[256];
  char signed_headers[512];
  char signature_hex[128];
} parsed_auth_t;

static int auth_parse(const char *authorization, parsed_auth_t *out) {
  const char *p = authorization;
  const char *comma;

  while (*p && isspace((unsigned char)*p))
    p++;
  {
    size_t algo_len = 0u;
    while (p[algo_len] && p[algo_len] != ' ')
      algo_len++;
    if (algo_len == 0u || algo_len >= sizeof(out->algorithm))
      return -1;
    memcpy(out->algorithm, p, algo_len);
    out->algorithm[algo_len] = '\0';
    p += algo_len;
    if (*p != ' ')
      return -1;
    p++;
  }
  out->credential[0] = '\0';
  out->signed_headers[0] = '\0';
  out->signature_hex[0] = '\0';

  while (*p) {
    const char *eq;
    size_t key_len;
    size_t value_len;

    while (*p && (*p == ',' || isspace((unsigned char)*p)))
      p++;
    if (!*p)
      break;
    eq = strchr(p, '=');
    if (!eq)
      return -1;
    key_len = (size_t)(eq - p);
    value_len = 0u;
    {
      const char *v = eq + 1u;
      while (v[value_len] && v[value_len] != ',')
        value_len++;
      if (key_len == 10u && strncmp(p, "Credential", 10u) == 0) {
        if (value_len >= sizeof(out->credential))
          return -1;
        memcpy(out->credential, v, value_len);
        out->credential[value_len] = '\0';
      } else if (key_len == 13u && strncmp(p, "SignedHeaders", 13u) == 0) {
        if (value_len >= sizeof(out->signed_headers))
          return -1;
        memcpy(out->signed_headers, v, value_len);
        out->signed_headers[value_len] = '\0';
      } else if (key_len == 9u && strncmp(p, "Signature", 9u) == 0) {
        if (value_len >= sizeof(out->signature_hex))
          return -1;
        memcpy(out->signature_hex, v, value_len);
        out->signature_hex[value_len] = '\0';
      }
      p = v + value_len;
    }
    comma = p;
    if (*comma == ',')
      p = comma + 1u;
    else if (*comma)
      return -1;
  }
  if (!out->credential[0] || !out->signed_headers[0] || !out->signature_hex[0]) {
    return -1;
  }
  return 0;
}

/* Parse "YYYYMMDDTHHMMSSZ" (x-amz-date) into a UTC epoch. */
static int parse_amzdate(const char *s, int64_t *out_epoch) {
  int year, month, day, hour, minute, second;
  int64_t days;
  static const int MONTH_DAYS[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

  if (!s || strlen(s) != 16u || s[8] != 'T' || s[15] != 'Z')
    return -1;
  if (sscanf(s, "%4d%2d%2dT%2d%2d%2d", &year, &month, &day, &hour, &minute, &second) != 6) {
    return -1;
  }
  if (month < 1 || month > 12 || day < 1 || hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
      second < 0 || second > 60) {
    return -1;
  }
  /* days_from_civil (Howard Hinnant): civil -> days since 1970-01-01. */
  {
    int y = year;
    unsigned m = (unsigned)month;
    unsigned d = (unsigned)day;
    y -= m <= 2u;
    {
      const int era = (y >= 0 ? y : y - 399) / 400;
      const unsigned yoe = (unsigned)(y - era * 400);
      const unsigned adjusted_month = m > 2u ? m - 3u : m + 9u;
      const unsigned doy = (153u * adjusted_month + 2u) / 5u + d - 1u;
      const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
      days = (int64_t)era * 146097 + (int64_t)doe - 719468;
    }
  }
  (void)MONTH_DAYS;
  *out_epoch = days * 86400 + (int64_t)hour * 3600 + (int64_t)minute * 60 + (int64_t)second;
  return 0;
}

static int build_canonical_headers(const char *signed_headers, m3_sigv4_header_lookup_fn lookup,
                                   void *lookup_context, char *out, size_t cap) {
  size_t o = 0u;
  const char *p = signed_headers;

  while (p && *p) {
    const char *semi = strchr(p, ';');
    size_t name_len = semi ? (size_t)(semi - p) : strlen(p);
    char name[128];
    const char *value;
    char normalized[1024];
    size_t i;
    size_t value_len;

    if (name_len == 0u || name_len >= sizeof(name))
      return -1;
    for (i = 0u; i < name_len; i++) {
      name[i] = (char)tolower((unsigned char)p[i]);
    }
    name[name_len] = '\0';
    value = lookup ? lookup(lookup_context, name) : NULL;
    if (!value)
      return -1;
    value_len = header_value_normalize(value, normalized, sizeof(normalized));
    if (value_len == 0u && normalized[0] != '\0')
      return -1;
    if (o + name_len + 1u + value_len + 1u + 1u >= cap)
      return -1;
    memcpy(out + o, name, name_len);
    o += name_len;
    out[o++] = ':';
    memcpy(out + o, normalized, value_len);
    o += value_len;
    out[o++] = '\n';
    if (semi)
      p = semi + 1u;
    else
      break;
  }
  out[o] = '\0';
  return 0;
}

/* Presigned URL signature parameters carried in the query string. */
typedef struct {
  char algorithm[64];
  char credential[256];
  char amzdate[32];
  char expires[32];
  char signed_headers[512];
  char signature_hex[128];
} presigned_query_t;

/* Extract the X-Amz-* parameters from a presigned URL query. */
static int presigned_query_parse(const char *raw_query, presigned_query_t *out) {
  query_pair_t pairs[64];
  char buf[2048];
  size_t count = 0u;
  size_t i;
  int have[6] = {0, 0, 0, 0, 0, 0};

  memset(out, 0, sizeof(*out));
  if (query_parse(raw_query, buf, sizeof(buf), pairs, 64u, &count) != 0) {
    return -1;
  }
  for (i = 0u; i < count; i++) {
    const char *name = pairs[i].name;
    const char *value = pairs[i].value;
    if (strcmp(name, "X-Amz-Algorithm") == 0) {
      if (have[0] || strlen(value) >= sizeof(out->algorithm))
        return -1;
      strcpy(out->algorithm, value);
      have[0] = 1;
    } else if (strcmp(name, "X-Amz-Credential") == 0) {
      if (have[1] || strlen(value) >= sizeof(out->credential))
        return -1;
      strcpy(out->credential, value);
      have[1] = 1;
    } else if (strcmp(name, "X-Amz-Date") == 0) {
      if (have[2] || strlen(value) >= sizeof(out->amzdate))
        return -1;
      strcpy(out->amzdate, value);
      have[2] = 1;
    } else if (strcmp(name, "X-Amz-Expires") == 0) {
      if (have[3] || strlen(value) >= sizeof(out->expires))
        return -1;
      strcpy(out->expires, value);
      have[3] = 1;
    } else if (strcmp(name, "X-Amz-SignedHeaders") == 0) {
      if (have[4] || strlen(value) >= sizeof(out->signed_headers))
        return -1;
      strcpy(out->signed_headers, value);
      have[4] = 1;
    } else if (strcmp(name, "X-Amz-Signature") == 0) {
      if (have[5] || strlen(value) >= sizeof(out->signature_hex))
        return -1;
      strcpy(out->signature_hex, value);
      have[5] = 1;
    }
  }
  if (!have[0] || !have[1] || !have[2] || !have[3] || !have[4] || !have[5]) {
    return -1;
  }
  return 0;
}

/* Shared verification context: everything m3_sigv4_verify_core needs after the
 * caller has parsed either the Authorization header or the presigned query. */
typedef struct {
  const char *method;
  const char *canonical_uri;
  const char *raw_query;
  const char *exclude_query_name; /* query parameter excluded from the canonical query, or NULL */
  const char *amzdate;            /* StringToSign date line (YYYYMMDDTHHMMSSZ) */
  const char *scope_access_key;   /* credential scope part 0 */
  const char *scope_date;         /* credential scope part 1 (YYYYMMDD) */
  const char *scope_region;       /* credential scope part 2 */
  const char *scope_service;      /* credential scope part 3 */
  const char *scope_terminator;   /* credential scope part 4 */
  const char *signed_headers;     /* "host;..." */
  const char *payload_hash;       /* hex digest, "UNSIGNED-PAYLOAD", or NULL to
                                     look up x-amz-content-sha256 via lookup */
  const char *signature_hex;      /* expected signature from the request */
  m3_sigv4_header_lookup_fn lookup;
  void *lookup_context;
  int64_t now_seconds;
  int64_t expires_seconds; /* >0: presigned window; <=0: Authorization skew window */
  const m3_sigv4_credential_v1_t *credential; /* may be NULL when resolver is set */
  m3_sigv4_credential_resolver_fn resolver;   /* may be NULL when credential is set */
  void *resolver_context;
} m3_sigv4_verify_context_t;

/* Resolve the credential for scope_access_key from a resolver or the single
 * configured credential. Returns M3_SIGV4_UNKNOWN_ACCESS_KEY when the resolver
 * fails or the single credential access key does not match the scope. */
static m3_sigv4_result_t m3_sigv4_resolve_credential(const char *scope_access_key,
                                                     const m3_sigv4_credential_v1_t *credential,
                                                     m3_sigv4_credential_resolver_fn resolver,
                                                     void *resolver_context,
                                                     m3_sigv4_credential_v1_t *out) {
  if (resolver) {
    memset(out, 0, sizeof(*out));
    if (resolver(resolver_context, scope_access_key, out) != 0) {
      return M3_SIGV4_UNKNOWN_ACCESS_KEY;
    }
    if (!out->region || !out->service) {
      return M3_SIGV4_UNKNOWN_ACCESS_KEY;
    }
    return M3_SIGV4_OK;
  }
  if (!credential || !credential->access_key[0] || !credential->region || !credential->service) {
    return M3_SIGV4_INVALID_ARG;
  }
  *out = *credential;
  if (strcmp(scope_access_key, credential->access_key) != 0) {
    return M3_SIGV4_UNKNOWN_ACCESS_KEY;
  }
  return M3_SIGV4_OK;
}

/* Shared pipeline: credential resolution, scope/time-window checks, canonical
 * request rebuild, HMAC chain and constant-time signature comparison. */
static m3_sigv4_result_t m3_sigv4_verify_core(const m3_sigv4_verify_context_t *ctx) {
  m3_sigv4_credential_v1_t cred;
  m3_sigv4_result_t rc;
  int64_t amzdate_epoch = 0;
  int64_t skew;
  char canonical_uri_enc[1024];
  char canonical_query[2048];
  char canonical_headers[4096];
  char canonical_request[8192];
  char signed_headers[512];
  uint8_t canonical_digest[M3_SIGV4_SECRET_KEY_SIZE];
  char canonical_digest_hex[65];
  char string_to_sign[8192];
  uint8_t signing_key[M3_SIGV4_SECRET_KEY_SIZE];
  uint8_t signature[M3_SIGV4_SECRET_KEY_SIZE];
  char signature_hex[65];
  uint8_t expected[M3_SIGV4_SECRET_KEY_SIZE];

  rc = m3_sigv4_resolve_credential(ctx->scope_access_key, ctx->credential, ctx->resolver,
                                   ctx->resolver_context, &cred);
  if (rc != M3_SIGV4_OK)
    return rc;
  if (strcmp(ctx->scope_region, cred.region) != 0 ||
      strcmp(ctx->scope_service, cred.service) != 0 ||
      strcmp(ctx->scope_terminator, M3_SIGV4_TERMINATOR) != 0) {
    return M3_SIGV4_BAD_SIGNATURE;
  }

  /* Time window. */
  if (parse_amzdate(ctx->amzdate, &amzdate_epoch) != 0) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  skew =
      cred.clock_skew_seconds > 0 ? cred.clock_skew_seconds : M3_SIGV4_DEFAULT_CLOCK_SKEW_SECONDS;
  if (ctx->expires_seconds > 0) {
    if (ctx->now_seconds > amzdate_epoch + ctx->expires_seconds ||
        ctx->now_seconds < amzdate_epoch - skew) {
      return M3_SIGV4_EXPIRED;
    }
  } else {
    int64_t delta = amzdate_epoch - ctx->now_seconds;
    if (delta < 0)
      delta = -delta;
    if (delta > skew)
      return M3_SIGV4_EXPIRED;
  }

  /* Canonical request. */
  if (uri_encode(ctx->canonical_uri, 0, canonical_uri_enc, sizeof(canonical_uri_enc)) != 0) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  if (canonical_query_build(ctx->raw_query, ctx->exclude_query_name, canonical_query,
                            sizeof(canonical_query)) != 0) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  if (build_canonical_headers(ctx->signed_headers, ctx->lookup, ctx->lookup_context,
                              canonical_headers, sizeof(canonical_headers)) != 0) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  if (strlen(ctx->signed_headers) >= sizeof(signed_headers)) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  strcpy(signed_headers, ctx->signed_headers);

  {
    const char *payload_hash = ctx->payload_hash;
    int n;
    if (!payload_hash) {
      payload_hash = ctx->lookup ? ctx->lookup(ctx->lookup_context, "x-amz-content-sha256") : NULL;
      if (!payload_hash || payload_hash[0] == '\0') {
        return M3_SIGV4_MALFORMED_AUTH;
      }
    }
    n = snprintf(canonical_request, sizeof(canonical_request), "%s\n%s\n%s\n%s%s\n%s", ctx->method,
                 canonical_uri_enc, canonical_query, canonical_headers, signed_headers,
                 payload_hash);
    if (n < 0 || (size_t)n >= sizeof(canonical_request)) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
  }
  if (turbo_crypto_sha256(canonical_request, strlen(canonical_request), canonical_digest) !=
      TURBO_CRYPTO_OK) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  hex_encode(canonical_digest, sizeof(canonical_digest), canonical_digest_hex);

  {
    char scope[192];
    int n;
    snprintf(scope, sizeof(scope), "%s/%s/%s/%s", ctx->scope_date, ctx->scope_region,
             ctx->scope_service, ctx->scope_terminator);
    n = snprintf(string_to_sign, sizeof(string_to_sign), "%s\n%s\n%s\n%s", M3_SIGV4_ALGORITHM,
                 ctx->amzdate, scope, canonical_digest_hex);
    if (n < 0 || (size_t)n >= sizeof(string_to_sign)) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
  }

  /* Signing key = HMAC chain over date/region/service. */
  {
    uint8_t first[32];
    uint8_t buf[36];

    memcpy(buf, "AWS4", 4u);
    memcpy(buf + 4u, cred.secret_key, M3_SIGV4_SECRET_KEY_SIZE);
    if (turbo_crypto_hmac_sha256(buf, sizeof(buf), ctx->scope_date, 8u, first) != TURBO_CRYPTO_OK) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
    if (turbo_crypto_hmac_sha256(first, sizeof(first), ctx->scope_region, strlen(ctx->scope_region),
                                 signing_key) != TURBO_CRYPTO_OK) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
    if (turbo_crypto_hmac_sha256(signing_key, sizeof(signing_key), ctx->scope_service,
                                 strlen(ctx->scope_service), signing_key) != TURBO_CRYPTO_OK) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
    if (turbo_crypto_hmac_sha256(signing_key, sizeof(signing_key), M3_SIGV4_TERMINATOR,
                                 sizeof(M3_SIGV4_TERMINATOR) - 1u,
                                 signing_key) != TURBO_CRYPTO_OK) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
  }
  if (turbo_crypto_hmac_sha256(signing_key, sizeof(signing_key), string_to_sign,
                               strlen(string_to_sign), signature) != TURBO_CRYPTO_OK) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  hex_encode(signature, sizeof(signature), signature_hex);

  if (hex_decode(ctx->signature_hex, strlen(ctx->signature_hex), expected, sizeof(expected)) != 0) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  if (turbo_crypto_verify(expected, signature, sizeof(expected)) != TURBO_CRYPTO_OK) {
    return M3_SIGV4_BAD_SIGNATURE;
  }
  return M3_SIGV4_OK;
}

m3_sigv4_result_t m3_sigv4_sign_request_v1(
    const char *method, const char *canonical_uri, const char *raw_query,
    const char *payload_hash, const uint8_t secret_key[32], const char *access_key,
    const char *region, const char *service, const char *host, const char *amzdate,
    char *authorization_out, size_t cap) {
  char canonical_request[4096];
  char canonical_headers[1024];
  char string_to_sign[2048];
  char scope[192];
  char date[9];
  uint8_t canonical_digest[32];
  char canonical_digest_hex[65];
  uint8_t signing_key[32];
  uint8_t signature[32];
  char signature_hex[65];
  int n;

  if (!method || !canonical_uri || !payload_hash || !secret_key || !access_key ||
      !region || !service || !host || !amzdate || !authorization_out) {
    return M3_SIGV4_INVALID_ARG;
  }
  if (strlen(amzdate) < 8)
    return M3_SIGV4_MALFORMED_AUTH;
  memcpy(date, amzdate, 8);
  date[8] = '\0';
  n = snprintf(canonical_headers, sizeof(canonical_headers),
               "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host,
               payload_hash, amzdate);
  if (n < 0 || (size_t)n >= sizeof(canonical_headers))
    return M3_SIGV4_MALFORMED_AUTH;
  n = snprintf(canonical_request, sizeof(canonical_request), "%s\n%s\n%s\n%shost;x-amz-content-sha256;x-amz-date\n%s",
               method, canonical_uri, raw_query ? raw_query : "", canonical_headers,
               payload_hash);
  if (n < 0 || (size_t)n >= sizeof(canonical_request))
    return M3_SIGV4_MALFORMED_AUTH;
  if (turbo_crypto_sha256((const uint8_t *)canonical_request,
                          strlen(canonical_request), canonical_digest) !=
      TURBO_CRYPTO_OK) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  hex_encode(canonical_digest, sizeof(canonical_digest), canonical_digest_hex);
  n = snprintf(scope, sizeof(scope), "%s/%s/%s/%s", date, region, service,
               M3_SIGV4_TERMINATOR);
  if (n < 0 || (size_t)n >= sizeof(scope))
    return M3_SIGV4_MALFORMED_AUTH;
  n = snprintf(string_to_sign, sizeof(string_to_sign), "%s\n%s\n%s\n%s",
               M3_SIGV4_ALGORITHM, amzdate, scope, canonical_digest_hex);
  if (n < 0 || (size_t)n >= sizeof(string_to_sign))
    return M3_SIGV4_MALFORMED_AUTH;

  /* Signing key = HMAC chain over date/region/service/terminator. */
  {
    uint8_t first[32];
    uint8_t buf[36];
    const uint8_t aws4[] = "AWS4";

    memcpy(buf, aws4, 4);
    memcpy(buf + 4, secret_key, 32);
    if (turbo_crypto_hmac_sha256(buf, sizeof(buf), date, 8u, first) !=
        TURBO_CRYPTO_OK ||
        turbo_crypto_hmac_sha256(first, sizeof(first), region, strlen(region),
                                 signing_key) != TURBO_CRYPTO_OK) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
    if (turbo_crypto_hmac_sha256(signing_key, sizeof(signing_key), service,
                                 strlen(service), first) != TURBO_CRYPTO_OK ||
        turbo_crypto_hmac_sha256(first, sizeof(first), M3_SIGV4_TERMINATOR,
                                 strlen(M3_SIGV4_TERMINATOR), signing_key) !=
            TURBO_CRYPTO_OK) {
      return M3_SIGV4_MALFORMED_AUTH;
    }
  }
  if (turbo_crypto_hmac_sha256(signing_key, sizeof(signing_key), string_to_sign,
                               strlen(string_to_sign), signature) !=
      TURBO_CRYPTO_OK) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  hex_encode(signature, sizeof(signature), signature_hex);
  n = snprintf(authorization_out, cap,
               "%s Credential=%s/%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s",
               M3_SIGV4_ALGORITHM, access_key, scope, signature_hex);
  if (n < 0 || (size_t)n >= cap)
    return M3_SIGV4_MALFORMED_AUTH;
  return M3_SIGV4_OK;
}

m3_sigv4_result_t m3_sigv4_verify_request_ex_v1(const m3_sigv4_credential_v1_t *credential,
                                                m3_sigv4_credential_resolver_fn resolver,
                                                void *resolver_context, const char *method,
                                                const char *canonical_uri, const char *raw_query,
                                                const char *authorization, const char *x_amz_date,
                                                const char *date, m3_sigv4_header_lookup_fn lookup,
                                                void *lookup_context, int64_t now_seconds) {
  parsed_auth_t auth;
  char scope_copy[256];
  char *slash[5];
  int scope_parts = 0;
  char *token;
  const char *amzdate;
  m3_sigv4_verify_context_t ctx;

  if (!method || !canonical_uri || !authorization) {
    return M3_SIGV4_INVALID_ARG;
  }
  if (!resolver) {
    if (!credential || !credential->access_key[0] || !credential->region || !credential->service) {
      return M3_SIGV4_INVALID_ARG;
    }
  }
  if (auth_parse(authorization, &auth) != 0) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  if (strcmp(auth.algorithm, M3_SIGV4_ALGORITHM) != 0) {
    return M3_SIGV4_UNSUPPORTED_ALGORITHM;
  }

  /* Credential: <access-key>/<date>/<region>/<service>/aws4_request */
  if (strlen(auth.credential) >= sizeof(scope_copy)) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  strcpy(scope_copy, auth.credential);
  token = strtok(scope_copy, "/");
  while (token && scope_parts < 5) {
    slash[scope_parts++] = token;
    token = strtok(NULL, "/");
  }
  if (scope_parts != 5)
    return M3_SIGV4_MALFORMED_AUTH;

  amzdate = x_amz_date ? x_amz_date : date;

  memset(&ctx, 0, sizeof(ctx));
  ctx.method = method;
  ctx.canonical_uri = canonical_uri;
  ctx.raw_query = raw_query;
  ctx.exclude_query_name = NULL;
  ctx.amzdate = amzdate;
  ctx.scope_access_key = slash[0];
  ctx.scope_date = slash[1];
  ctx.scope_region = slash[2];
  ctx.scope_service = slash[3];
  ctx.scope_terminator = slash[4];
  ctx.signed_headers = auth.signed_headers;
  ctx.payload_hash = NULL; /* resolved from x-amz-content-sha256 via lookup */
  ctx.signature_hex = auth.signature_hex;
  ctx.lookup = lookup;
  ctx.lookup_context = lookup_context;
  ctx.now_seconds = now_seconds;
  ctx.expires_seconds = 0;
  ctx.credential = credential;
  ctx.resolver = resolver;
  ctx.resolver_context = resolver_context;

  return m3_sigv4_verify_core(&ctx);
}

m3_sigv4_result_t m3_sigv4_verify_request_v1(const m3_sigv4_credential_v1_t *credential,
                                             const char *method, const char *canonical_uri,
                                             const char *raw_query, const char *authorization,
                                             const char *x_amz_date, const char *date,
                                             m3_sigv4_header_lookup_fn lookup, void *lookup_context,
                                             int64_t now_seconds) {
  return m3_sigv4_verify_request_ex_v1(credential, NULL, NULL, method, canonical_uri, raw_query,
                                       authorization, x_amz_date, date, lookup, lookup_context,
                                       now_seconds);
}

m3_sigv4_result_t m3_sigv4_verify_presigned_v1(const m3_sigv4_credential_v1_t *credential,
                                               m3_sigv4_credential_resolver_fn resolver,
                                               void *resolver_context, const char *method,
                                               const char *canonical_uri, const char *raw_query,
                                               m3_sigv4_header_lookup_fn lookup,
                                               void *lookup_context, int64_t now_seconds) {
  presigned_query_t params;
  char scope_copy[256];
  char *slash[5];
  int scope_parts = 0;
  char *token;
  char *end;
  long long expires;
  m3_sigv4_verify_context_t ctx;

  if (!method || !canonical_uri || !raw_query) {
    return M3_SIGV4_INVALID_ARG;
  }
  if (!credential && !resolver) {
    return M3_SIGV4_INVALID_ARG;
  }
  if (presigned_query_parse(raw_query, &params) != 0) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  if (strcmp(params.algorithm, M3_SIGV4_ALGORITHM) != 0) {
    return M3_SIGV4_UNSUPPORTED_ALGORITHM;
  }
  if (strlen(params.credential) >= sizeof(scope_copy)) {
    return M3_SIGV4_MALFORMED_AUTH;
  }
  strcpy(scope_copy, params.credential);
  token = strtok(scope_copy, "/");
  while (token && scope_parts < 5) {
    slash[scope_parts++] = token;
    token = strtok(NULL, "/");
  }
  if (scope_parts != 5)
    return M3_SIGV4_MALFORMED_AUTH;

  expires = strtoll(params.expires, &end, 10);
  if (end == params.expires || *end != '\0' || expires <= 0 ||
      expires > (long long)M3_SIGV4_EXPIRES_MAX_SECONDS) {
    return M3_SIGV4_MALFORMED_AUTH;
  }

  memset(&ctx, 0, sizeof(ctx));
  ctx.method = method;
  ctx.canonical_uri = canonical_uri;
  ctx.raw_query = raw_query;
  ctx.exclude_query_name = "X-Amz-Signature";
  ctx.amzdate = params.amzdate;
  ctx.scope_access_key = slash[0];
  ctx.scope_date = slash[1];
  ctx.scope_region = slash[2];
  ctx.scope_service = slash[3];
  ctx.scope_terminator = slash[4];
  ctx.signed_headers = params.signed_headers;
  ctx.payload_hash = "UNSIGNED-PAYLOAD";
  ctx.signature_hex = params.signature_hex;
  ctx.lookup = lookup;
  ctx.lookup_context = lookup_context;
  ctx.now_seconds = now_seconds;
  ctx.expires_seconds = (int64_t)expires;
  ctx.credential = credential;
  ctx.resolver = resolver;
  ctx.resolver_context = resolver_context;

  return m3_sigv4_verify_core(&ctx);
}
