#ifndef M3_GATEWAY_SIGV4_H
#define M3_GATEWAY_SIGV4_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define M3_SIGV4_ACCESS_KEY_MAX 128u
#define M3_SIGV4_SECRET_KEY_SIZE 32u
#define M3_SIGV4_DEFAULT_CLOCK_SKEW_SECONDS 900

typedef enum {
  M3_SIGV4_OK = 0,
  M3_SIGV4_INVALID_ARG = -1,
  M3_SIGV4_MALFORMED_AUTH = -2,
  M3_SIGV4_UNSUPPORTED_ALGORITHM = -3,
  M3_SIGV4_UNKNOWN_ACCESS_KEY = -4,
  M3_SIGV4_EXPIRED = -5,
  M3_SIGV4_BAD_SIGNATURE = -6,
} m3_sigv4_result_t;

/**
 * One server-side SigV4 credential. Phase 1 supports a single configured
 * access key; the secret key is 32 bytes and must be wiped by the owner.
 */
typedef struct {
  char access_key[M3_SIGV4_ACCESS_KEY_MAX];
  uint8_t secret_key[M3_SIGV4_SECRET_KEY_SIZE];
  const char *region;         /* e.g. "us-east-1" */
  const char *service;        /* e.g. "s3" */
  int64_t clock_skew_seconds; /* <=0 uses M3_SIGV4_DEFAULT_CLOCK_SKEW_SECONDS */
} m3_sigv4_credential_v1_t;

/**
 * Header lookup callback used to rebuild canonical headers for the signed
 * header set. name is lower-case; return the raw header value or NULL.
 */
typedef const char *(*m3_sigv4_header_lookup_fn)(void *context, const char *name);

/**
 * Verify an AWS Signature Version 4 Authorization header (server side).
 *
 * canonical_uri must be the already-normalized path (e.g. "/bucket/object").
 * raw_query is the original query string without '?' (may be NULL/empty).
 * x_amz_date/date are header values (at least one must be present).
 * now_seconds is the current UTC epoch for the clock-skew window.
 */
/**
 * Credential resolver for multi-credential deployments. Called with the
 * access key from the request scope; fills out_credential (secret, region,
 * service, skew) and returns 0 on success. NULL resolver keeps single
 * credential behavior.
 */
typedef int (*m3_sigv4_credential_resolver_fn)(void *context, const char *access_key,
                                               m3_sigv4_credential_v1_t *out_credential);

/**
 * Verify an AWS Signature Version 4 presigned URL.
 *
 * The signature is carried in the query string (X-Amz-* parameters) instead
 * of the Authorization header; raw_query must contain those parameters.
 * X-Amz-Expires bounds the validity window. lookup is still used for the
 * "host" header value (signed via X-Amz-SignedHeaders).
 */
m3_sigv4_result_t m3_sigv4_verify_presigned_v1(const m3_sigv4_credential_v1_t *credential,
                                               m3_sigv4_credential_resolver_fn resolver,
                                               void *resolver_context, const char *method,
                                               const char *canonical_uri, const char *raw_query,
                                               m3_sigv4_header_lookup_fn lookup,
                                               void *lookup_context, int64_t now_seconds);
/**
 * Verify an AWS Signature Version 4 Authorization header, resolving the
 * credential from either a single configured credential or a resolver.
 *
 * When resolver is non-NULL it is called with the access key from the
 * request scope and the returned secret/region/service/skew are used;
 * credential may be NULL in that case. Otherwise credential must be
 * non-NULL and the request scope access key must match it. All other
 * parameters and semantics match m3_sigv4_verify_request_v1.
 */
m3_sigv4_result_t m3_sigv4_verify_request_ex_v1(const m3_sigv4_credential_v1_t *credential,
                                                m3_sigv4_credential_resolver_fn resolver,
                                                void *resolver_context, const char *method,
                                                const char *canonical_uri, const char *raw_query,
                                                const char *authorization, const char *x_amz_date,
                                                const char *date, m3_sigv4_header_lookup_fn lookup,
                                                void *lookup_context, int64_t now_seconds);
m3_sigv4_result_t m3_sigv4_sign_request_v1(
    const char *method, const char *canonical_uri, const char *raw_query,
    const char *payload_hash, const uint8_t secret_key[32], const char *access_key,
    const char *region, const char *service, const char *host, const char *amzdate,
    char *authorization_out, size_t cap);

m3_sigv4_result_t m3_sigv4_verify_request_v1(const m3_sigv4_credential_v1_t *credential,
                                             const char *method, const char *canonical_uri,
                                             const char *raw_query, const char *authorization,
                                             const char *x_amz_date, const char *date,
                                             m3_sigv4_header_lookup_fn lookup, void *lookup_context,
                                             int64_t now_seconds);

#ifdef __cplusplus
}
#endif

#endif
