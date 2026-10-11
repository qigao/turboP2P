#ifndef MESHCTL_RPC_HTTP_H
#define MESHCTL_RPC_HTTP_H

#include <http_client/http.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESHD_CTL_RPC_ADDR_DEFAULT "127.0.0.1:7878"
#define MESHD_CTL_RPC_PORT_DEFAULT 7878
#define MESHD_CTL_RPC_TIMEOUT_MS 5000u
#define MESHD_CTL_RPC_MAX_RESPONSE_SIZE (1024u * 1024u)
#define MESHD_CTL_RPC_MAX_HEADER_SIZE (32u * 1024u)
#define MESHD_CTL_RPC_URL_MAX 512u
#define MESHD_CTL_RPC_TOKEN_HEADER_MAX 256u

/* Private CLI contracts; no installed ABI. Outputs are caller-owned storage. */
int meshctl_build_rpc_node_addr(const char *node, char *out, size_t out_size);
int meshctl_build_rpc_resolve_path(const char *node_id, char *out, size_t out_size);
int meshctl_rpc_token_is_valid(const char *token);

/* One blocking, bodyless H1 GET/POST; no redirects or retries. client and
 * response must be zero-initialized. The caller owns both on every return and
 * must destroy response, then client. A failed/timed-out client destroy retains
 * the owner for retry. Only the calling thread drives progress. HTTP status is
 * returned in response, including 3xx/4xx/5xx, as in the existing CLI. */
int meshctl_rpc_http_request(chttp_client *client, const char *addr,
                             const char *path, const char *method,
                             const char *token, chttp_response *response,
                             chttp_error *error);

/* CLI rendering and error consumption; returns the existing 0/1 exit status. */
int meshctl_rpc_send(const char *addr, const char *path, const char *method,
                     const char *token, int print_raw);

#ifdef __cplusplus
}
#endif

#endif
