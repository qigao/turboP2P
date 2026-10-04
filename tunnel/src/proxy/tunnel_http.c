/**
 * @file tunnel_http.c
 * @brief HTTP CONNECT proxy implementation (RFC 7231)
 */

#include "../core/tunnel_types.h"
#include "tunnel_proxy.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fmt.h>

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

/* =============================================================================
 * Base64 Encoding for Basic Auth
 * ============================================================================= */

static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_len) {
  size_t i, j;
  size_t out_len = 4 * ((src_len + 2) / 3);

  if (dst_len < out_len + 1) {
    return 0;
  }

  for (i = 0, j = 0; i < src_len;) {
    uint32_t a = i < src_len ? src[i++] : 0;
    uint32_t b = i < src_len ? src[i++] : 0;
    uint32_t c = i < src_len ? src[i++] : 0;
    uint32_t triple = (a << 16) | (b << 8) | c;

    dst[j++] = base64_table[(triple >> 18) & 0x3F];
    dst[j++] = base64_table[(triple >> 12) & 0x3F];
    dst[j++] = base64_table[(triple >> 6) & 0x3F];
    dst[j++] = base64_table[triple & 0x3F];
  }

  /* Padding */
  size_t mod = src_len % 3;
  if (mod > 0) {
    dst[out_len - 1] = '=';
    if (mod == 1) {
      dst[out_len - 2] = '=';
    }
  }

  dst[out_len] = '\0';
  return out_len;
}

/* =============================================================================
 * HTTP CONNECT - Build Request
 * ============================================================================= */

int tunnel_http_build_connect_request(const char *host, int port, const char *username,
                                      const char *password, uint8_t *buf, size_t *len,
                                      size_t buf_size) {
  if (!host || !host[0] || !buf || !len || port < 1 || port > UINT16_MAX)
    return TUNNEL_ERR_INVALID_ARG;

  char authority[512];
  for (const unsigned char *p = (const unsigned char *)host; *p; ++p)
    if (*p <= ' ' || *p == 127u || strchr("/@?#[]", *p)) return TUNNEL_ERR_INVALID_ARG;
  int count = snprintf(authority, sizeof(authority), strchr(host, ':') ? "[%s]:%d" : "%s:%d", host, port);
  if (count < 0 || (size_t)count >= sizeof(authority)) return TUNNEL_ERR_INVALID_ARG;
  char auth_header[512] = "";

  /* Build Basic auth header if credentials provided */
  if (username && username[0] != '\0') {
    char credentials[256];
    const char *password_value = password ? password : "";
    size_t username_len = strlen(username);
    size_t password_len = strlen(password_value);

    if (username_len > sizeof(credentials) - 2 ||
        password_len > sizeof(credentials) - 2 - username_len) {
      return TUNNEL_ERR_INVALID_ARG;
    }
    fmt(credentials, sizeof(credentials), "{}:{}", username, password_value);

    char encoded[512];
    base64_encode((const uint8_t *)credentials, strlen(credentials), encoded, sizeof(encoded));

    fmt(auth_header, sizeof(auth_header), "Proxy-Authorization: Basic {}\r\n", encoded);
  }

  /* Build CONNECT request */
  tstr request = tstr_format(
      "CONNECT {} HTTP/1.1\r\n"
      "Host: {}\r\n"
      "{}"
      "User-Agent: TurboTunnel/1.0\r\n"
      "Proxy-Connection: Keep-Alive\r\n"
      "\r\n",
      authority, authority, auth_header);
  if (!request) {
    return TUNNEL_ERR_NO_MEMORY;
  }

  size_t request_len = tstr_len(request);
  if (request_len >= buf_size) {
    tstr_free(request);
    return TUNNEL_ERR_INVALID_ARG;
  }

  memcpy(buf, request, request_len + 1);
  tstr_free(request);
  *len = request_len;
  return TUNNEL_OK;
}

/* =============================================================================
 * HTTP Response Parsing
 * ============================================================================= */

int tunnel_http_parse_response_frame(const uint8_t *data, size_t len, size_t *consumed) {
  size_t header_end = 0, line_end = 0;
  int status;
  if (!data || !consumed) return TUNNEL_ERR_INVALID_ARG;
  *consumed = 0;
  for (size_t i = 0; i + 3u < len; ++i) {
    if (!memcmp(data + i, "\r\n\r\n", 4u)) { header_end = i + 4u; break; }
  }
  if (!header_end) return TUNNEL_ERR_TIMEOUT;
  for (size_t i = 0; i + 1u < header_end; ++i) {
    if (data[i] == '\r' && data[i + 1u] == '\n') { line_end = i; break; }
  }
  if (line_end < 12u || memcmp(data, "HTTP/1.", 7u) ||
      (data[7] != '0' && data[7] != '1') || data[8] != ' ' ||
      data[9] < '0' || data[9] > '9' || data[10] < '0' || data[10] > '9' ||
      data[11] < '0' || data[11] > '9' || (line_end > 12u && data[12] != ' '))
    return TUNNEL_ERR_PROXY_CONNECT;
  status = (data[9] - '0') * 100 + (data[10] - '0') * 10 + data[11] - '0';
  if (status != 200) return status == 407 ? TUNNEL_ERR_PROXY_AUTH : TUNNEL_ERR_PROXY_REFUSED;
  *consumed = header_end;
  return TUNNEL_OK;
}

int tunnel_http_parse_response(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len) {
  size_t consumed;
  if (!conn) return TUNNEL_ERR_INVALID_ARG;
  return tunnel_http_parse_response_frame(data, len, &consumed);
}

/* =============================================================================
 * HTTP Status Code to Error
 * ============================================================================= */

int tunnel_http_status_to_error(int status_code) {
  switch (status_code) {
  case 200:
    return TUNNEL_OK;

  case 400: /* Bad Request */
  case 405: /* Method Not Allowed */
    return TUNNEL_ERR_PROXY_CONNECT;

  case 401: /* Unauthorized */
  case 407: /* Proxy Authentication Required */
    return TUNNEL_ERR_PROXY_AUTH;

  case 403: /* Forbidden */
    return TUNNEL_ERR_PROXY_REFUSED;

  case 502: /* Bad Gateway */
  case 503: /* Service Unavailable */
  case 504: /* Gateway Timeout */
    return TUNNEL_ERR_NETWORK;

  default:
    if (status_code >= 400 && status_code < 500) {
      return TUNNEL_ERR_PROXY_REFUSED;
    }
    if (status_code >= 500) {
      return TUNNEL_ERR_NETWORK;
    }
    return TUNNEL_OK;
  }
}

/* =============================================================================
 * HTTP Status Code to String
 * ============================================================================= */

const char *tunnel_http_status_string(int status_code) {
  switch (status_code) {
  case 200:
    return "OK";
  case 400:
    return "Bad Request";
  case 401:
    return "Unauthorized";
  case 403:
    return "Forbidden";
  case 404:
    return "Not Found";
  case 405:
    return "Method Not Allowed";
  case 407:
    return "Proxy Authentication Required";
  case 408:
    return "Request Timeout";
  case 500:
    return "Internal Server Error";
  case 502:
    return "Bad Gateway";
  case 503:
    return "Service Unavailable";
  case 504:
    return "Gateway Timeout";
  default:
    return "Unknown";
  }
}
