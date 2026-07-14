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
  if (!host || !buf || !len)
    return TUNNEL_ERR_INVALID_ARG;

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
  tstr_t request = tstr_format(
      "CONNECT {}:{} HTTP/1.1\r\n"
      "Host: {}:{}\r\n"
      "{}"
      "User-Agent: TurboTunnel/1.0\r\n"
      "Proxy-Connection: Keep-Alive\r\n"
      "\r\n",
      host, port, host, port, auth_header);
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

typedef struct {
  int status_code;
  char status_text[64];
  int content_length;
  int chunked;
  int keep_alive;
  size_t header_len;
} http_response_t;

static int parse_status_line(const char *line, http_response_t *resp) {
  /* HTTP/1.x XXX Status Text */
  if (strncmp(line, "HTTP/1.", 7) != 0) {
    return TUNNEL_ERR_PROXY_CONNECT;
  }

  const char *p = line + 9; /* Skip "HTTP/1.X " */
  while (*p == ' ')
    p++;

  /* Parse status code */
  resp->status_code = atoi(p);
  if (resp->status_code < 100 || resp->status_code > 599) {
    return TUNNEL_ERR_PROXY_CONNECT;
  }

  /* Skip to status text */
  while (*p && *p != ' ')
    p++;
  while (*p == ' ')
    p++;

  /* Copy status text */
  size_t i = 0;
  while (*p && *p != '\r' && *p != '\n' && i < sizeof(resp->status_text) - 1) {
    resp->status_text[i++] = *p++;
  }
  resp->status_text[i] = '\0';

  return TUNNEL_OK;
}

static void parse_header_line(const char *line, http_response_t *resp) {
  /* Content-Length */
  if (strncasecmp(line, "Content-Length:", 15) == 0) {
    resp->content_length = atoi(line + 15);
  }

  /* Transfer-Encoding: chunked */
  if (strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
    const char *p = line + 18;
    while (*p == ' ')
      p++;
    if (strncasecmp(p, "chunked", 7) == 0) {
      resp->chunked = 1;
    }
  }

  /* Connection/Proxy-Connection */
  if (strncasecmp(line, "Connection:", 11) == 0 ||
      strncasecmp(line, "Proxy-Connection:", 17) == 0) {
    const char *p = strchr(line, ':') + 1;
    while (*p == ' ')
      p++;
    if (strncasecmp(p, "keep-alive", 10) == 0) {
      resp->keep_alive = 1;
    }
  }
}

/* =============================================================================
 * HTTP CONNECT - Parse Response
 * ============================================================================= */

int tunnel_http_parse_response(tunnel_proxy_conn_t *conn, const uint8_t *data, size_t len) {
  if (!conn || !data || len < 12) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Find end of headers (\r\n\r\n) */
  const char *headers_end = NULL;
  for (size_t i = 0; i + 3 < len; i++) {
    if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
      headers_end = (const char *)&data[i + 4];
      break;
    }
  }

  if (!headers_end) {
    /* Headers incomplete, need more data */
    return TUNNEL_ERR_TIMEOUT; /* Signal incomplete */
  }

  http_response_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.header_len = headers_end - (const char *)data;

  /* Parse response line by line */
  const char *line_start = (const char *)data;
  const char *line_end;
  int first_line = 1;

  while (line_start < headers_end) {
    line_end = strstr(line_start, "\r\n");
    if (!line_end || line_end >= headers_end) {
      break;
    }

    /* Temporarily null-terminate the line */
    size_t line_len = line_end - line_start;
    char line_buf[1024];
    if (line_len >= sizeof(line_buf)) {
      line_len = sizeof(line_buf) - 1;
    }
    memcpy(line_buf, line_start, line_len);
    line_buf[line_len] = '\0';

    if (first_line) {
      int ret = parse_status_line(line_buf, &resp);
      if (ret != TUNNEL_OK) {
        return ret;
      }
      first_line = 0;
    } else {
      parse_header_line(line_buf, &resp);
    }

    line_start = line_end + 2;
  }

  /* Check for success (200 OK) */
  if (resp.status_code != 200) {
    if (resp.status_code == 407) {
      return TUNNEL_ERR_PROXY_AUTH;
    }
    return TUNNEL_ERR_PROXY_REFUSED;
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * HTTP CONNECT Full Flow
 * ============================================================================= */

int tunnel_http_connect(tunnel_proxy_conn_t *conn, const char *host, int port) {
  if (!conn || !conn->proxy || !host) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  tunnel_proxy_t *proxy = conn->proxy;

  /* Build CONNECT request */
  uint8_t buf[2048];
  size_t len;

  int ret = tunnel_http_build_connect_request(host, port, proxy->username, proxy->password, buf,
                                              &len, sizeof(buf));

  if (ret != TUNNEL_OK) {
    return ret;
  }

  /* TODO: Send via async_client and wait for response */
  (void)buf;
  (void)len;

  return TUNNEL_OK;
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
