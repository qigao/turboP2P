/**
 * @file tunnel_socks5.c
 * @brief SOCKS5 protocol implementation (RFC 1928)
 */

#include "../core/tunnel_types.h"
#include "tunnel_proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* =============================================================================
 * SOCKS5 Constants
 * ============================================================================= */

#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NOACCEPTABLE 0xFF

#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOC 0x03

#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAIL 0x01
#define SOCKS5_REP_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONN_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_CMD_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ATYP_NOT_SUPPORTED 0x08

/* Username/Password Auth version */
#define SOCKS5_USERPASS_VERSION 0x01

/* =============================================================================
 * SOCKS5 Handshake - Build Greeting
 * ============================================================================= */

int tunnel_socks5_build_greeting(tunnel_proxy_conn_t *conn, uint8_t *buf, size_t *len) {
  if (!conn || !buf || !len)
    return TUNNEL_ERR_INVALID_ARG;

  tunnel_proxy_t *proxy = conn->proxy;
  int has_auth = proxy->username[0] != '\0';

  buf[0] = SOCKS5_VERSION;

  if (has_auth) {
    buf[1] = 2; /* Two methods */
    buf[2] = SOCKS5_AUTH_NONE;
    buf[3] = SOCKS5_AUTH_USERPASS;
    *len = 4;
  } else {
    buf[1] = 1; /* One method */
    buf[2] = SOCKS5_AUTH_NONE;
    *len = 3;
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 Handshake - Parse Greeting Response
 * ============================================================================= */

int tunnel_socks5_parse_greeting_response(const uint8_t *data, size_t len, uint8_t *method) {
  if (!data || !method || len < 2) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  if (data[0] != SOCKS5_VERSION) {
    return TUNNEL_ERR_PROXY_CONNECT;
  }

  *method = data[1];
  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 Handshake
 * ============================================================================= */


/* =============================================================================
 * SOCKS5 Authentication - Build Request
 * ============================================================================= */

int tunnel_socks5_build_auth_request(tunnel_proxy_t *proxy, uint8_t *buf, size_t *len) {
  if (!proxy || !buf || !len)
    return TUNNEL_ERR_INVALID_ARG;

  size_t user_len = strlen(proxy->username);
  size_t pass_len = strlen(proxy->password);

  if (user_len > 255 || pass_len > 255) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  buf[0] = SOCKS5_USERPASS_VERSION;
  buf[1] = (uint8_t)user_len;
  memcpy(&buf[2], proxy->username, user_len);
  buf[2 + user_len] = (uint8_t)pass_len;
  memcpy(&buf[3 + user_len], proxy->password, pass_len);

  *len = 3 + user_len + pass_len;
  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 Authentication - Parse Response
 * ============================================================================= */

int tunnel_socks5_parse_auth_response(const uint8_t *data, size_t len) {
  if (!data || len < 2) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  if (data[0] != SOCKS5_USERPASS_VERSION) {
    return TUNNEL_ERR_PROXY_AUTH;
  }

  if (data[1] != 0x00) {
    return TUNNEL_ERR_PROXY_AUTH;
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 Authenticate
 * ============================================================================= */


/* =============================================================================
 * SOCKS5 Connect - Build Request
 * ============================================================================= */

int tunnel_socks5_build_connect_request(const char *host, int port, int use_domain, uint8_t *buf,
                                        size_t *len) {
  if (!host || !host[0] || !buf || !len || port < 1 || port > UINT16_MAX)
    return TUNNEL_ERR_INVALID_ARG;

  buf[0] = SOCKS5_VERSION;
  buf[1] = SOCKS5_CMD_CONNECT;
  buf[2] = 0x00; /* Reserved */

  size_t offset = 3;

  struct in6_addr ipv6;
  if (inet_pton(AF_INET6, host, &ipv6) == 1) {
    buf[offset++] = SOCKS5_ATYP_IPV6;
    memcpy(buf + offset, &ipv6, sizeof(ipv6));
    offset += sizeof(ipv6);
  } else if (use_domain) {
    /* Domain name */
    size_t host_len = strlen(host);
    if (host_len > 255) {
      return TUNNEL_ERR_INVALID_ARG;
    }

    buf[offset++] = SOCKS5_ATYP_DOMAIN;
    buf[offset++] = (uint8_t)host_len;
    memcpy(&buf[offset], host, host_len);
    offset += host_len;
  } else {
    /* IPv4 address */
    buf[offset++] = SOCKS5_ATYP_IPV4;

    struct in_addr ipv4;
    if (inet_pton(AF_INET, host, &ipv4) != 1) return TUNNEL_ERR_INVALID_ARG;
    memcpy(buf + offset, &ipv4, sizeof(ipv4));
    offset += sizeof(ipv4);
  }

  /* Port (network byte order) */
  buf[offset++] = (port >> 8) & 0xFF;
  buf[offset++] = port & 0xFF;

  *len = offset;
  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 Connect - Parse Response
 * ============================================================================= */

int tunnel_socks5_parse_connect_response(const uint8_t *data, size_t len, uint8_t *rep,
                                         tunnel_endpoint_t *bind_addr) {
  if (!data || !rep || len < 4) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  if (data[0] != SOCKS5_VERSION || data[2] != 0u) return TUNNEL_ERR_PROXY_CONNECT;
  size_t required;
  if (data[3] == SOCKS5_ATYP_IPV4) required = 10u;
  else if (data[3] == SOCKS5_ATYP_IPV6) required = 22u;
  else if (data[3] == SOCKS5_ATYP_DOMAIN && len >= 5u && data[4]) required = 7u + data[4];
  else return TUNNEL_ERR_PROXY_CONNECT;
  if (len < required) return TUNNEL_ERR_INVALID_ARG;

  *rep = data[1];

  if (bind_addr) {
    uint8_t atyp = data[3];

    if (atyp == SOCKS5_ATYP_IPV4) {
      bind_addr->family = AF_INET;
      memcpy(&bind_addr->addr.v4, &data[4], 4);
      bind_addr->port = (data[8] << 8) | data[9];
    } else if (atyp == SOCKS5_ATYP_IPV6 && len >= 22) {
      bind_addr->family = AF_INET6;
      memcpy(bind_addr->addr.v6, &data[4], 16);
      bind_addr->port = (data[20] << 8) | data[21];
    } else {
      memset(bind_addr, 0, sizeof(*bind_addr));
    }
  }

  if (*rep != SOCKS5_REP_SUCCESS) {
    return TUNNEL_ERR_PROXY_REFUSED;
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 Connect
 * ============================================================================= */


/* =============================================================================
 * SOCKS5 UDP Associate - Build Request
 * ============================================================================= */

int tunnel_socks5_build_udp_associate_request(uint8_t *buf, size_t *len) {
  if (!buf || !len)
    return TUNNEL_ERR_INVALID_ARG;

  buf[0] = SOCKS5_VERSION;
  buf[1] = SOCKS5_CMD_UDP_ASSOC;
  buf[2] = 0x00; /* Reserved */
  buf[3] = SOCKS5_ATYP_IPV4;

  /* Use 0.0.0.0:0 to let server choose */
  buf[4] = 0x00;
  buf[5] = 0x00;
  buf[6] = 0x00;
  buf[7] = 0x00;
  buf[8] = 0x00;
  buf[9] = 0x00;

  *len = 10;
  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 UDP Associate
 * ============================================================================= */


/* =============================================================================
 * SOCKS5 UDP Wrap/Unwrap
 * ============================================================================= */

int tunnel_socks5_wrap_udp(tunnel_proxy_conn_t *conn, const tunnel_endpoint_t *dst,
                           const uint8_t *data, size_t len, uint8_t *out, size_t *out_len) {
  if (!conn || !dst || !data || !out || !out_len) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  size_t header_len;

  /* RSV (2 bytes) + FRAG (1 byte) */
  out[0] = 0x00;
  out[1] = 0x00;
  out[2] = 0x00; /* No fragmentation */

  if (dst->family == AF_INET) {
    out[3] = SOCKS5_ATYP_IPV4;
    memcpy(&out[4], &dst->addr.v4, 4);
    out[8] = (dst->port >> 8) & 0xFF;
    out[9] = dst->port & 0xFF;
    header_len = 10;
  } else {
    out[3] = SOCKS5_ATYP_IPV6;
    memcpy(&out[4], dst->addr.v6, 16);
    out[20] = (dst->port >> 8) & 0xFF;
    out[21] = dst->port & 0xFF;
    header_len = 22;
  }

  /* Copy data */
  memcpy(out + header_len, data, len);
  *out_len = header_len + len;

  return TUNNEL_OK;
}

int tunnel_socks5_unwrap_udp(const uint8_t *data, size_t len, tunnel_endpoint_t *src,
                             const uint8_t **payload, size_t *payload_len) {
  if (!data || !payload || !payload_len || len < 10) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Skip RSV and FRAG */
  uint8_t atyp = data[3];
  size_t header_len;

  if (src) {
    memset(src, 0, sizeof(*src));
  }

  if (atyp == SOCKS5_ATYP_IPV4) {
    if (src) {
      src->family = AF_INET;
      memcpy(&src->addr.v4, &data[4], 4);
      src->port = (data[8] << 8) | data[9];
    }
    header_len = 10;
  } else if (atyp == SOCKS5_ATYP_IPV6) {
    if (len < 22) {
      return TUNNEL_ERR_INVALID_ARG;
    }
    if (src) {
      src->family = AF_INET6;
      memcpy(src->addr.v6, &data[4], 16);
      src->port = (data[20] << 8) | data[21];
    }
    header_len = 22;
  } else if (atyp == SOCKS5_ATYP_DOMAIN) {
    uint8_t domain_len = data[4];
    header_len = 5 + domain_len + 2;
    if (len < header_len) {
      return TUNNEL_ERR_INVALID_ARG;
    }
    if (src) {
      src->family = AF_INET;
      src->port = (data[5 + domain_len] << 8) | data[6 + domain_len];
    }
  } else {
    return TUNNEL_ERR_INVALID_ARG;
  }

  *payload = data + header_len;
  *payload_len = len - header_len;

  return TUNNEL_OK;
}

/* =============================================================================
 * SOCKS5 Error to String
 * ============================================================================= */

const char *tunnel_socks5_error_string(uint8_t rep) {
  switch (rep) {
  case SOCKS5_REP_SUCCESS:
    return "Success";
  case SOCKS5_REP_GENERAL_FAIL:
    return "General SOCKS server failure";
  case SOCKS5_REP_NOT_ALLOWED:
    return "Connection not allowed by ruleset";
  case SOCKS5_REP_NETWORK_UNREACHABLE:
    return "Network unreachable";
  case SOCKS5_REP_HOST_UNREACHABLE:
    return "Host unreachable";
  case SOCKS5_REP_CONN_REFUSED:
    return "Connection refused";
  case SOCKS5_REP_TTL_EXPIRED:
    return "TTL expired";
  case SOCKS5_REP_CMD_NOT_SUPPORTED:
    return "Command not supported";
  case SOCKS5_REP_ATYP_NOT_SUPPORTED:
    return "Address type not supported";
  default:
    return "Unknown error";
  }
}
