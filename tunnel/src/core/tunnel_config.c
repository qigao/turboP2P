/**
 * @file tunnel_config.c
 * @brief Tunnel configuration parsing
 */

#include "tunnel_types.h"
#include "turbo_tunnel.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stb_sprintf.h>


/* =============================================================================
 * CIDR Parsing
 * ============================================================================= */

/**
 * Parse CIDR notation (e.g., "10.0.0.0/8")
 */
int tunnel_config_parse_cidr(const char *cidr, tunnel_ip_addr_t *addr, tunnel_ip_addr_t *mask,
                             int *family) {
  if (!cidr || !addr || !mask || !family) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  char buf[64];
  strncpy(buf, cidr, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  /* Find prefix length separator */
  char *slash = strchr(buf, '/');
  int prefix = 32; /* Default for IPv4 */

  if (slash) {
    *slash = '\0';
    prefix = atoi(slash + 1);
  }

  /* Check for IPv6 */
  if (strchr(buf, ':')) {
    /* IPv6 */
    *family = AF_INET6;

    if (prefix < 0 || prefix > 128) {
      return TUNNEL_ERR_INVALID_ARG;
    }

    /* TODO: Parse IPv6 address */
    return TUNNEL_ERR_NOT_SUPPORTED;
  } else {
    /* IPv4 */
    *family = AF_INET;

    if (prefix < 0 || prefix > 32) {
      return TUNNEL_ERR_INVALID_ARG;
    }

    unsigned int a, b, c, d;
    if (sscanf(buf, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
      return TUNNEL_ERR_INVALID_ARG;
    }

    if (a > 255 || b > 255 || c > 255 || d > 255) {
      return TUNNEL_ERR_INVALID_ARG;
    }

    addr->v4 = htonl((a << 24) | (b << 16) | (c << 8) | d);

    /* Calculate mask from prefix */
    if (prefix == 0) {
      mask->v4 = 0;
    } else {
      mask->v4 = htonl(~((1U << (32 - prefix)) - 1));
    }
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * IP Range Parsing
 * ============================================================================= */

tunnel_route_rule_t *tunnel_config_parse_ip_range(const char *range) {
  if (!range)
    return NULL;

  tunnel_route_rule_t *rule = calloc(1, sizeof(tunnel_route_rule_t));
  if (!rule)
    return NULL;

  rule->type = TUNNEL_ROUTE_IP;

  int ret = tunnel_config_parse_cidr(range, &rule->ip.addr, &rule->ip.mask, &rule->ip.family);
  if (ret != TUNNEL_OK) {
    free(rule);
    return NULL;
  }

  return rule;
}

/* =============================================================================
 * Domain Pattern Parsing
 * ============================================================================= */

tunnel_route_rule_t *tunnel_config_parse_domain(const char *pattern) {
  if (!pattern)
    return NULL;

  tunnel_route_rule_t *rule = calloc(1, sizeof(tunnel_route_rule_t));
  if (!rule)
    return NULL;

  rule->type = TUNNEL_ROUTE_DOMAIN;

  /* Check for wildcard */
  if (pattern[0] == '*' && pattern[1] == '.') {
    rule->domain.wildcard = 1;
    strncpy(rule->domain.pattern, pattern + 2, sizeof(rule->domain.pattern) - 1);
  } else {
    rule->domain.wildcard = 0;
    strncpy(rule->domain.pattern, pattern, sizeof(rule->domain.pattern) - 1);
  }

  /* Normalize to lowercase */
  for (char *p = rule->domain.pattern; *p; p++) {
    *p = tolower((unsigned char)*p);
  }

  return rule;
}

/* =============================================================================
 * Routing Rules
 * ============================================================================= */

int tunnel_config_add_include_range(tunnel_t *tunnel, const char *range) {
  if (!tunnel || !range)
    return TUNNEL_ERR_INVALID_ARG;

  tunnel_route_rule_t *rule = tunnel_config_parse_ip_range(range);
  if (!rule)
    return TUNNEL_ERR_INVALID_ARG;

  rule->action = 1; /* Include */
  rule->next = tunnel->include_rules;
  tunnel->include_rules = rule;

  return TUNNEL_OK;
}

int tunnel_config_add_exclude_range(tunnel_t *tunnel, const char *range) {
  if (!tunnel || !range)
    return TUNNEL_ERR_INVALID_ARG;

  tunnel_route_rule_t *rule = tunnel_config_parse_ip_range(range);
  if (!rule)
    return TUNNEL_ERR_INVALID_ARG;

  rule->action = 0; /* Exclude */
  rule->next = tunnel->exclude_rules;
  tunnel->exclude_rules = rule;

  return TUNNEL_OK;
}

int tunnel_config_add_include_domain(tunnel_t *tunnel, const char *domain) {
  if (!tunnel || !domain)
    return TUNNEL_ERR_INVALID_ARG;

  tunnel_route_rule_t *rule = tunnel_config_parse_domain(domain);
  if (!rule)
    return TUNNEL_ERR_INVALID_ARG;

  rule->action = 1;
  rule->next = tunnel->include_rules;
  tunnel->include_rules = rule;

  return TUNNEL_OK;
}

int tunnel_config_add_exclude_domain(tunnel_t *tunnel, const char *domain) {
  if (!tunnel || !domain)
    return TUNNEL_ERR_INVALID_ARG;

  tunnel_route_rule_t *rule = tunnel_config_parse_domain(domain);
  if (!rule)
    return TUNNEL_ERR_INVALID_ARG;

  rule->action = 0;
  rule->next = tunnel->exclude_rules;
  tunnel->exclude_rules = rule;

  return TUNNEL_OK;
}

/* =============================================================================
 * Configuration Validation
 * ============================================================================= */

int tunnel_config_validate(const tunnel_config_t *config) {
  if (!config)
    return TUNNEL_ERR_INVALID_ARG;

  /* Validate proxy configuration */
  if (config->proxy.type != TUNNEL_PROXY_NONE) {
    if (!config->proxy.host || config->proxy.host[0] == '\0') {
      return TUNNEL_ERR_INVALID_ARG;
    }

    if (config->proxy.port <= 0 || config->proxy.port > 65535) {
      return TUNNEL_ERR_INVALID_ARG;
    }
  }

  /* Validate TUN configuration */
  if (config->tun.mtu < 0 || config->tun.mtu > 65535) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Validate IPv6 prefix */
  if (config->tun.ipv6_addr && config->tun.ipv6_addr[0]) {
    if (config->tun.ipv6_prefix < 0 || config->tun.ipv6_prefix > 128) {
      return TUNNEL_ERR_INVALID_ARG;
    }
  }

  return TUNNEL_OK;
}

/* =============================================================================
 * Simple Key-Value Config Parser
 * ============================================================================= */

typedef struct {
  const char *key;
  size_t key_len;
  const char *value;
  size_t value_len;
} config_kv_t;

static int parse_line(const char *line, config_kv_t *kv) {
  /* Skip whitespace */
  while (*line && isspace((unsigned char)*line))
    line++;

  /* Skip comments and empty lines */
  if (*line == '\0' || *line == '#' || *line == ';') {
    return 0;
  }

  /* Find key */
  kv->key = line;
  while (*line && !isspace((unsigned char)*line) && *line != '=' && *line != ':') {
    line++;
  }
  kv->key_len = line - kv->key;

  /* Skip separator */
  while (*line && (isspace((unsigned char)*line) || *line == '=' || *line == ':')) {
    line++;
  }

  /* Find value */
  kv->value = line;
  kv->value_len = strlen(line);

  /* Trim trailing whitespace */
  while (kv->value_len > 0 && isspace((unsigned char)kv->value[kv->value_len - 1])) {
    kv->value_len--;
  }

  return (kv->key_len > 0 && kv->value_len > 0) ? 1 : 0;
}

static int key_matches(const config_kv_t *kv, const char *key) {
  size_t len = strlen(key);
  return kv->key_len == len && strncmp(kv->key, key, len) == 0;
}

static char *value_dup(const config_kv_t *kv) {
  char *s = malloc(kv->value_len + 1);
  if (s) {
    memcpy(s, kv->value, kv->value_len);
    s[kv->value_len] = '\0';
  }
  return s;
}

/* =============================================================================
 * Config File Parser
 * ============================================================================= */

int tunnel_config_parse_file(const char *path, tunnel_config_t *config) {
  if (!path || !config)
    return TUNNEL_ERR_INVALID_ARG;

  FILE *fp = fopen(path, "r");
  if (!fp) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  /* Initialize with defaults */
  tunnel_config_init(config);

  char line[1024];
  config_kv_t kv;

  /* Temporary storage for strings */
  char *tun_name = NULL;
  char *tun_ipv4 = NULL;
  char *tun_netmask = NULL;
  char *proxy_host = NULL;
  char *proxy_user = NULL;
  char *proxy_pass = NULL;

  while (fgets(line, sizeof(line), fp)) {
    if (!parse_line(line, &kv))
      continue;

    /* TUN settings */
    if (key_matches(&kv, "tun.name")) {
      free(tun_name);
      tun_name = value_dup(&kv);
      config->tun.name = tun_name;
    } else if (key_matches(&kv, "tun.ipv4")) {
      free(tun_ipv4);
      tun_ipv4 = value_dup(&kv);
      config->tun.ipv4_addr = tun_ipv4;
    } else if (key_matches(&kv, "tun.netmask")) {
      free(tun_netmask);
      tun_netmask = value_dup(&kv);
      config->tun.ipv4_netmask = tun_netmask;
    } else if (key_matches(&kv, "tun.mtu")) {
      config->tun.mtu = atoi(kv.value);
    }

    /* Proxy settings */
    else if (key_matches(&kv, "proxy.type")) {
      if (strncmp(kv.value, "socks5", kv.value_len) == 0) {
        config->proxy.type = TUNNEL_PROXY_SOCKS5;
      } else if (strncmp(kv.value, "http", kv.value_len) == 0) {
        config->proxy.type = TUNNEL_PROXY_HTTP;
      } else if (strncmp(kv.value, "shadowsocks", kv.value_len) == 0) {
        config->proxy.type = TUNNEL_PROXY_SHADOWSOCKS;
      } else if (strncmp(kv.value, "none", kv.value_len) == 0) {
        config->proxy.type = TUNNEL_PROXY_NONE;
      }
    } else if (key_matches(&kv, "proxy.host")) {
      free(proxy_host);
      proxy_host = value_dup(&kv);
      config->proxy.host = proxy_host;
    } else if (key_matches(&kv, "proxy.port")) {
      config->proxy.port = atoi(kv.value);
    } else if (key_matches(&kv, "proxy.username")) {
      free(proxy_user);
      proxy_user = value_dup(&kv);
      config->proxy.username = proxy_user;
    } else if (key_matches(&kv, "proxy.password")) {
      free(proxy_pass);
      proxy_pass = value_dup(&kv);
      config->proxy.password = proxy_pass;
    }

    /* UDP mode */
    else if (key_matches(&kv, "udp.mode")) {
      if (strncmp(kv.value, "disabled", kv.value_len) == 0) {
        config->udp_mode = TUNNEL_UDP_DISABLED;
      } else if (strncmp(kv.value, "tcp", kv.value_len) == 0) {
        config->udp_mode = TUNNEL_UDP_OVER_TCP;
      } else if (strncmp(kv.value, "native", kv.value_len) == 0) {
        config->udp_mode = TUNNEL_UDP_NATIVE;
      }
    }

    /* DNS settings */
    else if (key_matches(&kv, "dns.hijack")) {
      config->dns.hijack_dns = (kv.value[0] == '1' || kv.value[0] == 't' || kv.value[0] == 'y');
    } else if (key_matches(&kv, "dns.fake")) {
      config->dns.fake_dns = (kv.value[0] == '1' || kv.value[0] == 't' || kv.value[0] == 'y');
    }

    /* General settings */
    else if (key_matches(&kv, "log.level")) {
      config->log_level = atoi(kv.value);
    } else if (key_matches(&kv, "session.timeout")) {
      config->session_timeout = atoi(kv.value);
    }
  }

  fclose(fp);

  return tunnel_config_validate(config);
}

/* =============================================================================
 * Config String Builder (for debugging)
 * ============================================================================= */

int tunnel_config_to_string(const tunnel_config_t *config, char *buf, size_t buf_len) {
  if (!config || !buf || buf_len < 256)
    return TUNNEL_ERR_INVALID_ARG;

  const char *proxy_types[] = {"none", "socks5", "http", "shadowsocks", "vmess", "trojan"};
  const char *udp_modes[] = {"disabled", "tcp", "native", "fullcone"};

  int written = stbsp_snprintf(
      buf, buf_len,
      "# Tunnel Configuration\n"
      "tun.name = %s\n"
      "tun.ipv4 = %s\n"
      "tun.netmask = %s\n"
      "tun.mtu = %d\n"
      "\n"
      "proxy.type = %s\n"
      "proxy.host = %s\n"
      "proxy.port = %d\n"
      "proxy.username = %s\n"
      "\n"
      "udp.mode = %s\n"
      "dns.hijack = %d\n"
      "dns.fake = %d\n"
      "\n"
      "log.level = %d\n"
      "session.timeout = %d\n",
      config->tun.name ? config->tun.name : "", config->tun.ipv4_addr ? config->tun.ipv4_addr : "",
      config->tun.ipv4_netmask ? config->tun.ipv4_netmask : "", config->tun.mtu,
      proxy_types[config->proxy.type < 6 ? config->proxy.type : 0],
      config->proxy.host ? config->proxy.host : "", config->proxy.port,
      config->proxy.username ? config->proxy.username : "",
      udp_modes[config->udp_mode < 4 ? config->udp_mode : 0], config->dns.hijack_dns,
      config->dns.fake_dns, config->log_level, config->session_timeout);

  return written > 0 ? TUNNEL_OK : TUNNEL_ERR_INVALID_ARG;
}

/* =============================================================================
 * Proxy URL Parser
 * ============================================================================= */

/**
 * Parse proxy URL (e.g., "socks5://user:pass@host:port")
 */
int tunnel_config_parse_proxy_url(const char *url, tunnel_proxy_config_t *proxy) {
  if (!url || !proxy)
    return TUNNEL_ERR_INVALID_ARG;

  memset(proxy, 0, sizeof(*proxy));

  /* Parse scheme */
  const char *p = url;
  const char *scheme_end = strstr(p, "://");

  if (!scheme_end) {
    return TUNNEL_ERR_INVALID_ARG;
  }

  size_t scheme_len = scheme_end - p;

  if (scheme_len == 6 && strncmp(p, "socks5", 6) == 0) {
    proxy->type = TUNNEL_PROXY_SOCKS5;
  } else if (scheme_len == 4 && strncmp(p, "http", 4) == 0) {
    proxy->type = TUNNEL_PROXY_HTTP;
  } else if (scheme_len == 5 && strncmp(p, "https", 5) == 0) {
    proxy->type = TUNNEL_PROXY_HTTP;
    proxy->use_tls = 1;
  } else if (scheme_len == 2 && strncmp(p, "ss", 2) == 0) {
    proxy->type = TUNNEL_PROXY_SHADOWSOCKS;
  } else {
    return TUNNEL_ERR_NOT_SUPPORTED;
  }

  p = scheme_end + 3;

  /* Parse auth (user:pass@) */
  const char *at = strchr(p, '@');
  if (at) {
    const char *colon = strchr(p, ':');
    if (colon && colon < at) {
      /* Has password */
      /* Note: In real implementation, we'd need to store these strings */
    }
    p = at + 1;
  }

  /* Parse host:port */
  const char *colon = strchr(p, ':');
  if (colon) {
    proxy->port = atoi(colon + 1);
  } else {
    /* Default ports */
    switch (proxy->type) {
    case TUNNEL_PROXY_SOCKS5:
      proxy->port = 1080;
      break;
    case TUNNEL_PROXY_HTTP:
      proxy->port = proxy->use_tls ? 443 : 8080;
      break;
    default:
      proxy->port = 1080;
      break;
    }
  }

  return TUNNEL_OK;
}
