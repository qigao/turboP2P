#include <tinytest.h>

#include "m3_gateway.h"
#include "m3_raft_node.h"
#include "mesh_release.h"

#include <http/http_client.h>
#include <iris/iris.h>
#include <iris/server.h>
#include <platform.h>
#include <turbo_crypto.h>
#include <turbo_error.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#endif

/* End-to-end HTTP smoke over the multi-node metadata backend: the gateway
 * embeds a single-voter raft node (always leader), an Iris server runs on the
 * http_client context, and signed S3 requests drive the real handler path
 * (SigV4 auth -> chunk store -> raft metadata -> reply). */

#ifndef M3_TEST_TLS_DIR
#define M3_TEST_TLS_DIR "mesh/tests/data/m3tls"
#endif

static const char k_dummy_fingerprint[] =
    "sha256:56fdbb74472b0d77a2fc182a44be32a41c4b9dbfab34a6cc68374b50066d24e1";

static void to_hex(const uint8_t *in, size_t len, char *out) {
  static const char HEX[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < len; i++) {
    out[i * 2] = HEX[in[i] >> 4];
    out[i * 2 + 1] = HEX[in[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

static void sha256_hex(const char *data, size_t len, char *out) {
  uint8_t digest[32];
  turbo_crypto_sha256((const uint8_t *)data, len, digest);
  to_hex(digest, sizeof(digest), out);
}

static void client_sign(const char *method, const char *uri, const char *query,
                        const char *amzdate, const char *payload_hash,
                        const uint8_t secret[32], const char *access_key, const char *region,
                        const char *service, const char *host, char *authorization_out,
                        size_t cap) {
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

static void amzdate_now(char *out, size_t cap) {
  time_t now = time(NULL);
  struct tm gmt;
#if defined(_WIN32)
  gmtime_s(&gmt, &now);
#else
  gmtime_r(&now, &gmt);
#endif
  strftime(out, cap, "%Y%m%dT%H%M%SZ", &gmt);
}

#ifdef _WIN32
static volatile LONG g_http_pump_stop = 0;

static DWORD WINAPI http_gateway_pump(LPVOID arg) {
  m3_gateway_t *gateway = (m3_gateway_t *)arg;
  while (InterlockedCompareExchange(&g_http_pump_stop, 0, 0) == 0) {
    m3_gateway_poll_v1(gateway);
    Sleep(1);
  }
  return 0;
}

static HANDLE start_http_pump(m3_gateway_t *gateway) {
  InterlockedExchange(&g_http_pump_stop, 0);
  return CreateThread(NULL, 0, http_gateway_pump, gateway, 0, NULL);
}

static void stop_http_pump(HANDLE thread) {
  if (thread == NULL) {
    return;
  }
  InterlockedExchange(&g_http_pump_stop, 1);
  WaitForSingleObject(thread, 5000);
  CloseHandle(thread);
}
#endif

static void make_store_dir(char *path, size_t cap, const char *tag) {
#ifdef _WIN32
  char tmp[MAX_PATH];
  DWORD len = GetTempPathA((DWORD)sizeof(tmp), tmp);
  if (len == 0u || len >= sizeof(tmp)) {
    strcpy(path, tag);
  } else {
    snprintf(path, cap, "%s%s-%lu", tmp, tag, (unsigned long)GetCurrentProcessId());
  }
  _mkdir(path);
#else
  snprintf(path, cap, "/tmp/%s-%d", tag, (int)getpid());
  mkdir(path, 0755);
#endif
}

static void fill_credential(m3_sigv4_credential_v1_t *cred) {
  memset(cred, 0, sizeof(*cred));
  strcpy(cred->access_key, "AKIDEXAMPLE");
  cred->region = "us-east-1";
  cred->service = "s3";
  cred->clock_skew_seconds = 900;
  for (int i = 0; i < 32; i++) {
    cred->secret_key[i] = (uint8_t)(0x60 + i);
  }
}

/* Build signed headers for one request. Returns the number of headers. */
static int build_signed_headers(const char *method, const char *uri, const char *body,
                                size_t body_len, const m3_sigv4_credential_v1_t *cred,
                                const char *host, char amzdate[32], char auth[512],
                                char payload_hex[65], const char *headers_out[3],
                                char header_buf[3][256]) {
  sha256_hex(body, body_len, payload_hex);
  amzdate_now(amzdate, 32);
  client_sign(method, uri, NULL, amzdate, payload_hex, cred->secret_key, cred->access_key,
              cred->region, cred->service, host, auth, 512);
  snprintf(header_buf[0], 256, "Authorization: %s", auth);
  snprintf(header_buf[1], 256, "x-amz-date: %s", amzdate);
  snprintf(header_buf[2], 256, "x-amz-content-sha256: %s", payload_hex);
  headers_out[0] = header_buf[0];
  headers_out[1] = header_buf[1];
  headers_out[2] = header_buf[2];
  return 3;
}

static void test_gateway_http_roundtrip(void) {
  m3_gateway_t gateway;
  m3_raft_node_config_t node_config;
  m3_raft_node_peer_config_t peers[1];
  static const tr_raft_node_id_t voters[] = {1u};
  m3_sigv4_credential_v1_t credential;
  iris_app_t *app = NULL;
  http_client_t *client = NULL;
  coro_socket_t *server = NULL;
  char store[512];
  char cert_path[256];
  char key_path[256];
  char ca_path[256];
  unsigned short port = 18888;
  const char *payload = "hello m3 http";
  size_t payload_len = strlen(payload);
  char k_release_digest_hex[65] = {0}; /* manifest-level digest anchor */

  memset(&gateway, 0, sizeof(gateway));
  make_store_dir(store, sizeof(store), "m3-gw-http");
  snprintf(cert_path, sizeof(cert_path), "%s/node1.crt", M3_TEST_TLS_DIR);
  snprintf(key_path, sizeof(key_path), "%s/node1.key", M3_TEST_TLS_DIR);
  snprintf(ca_path, sizeof(ca_path), "%s/m3ca.crt", M3_TEST_TLS_DIR);

  /* Single voter (always leader) with a dummy non-voter peer so the peer
   * service has one entry; the raft core never replicates to non-voters. */
  memset(&peers[0], 0, sizeof(peers[0]));
  peers[0].node_id = 2u;
  strcpy(peers[0].connect_host, "127.0.0.1");
  strcpy(peers[0].request_host, "localhost");
  peers[0].port = 19999;
  strcpy(peers[0].certificate_sha256, k_dummy_fingerprint);
  memset(&node_config, 0, sizeof(node_config));
  node_config.node_id = 1u;
  node_config.listen_host = "127.0.0.1";
  node_config.listen_port = 18889;
  node_config.sqlite_path = ":memory:";
  node_config.cert_file = cert_path;
  node_config.key_file = key_path;
  node_config.ca_file = ca_path;
  node_config.voters = voters;
  node_config.voter_count = 1u;
  node_config.peers = peers;
  node_config.peer_count = 1u;
  node_config.max_snapshot_bytes = 4u * 1024 * 1024;
  node_config.max_pending_reads = 64u;

  fill_credential(&credential);
  check_int_eq(0, m3_gateway_init_node_v1(&gateway, store, UINT64_C(1024) * 1024, &credential,
                                          1024u, &node_config));

  app = iris_app_create();
  check_not_null(app);
  m3_gateway_register_routes_v1(app);
  {
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u", (unsigned)port);
    client = http_client_create(url);
    check_not_null(client);
    http_client_set_timeout(client, 10000);
  }
  server = iris_server_start(app, http_client_get_context(client), port);
  check_not_null(server);
  {
    /* The single-voter node must be pumped continuously; the handlers now
     * sleep-poll instead of driving the node context themselves. */
    HANDLE pump = start_http_pump(&gateway);
    check_not_null(pump);

    {
      char host[64];
    char amzdate[32];
    char auth[512];
    char payload_hex[65];
    const char *headers[3];
    char header_buf[3][256];
    int hcount;
    http_response_t *r;

    snprintf(host, sizeof(host), "127.0.0.1:%u", (unsigned)port);

    /* PUT /bkt/obj */
    hcount = build_signed_headers("PUT", "/bkt/obj", payload, payload_len, &credential, host, amzdate,
                                  auth, payload_hex, headers, header_buf);
    r = http_request(client, HTTP_PUT, "bkt/obj", headers, hcount, payload, payload_len);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 200);
    http_response_free(r);

    /* GET /bkt/obj */
    hcount = build_signed_headers("GET", "/bkt/obj", "", 0, &credential, host, amzdate, auth,
                                  payload_hex, headers, header_buf);
    r = http_request(client, HTTP_GET, "bkt/obj", headers, hcount, NULL, 0);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 200);
    check_size_eq(payload_len, r->body_len);
    check_mem_eq(payload, r->body, payload_len);
    http_response_free(r);

    /* HEAD /bkt/obj */
    hcount = build_signed_headers("HEAD", "/bkt/obj", "", 0, &credential, host, amzdate, auth,
                                  payload_hex, headers, header_buf);
    r = http_request(client, HTTP_HEAD, "bkt/obj", headers, hcount, NULL, 0);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 200);
    http_response_free(r);

    /* GET /bkt/obj/playlist.m3u8 -> HLS media playlist from the manifest */
    /* SigV4 signs the canonical resource (/bkt/obj); the URL carries the
     * playlist suffix. */
    hcount = build_signed_headers("GET", "/bkt/obj", "", 0, &credential, host, amzdate, auth,
                                  payload_hex, headers, header_buf);
    r = http_request(client, HTTP_GET, "bkt/obj/playlist.m3u8", headers, hcount, NULL, 0);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 200);
    check_true(r->body != NULL && strstr(r->body, "#EXTM3U") != NULL);
    check_true(r->body != NULL && strstr(r->body, "#EXT-X-BYTERANGE:") != NULL);
    http_response_free(r);

    /* PUT a release manifest object, then GET /bkt/rel/release.txt -> listing */
    {
      mesh_release_v1_t release;
      mesh_release_entry_v1_t entry;
      uint8_t rel_bytes[1024];
      size_t rel_len = 0u;
      char rel_hex[2049];

      check_int_eq(MESH_RELEASE_OK,
                   mesh_release_init_v1(&release, "app-1.0", 1u));
      memset(&entry, 0, sizeof(entry));
      snprintf(entry.path, sizeof(entry.path), "%s", "tool.bin");
      snprintf(entry.object_key, sizeof(entry.object_key), "%s", "rel/tool");
      entry.size = 42u;
      memset(entry.object_cid, 0x11, sizeof(entry.object_cid));
      check_int_eq(MESH_RELEASE_OK, mesh_release_add_v1(&release, &entry));
      memset(&entry, 0, sizeof(entry));
      snprintf(entry.path, sizeof(entry.path), "%s", "config.json");
      snprintf(entry.object_key, sizeof(entry.object_key), "%s", "rel/config.json");
      entry.size = 7u;
      memset(entry.object_cid, 0x22, sizeof(entry.object_cid));
      check_int_eq(MESH_RELEASE_OK, mesh_release_add_v1(&release, &entry));
      check_int_eq(MESH_RELEASE_OK,
                   mesh_release_encode_v1(&release, rel_bytes, sizeof(rel_bytes),
                                          &rel_len));
      for (size_t i = 0u; i < rel_len; i++)
        snprintf(rel_hex + i * 2, sizeof(rel_hex) - i * 2, "%02x", rel_bytes[i]);
      {
        uint8_t rel_digest[32];

        if (mesh_release_digest_v1(&release, rel_digest) == MESH_RELEASE_OK) {
          for (size_t i = 0u; i < sizeof(rel_digest); i++)
            snprintf(k_release_digest_hex + i * 2,
                     sizeof(k_release_digest_hex) - i * 2, "%02x",
                     rel_digest[i]);
        }
      }

      hcount = build_signed_headers("PUT", "/bkt/rel", (const char *)rel_bytes,
                                    rel_len, &credential, host, amzdate, auth,
                                    rel_hex, headers, header_buf);
      r = http_request(client, HTTP_PUT, "bkt/rel", headers, hcount,
                       (const char *)rel_bytes, rel_len);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 200);
      http_response_free(r);

      hcount = build_signed_headers("GET", "/bkt/rel", "", 0, &credential, host,
                                    amzdate, auth, payload_hex, headers, header_buf);
      r = http_request(client, HTTP_GET, "bkt/rel/release.txt", headers, hcount,
                       NULL, 0);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 200);
      check_true(r->body != NULL && strstr(r->body, "RELEASE app-1.0 version=1 files=2 digest=") != NULL);
      check_true(r->body != NULL && strstr(r->body, "tool.bin rel/tool 42 ") != NULL);
      check_true(r->body != NULL && strstr(r->body, "config.json rel/config.json 7 ") != NULL);
      http_response_free(r);
    }

    /* PUT the release file objects, then download them through the
     * release-file route (GET /bkt/rel/<path>), which is signed over the
     * full request path and serves the resolved object with Range support. */
    {
      static const char k_tool_body[] =
          "012345678901234567890123456789012345678901"; /* 42 bytes */
      static const char k_config_body[] = "config!";   /* 7 bytes */
      char range_buf[4][256];
      const char *range_headers[4];

      hcount = build_signed_headers("PUT", "/rel/tool", k_tool_body,
                                    sizeof(k_tool_body) - 1u, &credential, host,
                                    amzdate, auth, payload_hex, headers, header_buf);
      r = http_request(client, HTTP_PUT, "rel/tool", headers, hcount,
                       k_tool_body, sizeof(k_tool_body) - 1u);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 200);
      http_response_free(r);

      hcount = build_signed_headers("PUT", "/rel/config.json", k_config_body,
                                    sizeof(k_config_body) - 1u, &credential, host,
                                    amzdate, auth, payload_hex, headers, header_buf);
      r = http_request(client, HTTP_PUT, "rel/config.json", headers, hcount,
                       k_config_body, sizeof(k_config_body) - 1u);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 200);
      http_response_free(r);

      /* Full-file download via the release route. */
      hcount = build_signed_headers("GET", "/bkt/rel/tool.bin", "", 0,
                                    &credential, host, amzdate, auth, payload_hex,
                                    headers, header_buf);
      r = http_request(client, HTTP_GET, "bkt/rel/tool.bin", headers, hcount,
                       NULL, 0);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 200);
      check_true(r->body_len == sizeof(k_tool_body) - 1u);
      check_true(r->body != NULL &&
                 memcmp(r->body, k_tool_body, sizeof(k_tool_body) - 1u) == 0);
      http_response_free(r);

      /* Range download through the release route (Range is not signed). */
      hcount = build_signed_headers("GET", "/bkt/rel/tool.bin", "", 0,
                                    &credential, host, amzdate, auth, payload_hex,
                                    headers, header_buf);
      snprintf(range_buf[0], sizeof(range_buf[0]), "Authorization: %s", auth);
      snprintf(range_buf[1], sizeof(range_buf[1]), "x-amz-date: %s", amzdate);
      snprintf(range_buf[2], sizeof(range_buf[2]), "x-amz-content-sha256: %s",
               payload_hex);
      snprintf(range_buf[3], sizeof(range_buf[3]), "Range: bytes=10-19");
      range_headers[0] = range_buf[0];
      range_headers[1] = range_buf[1];
      range_headers[2] = range_buf[2];
      range_headers[3] = range_buf[3];
      r = http_request(client, HTTP_GET, "bkt/rel/tool.bin", range_headers, 4,
                       NULL, 0);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 206);
      check_true(r->body_len == 10u);
      check_true(r->body != NULL && memcmp(r->body, k_tool_body + 10, 10u) == 0);
      http_response_free(r);

      /* Missing release path -> 404. */
      hcount = build_signed_headers("GET", "/bkt/rel/missing.bin", "", 0,
                                    &credential, host, amzdate, auth, payload_hex,
                                    headers, header_buf);
      r = http_request(client, HTTP_GET, "bkt/rel/missing.bin", headers, hcount,
                       NULL, 0);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 404);
      http_response_free(r);
    }

    /* Release entry point: ?listing=1 serves the listing directly, and
     * ?redirect=<segment> answers 302 to /bkt/rel/<segment>. Both are
     * signed over the object (/bkt/rel), not the query. */
    {
      hcount = build_signed_headers("GET", "/bkt/rel", "", 0, &credential,
                                    host, amzdate, auth, payload_hex, headers,
                                    header_buf);
      r = http_request(client, HTTP_GET, "bkt/rel?listing=1", headers, hcount,
                       NULL, 0);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 200);
      check_true(r->body != NULL &&
                 strstr(r->body, "RELEASE app-1.0 version=1 files=2 digest=") != NULL);
      check_true(r->body != NULL &&
                 strstr(r->body, "tool.bin rel/tool 42 ") != NULL);
      check_true(r->headers != NULL &&
                 strstr(r->headers, "X-M3-Release-Digest: ") != NULL &&
                 strstr(r->headers, k_release_digest_hex) != NULL);
      http_response_free(r);

      /* Redirects are followed by default; disable while asserting 302. */
      http_client_follow_redirects(client, 0);
      hcount = build_signed_headers("GET", "/bkt/rel", "", 0, &credential,
                                    host, amzdate, auth, payload_hex, headers,
                                    header_buf);
      r = http_request(client, HTTP_GET, "bkt/rel?redirect=release.txt", headers,
                       hcount, NULL, 0);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 302);
      check_true(r->headers != NULL &&
                 strstr(r->headers, "Location: /bkt/rel/release.txt") != NULL);
      http_response_free(r);

      hcount = build_signed_headers("GET", "/bkt/rel", "", 0, &credential,
                                    host, amzdate, auth, payload_hex, headers,
                                    header_buf);
      r = http_request(client, HTTP_GET, "bkt/rel?redirect=../x", headers,
                       hcount, NULL, 0);
      check_not_null(r);
      check_int_eq(r->error_code, HTTP_ERROR_NONE);
      check_int_eq(r->status_code, 400);
      http_response_free(r);
      http_client_follow_redirects(client, 1);
    }

    /* ListObjects (GET /bkt) */
    hcount = build_signed_headers("GET", "/bkt", "", 0, &credential, host, amzdate, auth, payload_hex,
                                  headers, header_buf);
    r = http_request(client, HTTP_GET, "bkt", headers, hcount, NULL, 0);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 200);
    check_true(r->body != NULL && strstr(r->body, "<Key>obj</Key>") != NULL);
    http_response_free(r);

    /* DELETE /bkt/obj */
    hcount = build_signed_headers("DELETE", "/bkt/obj", "", 0, &credential, host, amzdate, auth,
                                  payload_hex, headers, header_buf);
    r = http_request(client, HTTP_DELETE, "bkt/obj", headers, hcount, NULL, 0);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 204);
    http_response_free(r);

    /* GET after delete -> 404 */
    hcount = build_signed_headers("GET", "/bkt/obj", "", 0, &credential, host, amzdate, auth,
                                  payload_hex, headers, header_buf);
    r = http_request(client, HTTP_GET, "bkt/obj", headers, hcount, NULL, 0);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 404);
    http_response_free(r);

    /* Tampered signature -> 403 */
    sha256_hex(payload, payload_len, payload_hex);
    amzdate_now(amzdate, 32);
    client_sign("PUT", "/bkt/obj", NULL, amzdate, payload_hex, credential.secret_key,
                credential.access_key, credential.region, credential.service, host, auth, 512);
    auth[60] = (auth[60] == '0') ? '1' : '0'; /* corrupt the signature */
    snprintf(header_buf[0], 256, "Authorization: %s", auth);
    snprintf(header_buf[1], 256, "x-amz-date: %s", amzdate);
    snprintf(header_buf[2], 256, "x-amz-content-sha256: %s", payload_hex);
    headers[0] = header_buf[0];
    headers[1] = header_buf[1];
    headers[2] = header_buf[2];
    r = http_request(client, HTTP_PUT, "bkt/obj", headers, 3, payload, payload_len);
    check_not_null(r);
    check_int_eq(r->error_code, HTTP_ERROR_NONE);
    check_int_eq(r->status_code, 403);
    http_response_free(r);
    }
    stop_http_pump(pump);
  }

  if (server) {
    coro_socket_destroy(server);
  }
  if (client) {
    http_client_destroy(client);
  }
  if (app) {
    iris_app_destroy(app);
  }
  m3_gateway_destroy_v1(&gateway);
}


spec("m3 gateway http") {
  describe("S3 gateway over the raft-node metadata backend (HTTP)") {
    it("round-trips signed PUT/GET/HEAD/List/DELETE") {
      test_gateway_http_roundtrip();
    }
  }
}
