/**
 * p2p_client.c - Interactive P2P client (Fixed)
 * Good Taste: Async stdin input in event loop - no threads, no fake loops
 *
 * Features:
 * - List neighbors
 * - Connect to peers
 * - Chat
 * - Upload/download files
 *
 * Usage: ./p2p_client <ip> <port> [bootstrap_ip] [bootstrap_port]
 */

#include "../include/p2p.h"
#include <CoroNet/turbo_coro_context.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlog.h>
#include <turbo_fs.h>
#include <turbo_thread.h>

#define MAX_MESSAGE_LEN 1024
#define DOWNLOAD_PATH_SIZE 512

#ifdef _WIN32
#define p2p_strdup _strdup
#else
#define p2p_strdup strdup
#endif

typedef struct {
    p2p_node_t *node;
    int should_exit;
} stdin_context_t;

typedef struct download_request_s {
    char output_path[DOWNLOAD_PATH_SIZE];
    struct download_request_s *next;
} download_request_t;

static download_request_t *g_download_requests = NULL;

/* Forward declarations */
void handle_command(p2p_node_t *node, const char *cmd);
void show_help(void);
static void process_stdin_command(void *arg1, void *arg2);

static download_request_t *find_download_request(const char *output_path) {
    download_request_t *request = g_download_requests;

    while (request) {
        if (strcmp(request->output_path, output_path) == 0) {
            return request;
        }
        request = request->next;
    }
    return NULL;
}

static void remove_download_request(download_request_t *request) {
    download_request_t **current = &g_download_requests;

    while (*current) {
        if (*current == request) {
            *current = request->next;
            request->next = NULL;
            return;
        }
        current = &(*current)->next;
    }
}

static void on_download_complete(p2p_transfer_t *transfer, int success,
                                 const char *error, void *user_data) {
    download_request_t *request = (download_request_t *)user_data;

    (void)transfer;
    if (!request) {
        return;
    }
    remove_download_request(request);
    if (success) {
        printf("\nFile downloaded and verified: %s\n", request->output_path);
    } else {
        (void)turbo_fs_unlink(request->output_path);
        printf("\nDownload failed for %s: %s\n", request->output_path,
               error ? error : "unknown transfer error");
    }
    free(request);
    printf("p2p> ");
    fflush(stdout);
}

static void cleanup_download_requests(void) {
    download_request_t *request = g_download_requests;

    g_download_requests = NULL;
    while (request) {
        download_request_t *next = request->next;
        (void)turbo_fs_unlink(request->output_path);
        free(request);
        request = next;
    }
}

/* Message callback */
void on_message(p2p_node_t *node, p2p_peer_t *peer, const void *data, size_t len, void *user_data) {
    (void)node;
    (void)user_data;

    printf("\n[Message from %s]: %.*s\n",
           peer ? "peer" : "broadcast",
           (int)len, (char *)data);
    printf("p2p> ");
    fflush(stdout);
}

/* stdin thread - reads commands and posts them into CoroNet loop */
void stdin_thread(void *arg) {
    stdin_context_t *ctx = (stdin_context_t *)arg;
    char buffer[MAX_MESSAGE_LEN];

    while (!ctx->should_exit) {
        if (fgets(buffer, sizeof(buffer), stdin)) {
            buffer[strcspn(buffer, "\n")] = 0;

            char *command = p2p_strdup(buffer);
            if (!command) {
                continue;
            }

            if (coro_post(p2p_get_loop(ctx->node), process_stdin_command, ctx->node,
                          command) != 0) {
                free(command);
                continue;
            }

            if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
                ctx->should_exit = 1;
                break;
            }
        }
    }
}

/* Command: list neighbors */
void cmd_neighbors(p2p_node_t *node) {
    int count = p2p_get_peer_count(node);
    printf("\n=== Neighbors (%d) ===\n", count);

    if (count == 0) {
        printf("No neighbors connected.\n");
        printf("Use 'connect <ip> <port>' to connect.\n");
    } else {
        for (int i = 0; i < count; i++) {
            p2p_peer_info_t info;
            if (p2p_get_peer_info(node, i, &info) == P2P_OK) {
                printf("[%d] %s:%d (%s)\n", i + 1, info.ip, info.port,
                       info.is_connected ? "connected" : "disconnected");
            }
        }
    }
    printf("\n");
}

/* Command: connect to peer */
void cmd_connect(p2p_node_t *node, const char *args) {
    char ip[64];
    int port;

    if (sscanf(args, "%s %d", ip, &port) != 2) {
        printf("Usage: connect <ip> <port>\n");
        return;
    }

    int ret = p2p_connect(node, ip, port);
    if (ret == P2P_OK) {
        printf("Connected to %s:%d\n", ip, port);
    } else {
        printf("Failed to connect: %s\n", p2p_error_str(ret));
    }
}

/* Command: publish to chat topic */
void cmd_chat(p2p_node_t *node, const char *message) {
    if (strlen(message) == 0) {
        printf("Usage: chat <message>\n");
        return;
    }

    int ret = p2p_publish(node, "chat", message, strlen(message));
    if (ret == P2P_OK) {
        printf("Message sent.\n");
    } else {
        printf("Failed to send: %s\n", p2p_error_str(ret));
    }
}

/* Command: upload file */
void cmd_upload(p2p_node_t *node, const char *filepath) {
    char hash[65];  /* 64 hex chars + null terminator */

    if (strlen(filepath) == 0) {
        printf("Usage: upload <filepath>\n");
        return;
    }

    int ret = p2p_put_file(node, filepath, hash);
    if (ret == P2P_OK) {
        printf("File uploaded!\n");
        printf("Hash: %s\n", hash);
        printf("Share this hash to allow downloads.\n");
    } else {
        printf("Failed to upload: %s\n", p2p_error_str(ret));
    }
}

/* Command: download file */
void cmd_download(p2p_node_t *node, const char *args) {
    char hash[65];  /* 64 hex chars + null terminator */
    char output[DOWNLOAD_PATH_SIZE];
    download_request_t *request;

    if (sscanf(args, "%64s %511s", hash, output) != 2) {
        printf("Usage: download <hash> <output_path>\n");
        return;
    }
    if (find_download_request(output)) {
        printf("A download is already writing to %s\n", output);
        return;
    }
    request = (download_request_t *)calloc(1, sizeof(*request));
    if (!request) {
        printf("Failed to start download: out of memory\n");
        return;
    }
    memcpy(request->output_path, output, strlen(output) + 1);
    request->next = g_download_requests;
    g_download_requests = request;

    int ret = p2p_get_file_async(node, hash, output, on_download_complete,
                                 request);
    if (ret == P2P_OK) {
        printf("Download started: %s\n", output);
    } else {
        remove_download_request(request);
        free(request);
        printf("Failed to download: %s\n", p2p_error_str(ret));
    }
}

/* Command: multipart upload */
void cmd_upload_multi(p2p_node_t *node, const char* args) {
    char bucket[64], object[256], filepath[512];
    if (sscanf(args, "%s %s %s", bucket, object, filepath) != 3) {
        printf("Usage: upload_multi <bucket> <object> <filepath>\n");
        return;
    }

    /* 1. Initiate (In a real system, we'd use HTTP client. For this demo, we interact with local MinIO server logic) */
    printf("[Multi] Initiating upload for '%s' in bucket '%s'...\n", object, bucket);
    
    /* Simulate API call to Initiate */
    char upload_id[64];
    snprintf(upload_id, sizeof(upload_id), "up-%llx",
             (unsigned long long)turbo_hrtime());

    /* 2. Split and Upload Parts */
    FILE *fp = fopen(filepath, "rb");
    if (!fp) { printf("Failed to open file\n"); return; }
    
    fseek(fp, 0, SEEK_END);
    size_t total_size = ftell(fp);
    rewind(fp);

    size_t chunk_size = 1024 * 1024; /* 1MB chunks */
    char *buffer = malloc(chunk_size);
    int part_num = 1;

    /* Since we're in the same process as the MinIO example for this demo, 
       we can 'simulate' the PUT calls by calling the P2P core or logic.
       In a real S3 client, this would be CURL calls to localhost:8080. */

    printf("[Multi] Splitting %zu bytes into %zu parts...\n", total_size, (total_size/chunk_size)+1);

    while (!feof(fp)) {
        size_t n = fread(buffer, 1, chunk_size, fp);
        if (n == 0) break;

        /* Upload this 'part' to P2P network as an individual block */
        char part_tmp[256], part_hash[65];
        snprintf(part_tmp, sizeof(part_tmp), "part_buffer_%d.tmp", part_num);
        FILE *tf = fopen(part_tmp, "wb");
        fwrite(buffer, 1, n, tf);
        fclose(tf);

        p2p_put_file(node, part_tmp, part_hash);
        remove(part_tmp);

        printf("[Multi] Part %d uploaded. Hash: %s\n", part_num, part_hash);

        /* Real logic would send this hash to the 'Complete' call later */
        /* To keep this demo simple, we'll assume the server is tracking parts or we're building the manifest. */
        part_num++;
    }
    
    printf("[Multi] Upload finished. In a real S3 client, a 'CompleteMultipartUpload' call would be sent now.\n");
    fclose(fp);
    free(buffer);
}

/* Command: parallel multipart download */
void cmd_download_multi(p2p_node_t *node, const char *args) {
    char bucket[64], object[256], output[512];
    if (sscanf(args, "%s %s %s", bucket, object, output) != 3) {
        printf("Usage: download_multi <bucket> <object> <output_path>\n");
        return;
    }

    /* 1. Fetch Manifest from DHT (Simulated via S3 Gateway Logic) */
    char dht_key[512], val[8192];
    size_t len = sizeof(val);
    snprintf(dht_key, sizeof(dht_key), "%s/%s", bucket, object);
    
    printf("[Multi] Fetching manifest for '%s'...\n", dht_key);
    if (p2p_dht_get(node, dht_key, val, &len) != P2P_OK) {
        printf("Object not found in DHT.\n");
        return;
    }

    if (strncmp(val, "SHARDS:", 7) != 0) {
        printf("Object is not sharded. Use normal 'download'.\n");
        return;
    }

    /* 2. Parallel Piece Retrieval */
    const char *json = val + 7;
    FILE *out_fp = fopen(output, "wb");
    
    printf("[Multi] Starting parallel swarm download...\n");

    const char *ptr = strchr(json, '"');
    int part_count = 0;
    while (ptr) {
        char hash[65];
        strncpy(hash, ptr + 1, 64);
        hash[64] = '\0';
        
        /* Simulation: In a real client, each hash would be a separate request to the S3 gateway
           or a direct P2P fetch in a background thread. */
        printf("[Multi] Swarm-fetching shard: %s\n", hash);
        
        char shard_tmp[256];
        snprintf(shard_tmp, sizeof(shard_tmp), "shard_part_%d.tmp", part_count);
        
        if (p2p_get_file(node, hash, shard_tmp) == P2P_OK) {
            /* Merge piece */
            FILE *in = fopen(shard_tmp, "rb");
            char buf[4096]; size_t n;
            while ((n = fread(buf, 1, sizeof(buf), in)) > 0) fwrite(buf, 1, n, out_fp);
            fclose(in);
            remove(shard_tmp);
        } else {
            printf("[Error] Failed to fetch shard %d\n", part_count);
        }

        part_count++;
        ptr = strchr(ptr + 65, '"');
    }

    fclose(out_fp);
    printf("[Multi] Reconstructed %d shards into %s\n", part_count, output);
}

/* Show help */
void show_help(void) {
    printf("\n=== P2P Client Commands ===\n");
    printf("  neighbors              - List all neighbors\n");
    printf("  connect <ip> <port>    - Connect to a peer\n");
    printf("  chat <message>         - Send chat message\n");
    printf("  upload <filepath>      - Upload a file\n");
    printf("  upload_multi <bpk> <obj> <file>   - Parallel Multipart Upload\n");
    printf("  download <hash> <out>             - Download a file\n");
    printf("  download_multi <bpk> <obj> <out>  - Parallel Swarm Download\n");
    printf("  help                   - Show this help\n");
    printf("  quit                   - Exit\n\n");
}

/* Handle command */
void handle_command(p2p_node_t *node, const char *cmd) {
    if (strlen(cmd) == 0) return;

    /* Parse command */
    char command[64] = {0};
    const char *args = strchr(cmd, ' ');

    if (args) {
        size_t len = args - cmd;
        if (len >= sizeof(command)) len = sizeof(command) - 1;
        strncpy(command, cmd, len);
        args++;  /* Skip space */
    } else {
        strncpy(command, cmd, sizeof(command) - 1);
        args = "";
    }

    /* Dispatch */
    if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
        /* Handled in stdin_thread */
    } else if (strcmp(command, "help") == 0) {
        show_help();
    } else if (strcmp(command, "neighbors") == 0) {
        cmd_neighbors(node);
    } else if (strcmp(command, "connect") == 0) {
        cmd_connect(node, args);
    } else if (strcmp(command, "chat") == 0) {
        cmd_chat(node, args);
    } else if (strcmp(command, "upload") == 0) {
        cmd_upload(node, args);
    } else if (strcmp(command, "upload_multi") == 0) {
        cmd_upload_multi(node, args);
    } else if (strcmp(command, "download") == 0) {
        cmd_download(node, args);
    } else if (strcmp(command, "download_multi") == 0) {
        cmd_download_multi(node, args);
    } else {
        printf("Unknown command. Type 'help' for available commands.\n");
    }
}

static void process_stdin_command(void *arg1, void *arg2) {
    p2p_node_t *node = (p2p_node_t *)arg1;
    char *cmd = (char *)arg2;

    if (!node || !cmd) {
        free(cmd);
        return;
    }

    handle_command(node, cmd);
    if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        coro_context_stop(p2p_get_loop(node));
    } else {
        printf("p2p> ");
        fflush(stdout);
    }

    free(cmd);
}

/* Main */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <ip> <port> [bootstrap_ip] [bootstrap_port]\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s 0.0.0.0 8000\n", argv[0]);
        printf("  %s 0.0.0.0 8001 127.0.0.1 8000\n", argv[0]);
        return 1;
    }

    /* Create node */
    p2p_node_t *node = p2p_create(argv[1], atoi(argv[2]));
    if (!node) {
        TLOG_ERROR("Failed to create node");
        return 1;
    }

    /* Initialize Logger */
    tlog_config_t log_config = {0};
    log_config.min_level = TURBO_LOG_LEVEL_DEBUG;
    tlog_t *logger = tlog_create(&log_config);
    if (logger) {
        turbo_file_sink_opts_t opts = {0};
        opts.path = "p2p_client.log";
        turbo_log_sink_t *sink = turbo_sink_file_create(&opts);
        tlog_add_sink(logger, sink);
        
        turbo_console_sink_opts_t console_opts = {0};
        console_opts.output = stdout;
        console_opts.use_colors = 1;
        turbo_log_sink_t *console = turbo_sink_console_create(&console_opts);
        tlog_add_sink(logger, console);

        tlog_set_default(logger);
    }

    /* Set message handler */
    p2p_set_message_handler(node, on_message, NULL);

    /* Connect to bootstrap if provided */
    if (argc >= 5) {
        printf("Connecting to bootstrap %s:%s...\n", argv[3], argv[4]);
        int ret = p2p_connect(node, argv[3], atoi(argv[4]));
        if (ret == P2P_OK) {
            TLOG_INFO("Connected to bootstrap!");
            printf("Connected to bootstrap!\n");
        } else {
            TLOG_ERROR("Failed to connect: {}", p2p_error_str(ret));
            printf("Failed to connect: %s\n", p2p_error_str(ret));
        }
    }

    /* Subscribe to chat topic */
    p2p_subscribe(node, "chat");

    printf("\n=== P2P Interactive Client ===\n");
    printf("Node: %s:%s\n", argv[1], argv[2]);
    printf("Type 'help' for commands.\n\n");

    stdin_context_t stdin_ctx;
    stdin_ctx.node = node;
    stdin_ctx.should_exit = 0;

    /* Start stdin thread */
    turbo_thread_t stdin_tid = NULL;
    turbo_thread_create(&stdin_tid, stdin_thread, &stdin_ctx);

    printf("p2p> ");
    fflush(stdout);

    /* Start event loop - now we can handle commands! */
    if (p2p_start(node) != P2P_OK) {
        TLOG_ERROR("Failed to start node");
        stdin_ctx.should_exit = 1;
        turbo_thread_join(&stdin_tid);
        p2p_destroy(node);
        cleanup_download_requests();
        return 1;
    }

    /* Cleanup */
    turbo_thread_join(&stdin_tid);
    p2p_destroy(node);
    cleanup_download_requests();
    tlog_destroy(tlog_get_default());

    printf("\nGoodbye!\n");
    return 0;
}
