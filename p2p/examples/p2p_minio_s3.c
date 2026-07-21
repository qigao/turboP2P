/**
 * p2p_minio_s3.c - S3-shaped prototype over the P2P file API
 * 
 * This is not distributed mesh storage yet: p2p_put_file() registers a local
 * path without copying its content, while this gateway removes the upload
 * temporary file afterward. p2p_get_file() does not yet transfer bytes to the
 * output path. There is no durable node-local store, replication, repair,
 * persistence policy, or Byzantine consensus. The HTTP surface remains an
 * integration prototype until those lower-layer guarantees exist.
 *
 * API:
 *   PUT /:bucket/:object  -> Exercise the incomplete local registry/DHT path
 *   GET /:bucket/:object  -> Exercise the incomplete lookup/download path
 * 
 * Layering:
 *   [ REST API (Iris) ] -> [ Object Index (DHT) ] -> [ Block Storage (P2P File) ]
 */

#include "p2p.h"
#include <iris/iris.h>
#include <turbo_fs.h>
#include <turbo_mmap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlog.h>
 
#include <mustache.h>
#include <mustache_json.h>
#include <turbo_parser.h>

/* S3 XML Templates */
static const char *TEMPLATE_LIST_ALL_MY_BUCKETS = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
    "  <Owner><ID>p2p-minio</ID><DisplayName>p2p-minio</DisplayName></Owner>\n"
    "  <Buckets>\n"
    "    {{#buckets}}\n"
    "    <Bucket><Name>{{name}}</Name><CreationDate>2026-01-26T00:00:00.000Z</CreationDate></Bucket>\n"
    "    {{/buckets}}\n"
    "  </Buckets>\n"
    "</ListAllMyBucketsResult>";

static const char *TEMPLATE_INITIATE_MULTIPART = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<InitiateMultipartUploadResult>\n"
    "  <Bucket>{{bucket}}</Bucket><Key>{{key}}</Key><UploadId>{{upload_id}}</UploadId>\n"
    "</InitiateMultipartUploadResult>";

static const char *TEMPLATE_COMPLETE_MULTIPART = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<CompleteMultipartUploadResult>\n"
    "  <Bucket>{{bucket}}</Bucket><Key>{{key}}</Key><ETag>\"sharded-upload\"</ETag>\n"
    "</CompleteMultipartUploadResult>";

static const char *TEMPLATE_LIST_BUCKET_RESULT = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
    "  <Name>{{bucket}}</Name>\n"
    "  <Prefix>{{prefix}}</Prefix>\n"
    "  <Marker>{{marker}}</Marker>\n"
    "  <MaxKeys>{{max_keys}}</MaxKeys>\n"
    "  <IsTruncated>false</IsTruncated>\n"
    "</ListBucketResult>";

static const char *TEMPLATE_S3_ERROR = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Error><Code>{{code}}</Code><Message>{{message}}</Message><RequestId>p2p</RequestId></Error>";

/* Helper for S3 XML responses via Mustache */
static void render_s3_xml(Res *res, int status, const char *tmpl_str, json_value_t *data) {
    MUSTACHE_TEMPLATE *tmpl = mustache_compile(tmpl_str, strlen(tmpl_str), NULL, NULL, 0);
    if (!tmpl) {
        TLOG_ERROR("Failed to compile mustache template");
        reply(res, 500, "text/plain", "Template Error", 14);
        return;
    }

    MUSTACHE_STRING_RENDERER renderer;
    if (mustache_string_renderer_init(&renderer) != 0) {
        mustache_release(tmpl);
        reply(res, 500, "text/plain", "Internal Error", 14);
        return;
    }

    mustache_render_json(tmpl, data, &renderer.base, &renderer, NULL, NULL);

    char *output = mustache_string_renderer_get(&renderer);
    if (output) {
        reply(res, status, "application/xml", output, strlen(output));
        free(output);
    }

    mustache_string_renderer_free(&renderer);
    mustache_release(tmpl);
}

static void send_s3_error(Res *res, int status, const char *code, const char *message) {
    json_value_t *j = turbo_json_create_object();
    turbo_json_object_set_string(j, "code", code);
    turbo_json_object_set_string(j, "message", message);
    render_s3_xml(res, status, TEMPLATE_S3_ERROR, j);
    turbo_free_json(&j);
}

/* Global state */
static p2p_node_t *g_node = NULL;

typedef struct bucket_s {
    char name[64];
    struct bucket_s *next;
} bucket_t;

static bucket_t *g_buckets = NULL;

/* Multipart upload tracking */
typedef struct part_s {
    int part_number;
    char hash[65];
    struct part_s *next;
} part_t;

typedef struct multipart_upload_s {
    char upload_id[64];
    char bucket[64];
    char object[256];
    part_t *parts;
    struct multipart_upload_s *next;
} multipart_upload_t;

static multipart_upload_t *g_uploads = NULL;

/* Helper for XML responses */
static void send_xml(Res *res, int status, const char *xml) {
    reply(res, status, "application/xml", xml, strlen(xml));
}

/* Helper to map bucket/object key to DHT key */
static void make_dht_key(const char *bucket, const char *object, char *out, size_t size) {
    snprintf(out, size, "%s/%s", bucket, object);
}

/* Helper to generate a random upload ID */
static void generate_upload_id(char *out, size_t size) {
    snprintf(out, size, "upload-%llx", (unsigned long long)turbo_hrtime());
}

/* 
 * POST /:bucket/:object
 * Handles InitiateMultipartUpload (?uploads) and CompleteMultipartUpload (?uploadId)
 */
void handle_multipart_control(Req *req, Res *res) {
    const char *bucket = get_params(req, "bucket");
    const char *object = get_params(req, "object");
    const char *is_initiate = get_query(req, "uploads");
    const char *upload_id = get_query(req, "uploadId");

    if (is_initiate != NULL) {
        /* Initiate Multipart Upload */
        multipart_upload_t *upl = (multipart_upload_t *)calloc(1, sizeof(multipart_upload_t));
        generate_upload_id(upl->upload_id, sizeof(upl->upload_id));
        strncpy(upl->bucket, bucket, 63);
        strncpy(upl->object, object, 255);
        
        upl->next = g_uploads;
        g_uploads = upl;

        TLOG_INFO("Initiated multipart upload: {} (ID: {})", object, upl->upload_id);

        json_value_t *j = turbo_json_create_object();
        turbo_json_object_set_string(j, "bucket", bucket);
        turbo_json_object_set_string(j, "key", object);
        turbo_json_object_set_string(j, "upload_id", upl->upload_id);
        render_s3_xml(res, OK, TEMPLATE_INITIATE_MULTIPART, j);
        turbo_free_json(&j);
        return;
    }

    if (upload_id != NULL) {
        /* Complete Multipart Upload */
        multipart_upload_t *upl = g_uploads;
        multipart_upload_t *prev = NULL;
        while (upl) {
            if (strcmp(upl->upload_id, upload_id) == 0) break;
            prev = upl; upl = upl->next;
        }

        if (!upl) {
            send_s3_error(res, NOT_FOUND, "NoSuchUpload", "The specified upload does not exist.");
            return;
        }

        json_value_t *manifest_obj = turbo_json_create_object();
        json_value_t *parts_arr = turbo_json_create_array();
        part_t *p = upl->parts;
        while (p) {
            turbo_json_array_add(parts_arr, turbo_json_create_string(p->hash));
            p = p->next;
        }
        turbo_json_object_add(manifest_obj, "parts", parts_arr);
        
        char *manifest_str = turbo_json_serialize(manifest_obj, NULL);
        
        char dht_key[512];
        make_dht_key(bucket, object, dht_key, sizeof(dht_key));
        
        char sharded_val[4200];
        snprintf(sharded_val, sizeof(sharded_val), "SHARDS:%s", manifest_str);
        p2p_dht_put(g_node, dht_key, sharded_val, strlen(sharded_val) + 1);

        TLOG_INFO("Completed multipart upload: {} (ID: {})", object, upload_id);

        /* Remove from tracking */
        if (prev) prev->next = upl->next; else g_uploads = upl->next;
        /* Free upl and parts in real app */
        
        json_value_t *j = turbo_json_create_object();
        turbo_json_object_set_string(j, "bucket", bucket);
        turbo_json_object_set_string(j, "key", object);
        render_s3_xml(res, OK, TEMPLATE_COMPLETE_MULTIPART, j);
        
        turbo_json_serialize_free(manifest_str);
        turbo_free_json(&manifest_obj);
        turbo_free_json(&j);
        return;
    }

    send_s3_error(res, BAD_REQUEST, "InvalidRequest", "Missing required parameters.");
}


/* 
 * GET /
 * List all buckets
 */
void handle_list_buckets(Req *req, Res *res) {
    (void)req;
    json_value_t *root = turbo_json_create_object();
    json_value_t *buckets = turbo_json_create_array();

    bucket_t *curr = g_buckets;
    while (curr) {
        json_value_t *b = turbo_json_create_object();
        turbo_json_object_set_string(b, "name", curr->name);
        turbo_json_array_add(buckets, b);
        curr = curr->next;
    }
    turbo_json_object_add(root, "buckets", buckets);

    render_s3_xml(res, OK, TEMPLATE_LIST_ALL_MY_BUCKETS, root);
    turbo_free_json(&root);
}

/*
 * PUT /:bucket
 * Create a bucket
 */
void handle_create_bucket(Req *req, Res *res) {
    const char *name = get_params(req, "bucket");
    if (!name) {
        send_xml(res, BAD_REQUEST, "<Error><Code>InvalidBucketName</Code></Error>");
        return;
    }

    /* Check if exists */
    bucket_t *curr = g_buckets;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            send_xml(res, OK, ""); /* Already exists is OK in some S3 contexts or 409 Conflict */
            return;
        }
        curr = curr->next;
    }

    /* Add to list */
    bucket_t *new_bucket = (bucket_t *)malloc(sizeof(bucket_t));
    strncpy(new_bucket->name, name, sizeof(new_bucket->name) - 1);
    new_bucket->next = g_buckets;
    g_buckets = new_bucket;

    TLOG_INFO("Created bucket: {}", name);
    send_xml(res, OK, "");
}

/*
 * DELETE /:bucket
 * Delete a bucket
 */
void handle_delete_bucket(Req *req, Res *res) {
    const char *name = get_params(req, "bucket");
    if (!name) return;

    bucket_t **curr = &g_buckets;
    while (*curr) {
        if (strcmp((*curr)->name, name) == 0) {
            bucket_t *to_free = *curr;
            *curr = (*curr)->next;
            free(to_free);
            TLOG_INFO("Deleted bucket: {}", name);
            send_xml(res, NO_CONTENT, "");
            return;
        }
        curr = &(*curr)->next;
    }

    send_xml(res, NOT_FOUND, "<Error><Code>NoSuchBucket</Code></Error>");
}

/* 
 * HEAD /:bucket 
 * Check if bucket exists
 */
void handle_head_bucket(Req *req, Res *res) {
    const char *name = get_params(req, "bucket");
    bucket_t *curr = g_buckets;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            reply(res, OK, "application/xml", NULL, 0);
            return;
        }
        curr = curr->next;
    }
    reply(res, NOT_FOUND, "application/xml", NULL, 0);
}

/* 
 * GET /:bucket
 * List objects in a bucket
 */
void handle_list_objects(Req *req, Res *res) {
    const char *bucket = get_params(req, "bucket");
    const char *list_type = get_query(req, "list-type");
    const char *prefix = get_query(req, "prefix");
    
    char xml[2048];
    int pos = 0;
    
    if (list_type && strcmp(list_type, "2") == 0) {
        /* ListObjectsV2 */
        pos = snprintf(xml, sizeof(xml),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
            "  <Name>%s</Name>\n"
            "  <Prefix>%s</Prefix>\n"
            "  <KeyCount>0</KeyCount>\n"
            "  <MaxKeys>1000</MaxKeys>\n"
            "  <IsTruncated>false</IsTruncated>\n", bucket, prefix ? prefix : "");
    } else {
        /* ListObjectsV1 */
        pos = snprintf(xml, sizeof(xml),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
            "  <Name>%s</Name>\n"
            "  <Prefix>%s</Prefix>\n"
            "  <Marker></Marker>\n"
            "  <MaxKeys>1000</MaxKeys>\n"
            "  <IsTruncated>false</IsTruncated>\n", bucket, prefix ? prefix : "");
    }

    /* MOCK: In real P2P, query DHT for prefix and list entries */
    
    snprintf(xml + pos, sizeof(xml) - pos, "</ListBucketResult>");
    send_xml(res, OK, xml);
}

/* 
 * PUT /:bucket/:object
 */
void handle_put_object(Req *req, Res *res) {
    const char *bucket = get_params(req, "bucket");
    const char *object = get_params(req, "object");
    const char *copy_source = get_headers(req, "x-amz-copy-source");
    const char *part_num_str = get_query(req, "partNumber");
    const char *upload_id = get_query(req, "uploadId");
    
    if (!bucket || !object) {
        send_xml(res, BAD_REQUEST, "<Error><Code>InvalidRequest</Code></Error>");
        return;
    }

    if (upload_id && part_num_str) {
        /* Upload Part */
        int part_num = atoi(part_num_str);
        multipart_upload_t *upl = g_uploads;
        while (upl) {
            if (strcmp(upl->upload_id, upload_id) == 0) break;
            upl = upl->next;
        }

        if (!upl) {
            send_xml(res, NOT_FOUND, "<Error><Code>NoSuchUpload</Code></Error>");
            return;
        }

        /* Store part as a normal P2P file (shard) */
        char temp_path[256];
        snprintf(temp_path, sizeof(temp_path), "part_%s_%d.dat", upload_id, part_num);
        turbo_fs_buf_t buf = turbo_fs_buf_init(req->body, req->body_len);
        turbo_fs_write_file(temp_path, &buf);

        char content_hash[65];
        p2p_put_file(g_node, temp_path, content_hash);
        turbo_fs_unlink(temp_path);

        /* Log part */
        part_t *p = (part_t *)calloc(1, sizeof(part_t));
        p->part_number = part_num;
        strcpy(p->hash, content_hash);
        
        /* Insert in order */
        part_t **curr = &upl->parts;
        while (*curr && (*curr)->part_number < part_num) curr = &((*curr)->next);
        p->next = *curr;
        *curr = p;

        TLOG_INFO("Uploaded part {} for upload {} (Hash: {})", part_num, upload_id, content_hash);
        
        set_header(res, "ETag", content_hash);
        send_xml(res, OK, "");
        return;
    }

    char dht_key[512];
    make_dht_key(bucket, object, dht_key, sizeof(dht_key));

    if (copy_source) {
        /* CopyObject Logic */
        TLOG_INFO("COPY object: {} -> {}/{}", copy_source, bucket, object);
        
        /* copy_source is usually /bucket/object */
        const char *src_key = copy_source;
        if (src_key[0] == '/') src_key++;

        char content_hash[65];
        size_t len = sizeof(content_hash);
        
        /* Lookup source hash */
        int ret = p2p_dht_get(g_node, src_key, content_hash, &len);
        if (ret != P2P_OK) {
            send_xml(res, NOT_FOUND, "<Error><Code>NoSuchKey</Code></Error>");
            return;
        }

        /* Update target mapping in DHT */
        ret = p2p_dht_put(g_node, dht_key, content_hash, 65);
        if (ret != P2P_OK) {
            send_xml(res, INTERNAL_SERVER_ERROR, "<Error><Code>DHTError</Code></Error>");
            return;
        }

        send_xml(res, OK, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CopyObjectResult><LastModified>2026-01-26T00:00:00.000Z</LastModified></CopyObjectResult>");
        return;
    }

    /* Standard PutObject Logic */
    if (!req->body || req->body_len == 0) {
        send_xml(res, BAD_REQUEST, "<Error><Code>EmptyBody</Code></Error>");
        return;
    }

    TLOG_INFO("PUT object: {}/{}", bucket, object);

    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "tmp_%s_%s.dat", bucket, object);
    
    turbo_fs_buf_t buf = turbo_fs_buf_init(req->body, req->body_len);
    if (turbo_fs_write_file(temp_path, &buf) != 0) {
        send_xml(res, INTERNAL_SERVER_ERROR, "<Error><Code>InternalError</Code></Error>");
        return;
    }

    char content_hash[65];
    int ret = p2p_put_file(g_node, temp_path, content_hash);
    turbo_fs_unlink(temp_path);

    if (ret != P2P_OK) {
        send_xml(res, INTERNAL_SERVER_ERROR, "<Error><Code>P2PError</Code></Error>");
        return;
    }
    
    ret = p2p_dht_put(g_node, dht_key, content_hash, 65);
    if (ret != P2P_OK) {
        send_xml(res, INTERNAL_SERVER_ERROR, "<Error><Code>DHTError</Code></Error>");
        return;
    }

    set_header(res, "ETag", content_hash);
    send_xml(res, OK, "");
}

/* 
 * GET /:bucket/:object
 */
/* 
 * GET /:bucket/:object
 * Supports segmented parallel downloads via 'Range' header
 */
void handle_get_object(Req *req, Res *res) {
    const char *bucket = get_params(req, "bucket");
    const char *object = get_params(req, "object");
    const char *range_header = get_headers(req, "Range");

    if (!bucket || !object) {
        send_s3_error(res, BAD_REQUEST, "MissingParameter", "Bucket or Object name missing.");
        return;
    }

    TLOG_INFO("GET object: {}/{} (Range: {})", bucket, object, range_header ? range_header : "Full");

    char dht_key[512];
    make_dht_key(bucket, object, dht_key, sizeof(dht_key));

    char val[8192];
    size_t len = sizeof(val);
    
    int ret = p2p_dht_get(g_node, dht_key, val, &len);
    if (ret != P2P_OK) {
        send_s3_error(res, NOT_FOUND, "NoSuchKey", "The specified key does not exist.");
        return;
    }

    char final_path[256];
    snprintf(final_path, sizeof(final_path), "final_%llx",
             (unsigned long long)turbo_hrtime());

    if (strncmp(val, "SHARDS:", 7) == 0) {
        /* Reconstruct sharded file or handle Range */
        json_value_t *root = NULL;
        if (turbo_parse_json((uint8_t*)val + 7, strlen(val + 7), &root) == 0) {
            json_value_t *parts = turbo_json_object_get(root, "parts");
            if (parts && turbo_json_type(parts) == TURBO_JSON_ARRAY) {
                FILE *fp = fopen(final_path, "wb");
                if (fp) {
                    for (size_t i = 0; i < turbo_json_array_size(parts); i++) {
                        json_value_t *part = turbo_json_array_get(parts, i);
                        const char *hash = turbo_json_string(part);
                        if (hash) {
                            char part_path[256];
                            snprintf(part_path, sizeof(part_path), "shard_%s", hash);
                            p2p_get_file(g_node, hash, part_path);
                            
                            FILE *shard_fp = fopen(part_path, "rb");
                            if (shard_fp) {
                                char buffer[4096];
                                size_t n;
                                while ((n = fread(buffer, 1, sizeof(buffer), shard_fp)) > 0) {
                                    fwrite(buffer, 1, n, fp);
                                }
                                fclose(shard_fp);
                                turbo_fs_unlink(part_path);
                            }
                        }
                    }
                    fclose(fp);
                }
            }
            turbo_free_json(&root);
        }
    } else {
        p2p_get_file(g_node, val, final_path);
    }

    /* Handle HTTP Range */
    if (range_header && strncmp(range_header, "bytes=", 6) == 0) {
        long start = 0, end = 0;
        sscanf(range_header + 6, "%ld-%ld", &start, &end);
        
        /* In real S3, we would serve partial content with 206 status */
        /* Iris reply_file doesn't support ranges yet in this demo,
           so we would manually slice the file. */
        TLOG_INFO("Serving Range: {}-{}", start, end);
        /* Slice logic... left as exercise for performance */
    }

    if (reply_file(res, OK, "application/octet-stream", final_path) < 0) {
        send_s3_error(res, INTERNAL_SERVER_ERROR, "IOError", "Failed to serve the file pieces.");
    }
    
    turbo_fs_unlink(final_path);
}

/* 
 * HEAD /:bucket/:object
 */
void handle_head_object(Req *req, Res *res) {
    const char *bucket = get_params(req, "bucket");
    const char *object = get_params(req, "object");

    char dht_key[512];
    make_dht_key(bucket, object, dht_key, sizeof(dht_key));

    char content_hash[65];
    size_t len = sizeof(content_hash);
    
    int ret = p2p_dht_get(g_node, dht_key, content_hash, &len);
    if (ret != P2P_OK) {
        reply(res, NOT_FOUND, "application/xml", NULL, 0);
        return;
    }

    set_header(res, "ETag", content_hash);
    reply(res, OK, "application/octet-stream", NULL, 0);
}

/* 
 * DELETE /:bucket/:object
 */
void handle_delete_object(Req *req, Res *res) {
    const char *bucket = get_params(req, "bucket");
    const char *object = get_params(req, "object");

    TLOG_INFO("DELETE object: {}/{}", bucket, object);

    char dht_key[512];
    make_dht_key(bucket, object, dht_key, sizeof(dht_key));

    /* In this simple DT, putting NULL or empty might mean delete,
       depending on p2p_dht_put implementation. Usually DHTs have a TTL or explicit remove.
       For this demo, we'll just overwrite with empty. */
    p2p_dht_put(g_node, dht_key, "", 0);

    send_xml(res, NO_CONTENT, "");
}
    
 
int main(int argc, char **argv) {
    /* Initialize P2P Node */
    int port = 33333;
    const char *ip = "0.0.0.0";
    if (argc > 1) port = atoi(argv[1]);
 

    /* Initialize Logger */
    tlog_config_t log_config = {0};
    log_config.min_level = TURBO_LOG_LEVEL_INFO;
    tlog_t *logger = tlog_create(&log_config);
    if (logger) {
        turbo_file_sink_opts_t opts = {0};
        opts.path = "p2p_minio.log";
        turbo_log_sink_t *sink = turbo_sink_file_create(&opts);
        tlog_add_sink(logger, sink);
        
        turbo_console_sink_opts_t console_opts = {0};
        console_opts.output = stdout;
        console_opts.use_colors = 1;
        turbo_log_sink_t *console = turbo_sink_console_create(&console_opts);
        tlog_add_sink(logger, console);

        tlog_set_default(logger);
    }
    TLOG_INFO("Starting P2P Node on {}:{}...", ip, port);
    g_node = p2p_create(ip, port);
    if (!g_node) {
        TLOG_ERROR("Failed to create node");
        return 1;
    }

    /* Start P2P in non-blocking mode (so we can run Iris loop? 
       Iris typically takes over the main loop or runs on its own headers. 
       If Iris uses netcore loop, we should integrate them.
       Assuming Iris handles its own loop or uses standard libuv loop.) */
    
    /* For this example, we start P2P server background threads/loop if supported,
       OR we rely on P2P simply using netcore which uses libuv default loop.
       Iris also uses libuv default loop usually.
       So we just need to init services and run loop once. */

    if (p2p_start_nonblocking(g_node) != 0) {
        TLOG_ERROR("Failed to start P2P");
        return 1;
    }

    /* Initialize Iris Web Server */
    TLOG_INFO("Starting S3 Gateway on port 8080...");
    iris_app_t *app = iris_app_create();

    /* Register S3-like routes */
    iris_app_get(app, "/", handle_list_buckets);
    iris_app_get(app, "/:bucket", handle_list_objects);
    iris_app_put(app, "/:bucket", handle_create_bucket);
    iris_app_delete(app, "/:bucket", handle_delete_bucket);
    iris_app_route(app, "HEAD", "/:bucket", NO_MW, handle_head_bucket);

    iris_app_put(app, "/:bucket/:object", handle_put_object);
    iris_app_get(app, "/:bucket/:object", handle_get_object);
    iris_app_delete(app, "/:bucket/:object", handle_delete_object);
    iris_app_post(app, "/:bucket/:object", handle_multipart_control);
    iris_app_route(app, "HEAD", "/:bucket/:object", NO_MW, handle_head_object);

    /* Connect to a bootstrap peer if provided */
    /* Connect to a bootstrap peer if provided */
    if (argc > 3) {
        TLOG_INFO("Connecting to bootstrap {}:{}...", argv[2], atoi(argv[3]));
        p2p_connect(g_node, argv[2], atoi(argv[3]));
    }

    /* Run Loop */
    /* If both use the DEFAULT libuv loop, this is sufficient.
       If Iris wraps the loop run, we call iris_app_listen */
    iris_app_listen(app, 8080);
    
    /* Cleanup */
    p2p_destroy(g_node);
    iris_app_destroy(app);
    tlog_destroy(tlog_get_default());
    return 0;
}
