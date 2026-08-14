/*
 * j3ster - a minimal HTTP/3 client for testing RFC 9218 extensible
 *          priorities against an HTTP/3 server (e.g. nginx).
 *
 * Phase 1: perform a QUIC handshake and issue a single HTTP/3 GET request,
 *          optionally carrying a "priority" request header (RFC 9218), then
 *          print the response status, byte count and elapsed time.
 *
 * Built on ngtcp2 + nghttp3 + OpenSSL 3.5 native QUIC TLS (ngtcp2_crypto_ossl).
 * Portions adapted from the MIT-licensed ngtcp2 example simpleclient.c.
 *
 * This is a test tool, not production code: it favours clarity over
 * completeness and does minimal error recovery.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define J3_ALPN "\x2h3"

#define J3_MAX_REQUESTS 64

/*
 * QPACK stress traits.  Multiple traits combine (they are just booleans
 * that both nudge SETTINGS and mix into the request-header generator).
 */
#define J3_Q_INSERT       0x001  /* unique header names -> literal inserts */
#define J3_Q_REF_INSERT   0x002  /* repeated names + fresh values -> ref inserts */
#define J3_Q_DUPLICATE    0x004  /* identical (name,value) repeatedly */
#define J3_Q_LONG_VAL     0x008  /* inject 300-byte values (fast eviction) */
#define J3_Q_BLOCKED      0x010  /* qpack_blocked_streams>0, rapid submits */
#define J3_Q_EVICT        0x020  /* keep table pinned at capacity */
#define J3_Q_BIG_TABLE    0x040  /* advertise 64 KiB dtable to server */
#define J3_Q_ALL          (J3_Q_INSERT | J3_Q_REF_INSERT | J3_Q_DUPLICATE      \
                          | J3_Q_LONG_VAL | J3_Q_BLOCKED | J3_Q_EVICT          \
                          | J3_Q_BIG_TABLE)

#define J3_STRESS_MAX_CONCURRENT 96    /* keep some headroom below nginx's 128 */
#define J3_STRESS_MAX_HDRS       32
#define J3_STRESS_STABLE_POOL    8     /* # of "stable" repeated header names */

struct req_spec {
    const char *priority;    /* value of the priority header, or NULL */
    const char *path;        /* :path */
};

struct config {
    const char     *host;
    const char     *port;
    const char     *authority;   /* :authority header (host[:port]) */
    struct req_spec  reqs[J3_MAX_REQUESTS];
    int              nreqs;
    int              verbose;
    int              json;          /* emit machine-readable JSON output */
    uint64_t         conn_window;   /* connection-level initial_max_data */

    /* --- QPACK stress mode ---------------------------------------- */
    unsigned         q_traits;      /* bitmask of J3_Q_* (0 = stress off) */
    int              stress_total;  /* -N: total requests to submit */
    int              stress_hdrs;   /* -H: extra headers per request */
    int              dtable_cap;    /* -D: advertised qpack_max_dtable */
    int              encoder_cap;   /* -E: our own encoder max_dtable */
    int              blocked_streams; /* -B: qpack_blocked_streams */
    int              churn;         /* -C: reqs/conn before recycling (0=off) */
    int              dtable_cap_set;
    int              encoder_cap_set;
    int              blocked_streams_set;
};

/*
 * Number of evenly-spaced progress milestones recorded per stream, in
 * addition to first-byte and completion.  With J3_MILESTONES == 4 we sample
 * the 25%, 50%, 75% and 100% points, which is enough to reveal whether two
 * equally-urgent incremental streams advance in lockstep (interleaved) or one
 * drains before the other (sequential).
 */
#define J3_MILESTONES 4

struct request {
    int64_t      stream_id;
    uint64_t     recv_bytes;
    int          status;
    int          done;

    const char  *priority;       /* priority header value, or NULL */
    const char  *path;           /* :path */

    uint64_t     content_length; /* from content-length header, 0 if unknown */
    uint64_t     first_byte_ns;  /* timestamp of first DATA byte, 0 if none */
    uint64_t     milestone_ns[J3_MILESTONES];  /* time at 25/50/75/100% */

    uint64_t     finish_ns;      /* timestamp when the stream ended */
    int          finish_order;   /* 1-based completion order, 0 if unfinished */
};

struct client {
    ngtcp2_crypto_conn_ref conn_ref;

    int                    fd;
    int                    epfd;
    int                    timerfd;

    struct sockaddr_storage local_addr;
    socklen_t               local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t               remote_addrlen;

    SSL_CTX                *ssl_ctx;
    SSL                    *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;

    ngtcp2_conn            *conn;
    nghttp3_conn           *h3conn;

    ngtcp2_ccerr            last_error;

    struct config          *cfg;

    struct request          reqs[J3_MAX_REQUESTS];
    int                     nreqs;
    int                     ndone;
    int                     finish_counter;
    uint64_t                start_ns;

    int                     handshake_completed;
    int                     stop;

    /* --- QPACK stress runtime ------------------------------------ */
    int                     stress_submitted;        /* cumulative */
    int                     stress_done;             /* cumulative */
    int                     stress_errors;           /* cumulative */
    int                     stress_stream_blocked;   /* seen at least once */
    uint64_t                stress_counter;          /* monotonic req# for header gen */
    int                     conn_submitted;          /* this connection only */
    int                     conn_done;               /* this connection only */
    int                     conn_errors;             /* this connection only */
    int                     cycles;                  /* # of connections opened */
};


/* ---------------------------------------------------------------------- */

static uint64_t
timestamp(void)
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    return (uint64_t) tp.tv_sec * NGTCP2_SECONDS + (uint64_t) tp.tv_nsec;
}

static ngtcp2_conn *
get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    struct client *c = conn_ref->user_data;

    return c->conn;
}

static void
log_printf(void *user_data, const char *fmt, ...)
{
    va_list ap;
    (void) user_data;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static int
numeric_host_family(const char *hostname, int family)
{
    uint8_t dst[sizeof(struct in6_addr)];

    return inet_pton(family, hostname, dst) == 1;
}

static int
numeric_host(const char *hostname)
{
    return numeric_host_family(hostname, AF_INET)
           || numeric_host_family(hostname, AF_INET6);
}

/* ---------------------------------------------------------------------- */

static int
create_sock(struct client *c)
{
    struct addrinfo  hints = {};
    struct addrinfo *res, *rp;
    int              rv, fd = -1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    rv = getaddrinfo(c->cfg->host, c->cfg->port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) {
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    if (fd == -1) {
        fprintf(stderr, "could not connect to %s:%s\n",
                c->cfg->host, c->cfg->port);
        freeaddrinfo(res);
        return -1;
    }

    memcpy(&c->remote_addr, rp->ai_addr, rp->ai_addrlen);
    c->remote_addrlen = rp->ai_addrlen;

    c->local_addrlen = sizeof(c->local_addr);
    if (getsockname(fd, (struct sockaddr *) &c->local_addr,
                    &c->local_addrlen) == -1)
    {
        fprintf(stderr, "getsockname: %s\n", strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

    c->fd = fd;

    return 0;
}

/* ---------------------------------------------------------------------- */

static int
client_ssl_init(struct client *c)
{
    if (ngtcp2_crypto_ossl_init() != 0) {
        fprintf(stderr, "ngtcp2_crypto_ossl_init failed\n");
        return -1;
    }

    c->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (c->ssl_ctx == NULL) {
        fprintf(stderr, "SSL_CTX_new: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    SSL_CTX_set_min_proto_version(c->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(c->ssl_ctx, TLS1_3_VERSION);

    if (ngtcp2_crypto_ossl_ctx_new(&c->ossl_ctx, NULL) != 0) {
        fprintf(stderr, "ngtcp2_crypto_ossl_ctx_new failed\n");
        return -1;
    }

    c->ssl = SSL_new(c->ssl_ctx);
    if (c->ssl == NULL) {
        fprintf(stderr, "SSL_new: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    ngtcp2_crypto_ossl_ctx_set_ssl(c->ossl_ctx, c->ssl);

    if (ngtcp2_crypto_ossl_configure_client_session(c->ssl) != 0) {
        fprintf(stderr, "ngtcp2_crypto_ossl_configure_client_session failed\n");
        return -1;
    }

    SSL_set_app_data(c->ssl, &c->conn_ref);
    SSL_set_connect_state(c->ssl);
    SSL_set_alpn_protos(c->ssl, (const unsigned char *) J3_ALPN,
                        sizeof(J3_ALPN) - 1);

    if (!numeric_host(c->cfg->host)) {
        SSL_set_tlsext_host_name(c->ssl, c->cfg->host);
    }

    return 0;
}

/* ---------------------------------------------------------------------- */

static void
rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void) rand_ctx;

    if (RAND_bytes(dest, (int) destlen) != 1) {
        abort();
    }
}

static int
get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
    ngtcp2_stateless_reset_token *token, size_t cidlen, void *user_data)
{
    (void) conn;
    (void) user_data;

    if (RAND_bytes(cid->data, (int) cidlen) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if (RAND_bytes(token->data, sizeof(token->data)) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int http_consume(struct client *c, int64_t stream_id, size_t nconsumed);

static int
recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
    uint64_t offset, const uint8_t *data, size_t datalen, void *user_data,
    void *stream_user_data)
{
    struct client   *c = user_data;
    nghttp3_ssize    nconsumed;
    int              fin;
    (void) conn;
    (void) offset;
    (void) stream_user_data;

    fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;

    nconsumed = nghttp3_conn_read_stream(c->h3conn, stream_id, data, datalen,
                                         fin);
    if (nconsumed < 0) {
        fprintf(stderr, "nghttp3_conn_read_stream: %s\n",
                nghttp3_strerror((int) nconsumed));
        ngtcp2_ccerr_set_application_error(&c->last_error,
            nghttp3_err_infer_quic_app_error_code((int) nconsumed), NULL, 0);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (http_consume(c, stream_id, (size_t) nconsumed) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int
http_consume(struct client *c, int64_t stream_id, size_t nconsumed)
{
    ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, nconsumed);
    ngtcp2_conn_extend_max_offset(c->conn, nconsumed);

    return 0;
}

static int
acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
    uint64_t offset, uint64_t datalen, void *user_data,
    void *stream_user_data)
{
    struct client *c = user_data;
    int            rv;
    (void) conn;
    (void) offset;
    (void) stream_user_data;

    rv = nghttp3_conn_add_ack_offset(c->h3conn, stream_id, datalen);
    if (rv != 0) {
        fprintf(stderr, "nghttp3_conn_add_ack_offset: %s\n",
                nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int
stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
    uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    struct client *c = user_data;
    int            rv;
    (void) conn;
    (void) stream_user_data;

    if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
        app_error_code = NGHTTP3_H3_NO_ERROR;
    }

    rv = nghttp3_conn_close_stream(c->h3conn, stream_id, app_error_code);
    if (rv != 0) {
        fprintf(stderr, "nghttp3_conn_close_stream: %s\n",
                nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int
stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
    uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    struct client *c = user_data;
    (void) conn;
    (void) final_size;
    (void) app_error_code;
    (void) stream_user_data;

    if (c->h3conn) {
        nghttp3_conn_shutdown_stream_read(c->h3conn, stream_id);
    }

    return 0;
}

static int
extend_max_local_streams_bidi_cb(ngtcp2_conn *conn, uint64_t max_streams,
    void *user_data)
{
    (void) conn;
    (void) max_streams;
    (void) user_data;

    /* request submission is driven explicitly after handshake */
    return 0;
}

static int
extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id,
    uint64_t max_data, void *user_data, void *stream_user_data)
{
    struct client *c = user_data;
    int            rv;
    (void) conn;
    (void) max_data;
    (void) stream_user_data;

    rv = nghttp3_conn_unblock_stream(c->h3conn, stream_id);
    if (rv != 0) {
        fprintf(stderr, "nghttp3_conn_unblock_stream: %s\n",
                nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

/* ---------------------------------------------------------------------- */

static int
client_quic_init(struct client *c)
{
    ngtcp2_path                path;
    ngtcp2_callbacks           callbacks = {};
    ngtcp2_cid                 dcid, scid;
    ngtcp2_settings            settings;
    ngtcp2_transport_params    params;
    int                        rv;

    path.local.addr = (struct sockaddr *) &c->local_addr;
    path.local.addrlen = c->local_addrlen;
    path.remote.addr = (struct sockaddr *) &c->remote_addr;
    path.remote.addrlen = c->remote_addrlen;

    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.rand = rand_cb;
    callbacks.get_new_connection_id2 = get_new_connection_id_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx =
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data2 =
        ngtcp2_crypto_get_path_challenge_data2_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

    callbacks.recv_stream_data = recv_stream_data_cb;
    callbacks.acked_stream_data_offset = acked_stream_data_offset_cb;
    callbacks.stream_close = stream_close_cb;
    callbacks.stream_reset = stream_reset_cb;
    callbacks.extend_max_local_streams_bidi =
        extend_max_local_streams_bidi_cb;
    callbacks.extend_max_stream_data = extend_max_stream_data_cb;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    if (RAND_bytes(dcid.data, (int) dcid.datalen) != 1) {
        return -1;
    }

    scid.datalen = 8;
    if (RAND_bytes(scid.data, (int) scid.datalen) != 1) {
        return -1;
    }

    ngtcp2_settings_default(&settings);
    settings.initial_ts = timestamp();
    if (c->cfg->verbose) {
        settings.log_printf = log_printf;
    }

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = 0;
    params.initial_max_stream_data_bidi_local = 6 * 1024 * 1024;
    params.initial_max_stream_data_uni = 6 * 1024 * 1024;
    /*
     * Deliberately keep the connection-level window small relative to the
     * per-stream window so that concurrent downloads contend for the shared
     * MAX_DATA budget.  This is what exercises the server's stream scheduler
     * (RFC 9218 urgency ordering); with a huge connection window nothing ever
     * blocks on MAX_DATA and every stream's data is admitted at once.
     */
    params.initial_max_data = c->cfg->conn_window;

    rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path,
                                NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                &params, NULL, c);
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ossl_ctx);

    return 0;
}

/* ---------------------------------------------------------------------- */
/* nghttp3 callbacks                                                       */

static int
h3_recv_header_cb(nghttp3_conn *conn, int64_t stream_id, int32_t token,
    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
    void *conn_user_data, void *stream_user_data)
{
    struct client   *c = conn_user_data;
    struct request  *req = stream_user_data;
    nghttp3_vec      nv, vv;
    (void) conn;
    (void) stream_id;
    (void) flags;

    nv = nghttp3_rcbuf_get_buf(name);
    vv = nghttp3_rcbuf_get_buf(value);

    if (token == NGHTTP3_QPACK_TOKEN__STATUS && req) {
        req->status = atoi((const char *) vv.base);
    }

    if (token == NGHTTP3_QPACK_TOKEN_CONTENT_LENGTH && req) {
        req->content_length = strtoull((const char *) vv.base, NULL, 10);
    }

    if (c->cfg->verbose) {
        fprintf(stderr, "  %.*s: %.*s\n", (int) nv.len, nv.base,
                (int) vv.len, vv.base);
    }

    return 0;
}

static int
h3_recv_data_cb(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
    size_t datalen, void *conn_user_data, void *stream_user_data)
{
    struct client  *c = conn_user_data;
    struct request *req = stream_user_data;
    (void) conn;
    (void) data;

    if (req) {
        uint64_t  now = timestamp();

        if (req->first_byte_ns == 0) {
            req->first_byte_ns = now;
        }

        req->recv_bytes += datalen;

        /*
         * Stamp any progress milestones this chunk carries us past.  With a
         * known content-length we sample fixed 25/50/75/100% points; the
         * milestone timestamps expose interleaving because two lockstep
         * incremental streams reach the same fraction at nearly the same
         * time, whereas sequential streams reach them far apart.
         */
        if (req->content_length > 0) {
            int  m;

            for (m = 0; m < J3_MILESTONES; m++) {
                uint64_t  threshold =
                    req->content_length * (uint64_t) (m + 1) / J3_MILESTONES;

                if (req->milestone_ns[m] == 0
                    && req->recv_bytes >= threshold)
                {
                    req->milestone_ns[m] = now;
                }
            }
        }
    }

    /*
     * DATA frame payload is not counted as consumed by
     * nghttp3_conn_read_stream(), so credit both the stream- and
     * connection-level flow control here; otherwise the receive windows
     * fill up and the transfer stalls once the initial window is used.
     */
    ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(c->conn, datalen);

    return 0;
}

static int
h3_deferred_consume_cb(nghttp3_conn *conn, int64_t stream_id,
    size_t nconsumed, void *conn_user_data, void *stream_user_data)
{
    struct client *c = conn_user_data;
    (void) conn;
    (void) stream_user_data;

    ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, nconsumed);
    ngtcp2_conn_extend_max_offset(c->conn, nconsumed);

    return 0;
}

static int
h3_end_stream_cb(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data,
    void *stream_user_data)
{
    struct client  *c = conn_user_data;
    struct request *req = stream_user_data;
    (void) conn;
    (void) stream_id;

    if (c->cfg->q_traits) {
        c->stress_done++;
        c->conn_done++;
        if (c->stress_submitted >= c->cfg->stress_total
            && c->stress_done + c->stress_errors >= c->stress_submitted)
        {
            c->stop = 1;
        } else if (c->cfg->churn > 0
                   && c->conn_submitted >= c->cfg->churn
                   && c->conn_done + c->conn_errors >= c->conn_submitted)
        {
            /* churn: this connection has drained its quota -- recycle. */
            c->stop = 1;
        }
        return 0;
    }

    if (req && !req->done) {
        req->done = 1;
        req->finish_ns = timestamp();
        req->finish_order = ++c->finish_counter;
        c->ndone++;

        if (c->cfg->verbose) {
            fprintf(stderr, "[stream %" PRId64 "] complete order=%d\n",
                    stream_id, req->finish_order);
        }
    }

    if (c->ndone >= c->nreqs) {
        c->stop = 1;
    }

    return 0;
}

static int
h3_stop_sending_cb(nghttp3_conn *conn, int64_t stream_id,
    uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
    struct client *c = conn_user_data;
    (void) conn;
    (void) app_error_code;
    (void) stream_user_data;

    ngtcp2_conn_shutdown_stream_read(c->conn, 0, stream_id, app_error_code);

    return 0;
}

static int
h3_reset_stream_cb(nghttp3_conn *conn, int64_t stream_id,
    uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
    struct client *c = conn_user_data;
    (void) conn;
    (void) stream_user_data;

    ngtcp2_conn_shutdown_stream_write(c->conn, 0, stream_id, app_error_code);

    return 0;
}

static int
client_h3_init(struct client *c)
{
    nghttp3_settings   settings;
    nghttp3_callbacks  callbacks = {};
    int64_t            ctrl_id, qenc_id, qdec_id;
    int                rv;

    callbacks.recv_header = h3_recv_header_cb;
    callbacks.recv_data = h3_recv_data_cb;
    callbacks.deferred_consume = h3_deferred_consume_cb;
    callbacks.end_stream = h3_end_stream_cb;
    callbacks.stop_sending = h3_stop_sending_cb;
    callbacks.reset_stream = h3_reset_stream_cb;

    nghttp3_settings_default(&settings);

    if (c->cfg->q_traits) {
        /*
         * Advertise our decoder's tolerance to the peer.  Big-table trait
         * bumps this to 64 KiB so, if the server's http3_max_table_capacity
         * is raised too, larger elts arrays and longer eviction distances
         * get exercised.
         */
        settings.qpack_max_dtable_capacity =
            (c->cfg->q_traits & J3_Q_BIG_TABLE) ? (64 * 1024)
                                                : c->cfg->dtable_cap;

        /*
         * The encoder's advertised max_dtable_capacity feeds MaxEntries in
         * the QPACK section-prefix RIC encoding (RFC 9204 4.5.1.1).  The
         * server derives MaxEntries from its own SETTINGS_QPACK_MAX_TABLE_
         * CAPACITY, so unless our encoder capacity matches the peer's
         * advertised value the two sides disagree on MaxEntries and every
         * prefix decode fails with "negative base".  Also, if our encoder
         * capacity is greater than the peer's advertised value we'll issue
         * a Set Capacity that the peer rejects with H3_QPACK_ENCODER_STREAM_
         * ERROR.  By default we assume the peer advertises the same value
         * we do (dtable_cap), which holds for stock nginx (both 4096).
         * Use -E to override when the peer advertises something different.
         */
        settings.qpack_encoder_max_dtable_capacity =
            (unsigned) (c->cfg->encoder_cap_set
                        ? c->cfg->encoder_cap
                        : (int) settings.qpack_max_dtable_capacity);

        settings.qpack_blocked_streams =
            (c->cfg->q_traits & J3_Q_BLOCKED)
                ? (unsigned) c->cfg->blocked_streams : 0;

        settings.qpack_indexing_strat = NGHTTP3_QPACK_INDEXING_STRAT_EAGER;
    }

    rv = nghttp3_conn_client_new(&c->h3conn, &callbacks, &settings, NULL, c);
    if (rv != 0) {
        fprintf(stderr, "nghttp3_conn_client_new: %s\n", nghttp3_strerror(rv));
        return -1;
    }

    rv = ngtcp2_conn_open_uni_stream(c->conn, &ctrl_id, NULL);
    if (rv != 0) {
        fprintf(stderr, "open ctrl stream: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    rv = nghttp3_conn_bind_control_stream(c->h3conn, ctrl_id);
    if (rv != 0) {
        fprintf(stderr, "bind_control_stream: %s\n", nghttp3_strerror(rv));
        return -1;
    }

    rv = ngtcp2_conn_open_uni_stream(c->conn, &qenc_id, NULL);
    if (rv != 0) {
        fprintf(stderr, "open qpack enc stream: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    rv = ngtcp2_conn_open_uni_stream(c->conn, &qdec_id, NULL);
    if (rv != 0) {
        fprintf(stderr, "open qpack dec stream: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    rv = nghttp3_conn_bind_qpack_streams(c->h3conn, qenc_id, qdec_id);
    if (rv != 0) {
        fprintf(stderr, "bind_qpack_streams: %s\n", nghttp3_strerror(rv));
        return -1;
    }

    return 0;
}

/* ---------------------------------------------------------------------- */

#define MAKE_NV(NAME, VALUE)                                                   \
    {                                                                         \
        (uint8_t *) (NAME), (uint8_t *) (VALUE), sizeof(NAME) - 1,            \
        strlen(VALUE), NGHTTP3_NV_FLAG_NONE                                   \
    }

static int
client_submit_one(struct client *c, struct request *req)
{
    int64_t      stream_id;
    int          rv;
    size_t       nvlen;
    nghttp3_nv   nva[5];

    rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, req);
    if (rv != 0) {
        fprintf(stderr, "open bidi stream: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    req->stream_id = stream_id;

    nva[0] = (nghttp3_nv) MAKE_NV(":method", "GET");
    nva[1] = (nghttp3_nv) MAKE_NV(":scheme", "https");
    nva[2] = (nghttp3_nv) MAKE_NV(":authority", c->cfg->authority);
    nva[3] = (nghttp3_nv) MAKE_NV(":path", req->path);
    nvlen = 4;

    if (req->priority) {
        nva[4] = (nghttp3_nv) MAKE_NV("priority", req->priority);
        nvlen = 5;
    }

    rv = nghttp3_conn_submit_request(c->h3conn, stream_id, nva, nvlen, NULL,
                                     req);
    if (rv != 0) {
        fprintf(stderr, "nghttp3_conn_submit_request: %s\n",
                nghttp3_strerror(rv));
        return -1;
    }

    if (c->cfg->verbose) {
        fprintf(stderr, "[stream %" PRId64 "] GET %s priority=%s\n",
                stream_id, req->path, req->priority ? req->priority : "(none)");
    }

    return 0;
}

static int
client_submit_requests(struct client *c)
{
    int i;

    for (i = 0; i < c->nreqs; i++) {
        if (client_submit_one(c, &c->reqs[i]) != 0) {
            return -1;
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------- */
/* QPACK stress mode                                                      */

/*
 * Fill headers for the (n+1)-th stress request into caller-provided
 * name[]/value[] buffers, and set nva[] with pointers into them.  Returns
 * the number of headers populated.  The caller-provided buffers must be
 * sized:
 *
 *     name[MAX][64], value[MAX][MAX_VALLEN]
 *
 * where MAX >= 4 pseudo + cfg->stress_hdrs + 1 (longval slot).
 */
#define J3_STRESS_NAMELEN  64
#define J3_STRESS_VALLEN   320   /* room for a 300-byte long value + NUL */

static size_t
client_stress_build_headers(struct client *c, uint64_t seq,
    nghttp3_nv *nva, size_t nva_cap,
    char (*name)[J3_STRESS_NAMELEN], char (*value)[J3_STRESS_VALLEN])
{
    unsigned  traits = c->cfg->q_traits;
    int       n_extra = c->cfg->stress_hdrs;
    size_t    n = 0;
    int       j;

    /* pseudo-headers first (nghttp3 requires this order) */
#define PUT_LITERAL(NAME, VAL)                                                 \
    do {                                                                       \
        nva[n].name = (uint8_t *) NAME;                                        \
        nva[n].namelen = sizeof(NAME) - 1;                                     \
        nva[n].value = (uint8_t *) VAL;                                        \
        nva[n].valuelen = strlen(VAL);                                         \
        nva[n].flags = NGHTTP3_NV_FLAG_NONE;                                   \
        n++;                                                                   \
    } while (0)

    PUT_LITERAL(":method",    "GET");
    PUT_LITERAL(":scheme",    "https");
    PUT_LITERAL(":authority", c->cfg->authority);
    PUT_LITERAL(":path",      "/");
#undef PUT_LITERAL

    /*
     * With EVICT trait, roughly double the header count so we blow past
     * the table capacity every request.
     */
    if (traits & J3_Q_EVICT) {
        n_extra *= 2;
    }
    if (n_extra > (int) nva_cap - (int) n - 1) {
        n_extra = (int) nva_cap - (int) n - 1;
    }

    for (j = 0; j < n_extra && n < nva_cap; j++, n++) {
        int  use_stable;
        int  use_dup;

        /*
         * Trait mixing rules (evaluated left-to-right; first match wins):
         *   duplicate -> same (name,value) drawn from a small pool -> encourages
         *                Duplicate on the encoder stream once the entry is
         *                about to be evicted.
         *   ref-insert -> stable name pool, varying value -> Insert With Name
         *                 Reference.
         *   insert / evict -> unique name -> Literal With Name Reference / Insert.
         *
         * When multiple traits are active we split the extra headers across
         * them by taking j modulo the number of enabled traits.
         */
        use_dup    = (traits & J3_Q_DUPLICATE) && (j % 4 == 0);
        use_stable = (traits & J3_Q_REF_INSERT) && !use_dup && (j % 3 == 0);

        if (use_dup) {
            int slot = j % J3_STRESS_STABLE_POOL;
            snprintf(name[n], J3_STRESS_NAMELEN, "x-dup-%d", slot);
            snprintf(value[n], J3_STRESS_VALLEN, "dup-value-%d", slot);
        } else if (use_stable) {
            int slot = (int) (seq + j) % J3_STRESS_STABLE_POOL;
            snprintf(name[n], J3_STRESS_NAMELEN, "x-stable-%d", slot);
            snprintf(value[n], J3_STRESS_VALLEN, "sv-%d-%lu",
                     slot, (unsigned long) (seq & 0xffff));
        } else {
            /* insert / evict / fallback: unique name + value */
            snprintf(name[n], J3_STRESS_NAMELEN,
                     "x-uniq-%lu-%d", (unsigned long) seq, j);
            snprintf(value[n], J3_STRESS_VALLEN,
                     "val-%lu-%d", (unsigned long) seq, j);
        }

        nva[n].name = (uint8_t *) name[n];
        nva[n].namelen = strlen(name[n]);
        nva[n].value = (uint8_t *) value[n];
        nva[n].valuelen = strlen(value[n]);
        /* Nudge the encoder to try to index custom fields. */
        nva[n].flags = NGHTTP3_NV_FLAG_TRY_INDEX;
    }

    /*
     * Every 7th request, when LONG_VAL is enabled, tack on a header with a
     * 300-byte value: this fills the dtable quickly and forces evictions.
     */
    if ((traits & J3_Q_LONG_VAL) && (seq % 7 == 0) && n < nva_cap) {
        snprintf(name[n], J3_STRESS_NAMELEN, "x-long-%lu",
                 (unsigned long) seq);
        memset(value[n], 'A', 300);
        value[n][300] = '\0';
        nva[n].name = (uint8_t *) name[n];
        nva[n].namelen = strlen(name[n]);
        nva[n].value = (uint8_t *) value[n];
        nva[n].valuelen = 300;
        nva[n].flags = NGHTTP3_NV_FLAG_TRY_INDEX;
        n++;
    }

    return n;
}

/*
 * Submit a single stress request.  Returns:
 *    1  request submitted
 *    0  stream-id limit reached (peer flow control) -- try again later
 *   -1  fatal error
 */
static int
client_stress_submit_one(struct client *c)
{
    int64_t     stream_id;
    int         rv;
    size_t      nvlen;
    nghttp3_nv  nva[4 + J3_STRESS_MAX_HDRS + 1];
    char        name[4 + J3_STRESS_MAX_HDRS + 1][J3_STRESS_NAMELEN];
    char        value[4 + J3_STRESS_MAX_HDRS + 1][J3_STRESS_VALLEN];

    rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
        c->stress_stream_blocked = 1;
        return 0;
    }
    if (rv != 0) {
        fprintf(stderr, "stress open bidi stream: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    nvlen = client_stress_build_headers(c, c->stress_counter, nva,
                                        sizeof(nva) / sizeof(nva[0]),
                                        name, value);

    rv = nghttp3_conn_submit_request(c->h3conn, stream_id, nva, nvlen, NULL,
                                     NULL);
    if (rv != 0) {
        fprintf(stderr, "stress submit_request: %s\n", nghttp3_strerror(rv));
        c->stress_errors++;
        c->conn_errors++;
        return -1;
    }

    c->stress_counter++;
    c->stress_submitted++;
    c->conn_submitted++;
    return 1;
}

/*
 * Called from the run loop after each read/write cycle.  Submits more
 * stress requests up to J3_STRESS_MAX_CONCURRENT outstanding streams, or
 * until we've hit the target total.
 */
static int
client_stress_pump(struct client *c)
{
    int  outstanding;
    int  rv;

    if (c->cfg->q_traits == 0 || !c->handshake_completed) {
        return 0;
    }

    for (;;) {
        if (c->stress_submitted >= c->cfg->stress_total) {
            return 0;
        }
        if (c->cfg->churn > 0 && c->conn_submitted >= c->cfg->churn) {
            /* wait for this connection's outstanding to drain, then stop */
            return 0;
        }

        outstanding = c->stress_submitted - c->stress_done - c->stress_errors;
        if (outstanding >= J3_STRESS_MAX_CONCURRENT) {
            return 0;
        }

        rv = client_stress_submit_one(c);
        if (rv < 0) {
            return -1;
        }
        if (rv == 0) {
            /* stream-id blocked; will be retried after peer grants more */
            return 0;
        }

        /*
         * With BLOCKED trait we rapid-fire submits without letting the
         * write() drain per request -- this maximises the window in which
         * references can point at un-ACKed inserts.  Without it, cap the
         * submit batch to avoid starving the write path.
         */
        if (!(c->cfg->q_traits & J3_Q_BLOCKED)
            && (c->stress_submitted % 16) == 0)
        {
            return 0;
        }
    }
}

static void
client_stress_report(struct client *c, uint64_t elapsed_us)
{
    double  secs = elapsed_us / 1000000.0;
    double  rps  = secs > 0 ? c->stress_done / secs : 0.0;

    if (c->cfg->json) {
        printf("{ \"mode\": \"qpack-stress\","
               " \"traits\": %u,"
               " \"target\": %d,"
               " \"submitted\": %d,"
               " \"done\": %d,"
               " \"errors\": %d,"
               " \"stream_blocked\": %d,"
               " \"cycles\": %d,"
               " \"elapsed_us\": %" PRIu64 ","
               " \"rps\": %.1f }\n",
               c->cfg->q_traits, c->cfg->stress_total,
               c->stress_submitted, c->stress_done, c->stress_errors,
               c->stress_stream_blocked, c->cycles, elapsed_us, rps);
    } else {
        printf("stress: traits=0x%03x target=%d submitted=%d done=%d "
               "errors=%d stream_blocked=%d cycles=%d elapsed=%.3fs "
               "rps=%.1f\n",
               c->cfg->q_traits, c->cfg->stress_total, c->stress_submitted,
               c->stress_done, c->stress_errors, c->stress_stream_blocked,
               c->cycles,
               secs, rps);
    }
}

/*
 * Return 1 iff |arg| is a syntactically valid comma-separated list of known
 * QPACK stress trait names.  Used to decide whether a bare "-Q" should
 * consume the following argv element (getopt's "::" syntax only accepts the
 * no-space form; this lets us also honour "-Q insert,evict").
 */
static int
looks_like_q_traits(const char *arg)
{
    static const char *const names[] = {
        "insert", "ref-insert", "duplicate", "long-val",
        "blocked", "evict", "big-table", "all", NULL
    };
    char        buf[256];
    char       *p, *tok, *save;
    size_t      len;
    int         i;

    if (arg == NULL || *arg == '\0') {
        return 0;
    }
    len = strlen(arg);
    if (len >= sizeof(buf)) {
        return 0;
    }
    memcpy(buf, arg, len + 1);

    p = buf;
    while ((tok = strtok_r(p, ",", &save)) != NULL) {
        p = NULL;
        for (i = 0; names[i]; i++) {
            if (strcmp(tok, names[i]) == 0) {
                break;
            }
        }
        if (names[i] == NULL) {
            return 0;
        }
    }
    return 1;
}

/*
 * Parse a comma-separated list of QPACK stress traits.  An empty string
 * (or NULL) means "all".
 */
static int
parse_q_traits(struct config *cfg, const char *arg)
{
    static const struct {
        const char *name;
        unsigned    bit;
    } table[] = {
        { "insert",     J3_Q_INSERT },
        { "ref-insert", J3_Q_REF_INSERT },
        { "duplicate",  J3_Q_DUPLICATE },
        { "long-val",   J3_Q_LONG_VAL },
        { "blocked",    J3_Q_BLOCKED },
        { "evict",      J3_Q_EVICT },
        { "big-table",  J3_Q_BIG_TABLE },
        { "all",        J3_Q_ALL },
        { NULL, 0 }
    };
    char       buf[256];
    char      *p, *tok, *save;
    size_t     len;
    int        i;

    if (arg == NULL || *arg == '\0') {
        cfg->q_traits |= J3_Q_ALL;
        return 0;
    }

    len = strlen(arg);
    if (len >= sizeof(buf)) {
        fprintf(stderr, "-Q argument too long\n");
        return -1;
    }
    memcpy(buf, arg, len + 1);

    p = buf;
    while ((tok = strtok_r(p, ",", &save)) != NULL) {
        p = NULL;
        for (i = 0; table[i].name; i++) {
            if (strcmp(tok, table[i].name) == 0) {
                cfg->q_traits |= table[i].bit;
                break;
            }
        }
        if (table[i].name == NULL) {
            fprintf(stderr, "unknown -Q trait \"%s\"\n", tok);
            return -1;
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------- */

static int
client_send_packet(struct client *c, const uint8_t *data, size_t datalen)
{
    ssize_t nwrite;

    do {
        nwrite = send(c->fd, data, datalen, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        fprintf(stderr, "send: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int
client_write(struct client *c)
{
    uint8_t              buf[1452];
    ngtcp2_tstamp        ts = timestamp();
    ngtcp2_path_storage  ps;
    ngtcp2_pkt_info      pi;
    ngtcp2_ssize         nwrite, wdatalen;
    uint32_t             flags;
    int64_t              stream_id;
    nghttp3_vec          vec[16];
    nghttp3_ssize        sveccnt;
    int                  fin, rv;

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        stream_id = -1;
        fin = 0;
        sveccnt = 0;

        if (c->h3conn && ngtcp2_conn_get_max_data_left(c->conn)) {
            sveccnt = nghttp3_conn_writev_stream(c->h3conn, &stream_id, &fin,
                                                 vec, 16);
            if (sveccnt < 0) {
                fprintf(stderr, "nghttp3_conn_writev_stream: %s\n",
                        nghttp3_strerror((int) sveccnt));
                return -1;
            }
        }

        flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if (fin) {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }

        nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf,
                                           sizeof(buf), &wdatalen, flags,
                                           stream_id,
                                           (const ngtcp2_vec *) vec,
                                           (size_t) sveccnt, ts);
        if (nwrite < 0) {
            switch (nwrite) {
            case NGTCP2_ERR_WRITE_MORE:
                rv = nghttp3_conn_add_write_offset(c->h3conn, stream_id,
                                                   (size_t) wdatalen);
                if (rv != 0) {
                    fprintf(stderr, "nghttp3_conn_add_write_offset: %s\n",
                            nghttp3_strerror(rv));
                    return -1;
                }
                continue;

            case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                nghttp3_conn_block_stream(c->h3conn, stream_id);
                continue;

            default:
                fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
                        ngtcp2_strerror((int) nwrite));
                ngtcp2_ccerr_set_liberr(&c->last_error, (int) nwrite, NULL, 0);
                return -1;
            }
        }

        if (sveccnt > 0 && wdatalen >= 0) {
            rv = nghttp3_conn_add_write_offset(c->h3conn, stream_id,
                                               (size_t) wdatalen);
            if (rv != 0) {
                fprintf(stderr, "nghttp3_conn_add_write_offset: %s\n",
                        nghttp3_strerror(rv));
                return -1;
            }
        }

        if (nwrite == 0) {
            return 0;
        }

        if (client_send_packet(c, buf, (size_t) nwrite) != 0) {
            return -1;
        }
    }

    return 0;
}

static int
client_read(struct client *c)
{
    uint8_t          buf[65536];
    ssize_t          nread;
    ngtcp2_path      path;
    ngtcp2_pkt_info  pi = {};
    int              rv;

    for (;;) {
        nread = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (nread == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "recv: %s\n", strerror(errno));
            }
            break;
        }

        path.local.addr = (struct sockaddr *) &c->local_addr;
        path.local.addrlen = c->local_addrlen;
        path.remote.addr = (struct sockaddr *) &c->remote_addr;
        path.remote.addrlen = c->remote_addrlen;

        rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t) nread,
                                  timestamp());
        if (rv != 0) {
            fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
            if (!c->last_error.error_code) {
                if (rv == NGTCP2_ERR_CRYPTO) {
                    ngtcp2_ccerr_set_tls_alert(&c->last_error,
                        ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
                } else {
                    ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
                }
            }
            return -1;
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------- */

static void
arm_timer(struct client *c)
{
    ngtcp2_tstamp       expiry, now;
    struct itimerspec   its = {};
    uint64_t            ns;

    expiry = ngtcp2_conn_get_expiry(c->conn);
    now = timestamp();

    ns = (expiry <= now) ? 1 : (expiry - now);

    its.it_value.tv_sec = ns / NGTCP2_SECONDS;
    its.it_value.tv_nsec = ns % NGTCP2_SECONDS;

    timerfd_settime(c->timerfd, 0, &its, NULL);
}

static int
run(struct client *c)
{
    struct epoll_event  ev, events[4];
    int                 n, i;

    c->epfd = epoll_create1(0);
    c->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

    ev.events = EPOLLIN;
    ev.data.fd = c->fd;
    epoll_ctl(c->epfd, EPOLL_CTL_ADD, c->fd, &ev);

    ev.data.fd = c->timerfd;
    epoll_ctl(c->epfd, EPOLL_CTL_ADD, c->timerfd, &ev);

    if (client_write(c) != 0) {
        return -1;
    }
    arm_timer(c);

    while (!c->stop) {
        n = epoll_wait(c->epfd, events, 4, 1000);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
            return -1;
        }

        for (i = 0; i < n; i++) {
            if (events[i].data.fd == c->fd) {
                if (client_read(c) != 0) {
                    return -1;
                }
            } else if (events[i].data.fd == c->timerfd) {
                uint64_t exp;
                ssize_t r = read(c->timerfd, &exp, sizeof(exp));
                (void) r;

                if (ngtcp2_conn_handle_expiry(c->conn, timestamp()) != 0) {
                    fprintf(stderr, "handle_expiry failed\n");
                    return -1;
                }
            }
        }

        /* after handshake completes, set up h3 and submit requests */
        if (!c->handshake_completed
            && ngtcp2_conn_get_handshake_completed(c->conn))
        {
            c->handshake_completed = 1;

            if (client_h3_init(c) != 0) {
                return -1;
            }
            if (c->cfg->q_traits == 0) {
                if (client_submit_requests(c) != 0) {
                    return -1;
                }
            }
        }

        /* stress mode: keep the pipeline full */
        if (c->cfg->q_traits && c->handshake_completed) {
            if (client_stress_pump(c) != 0) {
                return -1;
            }
        }

        if (client_write(c) != 0) {
            return -1;
        }
        arm_timer(c);
    }

    return 0;
}

/*
 * Release everything created for a single connection cycle so the client
 * struct can be reused by run() for a fresh connection.  Cumulative stress
 * counters (stress_submitted, stress_done, ...) are preserved; per-connection
 * counters and the handshake/stop flags are reset.
 */
static void
client_teardown(struct client *c)
{
    if (c->h3conn) {
        nghttp3_conn_del(c->h3conn);
        c->h3conn = NULL;
    }
    if (c->conn) {
        ngtcp2_conn_del(c->conn);
        c->conn = NULL;
    }
    if (c->ssl) {
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->ossl_ctx) {
        ngtcp2_crypto_ossl_ctx_del(c->ossl_ctx);
        c->ossl_ctx = NULL;
    }
    if (c->ssl_ctx) {
        SSL_CTX_free(c->ssl_ctx);
        c->ssl_ctx = NULL;
    }
    if (c->epfd > 0) {
        close(c->epfd);
        c->epfd = -1;
    }
    if (c->timerfd > 0) {
        close(c->timerfd);
        c->timerfd = -1;
    }
    if (c->fd > 0) {
        close(c->fd);
        c->fd = 0;
    }

    memset(&c->last_error, 0, sizeof(c->last_error));
    memset(&c->local_addr, 0, sizeof(c->local_addr));
    memset(&c->remote_addr, 0, sizeof(c->remote_addr));
    c->local_addrlen = 0;
    c->remote_addrlen = 0;
    c->handshake_completed = 0;
    c->stop = 0;
    c->conn_submitted = 0;
    c->conn_done = 0;
    c->conn_errors = 0;
}

/* ---------------------------------------------------------------------- */
/* output                                                                  */

/* milliseconds since the connection start, or -1 if the event never fired */
static double
rel_ms(uint64_t event_ns, uint64_t start_ns)
{
    if (event_ns == 0) {
        return -1.0;
    }

    return (double) (event_ns - start_ns) / 1000000.0;
}

/*
 * Fill order[] with request indices sorted by completion: finished streams
 * first (in the order they finished), then any unfinished streams in send
 * order.  This lets the report read top-to-bottom from first-to-finish to
 * last, matching the "completion order" heading.
 */
static void
completion_order(struct client *c, int *order)
{
    int  i, n;

    n = 0;

    /* finished streams, ascending finish_order (1-based) */

    for (int fo = 1; fo <= c->nreqs; fo++) {
        for (i = 0; i < c->nreqs; i++) {
            if (c->reqs[i].finish_order == fo) {
                order[n++] = i;
                break;
            }
        }
    }

    /* any streams that never finished, in send order */

    for (i = 0; i < c->nreqs; i++) {
        if (c->reqs[i].finish_order == 0) {
            order[n++] = i;
        }
    }
}

static void
print_text_report(struct client *c, uint64_t elapsed_us)
{
    int              i, m;
    int              order[J3_MAX_REQUESTS];
    struct request  *r;

    if (c->nreqs == 1) {
        r = &c->reqs[0];
        printf("status=%d bytes=%" PRIu64 " time=%.3fms priority=%s\n",
               r->status, r->recv_bytes,
               (double) elapsed_us / 1000.0,
               r->priority ? r->priority : "(none)");
        return;
    }

    completion_order(c, order);

    printf("total time=%.3fms  (completion order below)\n",
           (double) elapsed_us / 1000.0);
    printf("%-6s %-4s %-7s %-9s %-7s %-10s %s\n",
           "order", "sent", "stream", "priority", "status", "bytes", "path");

    for (i = 0; i < c->nreqs; i++) {
        double  ms;

        r = &c->reqs[order[i]];
        ms = rel_ms(r->finish_ns, c->start_ns);

        printf("%-6d %-4d %-7" PRId64 " %-9s %-7d %-10" PRIu64 " %s",
               r->finish_order, order[i] + 1, r->stream_id,
               r->priority ? r->priority : "(none)",
               r->status, r->recv_bytes, r->path);
        if (ms >= 0) {
            printf("  (%.3fms)", ms);
        }
        printf("\n");
    }

    /*
     * Progress timeline: time (ms) to first byte and to each 25% milestone.
     * Reading down a column shows the relative pace of the streams: equally
     * urgent incremental streams reach a given milestone at about the same
     * time (interleaved), whereas non-incremental streams reach it one after
     * another (sequential).
     */
    printf("\nprogress (ms to first byte / 25%% / 50%% / 75%% / 100%%)\n");
    printf("%-4s %-7s %-9s %-9s %-9s %-9s %-9s %s\n",
           "sent", "stream", "priority", "first", "25%", "50%", "75%", "100%");

    for (i = 0; i < c->nreqs; i++) {
        r = &c->reqs[order[i]];

        printf("%-4d %-7" PRId64 " %-9s %-9.3f",
               order[i] + 1, r->stream_id,
               r->priority ? r->priority : "(none)",
               rel_ms(r->first_byte_ns, c->start_ns));

        for (m = 0; m < J3_MILESTONES; m++) {
            /* last column is not padded so the row has no trailing space */
            if (m == J3_MILESTONES - 1) {
                printf(" %.3f", rel_ms(r->milestone_ns[m], c->start_ns));
            } else {
                printf(" %-9.3f", rel_ms(r->milestone_ns[m], c->start_ns));
            }
        }
        printf("\n");
    }
}

static void
print_json_report(struct client *c, uint64_t elapsed_us)
{
    int              i, m;
    struct request  *r;

    printf("{\n");
    printf("  \"total_ms\": %.3f,\n", (double) elapsed_us / 1000.0);
    printf("  \"streams\": [\n");

    for (i = 0; i < c->nreqs; i++) {
        r = &c->reqs[i];

        printf("    {\n");
        printf("      \"sent_order\": %d,\n", i + 1);
        printf("      \"stream_id\": %" PRId64 ",\n", r->stream_id);
        printf("      \"priority\": %s%s%s,\n",
               r->priority ? "\"" : "",
               r->priority ? r->priority : "null",
               r->priority ? "\"" : "");
        printf("      \"path\": \"%s\",\n", r->path);
        printf("      \"status\": %d,\n", r->status);
        printf("      \"bytes\": %" PRIu64 ",\n", r->recv_bytes);
        printf("      \"content_length\": %" PRIu64 ",\n", r->content_length);
        printf("      \"finish_order\": %d,\n", r->finish_order);
        printf("      \"first_byte_ms\": %.3f,\n",
               rel_ms(r->first_byte_ns, c->start_ns));
        printf("      \"finish_ms\": %.3f,\n",
               rel_ms(r->finish_ns, c->start_ns));

        printf("      \"milestones_ms\": [");
        for (m = 0; m < J3_MILESTONES; m++) {
            printf("%s%.3f", m ? ", " : "",
                   rel_ms(r->milestone_ns[m], c->start_ns));
        }
        printf("]\n");

        printf("    }%s\n", (i + 1 < c->nreqs) ? "," : "");
    }

    printf("  ]\n");
    printf("}\n");
}

/* ---------------------------------------------------------------------- */

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [-v] [-j] [-p PRIORITY] [-r PRIORITY:PATH]... HOST PORT [PATH]\n"
        "       %s -Q [TRAITS] [-N N] [-H N] [-D BYTES] [-B N] HOST PORT\n"
        "  -v                verbose (per-stream + QUIC/header logging)\n"
        "  -j                emit machine-readable JSON (for the web demo)\n"
        "  -p PRIORITY       priority header for the single-request form,\n"
        "                    e.g. \"u=1,i\"\n"
        "  -r PRIORITY:PATH  add a concurrent request with the given RFC 9218\n"
        "                    priority and path; repeatable. Use an empty\n"
        "                    PRIORITY (\":/path\") to omit the header.\n"
        "  -w BYTES          connection flow-control window (initial_max_data),\n"
        "                    default 262144. A small window makes concurrent\n"
        "                    streams contend so the server's priority scheduler\n"
        "                    is exercised.\n"
        "  -Q [TRAITS]       enable QPACK stress mode. TRAITS is an optional\n"
        "                    comma-separated list; empty means \"all\". Traits:\n"
        "                      insert, ref-insert, duplicate, long-val,\n"
        "                      blocked, evict, big-table, all\n"
        "  -N N              stress: total requests to send (default 1000)\n"
        "  -H N              stress: extra headers per request (default 8)\n"
        "  -D BYTES          stress: advertised qpack_max_dtable_capacity\n"
        "                    (default 4096; 65536 with the big-table trait).\n"
        "                    Should match the peer's http3_max_table_capacity.\n"
        "  -E BYTES          stress: our encoder's own qpack_encoder_max_\n"
        "                    dtable_capacity. Defaults to match -D (which\n"
        "                    aligns MaxEntries with the peer). Override when\n"
        "                    the peer advertises a different value than we do.\n"
        "  -B N              stress: qpack_blocked_streams (default 100 with\n"
        "                    the blocked trait, otherwise 0)\n"
        "  -C N              stress: recycle the QUIC connection after N\n"
        "                    requests (0 = single connection). Useful when\n"
        "                    the server's keepalive_requests limit (nginx\n"
        "                    default 1000) caps a single connection.\n"
        "  PATH              request path for the single-request form"
        " (default \"/\")\n"
        "\n"
        "Examples:\n"
        "  %s 127.0.0.1 8443 /index.html\n"
        "  %s -p \"u=1,i\" 127.0.0.1 8443 /index.html\n"
        "  %s -r \"u=7:/big.bin\" -r \"u=1:/big.bin\" 127.0.0.1 8443\n"
        "  %s -Q -N 5000 127.0.0.1 8443\n"
        "  %s -Q -N 5000 -C 900 127.0.0.1 8443\n"
        "  %s -Q insert,evict,long-val -N 2000 127.0.0.1 8443\n",
        prog, prog, prog, prog, prog, prog, prog, prog);
}

static int
add_request(struct config *cfg, const char *priority, const char *path)
{
    if (cfg->nreqs >= J3_MAX_REQUESTS) {
        fprintf(stderr, "too many requests (max %d)\n", J3_MAX_REQUESTS);
        return -1;
    }

    cfg->reqs[cfg->nreqs].priority = (priority && *priority) ? priority : NULL;
    cfg->reqs[cfg->nreqs].path = path;
    cfg->nreqs++;

    return 0;
}

/* parse "PRIORITY:PATH" in place (mutates arg); PRIORITY may be empty */
static int
parse_req_spec(struct config *cfg, char *spec)
{
    char *colon;

    colon = strchr(spec, ':');
    if (colon == NULL) {
        fprintf(stderr, "invalid -r spec \"%s\" (want PRIORITY:PATH)\n", spec);
        return -1;
    }

    *colon = '\0';

    return add_request(cfg, spec, colon + 1);
}

int
main(int argc, char **argv)
{
    struct client  c = {};
    struct config  cfg = {};
    char           authority[256];
    const char    *single_priority = NULL;
    const char    *single_path = "/";
    int            opt, i;
    uint64_t       elapsed_us;

    cfg.conn_window = 256 * 1024;

    while ((opt = getopt(argc, argv, "vjp:r:w:Q::N:H:D:E:B:C:")) != -1) {
        switch (opt) {
        case 'v':
            cfg.verbose = 1;
            break;
        case 'j':
            cfg.json = 1;
            break;
        case 'p':
            single_priority = optarg;
            break;
        case 'r':
            if (parse_req_spec(&cfg, optarg) != 0) {
                return 1;
            }
            break;
        case 'w':
            cfg.conn_window = strtoull(optarg, NULL, 10);
            if (cfg.conn_window == 0) {
                fprintf(stderr, "invalid -w window\n");
                return 1;
            }
            break;
        case 'Q':
            {
                const char *q_arg = optarg;

                if (q_arg == NULL && optind < argc
                    && looks_like_q_traits(argv[optind]))
                {
                    q_arg = argv[optind++];
                }
                if (parse_q_traits(&cfg, q_arg) != 0) {
                    return 1;
                }
            }
            break;
        case 'N':
            cfg.stress_total = atoi(optarg);
            if (cfg.stress_total <= 0) {
                fprintf(stderr, "invalid -N count\n");
                return 1;
            }
            break;
        case 'H':
            cfg.stress_hdrs = atoi(optarg);
            if (cfg.stress_hdrs < 0
                || cfg.stress_hdrs > J3_STRESS_MAX_HDRS)
            {
                fprintf(stderr, "invalid -H count (0..%d)\n",
                        J3_STRESS_MAX_HDRS);
                return 1;
            }
            break;
        case 'D':
            cfg.dtable_cap = atoi(optarg);
            cfg.dtable_cap_set = 1;
            if (cfg.dtable_cap < 0) {
                fprintf(stderr, "invalid -D dtable capacity\n");
                return 1;
            }
            break;
        case 'E':
            cfg.encoder_cap = atoi(optarg);
            cfg.encoder_cap_set = 1;
            if (cfg.encoder_cap < 0) {
                fprintf(stderr, "invalid -E encoder capacity\n");
                return 1;
            }
            break;
        case 'B':
            cfg.blocked_streams = atoi(optarg);
            cfg.blocked_streams_set = 1;
            if (cfg.blocked_streams < 0) {
                fprintf(stderr, "invalid -B blocked_streams\n");
                return 1;
            }
            break;
        case 'C':
            cfg.churn = atoi(optarg);
            if (cfg.churn < 0) {
                fprintf(stderr, "invalid -C churn\n");
                return 1;
            }
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc - optind < 2) {
        usage(argv[0]);
        return 1;
    }

    cfg.host = argv[optind];
    cfg.port = argv[optind + 1];
    if (argc - optind >= 3) {
        single_path = argv[optind + 2];
    }

    /* QPACK stress: apply trait-driven defaults and skip the normal
     * per-request setup entirely. */
    if (cfg.q_traits) {
        if (cfg.stress_total == 0) {
            cfg.stress_total = 1000;
        }
        if (cfg.stress_hdrs == 0) {
            cfg.stress_hdrs = 8;
        }
        if (!cfg.dtable_cap_set) {
            cfg.dtable_cap = (cfg.q_traits & J3_Q_BIG_TABLE) ? (64 * 1024)
                                                             : 4096;
        }
        if (!cfg.blocked_streams_set) {
            cfg.blocked_streams = (cfg.q_traits & J3_Q_BLOCKED) ? 100 : 0;
        }
    } else if (cfg.nreqs == 0) {
        /* no -r specs were given -- synthesize a single request */
        if (add_request(&cfg, single_priority, single_path) != 0) {
            return 1;
        }
    }

    snprintf(authority, sizeof(authority), "%s:%s", cfg.host, cfg.port);
    cfg.authority = authority;

    c.cfg = &cfg;
    c.nreqs = cfg.nreqs;
    for (i = 0; i < c.nreqs; i++) {
        c.reqs[i].stream_id = -1;
        c.reqs[i].priority = cfg.reqs[i].priority;
        c.reqs[i].path = cfg.reqs[i].path;
    }

    c.conn_ref.get_conn = get_conn;
    c.conn_ref.user_data = &c;

    c.start_ns = timestamp();

    for (;;) {
        if (create_sock(&c) != 0) {
            return 1;
        }
        if (client_ssl_init(&c) != 0) {
            return 1;
        }
        if (client_quic_init(&c) != 0) {
            return 1;
        }

        if (run(&c) != 0) {
            fprintf(stderr, "request failed\n");
            /* still report partial progress in stress mode */
            if (cfg.q_traits) {
                c.cycles++;
                elapsed_us = (timestamp() - c.start_ns) / 1000;
                client_stress_report(&c, elapsed_us);
            }
            return 1;
        }

        c.cycles++;

        /* Only stress mode may need more connections. */
        if (!cfg.q_traits) {
            break;
        }
        if (c.stress_submitted >= cfg.stress_total) {
            break;
        }
        if (cfg.churn <= 0) {
            /* target not met but churn disabled -- give up gracefully */
            break;
        }

        client_teardown(&c);
    }

    elapsed_us = (timestamp() - c.start_ns) / 1000;

    if (cfg.q_traits) {
        client_stress_report(&c, elapsed_us);
    } else if (cfg.json) {
        print_json_report(&c, elapsed_us);
    } else {
        print_text_report(&c, elapsed_us);
    }

    return 0;
}
