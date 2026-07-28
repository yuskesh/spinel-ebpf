/*
 * otlp_grpc.c — 最小 HTTP/2 unary gRPC クライアント
 * 詳細は otlp_grpc.h を参照。HPACK は encode のみ (literal、Huffman/dynamic table なし)。
 */
#include "otlp_grpc.h"
#include "otlp_http.h"   /* otlp_http_post / otlp_http_parse_endpoint (HTTP 経路) */
#ifdef OTLP_WITH_TLS
#include "otlp_tls.h"    /* ADR-013 T2: grpcs:// (gRPC over TLS) — gated */
#endif

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

/* HTTP/2 frame types / flags */
#define H2_DATA     0x0
#define H2_HEADERS  0x1
#define H2_RSTSTREAM 0x3
#define H2_SETTINGS 0x4
#define H2_PING     0x6
#define H2_GOAWAY   0x7
#define H2_WINDOW_UPDATE 0x8
#define H2_FLAG_ACK         0x1
#define H2_FLAG_END_STREAM  0x1
#define H2_FLAG_END_HEADERS 0x4

static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static void set_err(char *err, size_t n, const char *m) { if (err && n) snprintf(err, n, "%s", m); }

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf; size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)n;
    }
    return 0;
}
static int read_full(int fd, void *buf, size_t len) {
    char *p = (char *)buf; size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return 1; /* EOF */
        off += (size_t)n;
    }
    return 0;
}

/* TLS handle (tls_h) があれば TLS、無ければ raw fd で I/O (ADR-013 T2、gated)。 */
static int io_write_all(void *tls_h, int fd, const void *buf, size_t len) {
#ifdef OTLP_WITH_TLS
    if (tls_h) return otlp_tls_write((otlp_tls_t *)tls_h, buf, len);
#endif
    (void)tls_h;
    return write_all(fd, buf, len);
}
static int io_read_full(void *tls_h, int fd, void *buf, size_t len) {
#ifdef OTLP_WITH_TLS
    if (tls_h) {
        unsigned char *p = (unsigned char *)buf; size_t off = 0;
        while (off < len) {
            int n = otlp_tls_read((otlp_tls_t *)tls_h, p + off, len - off);
            if (n == 0) return 1;   /* EOF */
            if (n < 0) return -1;
            off += (size_t)n;
        }
        return 0;
    }
#endif
    (void)tls_h;
    return read_full(fd, buf, len);
}
static void io_close(void *tls_h, int fd) {
#ifdef OTLP_WITH_TLS
    if (tls_h) otlp_tls_free((otlp_tls_t *)tls_h);
#endif
    (void)tls_h;
    close(fd);
}

static void put_be24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }
static void put_be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint32_t get_be24(const uint8_t *p) { return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2]; }
static uint32_t get_be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static int send_frame(void *tls_h, int fd, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid, const uint8_t *payload) {
    uint8_t h[9];
    put_be24(h, len); h[3] = type; h[4] = flags; put_be32(h + 5, sid & 0x7fffffff);
    if (io_write_all(tls_h, fd, h, 9)) return -1;
    if (len && io_write_all(tls_h, fd, payload, len)) return -1;
    return 0;
}

/* HPACK 7-bit-prefix 整数 (H=0) で文字列長を書く (>=127 も対応 → 長い auth token 可)。 */
static int hpack_strlen(uint8_t *buf, size_t cap, size_t *off, size_t len) {
    if (len < 127) {
        if (*off + 1 > cap) return -1;
        buf[(*off)++] = (uint8_t)len;
        return 0;
    }
    if (*off + 1 > cap) return -1;
    buf[(*off)++] = 0x7F;
    size_t v = len - 127;
    while (v >= 128) {
        if (*off + 1 > cap) return -1;
        buf[(*off)++] = (uint8_t)((v & 0x7F) | 0x80);
        v >>= 7;
    }
    if (*off + 1 > cap) return -1;
    buf[(*off)++] = (uint8_t)v;
    return 0;
}

/* HPACK: literal header field without indexing, new name, no Huffman。任意長 (auth token 等)。 */
static int hpack_lit(uint8_t *buf, size_t cap, size_t *off, const char *name, const char *val) {
    size_t nl = strlen(name), vl = strlen(val);
    if (*off + 1 > cap) return -1;
    buf[(*off)++] = 0x00;
    if (hpack_strlen(buf, cap, off, nl) || *off + nl > cap) return -1;
    memcpy(buf + *off, name, nl); *off += nl;
    if (hpack_strlen(buf, cap, off, vl) || *off + vl > cap) return -1;
    memcpy(buf + *off, val, vl); *off += vl;
    return 0;
}

static int connect_once(const char *host, const char *port, char *err, size_t errlen) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0) { set_err(err, errlen, gai_strerror(gai)); return -1; }
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) set_err(err, errlen, "connect failed");
    return fd;
}

int otlp_grpc_export(const char *host, const char *port, const char *grpc_path,
                     const uint8_t *body, size_t body_len, int tls, int max_retries,
                     int *ok, char *err, size_t errlen) {
    if (ok) *ok = 0;
    if (!host || !port || !grpc_path || (!body && body_len)) { set_err(err, errlen, "invalid argument"); return -1; }
    if (max_retries <= 0) max_retries = 5;

    int fd = -1;
    for (int a = 0; a < max_retries; a++) {
        fd = connect_once(host, port, err, errlen);
        if (fd >= 0) break;
        long ms = 100L << a; if (ms > 2000) ms = 2000;
        struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    if (fd < 0) return -1;

    /* recv にタイムアウト (応答待ちでハングしない) */
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* grpcs:// は HTTP/2 preface の前に TLS handshake (gated) */
    void *tls_h = NULL;
    if (tls) {
#ifdef OTLP_WITH_TLS
        tls_h = otlp_tls_connect(fd, host, "h2" /* gRPC-over-TLS は ALPN h2 必須 */, err, errlen);
        if (!tls_h) { io_close(tls_h, fd); return -1; }
#else
        set_err(err, errlen, "TLS (grpcs://) not compiled in — rebuild with mbedTLS (OTLP_WITH_TLS)");
        io_close(tls_h, fd); return -1;
#endif
    }

    /* 1) preface + 2) 空 SETTINGS */
    if (io_write_all(tls_h, fd, H2_PREFACE, sizeof H2_PREFACE - 1) || send_frame(tls_h, fd, 0, H2_SETTINGS, 0, 0, NULL)) {
        set_err(err, errlen, "send preface/settings failed"); io_close(tls_h, fd); return -1;
    }

    /* gzip 有効時は body を圧縮 (grpc-encoding: gzip + compressed-flag=1) */
    static uint8_t gzbuf[1 << 18];
    const uint8_t *gb = body; size_t gl = body_len; size_t gzlen = 0;
    int gzipped = otlp_gzip_if_enabled(body, body_len, gzbuf, sizeof gzbuf, &gzlen);
    if (gzipped) { gb = gzbuf; gl = gzlen; }

    /* 3) HEADERS (pseudo-headers 先 + content-type/te + 任意 grpc-encoding/auth) */
    char authority[300];
    snprintf(authority, sizeof authority, "%s:%s", host, port);
    uint8_t hb[4096]; size_t ho = 0;
    if (hpack_lit(hb, sizeof hb, &ho, ":method", "POST") ||
        hpack_lit(hb, sizeof hb, &ho, ":scheme", "http") ||
        hpack_lit(hb, sizeof hb, &ho, ":path", grpc_path) ||
        hpack_lit(hb, sizeof hb, &ho, ":authority", authority) ||
        hpack_lit(hb, sizeof hb, &ho, "content-type", "application/grpc+proto") ||
        hpack_lit(hb, sizeof hb, &ho, "te", "trailers") ||
        (gzipped && hpack_lit(hb, sizeof hb, &ho, "grpc-encoding", "gzip"))) {
        set_err(err, errlen, "hpack build failed"); io_close(tls_h, fd); return -1;
    }
    /* OTEL_EXPORTER_OTLP_HEADERS の auth ヘッダ (HTTP/2 は小文字キー必須) */
    {
        otlp_kv_t hdrs[16];
        int nh = otlp_env_headers(hdrs, 16);
        for (int i = 0; i < nh; i++) {
            char lk[128]; size_t k = 0;
            for (; hdrs[i].key[k] && k < sizeof lk - 1; k++) {
                char ch = hdrs[i].key[k];
                lk[k] = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
            }
            lk[k] = '\0';
            if (hpack_lit(hb, sizeof hb, &ho, lk, hdrs[i].val)) {
                set_err(err, errlen, "hpack header too long"); io_close(tls_h, fd); return -1;
            }
        }
    }
    if (send_frame(tls_h, fd,(uint32_t)ho, H2_HEADERS, H2_FLAG_END_HEADERS, 1, hb)) {
        set_err(err, errlen, "send headers failed"); io_close(tls_h, fd); return -1;
    }

    /* 4) DATA: gRPC length-prefixed message (END_STREAM)。gzip 時は compressed-flag=1。 */
    {
        size_t mlen = 5 + gl;
        uint8_t *msg = (uint8_t *)malloc(mlen);
        if (!msg) { set_err(err, errlen, "oom"); io_close(tls_h, fd); return -1; }
        msg[0] = gzipped ? 1 : 0;
        put_be32(msg + 1, (uint32_t)gl);
        if (gl) memcpy(msg + 5, gb, gl);
        int rc = send_frame(tls_h, fd,(uint32_t)mlen, H2_DATA, H2_FLAG_END_STREAM, 1, msg);
        free(msg);
        if (rc) { set_err(err, errlen, "send data failed"); io_close(tls_h, fd); return -1; }
    }

    /* 5) 応答 frame を読む: SETTINGS は ACK、PING は ACK、stream1 の END_STREAM で完了。 */
    uint8_t fh[9];
    static uint8_t fpayload[16384 + 1];
    int done = 0, err_seen = 0, guard = 0;
    while (!done && guard++ < 256) {
        int r = io_read_full(tls_h, fd, fh, 9);
        if (r != 0) break; /* EOF or error */
        uint32_t flen = get_be24(fh);
        uint8_t ftype = fh[3], fflags = fh[4];
        uint32_t fsid = get_be32(fh + 5) & 0x7fffffff;
        if (flen > sizeof fpayload - 1) { /* 大きすぎる: 読み飛ばし */
            uint32_t left = flen; char dump[1024];
            while (left) { size_t c = left > sizeof dump ? sizeof dump : left; if (io_read_full(tls_h, fd, dump, c)) { left = 0; break; } left -= (uint32_t)c; }
            continue;
        }
        if (flen && io_read_full(tls_h, fd, fpayload, flen)) break;

        switch (ftype) {
        case H2_SETTINGS:
            if (!(fflags & H2_FLAG_ACK)) send_frame(tls_h, fd,0, H2_SETTINGS, H2_FLAG_ACK, 0, NULL);
            break;
        case H2_PING:
            if (!(fflags & H2_FLAG_ACK) && flen == 8) send_frame(tls_h, fd,8, H2_PING, H2_FLAG_ACK, 0, fpayload);
            break;
        case H2_GOAWAY:
            err_seen = 1; done = 1; break;
        case H2_RSTSTREAM:
            if (fsid == 1) { err_seen = 1; done = 1; }
            break;
        case H2_HEADERS:
        case H2_DATA:
            if (fsid == 1 && (fflags & H2_FLAG_END_STREAM)) done = 1;
            break;
        default: break; /* WINDOW_UPDATE 等は無視 */
        }
    }
    io_close(tls_h, fd);
    if (ok) *ok = (done && !err_seen) ? 1 : 0;
    return 0;
}

/* http_path ("/v1/traces" 等) から対応する per-signal endpoint env 名を返す。
 * OTel 標準: OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT。無ければ NULL。 */
static const char *otlp_signal_endpoint_env(const char *http_path) {
    if (!http_path) return NULL;
    if (strstr(http_path, "traces"))  return "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
    if (strstr(http_path, "metrics")) return "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT";
    if (strstr(http_path, "logs"))    return "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT";
    return NULL;
}

int otlp_transport_send(const char *endpoint, const char *http_path, const char *grpc_path,
                        const char *content_type,
                        const uint8_t *body, size_t body_len, int *status, char *err, size_t errlen) {
    /* OTel per-signal endpoint override。OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT が
     * 設定されていたら base endpoint を上書きし、その値を verbatim で使う —
     * URL の path を honor し、/v1/<signal> を付け足さない (OTel 仕様)。
     * 未設定なら従来どおり base endpoint + 呼び出し元の http_path (後方互換)。 */
    char sig_path[512];
    const char *sig_env = otlp_signal_endpoint_env(http_path);
    const char *sig_ep  = sig_env ? getenv(sig_env) : NULL;
    if (sig_ep && sig_ep[0]) {
        endpoint = sig_ep;
        if (otlp_http_endpoint_path(sig_ep, sig_path, sizeof sig_path) == 0 && sig_path[0])
            http_path = sig_path;   /* path 込みで verbatim (例 Splunk /v2/trace/otlp) */
        else
            http_path = "/";        /* per-signal で path 無し: root、/v1/<signal> は付けない */
    }

    char host[256], port[16];
    if (otlp_http_parse_endpoint(endpoint, host, sizeof host, port, sizeof port) != 0) {
        set_err(err, errlen, "bad endpoint");
        return -1;
    }
    int is_grpc = (strncmp(endpoint, "grpc://", 7) == 0) || (strncmp(endpoint, "grpcs://", 8) == 0);
    int tls = (strncmp(endpoint, "https://", 8) == 0) || (strncmp(endpoint, "grpcs://", 8) == 0);
    if (is_grpc) {
        int ok = 0;
        int rc = otlp_grpc_export(host, port, grpc_path, body, body_len, tls, 0, &ok, err, errlen);
        if (rc != 0) return -1;
        if (status) *status = ok ? 200 : 0;
        return 0;
    }
    /* http:// / https:// (https は tls=1、要 OTLP_WITH_TLS ビルド) */
    return otlp_http_post(host, port, http_path,
                          content_type ? content_type : "application/x-protobuf",
                          body, body_len, tls, 0, status, err, errlen);
}
