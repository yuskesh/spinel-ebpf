/*
 * otlp_http.c — OTLP/HTTP+protobuf 転送の最小 HTTP/1.1 クライアント
 *
 * POSIX socket だけで http://host:port<path> に protobuf body を POST する。
 * 応答はステータス行だけ見る (OTLP の partial-success 本文は v1 では無視可)。
 */
#include "otlp_http.h"
#ifdef OTLP_WITH_TLS
#include "otlp_tls.h"   /* ADR-013 T1: https:// 直送の TLS 層 (gated、非 TLS ビルドは未参照) */
#endif

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>   /* getenv */
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>     /* gzip (OTEL_EXPORTER_OTLP_COMPRESSION=gzip) */
#include <sys/socket.h>
#include <sys/types.h>

static void set_err(char *err, size_t errlen, const char *msg) {
    if (err && errlen) { snprintf(err, errlen, "%s", msg); }
}

/* fd に len バイトを全部書く。成功で 0。 */
static int write_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* TLS handle (tls_h) があれば TLS、無ければ raw fd で I/O。
 * tls_h は opaque (void*) — 非 TLS ビルドでは常に NULL で otlp_tls 型に触れない。 */
static int io_write(void *tls_h, int fd, const void *buf, size_t len) {
#ifdef OTLP_WITH_TLS
    if (tls_h) return otlp_tls_write((otlp_tls_t *)tls_h, buf, len);
#endif
    (void)tls_h;
    return write_all(fd, buf, len);
}
static ssize_t io_read(void *tls_h, int fd, void *buf, size_t len) {
#ifdef OTLP_WITH_TLS
    if (tls_h) return otlp_tls_read((otlp_tls_t *)tls_h, buf, len);
#endif
    (void)tls_h;
    return read(fd, buf, len);
}
static void io_close(void *tls_h, int fd) {
#ifdef OTLP_WITH_TLS
    if (tls_h) otlp_tls_free((otlp_tls_t *)tls_h);
#endif
    (void)tls_h;
    close(fd);
}

/* [start,end) を spaces トリムして dst にコピー */
static void copy_trim(char *dst, size_t cap, const char *s, const char *e) {
    while (s < e && (*s == ' ' || *s == '\t')) s++;
    while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
    size_t n = (size_t)(e - s);
    if (n >= cap) n = cap - 1;
    memcpy(dst, s, n);
    dst[n] = '\0';
}

int otlp_env_headers(otlp_kv_t *out, int max) {
    const char *e = getenv("OTEL_EXPORTER_OTLP_HEADERS");
    if (!e || !*e || !out || max <= 0) return 0;
    int n = 0;
    const char *p = e;
    while (*p && n < max) {
        while (*p == ',' || *p == ' ') p++;
        if (!*p) break;
        const char *comma = strchr(p, ',');
        const char *segend = comma ? comma : p + strlen(p);
        const char *eq = (const char *)memchr(p, '=', (size_t)(segend - p));
        if (eq) {
            copy_trim(out[n].key, sizeof out[n].key, p, eq);
            copy_trim(out[n].val, sizeof out[n].val, eq + 1, segend);
            if (out[n].key[0]) n++;
        }
        p = comma ? comma + 1 : segend;
    }
    return n;
}

int otlp_gzip_if_enabled(const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t outcap, size_t *outlen) {
    const char *c = getenv("OTEL_EXPORTER_OTLP_COMPRESSION");
    if (!c || strcmp(c, "gzip") != 0 || !in || !out || !outlen) return 0;
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    /* windowBits 15+16 = gzip ヘッダ付き (HTTP Content-Encoding / gRPC grpc-encoding 用) */
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return 0;
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)inlen;
    zs.next_out = out;
    zs.avail_out = (uInt)outcap;
    int rc = deflate(&zs, Z_FINISH);
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) return 0; /* 収まらない/失敗 -> 非圧縮で送る */
    *outlen = outcap - zs.avail_out;
    return 1;
}

int otlp_http_parse_endpoint(const char *endpoint,
                             char *host, size_t hostlen,
                             char *port, size_t portlen) {
    if (!endpoint || !host || !port || hostlen == 0 || portlen == 0) return -1;

    const char *p = endpoint;
    const char *defport = "4318";              /* OTLP/HTTP 既定 (plain http) */
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) { p += 8; defport = "443"; }  /* E290: 標準 URL 既定 (SaaS ingest は 443) */
    else if (strncmp(p, "grpcs://", 8) == 0) { p += 8; defport = "4317"; } /* OTLP/gRPC+TLS */
    else if (strncmp(p, "grpc://", 7) == 0) { p += 7; defport = "4317"; } /* OTLP/gRPC 既定 */

    /* host[:port] (path 以降は捨てる) */
    size_t n = strcspn(p, ":/");
    if (n == 0 || n >= hostlen) return -1;
    memcpy(host, p, n);
    host[n] = '\0';

    const char *rest = p + n;
    if (*rest == ':') {
        rest++;
        size_t pn = strcspn(rest, "/");
        if (pn == 0 || pn >= portlen) return -1;
        memcpy(port, rest, pn);
        port[pn] = '\0';
    } else {
        snprintf(port, portlen, "%s", defport);
    }
    return 0;
}

/* endpoint URL の path 部分を取り出す (例 "https://h/v2/trace/otlp" -> "/v2/trace/otlp")。
 * path が無ければ空文字。OTel の per-signal endpoint (OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT) を
 * verbatim で使う (signal パスを付け足さない) ために必要。0 で成功。 */
int otlp_http_endpoint_path(const char *endpoint, char *path, size_t pathlen) {
    if (!endpoint || !path || pathlen == 0) return -1;
    const char *p = endpoint;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "grpcs://", 8) == 0) p += 8;
    else if (strncmp(p, "grpc://", 7) == 0) p += 7;
    const char *slash = strchr(p, '/');   /* host[:port] の後の最初の '/' 以降が path */
    if (!slash) { path[0] = '\0'; return 0; }
    size_t n = strlen(slash);
    if (n + 1 > pathlen) return -1;
    memcpy(path, slash, n + 1);
    return 0;
}

/* host:port に connect した fd を返す。失敗で -1。 */
static int connect_once(const char *host, const char *port, char *err, size_t errlen) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0) {
        set_err(err, errlen, gai_strerror(gai));
        return -1;
    }
    int fd = -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) set_err(err, errlen, "connect failed");
    return fd;
}

int otlp_http_post(const char *host, const char *port, const char *path,
                   const char *content_type,
                   const uint8_t *body, size_t body_len,
                   int tls,
                   int max_retries,
                   int *status, char *err, size_t errlen) {
    if (!host || !port || !path || !content_type || (!body && body_len)) {
        set_err(err, errlen, "invalid argument");
        return -1;
    }
    if (max_retries <= 0) max_retries = 5;

    int fd = -1;
    for (int attempt = 0; attempt < max_retries; attempt++) {
        fd = connect_once(host, port, err, errlen);
        if (fd >= 0) break;
        /* 指数バックオフ: 100ms, 200ms, 400ms, ... (receiver 起動待ち / 一過性) */
        long ms = 100L << attempt;
        if (ms > 2000) ms = 2000;
        struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    if (fd < 0) return -1; /* err は connect_once が設定済 */

    /* https:// の場合は connected fd に TLS を被せる (gated) */
    void *tls_h = NULL;
    if (tls) {
#ifdef OTLP_WITH_TLS
        tls_h = otlp_tls_connect(fd, host, NULL /* HTTP/1.1: ALPN 無し */, err, errlen);
        if (!tls_h) { close(fd); return -1; }
#else
        set_err(err, errlen, "TLS (https://) not compiled in — rebuild with mbedTLS (OTLP_WITH_TLS)");
        close(fd); return -1;
#endif
    }

    /* gzip 有効時は body を圧縮 (Content-Encoding: gzip) */
    static uint8_t gzbuf[1 << 18];
    const uint8_t *sendb = body;
    size_t sendn = body_len;
    size_t gzlen = 0;
    int gzipped = otlp_gzip_if_enabled(body, body_len, gzbuf, sizeof gzbuf, &gzlen);
    if (gzipped) { sendb = gzbuf; sendn = gzlen; }

    /* リクエストヘッダ (標準 + 任意 Content-Encoding) */
    char header[2048];
    int hn = snprintf(header, sizeof header,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "User-Agent: spinel-ebpf-otlp/0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s",
        path, host, port, content_type, sendn,
        gzipped ? "Content-Encoding: gzip\r\n" : "");
    if (hn < 0 || (size_t)hn >= sizeof header) {
        set_err(err, errlen, "header too long");
        io_close(tls_h, fd);
        return -1;
    }
    /* OTEL_EXPORTER_OTLP_HEADERS の認証ヘッダ等を追加 (直送時の token 等) */
    otlp_kv_t hdrs[16];
    int nh = otlp_env_headers(hdrs, 16);
    for (int i = 0; i < nh; i++) {
        int a = snprintf(header + hn, sizeof header - (size_t)hn, "%s: %s\r\n",
                         hdrs[i].key, hdrs[i].val);
        if (a < 0 || (size_t)(hn + a) >= sizeof header) {
            set_err(err, errlen, "headers too long"); io_close(tls_h, fd); return -1;
        }
        hn += a;
    }
    /* 終端の空行 */
    if ((size_t)hn + 2 >= sizeof header) { set_err(err, errlen, "header too long"); io_close(tls_h, fd); return -1; }
    header[hn++] = '\r'; header[hn++] = '\n';

    if (io_write(tls_h, fd, header, (size_t)hn) != 0 ||
        (sendn && io_write(tls_h, fd, sendb, sendn) != 0)) {
        set_err(err, errlen, "send failed");
        io_close(tls_h, fd);
        return -1;
    }

    /* 応答: ステータス行だけ読めれば十分 */
    char resp[1024];
    size_t got = 0;
    while (got < sizeof resp - 1) {
        ssize_t n = io_read(tls_h, fd, resp + got, sizeof resp - 1 - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            set_err(err, errlen, "recv failed");
            io_close(tls_h, fd);
            return -1;
        }
        if (n == 0) break; /* server closed */
        got += (size_t)n;
        if (memchr(resp, '\n', got)) break; /* ステータス行が揃った */
    }
    io_close(tls_h, fd);
    resp[got] = '\0';

    /* "HTTP/1.1 200 ..." をパース */
    int code = 0;
    if (sscanf(resp, "HTTP/%*d.%*d %d", &code) != 1) {
        set_err(err, errlen, "malformed HTTP response");
        return -1;
    }
    if (status) *status = code;
    return 0;
}
