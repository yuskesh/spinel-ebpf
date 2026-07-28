/*
 * otlp_tls.c — mbedTLS による OTLP egress 用 TLS クライアント (ADR-013 T0/T1)
 * 詳細は otlp_tls.h を参照。connected fd の上に TLS を被せる薄い層。
 */
#include "otlp_tls.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>           /* mTLS: client key (mbedtls_pk_parse_keyfile) */
#include <mbedtls/net_sockets.h>  /* MBEDTLS_ERR_NET_SEND/RECV_FAILED */
#include <mbedtls/error.h>

struct otlp_tls {
    int fd;                          /* 所有権は呼び出し側 (close しない) */
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;        /* mTLS: client 証明書 */
    mbedtls_pk_context pkey;         /* mTLS: client 秘密鍵 */
    const char *alpn_protos[2];      /* ALPN リスト (mbedtls は handshake 中に参照、struct で延命) */
};

static void set_err(char *err, size_t n, const char *m) { if (err && n) snprintf(err, n, "%s", m); }

/* BIO: blocking fd 上の send/recv (EINTR は再試行、EAGAIN は WANT_*) */
static int net_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    for (;;) {
        ssize_t n = write(fd, buf, len);
        if (n >= 0) return (int)n;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
}
static int net_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    for (;;) {
        ssize_t n = read(fd, buf, len);
        if (n >= 0) return (int)n;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
}

/* system CA bundle を順に試して cacert に読む。読めた本数を返す。 */
static int load_system_ca(mbedtls_x509_crt *cacert) {
    static const char *const paths[] = {
        "/etc/ssl/certs/ca-certificates.crt",   /* Debian/Ubuntu/Alpine */
        "/etc/pki/tls/certs/ca-bundle.crt",     /* RHEL/Fedora */
        "/etc/ssl/cert.pem",                    /* macOS/BSD */
        NULL,
    };
    for (int i = 0; paths[i]; i++) {
        if (mbedtls_x509_crt_parse_file(cacert, paths[i]) == 0) return 1;
    }
    return 0;
}

otlp_tls_t *otlp_tls_connect(int fd, const char *hostname, const char *alpn, char *err, size_t errlen) {
    otlp_tls_t *t = (otlp_tls_t *)calloc(1, sizeof *t);
    if (!t) { set_err(err, errlen, "oom"); return NULL; }
    t->fd = fd;
    mbedtls_ssl_init(&t->ssl);
    mbedtls_ssl_config_init(&t->conf);
    mbedtls_ctr_drbg_init(&t->drbg);
    mbedtls_entropy_init(&t->entropy);
    mbedtls_x509_crt_init(&t->cacert);
    mbedtls_x509_crt_init(&t->clicert);
    mbedtls_pk_init(&t->pkey);

    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&t->drbg, mbedtls_entropy_func, &t->entropy,
                                     (const unsigned char *)"spinel-ebpf-otlp", 16)) != 0) {
        set_err(err, errlen, "ctr_drbg_seed failed"); goto fail;
    }
    if ((ret = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        set_err(err, errlen, "ssl_config_defaults failed"); goto fail;
    }

    /* ALPN (gRPC-over-TLS は "h2" 必須)。配列は struct で延命させる。 */
    if (alpn) {
        t->alpn_protos[0] = alpn;
        t->alpn_protos[1] = NULL;
        if ((ret = mbedtls_ssl_conf_alpn_protocols(&t->conf, t->alpn_protos)) != 0) {
            set_err(err, errlen, "ssl_conf_alpn failed"); goto fail;
        }
    }

    const char *insecure = getenv("OTEL_EXPORTER_OTLP_INSECURE_SKIP_VERIFY");
    if (insecure && insecure[0] == '1') {
        mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);
    } else {
        const char *cafile = getenv("OTEL_EXPORTER_OTLP_CERTIFICATE");
        int have_ca = 0;
        if (cafile && cafile[0]) {
            have_ca = (mbedtls_x509_crt_parse_file(&t->cacert, cafile) == 0);
            if (!have_ca) { set_err(err, errlen, "failed to load OTEL_EXPORTER_OTLP_CERTIFICATE"); goto fail; }
        } else {
            have_ca = load_system_ca(&t->cacert);
            if (!have_ca) { set_err(err, errlen, "no system CA bundle (set OTEL_EXPORTER_OTLP_CERTIFICATE)"); goto fail; }
        }
        mbedtls_ssl_conf_ca_chain(&t->conf, &t->cacert, NULL);
        mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }

    /* mTLS (client cert)。両 env が揃ったときだけ client 証明書を提示する。
     * OTel 標準 env: OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE / OTEL_EXPORTER_OTLP_CLIENT_KEY。 */
    const char *ccert = getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE");
    const char *ckey  = getenv("OTEL_EXPORTER_OTLP_CLIENT_KEY");
    if (ccert && ccert[0] && ckey && ckey[0]) {
        if (mbedtls_x509_crt_parse_file(&t->clicert, ccert) != 0) {
            set_err(err, errlen, "failed to load OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"); goto fail;
        }
        if (mbedtls_pk_parse_keyfile(&t->pkey, ckey, NULL,
                                     mbedtls_ctr_drbg_random, &t->drbg) != 0) {
            set_err(err, errlen, "failed to load OTEL_EXPORTER_OTLP_CLIENT_KEY"); goto fail;
        }
        if ((ret = mbedtls_ssl_conf_own_cert(&t->conf, &t->clicert, &t->pkey)) != 0) {
            set_err(err, errlen, "ssl_conf_own_cert failed"); goto fail;
        }
    }

    mbedtls_ssl_conf_rng(&t->conf, mbedtls_ctr_drbg_random, &t->drbg);

    if ((ret = mbedtls_ssl_setup(&t->ssl, &t->conf)) != 0) {
        set_err(err, errlen, "ssl_setup failed"); goto fail;
    }
    if ((ret = mbedtls_ssl_set_hostname(&t->ssl, hostname)) != 0) {  /* SNI + 検証名 */
        set_err(err, errlen, "ssl_set_hostname failed"); goto fail;
    }
    mbedtls_ssl_set_bio(&t->ssl, &t->fd, net_send, net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&t->ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (err && errlen) {
            char eb[128]; mbedtls_strerror(ret, eb, sizeof eb);
            snprintf(err, errlen, "tls handshake failed: %s", eb);
        }
        goto fail;
    }
    return t;

fail:
    otlp_tls_free(t);
    return NULL;
}

int otlp_tls_write(otlp_tls_t *t, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    while (off < len) {
        int n = mbedtls_ssl_write(&t->ssl, p + off, len - off);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

int otlp_tls_read(otlp_tls_t *t, void *buf, size_t len) {
    for (;;) {
        int n = mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, len);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
        if (n < 0) return -1;
        return n;
    }
}

void otlp_tls_free(otlp_tls_t *t) {
    if (!t) return;
    mbedtls_ssl_close_notify(&t->ssl);
    mbedtls_x509_crt_free(&t->cacert);
    mbedtls_x509_crt_free(&t->clicert);
    mbedtls_pk_free(&t->pkey);
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
    mbedtls_ctr_drbg_free(&t->drbg);
    mbedtls_entropy_free(&t->entropy);
    free(t);
}
