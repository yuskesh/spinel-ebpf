/*
 * otlp_endpoint_test.c -- path extraction from an endpoint URL, and the default
 * port for each scheme.
 *
 * A per-signal endpoint (OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT) has to be used
 * verbatim, so this checks that otlp_http_endpoint_path preserves the path, and
 * that https:// defaults to port 443 (what SaaS ingest endpoints expect). A pure
 * parse test -- no network needed.
 *
 * Usage: otlp_endpoint_test  (no arguments; prints "PASS" and exits 0 when every
 * assertion holds)
 */
#include <stdio.h>
#include <string.h>
#include "otlp_http.h"

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } } while (0)

static void expect_path(const char *ep, const char *want) {
    char path[256];
    int rc = otlp_http_endpoint_path(ep, path, sizeof path);
    CHECK(rc == 0, ep);
    if (rc == 0 && strcmp(path, want) != 0) {
        printf("FAIL: path(%s) = [%s], want [%s]\n", ep, path, want);
        fails++;
    }
}

static void expect_hostport(const char *ep, const char *whost, const char *wport) {
    char host[256], port[16];
    int rc = otlp_http_parse_endpoint(ep, host, sizeof host, port, sizeof port);
    CHECK(rc == 0, ep);
    if (rc == 0 && (strcmp(host, whost) != 0 || strcmp(port, wport) != 0)) {
        printf("FAIL: parse(%s) = %s:%s, want %s:%s\n", ep, host, port, whost, wport);
        fails++;
    }
}

int main(void) {
    /* --- path extraction (per-signal endpoints must be used verbatim) --- */
    expect_path("https://ingest.realm0.observability.splunkcloud.com/v2/trace/otlp",
                "/v2/trace/otlp");
    expect_path("http://127.0.0.1:4318/v1/traces", "/v1/traces");
    expect_path("https://host", "");                 /* no path -> empty */
    expect_path("https://host:8443/", "/");           /* just the root */
    expect_path("grpc://collector:4317/some/path", "/some/path");

    /* --- default port per scheme --- */
    expect_hostport("https://ingest.realm0.observability.splunkcloud.com/v2/trace/otlp",
                    "ingest.realm0.observability.splunkcloud.com", "443");  /* https -> 443 */
    expect_hostport("http://127.0.0.1/v1/traces", "127.0.0.1", "4318");  /* plain http stays on 4318 */
    expect_hostport("https://host:9443/x", "host", "9443");              /* an explicit port wins */
    expect_hostport("grpc://c", "c", "4317");
    expect_hostport("grpcs://c", "c", "4317");

    if (fails == 0) { printf("PASS (otlp_endpoint_test)\n"); return 0; }
    printf("%d checks FAILED\n", fails);
    return 1;
}
