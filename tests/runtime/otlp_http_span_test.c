/*
 * otlp_http_span_test.c -- HTTP server span, W3C traceparent propagation, and
 * agreement with the OpenTelemetry semantic conventions.
 * Opens one real TCP loopback socket to obtain an accepted fd and hands it to
 * spnl_otlp_http_span_fd, which then derives server.address (127.0.0.1),
 * server.port and client.address from getsockname/getpeername.
 * Usage: otlp_http_span_test <endpoint> [traceparent] [status] [route]
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "otlp_httpspan.h"

/* Self-connect over 127.0.0.1 and return the server-side accepted fd (the client
 * fd goes to *client_out). Returns -1 on failure. */
static int self_connect(int *client_out) {
    int ln = socket(AF_INET, SOCK_STREAM, 0);
    if (ln < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;  /* ephemeral */
    if (bind(ln, (struct sockaddr *)&a, sizeof a) != 0) { close(ln); return -1; }
    if (listen(ln, 1) != 0) { close(ln); return -1; }
    socklen_t sl = sizeof a;
    if (getsockname(ln, (struct sockaddr *)&a, &sl) != 0) { close(ln); return -1; }
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    if (cl < 0) { close(ln); return -1; }
    if (connect(cl, (struct sockaddr *)&a, sizeof a) != 0) { close(ln); close(cl); return -1; }
    int sv = accept(ln, NULL, NULL);
    close(ln);
    if (sv < 0) { close(cl); return -1; }
    *client_out = cl;
    return sv;
}

int main(int argc, char **argv) {
    const char *ep = (argc > 1) ? argv[1] : "http://127.0.0.1:4318";
    const char *tp = (argc > 2) ? argv[2]
        : "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    int status = (argc > 3) ? atoi(argv[3]) : 200;
    const char *route = (argc > 4) ? argv[4] : "/hello";

    int cl = -1;
    int sv = self_connect(&cl);  /* server-side accepted fd; -1 means the addresses are omitted */

    uint64_t t0 = spnl_otlp_now_unix_ns();
    uint64_t t1 = t0 + 1234567;  /* ~1.2ms */
    int st = spnl_otlp_http_span_fd(sv, tp, "GET", "/hello", route, status, t0, t1, ep);
    fprintf(stderr, "[http-span] %s tp=%.16s... status=%d route=%s -> otlp %d\n",
            ep, tp, status, route, st);

    if (sv >= 0) close(sv);
    if (cl >= 0) close(cl);
    return st == 200 ? 0 : 1;
}
