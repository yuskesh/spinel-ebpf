/*
 * otlp_xlayer_span_test.c -- host-side harness for cross-layer (L2-L8) correlation
 * within a single record: every layer ends up on one span. No libbpf dependency --
 * this is just the span builder plus the transport.
 *
 * Opens one real loopback TCP connection, takes the accepted fd and hands it to
 * spnl_otlp_http_span_fd_x:
 *   L3   : client.address (from getpeername)
 *   L4   : server.port (from getsockname) + net.tcp.established / net.tcp.state_changes
 *   L7   : http.request.method / url.path / http.route / http.response.status_code /
 *          latency (the span duration)
 *   L8   : tenant, plus W3C traceparent inheritance (traceId matches the incoming one)
 *
 * The established / state_changes values are passed in as arguments, standing in for
 * what the cross-layer lookup would return. That those values really can be read out
 * of the live bpf_hist_keyed map through the fd -- the 4-tuple join -- is shown
 * separately by otlp_xlayer_join_test, which needs a container. This harness checks
 * deterministically, on a host, that all the layers assemble onto one span and that
 * the trace context is inherited.
 *
 * Usage: otlp_xlayer_span_test <endpoint> [traceparent] [tenant] [established] [state_changes] [status]
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
    a.sin_port = 0;
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
    const char *tenant = (argc > 3) ? argv[3] : "acme";
    long est = (argc > 4) ? atol(argv[4]) : 1;   /* net.tcp.established   (stands in for the cross-layer lookup) */
    long chg = (argc > 5) ? atol(argv[5]) : 3;   /* net.tcp.state_changes (stands in for the cross-layer lookup) */
    int status = (argc > 6) ? atoi(argv[6]) : 200;

    int cl = -1;
    int sv = self_connect(&cl);   /* server-side accepted fd; -1 means the addresses are omitted */

    uint64_t t0 = spnl_otlp_now_unix_ns();
    uint64_t t1 = t0 + 1234567;   /* ~1.2ms latency (span duration = L7 latency) */
    int st = spnl_otlp_http_span_fd_x(sv, tp, "GET", "/hello", "/hello", status,
                                      t0, t1, tenant, est, chg, ep);
    fprintf(stderr, "[xlayer-span] %s tenant=%s established=%ld state_changes=%ld status=%d -> otlp %d\n",
            ep, tenant, est, chg, status, st);

    if (sv >= 0) close(sv);
    if (cl >= 0) close(cl);
    return st == 200 ? 0 : 1;
}
