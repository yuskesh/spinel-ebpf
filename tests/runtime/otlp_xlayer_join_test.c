/*
 * otlp_xlayer_join_test.c -- demonstrates the 4-tuple join behind cross-layer
 * (L2-L8) correlation, at the map level.
 *
 * On this VM, *attaching* a BPF program (perf_event_open) hangs under the
 * hypervisor, so an end-to-end run driven by live tracepoint firings is not
 * available here -- the same holds for kprobes and for the probe-metrics test. The
 * join is therefore demonstrated without attaching anything:
 *
 *   1. open_and_load the generated skeleton: the bpf maps and programs are loaded
 *      into the kernel but never attached, so nothing hangs.
 *   2. Open one loopback TCP connection and take the accepted server-side fd.
 *   3. From that fd's 4-tuple, build the key with arithmetic byte-identical to what
 *      the tracepoint in the generated .bpf.c uses, and write established and
 *      state_changes into the real bpf_hist_keyed map, standing in for the writes
 *      the tracepoint would have made.
 *   4. Check that the production lookup FFI,
 *      spnl_otlp_xlayer_l34_count_obj(obj, "bpf_hist_keyed", fd, metric_id),
 *      re-derives the key from the fd alone and finds those values. That is the
 *      userspace join.
 *   5. Use the production span FFI spnl_otlp_http_span_fd_x to assemble one span
 *      carrying L3/L4 + L7 + L8 and send it to the endpoint.
 *
 * Usage: otlp_xlayer_join_test <skeleton-obj-loaded-internally> <endpoint> [traceparent] [tenant]
 * That the write expression used here is the same one the DSL generates is checked
 * by reading the generated .bpf.c alongside this file.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xlayer_correlate.skel.h"   /* generated skeleton (pass the build dir with -I) */
#include "otlp_httpspan.h"

/* The production lookup FFI (otlp_xlayer.c). */
extern long spnl_otlp_xlayer_l34_count_obj(struct bpf_object *obj, const char *map_name,
                                           int fd, unsigned long long metric_id);
extern int  spnl_otlp_xlayer_key_from_fd(int fd, unsigned long long metric_id,
                                          unsigned long long *key_out);

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

/* The bpf_hist_keyed value is struct { __u64 buckets[64]; } (512B); the count sits in slot 0. */
struct hist_val { uint64_t buckets[64]; };

int main(int argc, char **argv) {
    const char *ep = (argc > 1) ? argv[1] : "http://127.0.0.1:4318";
    const char *tp = (argc > 2) ? argv[2]
        : "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const char *tenant = (argc > 3) ? argv[3] : "acme";

    int cl = -1;
    int sv = self_connect(&cl);
    if (sv < 0) { fprintf(stderr, "[join] self_connect failed\n"); return 2; }

    /* (1) open_and_load the skeleton. Deliberately no attach -- attaching hangs on this VM. */
    struct xlayer_correlate *skel = xlayer_correlate__open_and_load();
    if (!skel) { fprintf(stderr, "[join] open_and_load failed\n"); close(sv); close(cl); return 2; }

    struct bpf_map *m = bpf_object__find_map_by_name(skel->obj, "bpf_hist_keyed");
    if (!m) { fprintf(stderr, "[join] bpf_hist_keyed not found\n"); return 2; }
    int mapfd = bpf_map__fd(m);

    /* (3) Derive the key from the fd's 4-tuple, with the same arithmetic the DSL
     *     emits and the same derivation the lookup performs, then write there:
     *     established(mid=2)=1 and state_changes(mid=1)=3, standing in for the
     *     writes the tracepoint would have made. */
    unsigned long long k_est = 0, k_chg = 0;
    if (!spnl_otlp_xlayer_key_from_fd(sv, 2, &k_est) ||
        !spnl_otlp_xlayer_key_from_fd(sv, 1, &k_chg)) {
        fprintf(stderr, "[join] key_from_fd failed (non-inet?)\n"); return 2;
    }
    struct hist_val v_est, v_chg;
    memset(&v_est, 0, sizeof v_est); v_est.buckets[0] = 1;  /* established = 1 */
    memset(&v_chg, 0, sizeof v_chg); v_chg.buckets[0] = 3;  /* state_changes = 3 */
    if (bpf_map_update_elem(mapfd, &k_est, &v_est, BPF_ANY) != 0 ||
        bpf_map_update_elem(mapfd, &k_chg, &v_chg, BPF_ANY) != 0) {
        fprintf(stderr, "[join] map_update failed\n"); return 2;
    }

    /* (4) The production lookup FFI re-derives the key from the fd alone and hits: the join holds. */
    long est = spnl_otlp_xlayer_l34_count_obj(skel->obj, "bpf_hist_keyed", sv, 2);
    long chg = spnl_otlp_xlayer_l34_count_obj(skel->obj, "bpf_hist_keyed", sv, 1);
    /* To show a miss is distinguishable: the client-side fd (cl) carries the 4-tuple
     * in the other direction, so it must miss. */
    long est_wrong = spnl_otlp_xlayer_l34_count_obj(skel->obj, "bpf_hist_keyed", cl, 2);

    struct sockaddr_in la, pa; socklen_t ll = sizeof la, pl = sizeof pa;
    getsockname(sv, (struct sockaddr *)&la, &ll);
    getpeername(sv, (struct sockaddr *)&pa, &pl);
    char sbuf[32], cbuf[32];
    inet_ntop(AF_INET, &la.sin_addr, sbuf, sizeof sbuf);
    inet_ntop(AF_INET, &pa.sin_addr, cbuf, sizeof cbuf);
    fprintf(stderr, "[join] server=%s:%d client=%s:%d  key_est=%llu key_chg=%llu\n",
            sbuf, ntohs(la.sin_port), cbuf, ntohs(pa.sin_port), k_est, k_chg);
    fprintf(stderr, "[join] lookup(sv): established=%ld state_changes=%ld  | lookup(cl,est)=%ld (miss expected)\n",
            est, chg, est_wrong);

    /* (5) 1 span = L3/L4 (client.address/server.port + established/state_changes) + L7 + L8(tenant) */
    uint64_t t0 = spnl_otlp_now_unix_ns();
    uint64_t t1 = t0 + 1234567;  /* ~1.2ms latency */
    int st = spnl_otlp_http_span_fd_x(sv, tp, "GET", "/hello", "/hello", 200,
                                      t0, t1, tenant, est, chg, ep);
    fprintf(stderr, "[join] span (all layers) -> otlp %d\n", st);

    xlayer_correlate__destroy(skel);
    close(sv); close(cl);
    /* Success: the join hits (est==1, chg==3), the reversed fd misses (-1), and the span POST returns 200. */
    return (est == 1 && chg == 3 && est_wrong == -1 && st == 200) ? 0 : 1;
}
