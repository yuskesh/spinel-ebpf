/*
 * otlp_trace_asm_test.c -- host verification of multi-span trace assembly, the
 * userspace layer that turns related events into a span tree.
 *
 * Renders an off-CPU record into a two-span tree -- parent (the request span,
 * SERVER, duration = the request window) plus child (the off-CPU wait, INTERNAL,
 * duration = offcpu_ns) -- using the runtime primitives otlp_span_new_root and
 * otlp_span_new_child, then
 *   (1) asserts the shared trace_id, the parent/child link, the kinds and the
 *       start/duration nesting at the C level, and
 *   (2) writes the OTLP bytes to argv[1] so the runner can check them with
 *       protoc --decode.
 * It also verifies traceparent inheritance (otlp_span_root_from_traceparent).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "otlp_traces.h"

/* Turn an off-CPU record into a two-span tree, the same shape the runtime
 * (otlp_agent.c) builds, reproduced here on the host.
 * spans[0]=parent, spans[1]=child (only when offcpu>0). Returns the span count. */
static int render_offcpu_tree(otlp_generic_span_t *spans,
                              otlp_kv_t pattrs[], otlp_kv_t cattrs[],
                              char *pname, char *cname,   /* caller storage (per-case, no aliasing) */
                              uint64_t start_unix, uint64_t duration_ns, uint64_t offcpu_ns,
                              const char *method, const char *path, int status,
                              const char *wait_kind, uint64_t *seed) {
    int nsp = 0;
    otlp_generic_span_t *p = &spans[nsp++];
    memset(p, 0, sizeof *p);
    otlp_span_new_root(p, seed);
    p->start_unix_ns = start_unix; p->end_unix_ns = start_unix + duration_ns;
    p->kind = 2 /* SERVER */; p->is_error = (status >= 500);
    snprintf(pname, 96, "%s %s", method, path); p->name = pname;
    int n = 0;
    snprintf(pattrs[n].key,sizeof pattrs[n].key,"http.request.method"); snprintf(pattrs[n].val,sizeof pattrs[n].val,"%s",method); n++;
    snprintf(pattrs[n].key,sizeof pattrs[n].key,"url.path"); snprintf(pattrs[n].val,sizeof pattrs[n].val,"%s",path); n++;
    p->attrs = pattrs; p->nattrs = n;

    if (offcpu_ns > 0) {
        otlp_generic_span_t *c = &spans[nsp++];
        memset(c, 0, sizeof *c);
        otlp_span_new_child(c, p, seed);
        c->start_unix_ns = start_unix; c->end_unix_ns = start_unix + offcpu_ns;
        c->kind = 1 /* INTERNAL */;
        snprintf(cname, 64, "off-CPU wait (%s)", wait_kind); c->name = cname;
        int cn = 0;
        snprintf(cattrs[cn].key,sizeof cattrs[cn].key,"spnl.wait.kind"); snprintf(cattrs[cn].val,sizeof cattrs[cn].val,"%s",wait_kind); cn++;
        c->attrs = cattrs; c->nattrs = cn;
    }
    return nsp;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.pb>\n", argv[0]); return 2; }
    int fail = 0;

    /* ---- Case A: the /sleep shape (offcpu is most of the duration) -> 2 spans, parent + child ---- */
    otlp_generic_span_t spans[4];
    otlp_kv_t pattrs[8], cattrs[8];
    char pnameA[96], cnameA[64];
    uint64_t seed = 0xABCDEF12ULL;
    const uint64_t T0 = 1000000000000ULL, DUR = 310000000ULL, OFF = 305000000ULL;
    int nsp = render_offcpu_tree(spans, pattrs, cattrs, pnameA, cnameA, T0, DUR, OFF, "GET", "/sleep", 200, "sleep", &seed);
    if (nsp != 2) { fprintf(stderr, "FAIL: /sleep nsp=%d (want 2)\n", nsp); return 1; }
    otlp_generic_span_t *P = &spans[0], *C = &spans[1];
    if (P->has_parent) { fprintf(stderr, "FAIL: parent should be root\n"); fail = 1; }
    if (!C->has_parent) { fprintf(stderr, "FAIL: child should have parent\n"); fail = 1; }
    if (memcmp(P->trace_id, C->trace_id, 16) != 0) { fprintf(stderr, "FAIL: trace_id differs\n"); fail = 1; }
    if (memcmp(C->parent_span_id, P->span_id, 8) != 0) { fprintf(stderr, "FAIL: child.parent != parent.span_id\n"); fail = 1; }
    if (memcmp(P->span_id, C->span_id, 8) == 0) { fprintf(stderr, "FAIL: parent/child span_id equal\n"); fail = 1; }
    if (P->kind != 2 || C->kind != 1) { fprintf(stderr, "FAIL: kinds %d/%d (want 2/1)\n", P->kind, C->kind); fail = 1; }
    if (P->end_unix_ns - P->start_unix_ns != DUR) { fprintf(stderr, "FAIL: parent dur\n"); fail = 1; }
    if (C->end_unix_ns - C->start_unix_ns != OFF) { fprintf(stderr, "FAIL: child dur\n"); fail = 1; }
    if (C->start_unix_ns < P->start_unix_ns || C->end_unix_ns > P->end_unix_ns) {
        fprintf(stderr, "FAIL: child not nested in parent window\n"); fail = 1; }
    if (fail) return 1;
    fprintf(stderr, "[trace_asm] /sleep OK: 2 spans, child nested in parent, 1 trace_id, kinds SERVER/INTERNAL\n");

    /* ---- Case B: the /spin shape (offcpu=0) -> no tree, just the one parent span ---- */
    otlp_generic_span_t spins[4]; otlp_kv_t sp_p[8], sp_c[8];
    char pnameB[96], cnameB[64];
    uint64_t seed2 = 0x99ULL;
    int nspin = render_offcpu_tree(spins, sp_p, sp_c, pnameB, cnameB, T0, 300000000ULL, 0, "GET", "/spin", 200, "none", &seed2);
    if (nspin != 1) { fprintf(stderr, "FAIL: /spin nsp=%d (want 1, no wait child)\n", nspin); return 1; }
    if (spins[0].has_parent) { fprintf(stderr, "FAIL: /spin parent should be root\n"); return 1; }
    fprintf(stderr, "[trace_asm] /spin OK: 1 span (CPU-bound, no off-CPU child)\n");

    /* ---- Case C: traceparent inheritance ---- */
    otlp_generic_span_t inh; memset(&inh, 0, sizeof inh);
    const char *tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    uint64_t seed3 = 0x7ULL;
    int inherited = otlp_span_root_from_traceparent(&inh, tp, &seed3);
    if (!inherited) { fprintf(stderr, "FAIL: valid traceparent not inherited\n"); return 1; }
    if (!inh.has_parent) { fprintf(stderr, "FAIL: inherited span should have parent\n"); return 1; }
    static const uint8_t want_tid[16] = {0x4b,0xf9,0x2f,0x35,0x77,0xb3,0x4d,0xa6,0xa3,0xce,0x92,0x9d,0x0e,0x0e,0x47,0x36};
    static const uint8_t want_pid[8]  = {0x00,0xf0,0x67,0xaa,0x0b,0xa9,0x02,0xb7};
    if (memcmp(inh.trace_id, want_tid, 16) != 0) { fprintf(stderr, "FAIL: inherited trace_id mismatch\n"); return 1; }
    if (memcmp(inh.parent_span_id, want_pid, 8) != 0) { fprintf(stderr, "FAIL: inherited parent_span_id mismatch\n"); return 1; }
    /* an invalid traceparent yields a freshly generated root, nothing inherited */
    otlp_generic_span_t gen; memset(&gen, 0, sizeof gen); uint64_t seed4 = 0x7ULL;
    if (otlp_span_root_from_traceparent(&gen, "garbage", &seed4) != 0) { fprintf(stderr, "FAIL: garbage traceparent inherited\n"); return 1; }
    if (gen.has_parent) { fprintf(stderr, "FAIL: garbage -> should be root\n"); return 1; }
    fprintf(stderr, "[trace_asm] traceparent OK: valid inherited (trace_id+parent), garbage generated (root)\n");

    /* ---- Case D: the predicate that correlates records across channels ---- */
    /* parent window: tgid=1234, [1000, 1000+310]. The ktime scale is arbitrary here. */
    const uint32_t PT = 1234; const uint64_t PS = 1000, PD = 310;
    if (!otlp_child_in_window(1234, 1100, PT, PS, PD)) { fprintf(stderr, "FAIL: in-window same-tgid should match\n"); return 1; }
    if (!otlp_child_in_window(1234, 1000, PT, PS, PD)) { fprintf(stderr, "FAIL: window start boundary should match\n"); return 1; }
    if (!otlp_child_in_window(1234, 1310, PT, PS, PD)) { fprintf(stderr, "FAIL: window end boundary should match\n"); return 1; }
    if (otlp_child_in_window(1234,  999, PT, PS, PD))  { fprintf(stderr, "FAIL: before window should NOT match\n"); return 1; }
    if (otlp_child_in_window(1234, 1311, PT, PS, PD))  { fprintf(stderr, "FAIL: after window should NOT match\n"); return 1; }
    if (otlp_child_in_window(9999, 1100, PT, PS, PD))  { fprintf(stderr, "FAIL: different tgid should NOT match\n"); return 1; }
    if (otlp_child_in_window(1234, 1100, PT, 0,  PD))  { fprintf(stderr, "FAIL: unknown window (start=0) should NOT match\n"); return 1; }
    fprintf(stderr, "[trace_asm] correlation OK: in-window+same-tgid matches, out-of-window / other-tgid / no-window reject\n");

    /* ---- OTLP encode: both /sleep spans into a single request (the multi-span build) ---- */
    uint8_t buf[8192];
    long b = otlp_traces_generic_build_multi(buf, sizeof buf, "spinel-e312-test", "0", "spinel-ebpf", spans, (size_t)nsp);
    if (b < 0) { fprintf(stderr, "FAIL: build_multi\n"); return 1; }
    fprintf(stderr, "[trace_asm] encoded %ld bytes (2 spans, 1 ResourceSpans)\n", b);

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror("fopen"); return 1; }
    if (fwrite(buf, 1, (size_t)b, fp) != (size_t)b) { perror("fwrite"); fclose(fp); return 1; }
    fclose(fp);
    return 0;
}
