/*
 * otlp_traces_test.c -- host verification of span assembly and the conversion to
 * OTLP traces.
 *
 * Feeds the call nesting driver { square{} add{} } in as a sequence of enter/exit
 * events, then
 *  (1) asserts the assembled tree at the C level (parent links, a single trace_id,
 *      the time offset), and
 *  (2) writes the OTLP bytes to argv[1] so the runner can check the names and the
 *      rest with protoc --decode.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "otlp_traces.h"

#define IDX_ADD 0
#define IDX_SQ  1
#define IDX_DRV 2

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.pb>\n", argv[0]); return 2; }

    /* tid 100: driver { square{} add{} } (kind 0=enter, 1=exit) */
    otlp_span_event_t ev[] = {
        {0, IDX_DRV, 1000, 100},
        {0, IDX_SQ,  1010, 100},
        {1, IDX_SQ,  1020, 100},
        {0, IDX_ADD, 1030, 100},
        {1, IDX_ADD, 1040, 100},
        {1, IDX_DRV, 2000, 100},
    };
    const int64_t off = 1000000000LL; /* ktime -> unix offset (a test value) */

    otlp_span_t spans[16];
    int n = otlp_traces_assemble(ev, 6, off, 0x1234ULL, spans, 16);
    if (n != 3) { fprintf(stderr, "FAIL: nspans=%d (want 3)\n", n); return 1; }

    otlp_span_t *drv = 0, *sq = 0, *add = 0;
    for (int i = 0; i < n; i++) {
        if (spans[i].method_idx == IDX_DRV) drv = &spans[i];
        else if (spans[i].method_idx == IDX_SQ) sq = &spans[i];
        else if (spans[i].method_idx == IDX_ADD) add = &spans[i];
    }
    int fail = 0;
    if (!drv || !sq || !add) { fprintf(stderr, "FAIL: missing span\n"); return 1; }
    if (drv->has_parent) { fprintf(stderr, "FAIL: driver should be root\n"); fail = 1; }
    if (!sq->has_parent || memcmp(sq->parent_span_id, drv->span_id, 8) != 0) {
        fprintf(stderr, "FAIL: square.parent != driver\n"); fail = 1; }
    if (!add->has_parent || memcmp(add->parent_span_id, drv->span_id, 8) != 0) {
        fprintf(stderr, "FAIL: add.parent != driver\n"); fail = 1; }
    if (memcmp(drv->trace_id, sq->trace_id, 16) || memcmp(drv->trace_id, add->trace_id, 16)) {
        fprintf(stderr, "FAIL: trace_id differs across spans\n"); fail = 1; }
    if (drv->start_unix_ns != 1000ULL + (uint64_t)off || drv->end_unix_ns != 2000ULL + (uint64_t)off) {
        fprintf(stderr, "FAIL: driver times %llu/%llu\n",
                (unsigned long long)drv->start_unix_ns, (unsigned long long)drv->end_unix_ns); fail = 1; }
    if (fail) return 1;
    fprintf(stderr, "[otlp_traces] assemble OK: 3 spans, square/add parented to driver, 1 trace_id, offset applied\n");

    otlp_method_meta_t metas[] = {
        {IDX_ADD, "add",    "workload.rb", 19},
        {IDX_SQ,  "square", "workload.rb", 23},
        {IDX_DRV, "driver", "workload.rb", 27},
    };
    uint8_t buf[8192];
    long b = otlp_traces_build(buf, sizeof buf, "spinel-app", "0.1.0", "spinel-ebpf", spans, n, metas, 3);
    if (b < 0) { fprintf(stderr, "FAIL: build\n"); return 1; }
    fprintf(stderr, "[otlp_traces] encoded %ld bytes\n", b);

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror("fopen"); return 1; }
    if (fwrite(buf, 1, (size_t)b, fp) != (size_t)b) { perror("fwrite"); fclose(fp); return 1; }
    fclose(fp);
    return 0;
}
