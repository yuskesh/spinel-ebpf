/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Smoke test for spnl_runtime against a generated BPF object.
 * Expects to be run inside debian:trixie with the BPF object pre-built.
 *
 *   clang -O2 -I include -I src/runtime tests/runtime/runtime_smoke_test.c \
 *         src/runtime/spnl_runtime.c -lbpf -lelf -lz -o /tmp/smoke
 *   /tmp/smoke <path-to-bpf.o> <ringbuf-map-name>
 */

#include "spnl_runtime.h"
#include <stdio.h>
#include <string.h>

struct args1 { long long x; };

struct unit_event {
    struct spnl_event_hdr hdr;
    long long value;
};

static int on_event(void *uc, const void *data, size_t sz)
{
    int *count = uc;
    const struct unit_event *e = data;
    printf("  [event] type=0x%04x ver=%u value=%lld\n",
           e->hdr.type, e->hdr.version, e->value);
    (*count)++;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <bpf.o> <ringbuf-map-name>\n", argv[0]);
        return 1;
    }
    spnl_runtime *rt = spnl_runtime_init(argv[1]);
    if (!rt) return 2;
    printf("[rt] loaded %s\n", argv[1]);

    /* Invoke spinel-ebpf-emitted SEC("syscall") programs by name. */
    int errs = 0;
    struct args1 ctx = {0};
    __u32 ret = 0;

    ctx.x = 42;
    if (spnl_runtime_call(rt, "report", &ctx, sizeof(ctx), &ret) == 0)
        printf("[rt] report(42) -> retval=%u\n", ret);
    else errs++;

    ctx.x = 10;
    if (spnl_runtime_call(rt, "report_doubled", &ctx, sizeof(ctx), &ret) == 0)
        printf("[rt] report_doubled(10) -> retval=%u\n", ret);
    else errs++;

    ctx.x = 7;
    if (spnl_runtime_call(rt, "report", &ctx, sizeof(ctx), &ret) == 0)
        printf("[rt] report(7) -> retval=%u\n", ret);
    else errs++;

    int got = 0;
    int n = spnl_runtime_ringbuf_drain(rt, argv[2], on_event, &got, 100);
    printf("[rt] drain returned %d, callbacks=%d\n", n, got);

    spnl_runtime_destroy(rt);
    return errs ? 3 : 0;
}
