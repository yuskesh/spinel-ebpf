/*
 * amp_trace_test.c -- correlates M7 events with an A55 request span through a
 * PHC timestamp window.
 *
 * The A55 request span [1000,2000] (PHC ns) is the parent: an M7 ring record
 * whose hdr.timestamp falls inside the window becomes a child span, one that
 * falls outside is emitted standalone. That is what puts the two cores on a
 * single time axis. Writes the payload bytes to argv[1] so the runner
 * (run_amp_trace.sh) can verify them with protoc --decode.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "spnl/amp_ring.h"
#include "amp_otlp.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.pb>\n", argv[0]); return 2; }

    const uint32_t CAP = 8;
    struct amp_ring *r = calloc(1, sizeof(struct amp_ring) + CAP * sizeof(struct amp_ring_rec));
    amp_ring_init(r, CAP);

    /* M7 emits 3: ts 1200 (in), 1800 (in), 2500 (out of the [1000,2000] window). */
    amp_ring_emit(r, 1200, 11);
    amp_ring_emit(r, 1800, 22);
    amp_ring_emit(r, 2500, 33);

    /* A55 request span (fixed ids for the decode assertions). */
    uint8_t tid[16], sid[8];
    for (int i = 0; i < 16; i++) tid[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 8;  i++) sid[i] = (uint8_t)(0xB0 + i);

    uint8_t buf[16384]; size_t nin = 0;
    long n = amp_ring_drain_trace(r, tid, sid, 1000, 2000, "GET /fetch",
                                  buf, sizeof buf, "spinel-amp-m7", "0.1.0",
                                  0x9E3779B97F4A7C15ULL, &nin);
    if (n <= 0) { fprintf(stderr, "drain_trace failed (n=%ld)\n", n); return 1; }
    if (nin != 2) { fprintf(stderr, "expected 2 in-window children, got %zu\n", nin); return 1; }
    fprintf(stderr, "[amp_trace] %zu in-window children (of 3 records)\n", nin);

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror("fopen"); return 1; }
    fwrite(buf, 1, (size_t)n, fp); fclose(fp);
    free(r);
    return 0;
}
