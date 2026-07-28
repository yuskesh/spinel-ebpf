/*
 * amp_ring_test.c -- host-side verification of the M7<->A55 shared ring
 * (spnl/amp_ring.h).
 *
 * The producer (the M7 amp_emit side) writes records carrying the common 16-byte
 * event header into the ring; the consumer (the A55 side) drains them and builds
 * OTLP logs. Also exercises the single-producer/single-consumer wrap-around and
 * the full-drop path. Writes the payload bytes to argv[1] so the runner
 * (run_amp_ring.sh) can verify them with protoc --decode.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "spnl/amp_ring.h"
#include "amp_otlp.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out.pb>\n", argv[0]); return 2; }

    /* carveout stand-in: control block + 4 record slots (small, to force wrap). */
    const uint32_t CAP = 4;
    size_t bytes = sizeof(struct amp_ring) + CAP * sizeof(struct amp_ring_rec);
    struct amp_ring *r = calloc(1, bytes);
    amp_ring_init(r, CAP);

    const uint64_t base = 1700000000000000000ULL;

    /* Producer emits 3 (as the blink probe would: values 1,2,3). */
    for (int i = 1; i <= 3; i++)
        if (!amp_ring_emit(r, base + (uint64_t)i, i)) { fprintf(stderr, "unexpected full\n"); return 1; }

    /* Consumer drains -> first OTLP payload (3 records). */
    uint8_t buf[8192];
    size_t nd = 0;
    long n = amp_ring_drain_logs(r, buf, sizeof buf, "spinel-amp-m7", "0.1.0", 0, &nd);
    if (n <= 0 || nd != 3) { fprintf(stderr, "drain1 failed (n=%ld nd=%zu)\n", n, nd); return 1; }
    fprintf(stderr, "[amp_ring] drain1: %zu records, %ld bytes\n", nd, n);

    /* Stress full-drop on a fresh 4-slot ring: emit 6 (values 1..6); 4 fit,
     * 5 and 6 are dropped (never clobber unread records). */
    amp_ring_init(r, CAP);
    int written = 0, dropped = 0;
    for (int v = 1; v <= 6; v++) { if (amp_ring_emit(r, base + (uint64_t)v, v)) written++; else dropped++; }
    if (written != 4 || dropped != 2) { fprintf(stderr, "wrap/full wrong (w=%d d=%d)\n", written, dropped); return 1; }
    fprintf(stderr, "[amp_ring] full-drop ok: wrote 4, dropped 2 (values 1..4 kept)\n");

    /* drain the 4 survivors, then emit 4 more across the wrap boundary, drain again. */
    size_t nd2 = 0;
    uint8_t buf2[8192];
    long n2 = amp_ring_drain_logs(r, buf2, sizeof buf2, "spinel-amp-m7", "0.1.0", 0, &nd2);
    if (n2 <= 0 || nd2 != 4) { fprintf(stderr, "drain2 failed (nd=%zu)\n", nd2); return 1; }
    for (int v = 5; v <= 8; v++) if (!amp_ring_emit(r, base + (uint64_t)v, v)) { fprintf(stderr, "wrap emit full\n"); return 1; }
    size_t nd3 = 0;
    long n3 = amp_ring_drain_logs(r, buf2, sizeof buf2, "spinel-amp-m7", "0.1.0", 0, &nd3);
    if (n3 <= 0 || nd3 != 4) { fprintf(stderr, "drain3 (wrap) failed (nd=%zu)\n", nd3); return 1; }
    fprintf(stderr, "[amp_ring] wrap drain ok: values 5..8 across slot boundary\n");

    /* write the FIRST payload (values 1,2,3) for protoc decode by the runner. */
    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror("fopen"); return 1; }
    if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) { perror("fwrite"); fclose(fp); return 1; }
    fclose(fp);
    free(r);
    return 0;
}
