/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Unit test for the event-boxed one-shot counter (SPNL_MAX_EVENTS).
 *
 * Exercises spnl_oneshot_add / spnl_oneshot_count threshold semantics WITHOUT
 * calling spnl_oneshot_exit (which would exit the process). The K limit is read
 * once, lazily, from the env, so run_oneshot.sh runs this binary once per
 * scenario with a different SPNL_MAX_EVENTS.
 */
#include "spnl_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) printf("  ok: %s\n", (msg)); \
    else { printf("  FAIL: %s\n", (msg)); fails++; } \
} while (0)

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";

    if (strcmp(mode, "unlimited") == 0) {
        /* SPNL_MAX_EVENTS unset/0 -> add never signals; count accumulates. */
        int hit = 0;
        for (int i = 0; i < 1000; i++) hit |= spnl_oneshot_add(1);
        CHECK(hit == 0, "unlimited: add never returns 1 (legacy/backward-compat)");
        CHECK(spnl_oneshot_count() == 1000, "unlimited: count == 1000");
    } else if (strcmp(mode, "single") == 0) {
        /* SPNL_MAX_EVENTS=100 -> flips to 1 exactly at the 100th event. */
        int flip = -1;
        for (int i = 1; i <= 150; i++)
            if (spnl_oneshot_add(1) && flip < 0) flip = i;
        CHECK(flip == 100, "single: threshold flips exactly at the 100th add");
        CHECK(spnl_oneshot_count() == 150, "single: count keeps accumulating past K");
    } else if (strcmp(mode, "batch") == 0) {
        /* SPNL_MAX_EVENTS=100 -> a batch add crosses K; overshoot is honest. */
        CHECK(spnl_oneshot_add(60) == 0, "batch: 60 < 100 -> 0");
        CHECK(spnl_oneshot_add(60) == 1, "batch: 60+60=120 >= 100 -> 1 (overshoot 20)");
        CHECK(spnl_oneshot_count() == 120, "batch: count == 120");
    } else if (strcmp(mode, "zero") == 0) {
        /* SPNL_MAX_EVENTS=0 is explicitly unlimited (same as unset). */
        int hit = 0;
        for (int i = 0; i < 500; i++) hit |= spnl_oneshot_add(1);
        CHECK(hit == 0, "zero: SPNL_MAX_EVENTS=0 -> unlimited");
    } else {
        fprintf(stderr, "usage: %s unlimited|single|batch|zero\n", argv[0]);
        return 2;
    }

    if (fails) { printf("FAIL (%d)\n", fails); return 1; }
    printf("PASS\n");
    return 0;
}
