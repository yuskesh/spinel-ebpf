/* SPDX-License-Identifier: GPL-2.0
 *
 * probe_capability_test.c -- publish -> read -> admit, on the host.
 *
 * No hardware and no firmware: the shared-memory region is a buffer, which is
 * exactly what the contract says it is. What is being pinned here is the shape
 * of the negotiation, before a dispatcher exists to depend on it -- so that the
 * capability format is settled by this test rather than by whatever the first
 * QEMU proof-of-concept happened to need (the table is built before the
 * reason).
 *
 * The positive case is one assertion. The rest are negative controls, because an
 * admission check that admits everything looks identical to one that works.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "probe_capability.h"

/* Zephyr's IF_ENABLED, minimally, so the generated table initialiser can be
 * instantiated on the host. Without this the macro is only ever expanded by a
 * firmware build, and a stray comma or paren in the generator would surface
 * there -- days later, in the place least convenient to debug. */
#define _STRIP(...) __VA_ARGS__
#define _IF_ENABLED_1(code) _STRIP code
#define _IF_ENABLED_0(code)
#define _IF_ENABLED_(flag, code) _IF_ENABLED_##flag(code)
#define IF_ENABLED(flag, code) _IF_ENABLED_(flag, code)

static int fails;

#define CHECK(cond, ...) do { \
    if (cond) { printf("  ok: "); printf(__VA_ARGS__); printf("\n"); } \
    else { printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); fails++; } \
} while (0)

/* The one attach point v0 publishes, taken from the generated schema rather than
 * hand-written here -- a test that restates the table cannot catch it drifting. */
static const struct probe_attach_capability TABLE[] = {
    { .attach_id = PROBE_ATTACH_THREAD_SWITCHED_IN,
      .exec_class = PROBE_EXEC_SCHED_LOCKED,
      .max_cycle_budget = 500u,
      .field_bitmap_words = PROBE_CTX_BITMAP_WORDS,
      .field_bitmap = PROBE_ATTACH_THREAD_SWITCHED_IN_BITMAP },
};
#define N_TABLE ((uint32_t)(sizeof TABLE / sizeof TABLE[0]))

static const uint8_t BUILD_A[20] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4 };
static const uint8_t BUILD_B[20] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4 };

static void want_field(struct probe_requirement *r, unsigned id) {
    r->context_fields[id / 64] |= 1ULL << (id % 64);
}

int main(void) {
    uint8_t shm[4096];

    printf("[u3] publish\n");
    size_t n = probe_capability_publish(shm, sizeof shm, TABLE, N_TABLE, BUILD_A, 7);
    CHECK(n == sizeof(struct probe_capability_header) + sizeof TABLE,
          "published %zu bytes (header + %u entries)", n, N_TABLE);

    struct probe_capability_view v;
    int st = probe_capability_open(shm, sizeof shm, &v);
    CHECK(st == PROBE_CAP_OK, "readable: %s", probe_capability_strstatus(st));
    CHECK(v.n == N_TABLE && v.entries[0].attach_id == PROBE_ATTACH_THREAD_SWITCHED_IN,
          "one attach point, thread.switched_in");
    CHECK(v.hdr->boot_generation == 7, "boot generation carried through");

    printf("[u3] admission: a probe that asks for what is published\n");
    struct probe_requirement ok = { .attach_id = PROBE_ATTACH_THREAD_SWITCHED_IN, .cost_units = 200 };
    want_field(&ok, PROBE_CTX_FIELD_THREAD_CURRENT_ID);
    want_field(&ok, PROBE_CTX_FIELD_TIMESTAMP_CYCLES);
    uint32_t missing = 0;
    CHECK(probe_capability_admit(&v, &ok, &missing) == PROBE_ADMIT_OK, "admitted");

    printf("[u3] negative controls\n");

    /* the case the plan names: the attach point exists, the field does not */
    struct probe_requirement nofield = ok;
    want_field(&nofield, PROBE_CTX_N_FIELDS + 1);   /* an id past everything declared */
    int r = probe_capability_admit(&v, &nofield, &missing);
    CHECK(r == PROBE_ADMIT_MISSING_FIELD && missing == PROBE_CTX_N_FIELDS + 1,
          "unpublished field rejected, and named (id %u): %s", missing,
          probe_capability_stradmit(r));

    struct probe_requirement noattach = ok;
    noattach.attach_id = 0x0999u;
    r = probe_capability_admit(&v, &noattach, &missing);
    CHECK(r == PROBE_ADMIT_NO_SUCH_ATTACH, "unknown attach point rejected: %s",
          probe_capability_stradmit(r));

    struct probe_requirement pricey = ok;
    pricey.cost_units = 501;   /* one over the published ceiling */
    r = probe_capability_admit(&v, &pricey, &missing);
    CHECK(r == PROBE_ADMIT_OVER_BUDGET, "cost one unit over the ceiling rejected: %s",
          probe_capability_stradmit(r));
    pricey.cost_units = 500;
    CHECK(probe_capability_admit(&v, &pricey, &missing) == PROBE_ADMIT_OK,
          "cost exactly at the ceiling admitted (the boundary is inclusive)");

    /* the TOCTOU case: read the table, firmware is replaced, stage anyway */
    struct probe_requirement bound = ok;
    bound.bind_build_id = 1;
    memcpy(bound.firmware_build_id, BUILD_A, sizeof bound.firmware_build_id);
    CHECK(probe_capability_admit(&v, &bound, &missing) == PROBE_ADMIT_OK,
          "bound to the image it was checked against: admitted");
    probe_capability_publish(shm, sizeof shm, TABLE, N_TABLE, BUILD_B, 8);
    probe_capability_open(shm, sizeof shm, &v);
    r = probe_capability_admit(&v, &bound, &missing);
    CHECK(r == PROBE_ADMIT_WRONG_FIRMWARE, "firmware swapped under us: rejected: %s",
          probe_capability_stradmit(r));

    printf("[u3] reader refuses a table it cannot trust\n");

    uint8_t blank[4096] = {0};
    CHECK(probe_capability_open(blank, sizeof blank, &v) == PROBE_CAP_NOT_PUBLISHED,
          "never published: %s", probe_capability_strstatus(PROBE_CAP_NOT_PUBLISHED));

    probe_capability_publish(shm, sizeof shm, TABLE, N_TABLE, BUILD_A, 9);
    ((struct probe_capability_header *)shm)->format_version += 1;
    CHECK(probe_capability_open(shm, sizeof shm, &v) == PROBE_CAP_BAD_FORMAT,
          "a format this installer cannot read is refused, not guessed at");

    probe_capability_publish(shm, sizeof shm, TABLE, N_TABLE, BUILD_A, 9);
    ((struct probe_capability_header *)shm)->n_attach = 1000;
    CHECK(probe_capability_open(shm, sizeof shm, &v) == PROBE_CAP_TRUNCATED,
          "more entries claimed than the region holds: refused");

    /* one bit flipped in an entry: the hash is what notices */
    probe_capability_publish(shm, sizeof shm, TABLE, N_TABLE, BUILD_A, 9);
    shm[sizeof(struct probe_capability_header) + 8] ^= 0x01;
    CHECK(probe_capability_open(shm, sizeof shm, &v) == PROBE_CAP_BAD_HASH,
          "a single flipped bit in the entries is caught by the hash");

    /* a region too small to hold what was asked for must fail loudly, not
     * publish a header with no entries behind it */
    CHECK(probe_capability_publish(shm, sizeof(struct probe_capability_header), TABLE, N_TABLE,
                                   BUILD_A, 1) == 0,
          "a region too small to hold the table publishes nothing");

    printf("[u3] the generated table initialiser, and the Kconfig gate on it\n");
    {
        /* built in: the entry is published, and it is the one the schema declares */
#define CONFIG_OBS_ATTACH_THREAD_SWITCHED_IN 1
        static const struct probe_attach_capability GEN_ON[] = { PROBE_CAPABILITY_TABLE_INIT };
#undef CONFIG_OBS_ATTACH_THREAD_SWITCHED_IN
        CHECK(sizeof GEN_ON / sizeof GEN_ON[0] == 1,
              "generated initialiser yields 1 entry when the attach point is built in");
        CHECK(memcmp(GEN_ON, TABLE, sizeof TABLE) == 0,
              "generated entry is byte-identical to the declared one "
              "(id, exec class, budget and bitmap all come from the schema)");

        /* not built in: nothing is published. The hook inventory upstream is
         * Zephyr's hook inventory is not this firmware's exported attach set --
         * and it is checked here rather than left as prose. */
#define CONFIG_OBS_ATTACH_THREAD_SWITCHED_IN 0
        static const struct probe_attach_capability GEN_OFF[] = { PROBE_CAPABILITY_TABLE_INIT 0 };
#undef CONFIG_OBS_ATTACH_THREAD_SWITCHED_IN
        CHECK(GEN_OFF[0].attach_id == 0,
              "an attach point that was not built in is not published");
    }

    if (fails) { printf("FAIL: probe capability (%d)\n", fails); return 1; }
    printf("PASS: probe capability — publish / read / admit, with negative controls\n");
    return 0;
}
