/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * probe_capability.c -- publish, read and admit against the capability
 * table. Freestanding C: no allocation, no libc beyond memcpy/memset, so the
 * same object builds for the M-core firmware and for the Linux installer.
 */
#include <string.h>

#include "probe_capability.h"

/* FNV-1a, 64-bit. Chosen for what it is asked to do -- notice corruption and a
 * changed table -- and named `hash` rather than `digest` so nothing reads it as
 * a security property. See the note in probe_capability.h. */
uint64_t probe_capability_hash(const struct probe_attach_capability *entries, uint32_t n) {
    const uint8_t *p = (const uint8_t *)entries;
    size_t len = (size_t)n * sizeof(*entries);
    uint64_t h = 1469598103934665603ULL;   /* offset basis */
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;             /* prime */
    }
    return h;
}

size_t probe_capability_publish(void *dst, size_t dst_bytes,
                                const struct probe_attach_capability *entries, uint32_t n,
                                const uint8_t build_id[20], uint64_t boot_generation) {
    size_t need = sizeof(struct probe_capability_header) + (size_t)n * sizeof(*entries);
    if (!dst || dst_bytes < need) return 0;

    /* Zero first: the region is shared memory that may hold a previous boot's
     * table, and a partially overwritten one is worse than none -- it would pass
     * the magic check with stale entries behind it. */
    memset(dst, 0, dst_bytes);

    struct probe_capability_header *h = (struct probe_capability_header *)dst;
    h->format_version = (uint16_t)PROBE_CTX_FORMAT_VERSION;
    h->firmware_abi_version = 0;   /* filled by the firmware; 0 = unset in host tests */
    h->boot_generation = boot_generation;
    if (build_id) memcpy(h->firmware_build_id, build_id, sizeof h->firmware_build_id);
    h->n_attach = n;
    h->entry_bytes = (uint32_t)sizeof(*entries);

    struct probe_attach_capability *e =
        (struct probe_attach_capability *)((uint8_t *)dst + sizeof *h);
    if (n) memcpy(e, entries, (size_t)n * sizeof(*entries));
    h->table_hash = probe_capability_hash(e, n);

    /* Magic last. A reader that catches the region mid-write sees "not
     * published" rather than a header whose entries have not landed yet. On the
     * M-core this store is followed by a cache flush of the whole region, in
     * that order, for the same reason the ring publishes its index last. */
    h->magic = PROBE_CAP_MAGIC;
    return need;
}

int probe_capability_open(const void *src, size_t src_bytes, struct probe_capability_view *out) {
    if (!src || !out || src_bytes < sizeof(struct probe_capability_header))
        return PROBE_CAP_NOT_PUBLISHED;

    const struct probe_capability_header *h = (const struct probe_capability_header *)src;
    if (h->magic != PROBE_CAP_MAGIC) return PROBE_CAP_NOT_PUBLISHED;
    if (h->format_version != (uint16_t)PROBE_CTX_FORMAT_VERSION) return PROBE_CAP_BAD_FORMAT;
    if (h->entry_bytes != (uint32_t)sizeof(struct probe_attach_capability)) return PROBE_CAP_BAD_FORMAT;

    size_t need = sizeof(*h) + (size_t)h->n_attach * sizeof(struct probe_attach_capability);
    if (need > src_bytes) return PROBE_CAP_TRUNCATED;

    const struct probe_attach_capability *e =
        (const struct probe_attach_capability *)((const uint8_t *)src + sizeof *h);
    if (probe_capability_hash(e, h->n_attach) != h->table_hash) return PROBE_CAP_BAD_HASH;

    out->hdr = h;
    out->entries = e;
    out->n = h->n_attach;
    return PROBE_CAP_OK;
}

const char *probe_capability_strstatus(int status) {
    switch (status) {
    case PROBE_CAP_OK:              return "ok";
    case PROBE_CAP_NOT_PUBLISHED:   return "no capability table published (is the firmware running?)";
    case PROBE_CAP_BAD_FORMAT:      return "capability table format this installer cannot read";
    case PROBE_CAP_TRUNCATED:       return "capability table claims more entries than the region holds";
    case PROBE_CAP_BAD_HASH:        return "capability table hash mismatch (corrupt or written mid-read)";
    default:                        return "unknown capability status";
    }
}

int probe_capability_admit(const struct probe_capability_view *view,
                           const struct probe_requirement *req,
                           uint32_t *missing_field_id) {
    if (missing_field_id) *missing_field_id = 0;
    if (!view || !req) return PROBE_ADMIT_NO_SUCH_ATTACH;

    /* The image must still be the one this probe was checked against. Checked
     * first: if the firmware changed, every other answer below is about the
     * wrong firmware, and reporting "missing field" for that would send the
     * reader looking at their probe instead of at the swap. */
    if (req->bind_build_id &&
        memcmp(req->firmware_build_id, view->hdr->firmware_build_id,
               sizeof req->firmware_build_id) != 0)
        return PROBE_ADMIT_WRONG_FIRMWARE;

    const struct probe_attach_capability *at = NULL;
    for (uint32_t i = 0; i < view->n; i++) {
        if (view->entries[i].attach_id == req->attach_id) { at = &view->entries[i]; break; }
    }
    if (!at) return PROBE_ADMIT_NO_SUCH_ATTACH;

    /* Every field the probe reads must be one this attach point fills. The
     * capability publishes a bitmap in the generated numbering, so this is an
     * AND -- and the first bit that is asked for and not provided is reported by
     * id, because "thread.previous.id is not published here" is actionable and
     * "some field is missing" is not. */
    for (uint32_t w = 0; w < PROBE_CTX_BITMAP_WORDS && w < at->field_bitmap_words; w++) {
        uint64_t want = req->context_fields[w];
        uint64_t missing = want & ~at->field_bitmap[w];
        if (!missing) continue;
        if (missing_field_id) {
            for (int b = 0; b < 64; b++) {
                if (missing & (1ULL << b)) { *missing_field_id = w * 64u + (uint32_t)b; break; }
            }
        }
        return PROBE_ADMIT_MISSING_FIELD;
    }
    /* A requirement wider than the published bitmap asks for fields this
     * firmware's numbering does not even have. */
    for (uint32_t w = at->field_bitmap_words; w < PROBE_CTX_BITMAP_WORDS; w++) {
        if (!req->context_fields[w]) continue;
        if (missing_field_id) {
            for (int b = 0; b < 64; b++) {
                if (req->context_fields[w] & (1ULL << b)) {
                    *missing_field_id = w * 64u + (uint32_t)b; break;
                }
            }
        }
        return PROBE_ADMIT_MISSING_FIELD;
    }

    if (req->cost_units > at->max_cycle_budget) return PROBE_ADMIT_OVER_BUDGET;
    return PROBE_ADMIT_OK;
}

const char *probe_capability_stradmit(int status) {
    switch (status) {
    case PROBE_ADMIT_OK:                return "admitted";
    case PROBE_ADMIT_NO_SUCH_ATTACH:    return "this firmware does not export that attach point";
    case PROBE_ADMIT_MISSING_FIELD:     return "that attach point does not provide a context field the probe reads";
    case PROBE_ADMIT_OVER_BUDGET:       return "the probe's computed cost exceeds what that attach point admits";
    case PROBE_ADMIT_WRONG_FIRMWARE:    return "the running firmware is not the image this probe was checked against";
    default:                            return "unknown admission status";
    }
}
