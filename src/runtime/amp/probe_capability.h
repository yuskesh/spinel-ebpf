/* SPDX-License-Identifier: GPL-2.0
 *
 * probe_capability.h -- the capability table, and admission against it.
 *
 * The firmware is the authority on what it can observe. Which attach points were
 * compiled in, which context fields each one fills, how much time a probe may
 * spend there — all of that is decided when the firmware is built, so asking the
 * Linux side to guess is how an installer ends up staging a probe the firmware
 * cannot run. Instead the firmware publishes the answer at boot and the
 * installer reads it.
 *
 * Two readers, deliberately:
 *
 *   the installer   rejects early, on the Linux side, where the error can name
 *                   the field that is missing and the person can fix the probe
 *   the loader      re-checks at install time, because the firmware may have
 *                   been swapped between the read and the stage
 *
 * The binding is `firmware_build_id` + `table_hash`, not `boot_generation`.
 * Requiring the generation to match would make a probe un-installable across a
 * restart that changed nothing; the generation is here so a mismatch can be
 * *detected* and reported as the time-of-check/time-of-use race it is, which is
 * diagnosis rather than policy.
 */
#ifndef SPNL_PROBE_CAPABILITY_H
#define SPNL_PROBE_CAPABILITY_H

#include <stdint.h>
#include <stddef.h>

#include "probe_ctx_gen.h"   /* struct probe_attach_capability, ids, bitmap width */

#define PROBE_CAP_MAGIC 0x50414341u   /* 'A''C''A''P' (LE) */

/* Fixed layout: the other core reads these bytes directly out of shared memory,
 * so every field is explicitly sized and the asserts below pin the whole thing.
 * Same discipline as the ringbuf record contract, for the same reason. */
struct probe_capability_header {
    uint32_t magic;                /* PROBE_CAP_MAGIC; anything else = not published */
    uint16_t format_version;       /* PROBE_CTX_FORMAT_VERSION */
    uint16_t firmware_abi_version; /* AMP_ABI_VERSION the firmware was built against */
    uint64_t boot_generation;      /* bumped every boot; TOCTOU detection, not a binding */
    uint8_t  firmware_build_id[20];/* identity of the running image */
    uint64_t table_hash;           /* over the entries; see the note below */
    uint32_t n_attach;             /* how many entries follow */
    uint32_t entry_bytes;          /* sizeof(struct probe_attach_capability) */
};

/* `table_hash` answers "is this the same table I read a moment ago", not "was
 * this authored by someone I trust". It is a 64-bit FNV-1a, not a digest, and
 * the field is typed as an integer rather than a 32-byte array so that nothing
 * reads as a SHA-256 that is not one.
 *
 * That is the right strength for the threat model this design actually has: the
 * A55 writes the staging area, so an A55 that is hostile can stage any blob it
 * likes and a signature over the capability table would not stop it. Trust in
 * the writer is assumed, and what is left to detect is corruption and staleness.
 * Introducing a real signature means introducing a key, and that belongs to the
 * multi-tenant / OTA design where the writer is *not* trusted -- a separate
 * decision, with its own ADR, not a field widened here in advance. */
uint64_t probe_capability_hash(const struct probe_attach_capability *entries, uint32_t n);

_Static_assert(sizeof(struct probe_capability_header) == 56,
               "probe_capability_header has implicit padding; the two cores would disagree");

/* --- publish (M-core) --- */

/* Write the table into `dst` (>= dst_bytes). Returns the bytes written, or 0 if
 * the region is too small -- which the firmware must treat as a boot failure
 * rather than a silent no-op, since an unpublished table makes every install
 * fail with "no capability" later and far away from the cause. */
size_t probe_capability_publish(void *dst, size_t dst_bytes,
                                const struct probe_attach_capability *entries, uint32_t n,
                                const uint8_t build_id[20], uint64_t boot_generation);

/* --- read (Linux installer, and the loader re-check) --- */

struct probe_capability_view {
    const struct probe_capability_header *hdr;
    const struct probe_attach_capability *entries;
    uint32_t n;
};

enum probe_cap_status {
    PROBE_CAP_OK = 0,
    PROBE_CAP_NOT_PUBLISHED = -1,  /* magic absent: the firmware never wrote it */
    PROBE_CAP_BAD_FORMAT    = -2,  /* format_version or entry_bytes we cannot read */
    PROBE_CAP_TRUNCATED     = -3,  /* n_attach does not fit the region */
    PROBE_CAP_BAD_HASH      = -4,  /* the entries do not match the header */
};

int probe_capability_open(const void *src, size_t src_bytes, struct probe_capability_view *out);
const char *probe_capability_strstatus(int status);

/* --- admission (the installer's decision) --- */

/* What a probe asks for. `context_fields` is a bitmap in the same numbering the
 * capability publishes, so the comparison is one AND rather than a name walk. */
struct probe_requirement {
    uint32_t attach_id;
    uint64_t context_fields[PROBE_CTX_BITMAP_WORDS];
    uint32_t cost_units;            /* what the toolchain computed */
    uint8_t  firmware_build_id[20]; /* the image this probe was admitted against */
    int      bind_build_id;         /* 0 = first admission, no image to bind to yet */
};

enum probe_admit_status {
    PROBE_ADMIT_OK = 0,
    PROBE_ADMIT_NO_SUCH_ATTACH   = -1,
    PROBE_ADMIT_MISSING_FIELD    = -2,  /* asked for a field this point does not fill */
    PROBE_ADMIT_OVER_BUDGET      = -3,
    PROBE_ADMIT_WRONG_FIRMWARE   = -4,  /* the image changed under us */
};

/* Returns PROBE_ADMIT_OK or one of the negatives above. On MISSING_FIELD,
 * *missing_field_id receives one field id that was asked for and not provided,
 * so the rejection can name it instead of saying "some field". */
int probe_capability_admit(const struct probe_capability_view *view,
                           const struct probe_requirement *req,
                           uint32_t *missing_field_id);
const char *probe_capability_stradmit(int status);

#endif /* SPNL_PROBE_CAPABILITY_H */
