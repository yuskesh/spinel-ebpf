/* SPDX-License-Identifier: GPL-2.0
 *
 * spnl/amp_ring.h -- SPSC event ring in the DDR carveout shared between the M7 and the A55.
 *
 * producer = M7 (amp_emit = helper id 1), consumer = A55 (drain -> OTLP).
 * A record is the shared 16-byte event header plus an int payload. A pure header
 * that compiles for both the M7 firmware and the host (on the M7 side the caller
 * or the runtime adds the cache flushes).
 *
 * On a real M7, base is the reserved address of the DDR carveout (set aside via
 * the system-manager config / device tree, either non-cacheable or explicitly
 * flushed to keep the two cores coherent). On the QEMU/host mock it is ordinary RAM.
 */
#ifndef SPNL_AMP_RING_H
#define SPNL_AMP_RING_H

#include <stdint.h>

#define AMP_RING_MAGIC   0x474E5241u  /* 'ARNG' */
#define AMP_RING_VERSION 1
#define AMP_EVT_USER_BASE 0x0100      /* SPNL_EVT_USER_BASE */

/* Shared event header (16 bytes; layout == struct spnl_event_hdr). */
struct amp_evt_hdr {
    uint16_t type;
    uint16_t version;
    uint32_t reserved;
    uint64_t timestamp;   /* producer ktime / NETC PHC ns */
};

struct amp_ring_rec {
    struct amp_evt_hdr hdr;   /* 16B */
    int64_t  value;           /* spnl_emit payload */
};

/* Ring control block; `capacity` record slots follow immediately after it. */
struct amp_ring {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;        /* number of record slots */
    uint32_t rec_size;        /* sizeof(struct amp_ring_rec) */
    volatile uint32_t prod;   /* producer index (monotonic; wraps at 2^32) */
    volatile uint32_t cons;   /* consumer index (monotonic) */
    uint32_t _pad[2];
};

static inline struct amp_ring_rec *amp_ring_slots(struct amp_ring *r) {
    return (struct amp_ring_rec *)((char *)r + sizeof(struct amp_ring));
}

static inline void amp_ring_init(struct amp_ring *r, uint32_t capacity) {
    r->magic = AMP_RING_MAGIC;
    r->version = AMP_RING_VERSION;
    r->capacity = capacity;
    r->rec_size = (uint32_t)sizeof(struct amp_ring_rec);
    r->prod = 0;
    r->cons = 0;
    r->_pad[0] = r->_pad[1] = 0;
}

/* Producer (M7 side = amp_emit helper). Single producer. Full ring drops the
 * newest (returns 0) rather than clobbering unread records; else writes the
 * slot and publishes by bumping `prod`. Returns 1 on write.
 * On the real M7 the runtime flushes the record cacheline THEN the prod index;
 * the index bump is the release. */
static inline int amp_ring_emit(struct amp_ring *r, uint64_t ts, int64_t value) {
    uint32_t prod = r->prod;
    uint32_t cons = r->cons;
    if (prod - cons >= r->capacity) return 0;   /* full: drop newest */
    struct amp_ring_rec *rec = &amp_ring_slots(r)[prod % r->capacity];
    rec->hdr.type = AMP_EVT_USER_BASE;
    rec->hdr.version = AMP_RING_VERSION;
    rec->hdr.reserved = 0;
    rec->hdr.timestamp = ts;
    rec->value = value;
    r->prod = prod + 1;   /* publish */
    return 1;
}

#endif /* SPNL_AMP_RING_H */
