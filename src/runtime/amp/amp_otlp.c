/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * amp_otlp.c -- the drain on the application core. Turns the records in the shared
 * ring into OTLP logs. On real hardware the consumer invalidates the index before
 * reading it, as the cache contract requires.
 * Under a host or emulator mock it is ordinary memory.
 */
#include <string.h>
#include <stdio.h>
#include "spnl/amp_ring.h"
#include "amp_otlp.h"
#include "otlp_logs.h"
#include "otlp_traces.h"

#define AMP_DRAIN_MAX 64   /* records per build (matches SPNL_OTLP_BATCH_MAX spirit) */

long amp_ring_drain_logs(struct amp_ring *r, uint8_t *buf, size_t cap,
                         const char *service, const char *version,
                         size_t max, size_t *n_drained) {
    if (n_drained) *n_drained = 0;
    if (!r || r->magic != AMP_RING_MAGIC) return -1;
    if (max == 0 || max > AMP_DRAIN_MAX) max = AMP_DRAIN_MAX;

    otlp_log_record_t recs[AMP_DRAIN_MAX];
    struct amp_ring_rec *slots = amp_ring_slots(r);
    size_t n = 0;
    uint32_t cons = r->cons;
    while (n < max && cons != r->prod) {
        struct amp_ring_rec *src = &slots[cons % r->capacity];
        otlp_log_record_t *dst = &recs[n];
        dst->time_unix_ns = src->hdr.timestamp;
        dst->severity     = 0;              /* INFO */
        dst->body_is_str  = false;
        dst->body_str     = 0;
        dst->body_int     = src->value;
        dst->event_name   = "amp.emit";
        n++;
        cons++;
    }
    if (n == 0) return 0;   /* nothing pending */

    long len = otlp_logs_build(buf, cap, service, version, "spinel-amp-m7", recs, n);
    if (len < 0) return -1;   /* leave cons unchanged so records aren't lost */
    r->cons = cons;           /* commit consumption only after a successful build */
    if (n_drained) *n_drained = n;
    return len;
}

long amp_ring_drain_trace(struct amp_ring *r,
                          const uint8_t req_trace_id[16], const uint8_t req_span_id[8],
                          uint64_t req_start_ns, uint64_t req_end_ns, const char *req_name,
                          uint8_t *buf, size_t cap, const char *service, const char *version,
                          uint64_t seed, size_t *n_children) {
    if (n_children) *n_children = 0;
    if (!r || r->magic != AMP_RING_MAGIC) return -1;

    /* spans[0] = the A55 request span (parent). Children/standalones follow. */
    otlp_generic_span_t spans[AMP_DRAIN_MAX + 1];
    otlp_kv_t attrs[AMP_DRAIN_MAX];
    memset(spans, 0, sizeof spans);

    otlp_generic_span_t *req = &spans[0];
    memcpy(req->trace_id, req_trace_id, 16);
    memcpy(req->span_id, req_span_id, 8);
    req->has_parent = false;
    req->start_unix_ns = req_start_ns;
    req->end_unix_ns = req_end_ns;
    req->name = req_name ? req_name : "a55.request";
    req->kind = 2;   /* SERVER */

    struct amp_ring_rec *slots = amp_ring_slots(r);
    size_t ns = 1, nin = 0;
    uint32_t cons = r->cons;
    while (ns <= AMP_DRAIN_MAX && cons != r->prod) {
        struct amp_ring_rec *src = &slots[cons % r->capacity];
        uint64_t ts = src->hdr.timestamp;
        otlp_generic_span_t *s = &spans[ns];
        int in_window = (ts >= req_start_ns && ts <= req_end_ns);
        if (in_window) { otlp_span_new_child(s, req, &seed); nin++; }
        else           { otlp_span_new_root(s, &seed); }
        s->start_unix_ns = ts;
        s->end_unix_ns = ts;
        s->name = "amp.emit";
        s->kind = 1;   /* INTERNAL */
        snprintf(attrs[ns - 1].key, sizeof attrs[ns - 1].key, "amp.value");
        snprintf(attrs[ns - 1].val, sizeof attrs[ns - 1].val, "%lld", (long long)src->value);
        s->attrs = &attrs[ns - 1];
        s->nattrs = 1;
        ns++; cons++;
    }

    long len = otlp_traces_generic_build_multi(buf, cap, service, version, "spinel-amp-m7", spans, ns);
    if (len < 0) return -1;
    r->cons = cons;
    if (n_children) *n_children = nin;
    return len;
}
