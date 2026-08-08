/*
 * egress_contract_test.c -- does the DECLARATION describe the span the runtime
 * actually builds?
 *
 * Three things moved out of prose and into src/codegen_c/record_schema.h:
 * when each egress attribute is on the span (`present`), when a record produces
 * no span at all (`drop_when`), and what the span's start and end are
 * (`timing_form`). The generator turns those into predicates and timing helpers.
 *
 * A declaration that nothing checks is a second copy of the prose. So this test
 * takes synthetic records through BOTH paths --
 *
 *   (1) the declaration : the generated table spnl_egress_rules_<ch>[] and the
 *                         generated spnl_rec_<ch>_span_{start,end}_unix()
 *   (2) the wire        : <ch>_fill_span(), the builder the concise push and the
 *                         typed consumer's to_span() both go through
 *
 * -- and compares them. The two are written independently: the runtime's `if
 * (method[0])` was there before the declaration existed and has not been changed
 * to call the generated predicate, precisely so that this test measures an
 * agreement instead of a tautology (the same argument record_span_parity_test.c
 * makes for values).
 *
 * The comparison is by SET, not by count: for every rule in the generated table
 * the attribute must be present exactly when the predicate says, and every
 * attribute on the span must have a rule. So an attribute added to the
 * declaration but not to the builder (or the reverse) fails without anybody
 * remembering to update a number here.
 *
 * Rules the declaration REFUSES to express (redis's two RESP-gated attributes)
 * carry a NULL predicate and their reason; they are skipped by name, and the
 * skip is printed, so "cannot say" never quietly reads as "always".
 *
 * No kernel, no probe, no collector: the records are synthetic. libbpf is linked
 * because otlp_agent.c drains ringbufs (never called here).
 *
 *   sh tests/runtime/run_egress_contract.sh
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "otlp_agent.c"

static int g_fail;
static int g_checks;

static const char *attr_of(const otlp_kv_t *a, int n, const char *key) {
    for (int i = 0; i < n; i++) if (strcmp(a[i].key, key) == 0) return a[i].val;
    return NULL;
}

static void ok(const char *ch, const char *what, const char *detail, int good) {
    g_checks++;
    if (!good) g_fail = 1;
    printf("  %-7s %-34s %-34s %s\n", ch, what, detail, good ? "MATCH" : "**DIFF**");
}

/* ---------------------------------------------------------- channel adapters */

typedef int      (*build_fn)(const void *rec, int64_t off, uint64_t now,
                             otlp_generic_span_t *s, otlp_kv_t *attrs, char *nb, size_t nc);
typedef int      (*drop_fn)(const void *rec);
typedef uint64_t (*time_fn)(const void *rec, int64_t off, uint64_t now);

typedef struct {
    const char               *id;
    const spnl_egress_rule_t *rules;
    int                       nrules;
    build_fn                  build;
    drop_fn                   dropped;   /* NULL = the channel declares no drop rule */
    time_fn                   start;
    time_fn                   end;
} chan_t;

#define ADAPT(ch, TYPE, BUILDER, PASS_NOW)                                                    \
    static int ch##_build(const void *rec, int64_t off, uint64_t now,                         \
                          otlp_generic_span_t *s, otlp_kv_t *attrs, char *nb, size_t nc) {    \
        uint64_t seed = 1;                                                                    \
        (void)off; (void)now;                                                                 \
        return BUILDER((const TYPE *)rec, PASS_NOW, &seed, s, attrs, nb, nc);                 \
    }                                                                                         \
    static uint64_t ch##_start(const void *rec, int64_t off, uint64_t now) {                  \
        return spnl_rec_##ch##_span_start_unix((const TYPE *)rec, off, now);                   \
    }                                                                                         \
    static uint64_t ch##_end(const void *rec, int64_t off, uint64_t now) {                    \
        return spnl_rec_##ch##_span_end_unix((const TYPE *)rec, off, now);                     \
    }

ADAPT(dns,    spnl_rec_dns_t,    dns_fill_span,    off)
ADAPT(conn,   spnl_rec_conn_t,   conn_fill_span,   off)
ADAPT(l7,     spnl_rec_l7_t,     l7_fill_span,     off)
ADAPT(http,   spnl_rec_http_t,   http_fill_span,   off)
/* offcpu's start is not a record field (wall_now_minus:duration_ns), which is
 * why its builder takes `now` where the others take the ktime offset -- the one
 * asymmetry the declared vocabulary had to grow a second start form for. */
ADAPT(offcpu, spnl_rec_offcpu_t, offcpu_fill_span, now)

static int dns_dropv(const void *r) { return spnl_rec_dns_dropped((const spnl_rec_dns_t *)r); }

/* ------------------------------------------------------------- the comparison */

static void check_case(const chan_t *c, const void *rec, const char *what,
                       int64_t off, uint64_t now) {
    otlp_generic_span_t s;
    otlp_kv_t attrs[32];
    char namebuf[256];
    char detail[128];
    int built;

    memset(attrs, 0, sizeof attrs);
    built = c->build(rec, off, now, &s, attrs, namebuf, sizeof namebuf);

    /* (a) the drop rule: a record the declaration says produces no span must be
     * exactly the record the builder refuses to build. */
    if (c->dropped) {
        int declared = c->dropped(rec);
        snprintf(detail, sizeof detail, "declared drop=%d built=%d", declared, built);
        ok(c->id, what, detail, declared == !built);
        if (declared) return;   /* nothing else to compare on a record with no span */
    } else {
        snprintf(detail, sizeof detail, "no drop rule; built=%d", built);
        ok(c->id, what, detail, built == 1);
        if (!built) return;
    }

    /* (b) presence, by set. */
    for (int i = 0; i < c->nrules; i++) {
        const spnl_egress_rule_t *r = &c->rules[i];
        int on_span, declared;
        if (!r->present) {
            printf("  %-7s %-34s %-34s SKIP (declaration refuses to express this rule)\n",
                   c->id, what, r->key);
            continue;
        }
        on_span  = attr_of(attrs, s.nattrs, r->key) != NULL;
        declared = r->present(rec) != 0;
        snprintf(detail, sizeof detail, "%s declared=%d span=%d", r->key, declared, on_span);
        ok(c->id, what, detail, declared == on_span);
    }
    /* the other direction: nothing on the span that the declaration never named */
    for (int i = 0; i < s.nattrs; i++) {
        int known = 0;
        for (int k = 0; k < c->nrules; k++) if (strcmp(c->rules[k].key, attrs[i].key) == 0) known = 1;
        snprintf(detail, sizeof detail, "%s is on the span", attrs[i].key);
        ok(c->id, what, detail, known);
    }

    /* (c) the timing, from the declared form. */
    {
        uint64_t ds = c->start(rec, off, now), de = c->end(rec, off, now);
        snprintf(detail, sizeof detail, "start decl=%" PRIu64 " span=%" PRIu64, ds, s.start_unix_ns);
        ok(c->id, what, detail, ds == s.start_unix_ns);
        snprintf(detail, sizeof detail, "end   decl=%" PRIu64 " span=%" PRIu64, de, s.end_unix_ns);
        ok(c->id, what, detail, de == s.end_unix_ns);
    }
}

/* --------------------------------------------------------------- the records */

/* "example.com" as a DNS question: the walk starts at raw[12]. */
static void dns_question(unsigned char *raw) {
    memset(raw, 0, 64);
    raw[12] = 7; memcpy(raw + 13, "example", 7);
    raw[20] = 3; memcpy(raw + 21, "com", 3);
    raw[24] = 0;
}

int main(void) {
    const int64_t  off = 1700000000000000000LL;   /* an implausible but exact offset */
    const uint64_t now = 1800000000000000000ULL;

    printf("[egress] egress contract: the declaration vs the span the runtime builds\n\n");

    /* -------- dns */
    {
        static const chan_t C = { "dns", spnl_egress_rules_dns,
                                  (int)(sizeof spnl_egress_rules_dns / sizeof spnl_egress_rules_dns[0]),
                                  dns_build, dns_dropv, dns_start, dns_end };
        spnl_rec_dns_t r;
        memset(&r, 0, sizeof r);
        r.hdr.timestamp = 4242424242ULL;
        dns_question(r.raw);
        snprintf(r.comm, sizeof r.comm, "getent");
        r.duration_ns = 60ULL * 1000 * 1000;
        check_case(&C, &r, "query + comm + rtt", off, now);

        r.comm[0] = '\0';
        r.duration_ns = 0;
        check_case(&C, &r, "no comm, no rtt", off, now);

        memset(r.raw, 0, sizeof r.raw);   /* not a parseable question */
        check_case(&C, &r, "unparseable -> no span", off, now);
    }

    /* -------- conn */
    {
        static const chan_t C = { "conn", spnl_egress_rules_conn,
                                  (int)(sizeof spnl_egress_rules_conn / sizeof spnl_egress_rules_conn[0]),
                                  conn_build, NULL, conn_start, conn_end };
        spnl_rec_conn_t r;
        memset(&r, 0, sizeof r);
        r.hdr.timestamp = 777000ULL;
        r.daddr = 0x0100007f; r.dport = 443; r.family = 2;
        r.srtt_us = 8000; r.oldstate = 2;
        snprintf(r.comm, sizeof r.comm, "curl");
        check_case(&C, &r, "v4 active + comm", off, now);

        r.comm[0] = '\0';
        r.family = 10; r.daddr6_hi = 0; r.daddr6_lo = 0x0100000000000000ULL;
        check_case(&C, &r, "v6, no comm", off, now);
    }

    /* -------- l7 */
    {
        static const chan_t C = { "l7", spnl_egress_rules_l7,
                                  (int)(sizeof spnl_egress_rules_l7 / sizeof spnl_egress_rules_l7[0]),
                                  l7_build, NULL, l7_start, l7_end };
        spnl_rec_l7_t r;
        memset(&r, 0, sizeof r);
        r.start_ktime = 1234567ULL; r.duration_ns = 5000000ULL;
        r.daddr = 0x0100007f; r.dport = 6379; r.family = 2;
        snprintf(r.comm, sizeof r.comm, "app");
        check_case(&C, &r, "round trip + comm", off, now);

        r.comm[0] = '\0';
        check_case(&C, &r, "no comm", off, now);
    }

    /* -------- http */
    {
        static const chan_t C = { "http", spnl_egress_rules_http,
                                  (int)(sizeof spnl_egress_rules_http / sizeof spnl_egress_rules_http[0]),
                                  http_build, NULL, http_start, http_end };
        spnl_rec_http_t r;
        memset(&r, 0, sizeof r);
        r.start_ktime = 99ULL; r.duration_ns = 1500000ULL;
        r.daddr = 0x0100007f; r.dport = 8080; r.family = 2;
        memcpy(r.req, "GET /health HTTP/1.1", 20);
        memcpy(r.resp, "HTTP/1.1 200 OK", 15);
        snprintf(r.comm, sizeof r.comm, "curl");
        check_case(&C, &r, "GET + status + peer", off, now);

        /* the TLS path: no sock at all. */
        r.daddr = 0; r.dport = 0;
        check_case(&C, &r, "tls path (no sock)", off, now);

        /* The reachable head with no space: a method and NO path. This is the
         * case the prose "the request head parses" covered with one sentence and
         * the runtime has always decided with two tests. */
        memset(r.req, 0, sizeof r.req);
        memcpy(r.req, "DELETEDELETEDELETE", 18);
        memset(r.resp, 0, sizeof r.resp);
        r.daddr = 0x0100007f; r.dport = 8080;
        r.comm[0] = '\0';
        check_case(&C, &r, "method but no path/status", off, now);

        /* daddr zero, dport not: the record the conjunction reading gets wrong. */
        r.daddr = 0; r.dport = 8080;
        check_case(&C, &r, "daddr 0, dport set", off, now);
    }

    /* -------- offcpu */
    {
        static const chan_t C = { "offcpu", spnl_egress_rules_offcpu,
                                  (int)(sizeof spnl_egress_rules_offcpu / sizeof spnl_egress_rules_offcpu[0]),
                                  offcpu_build, NULL, offcpu_start, offcpu_end };
        spnl_rec_offcpu_t r;
        memset(&r, 0, sizeof r);
        r.duration_ns = 310000000ULL; r.offcpu_ns = 90000000ULL; r.wait_stack = -1;
        memcpy(r.req, "POST /api HTTP/1.1", 18);
        memcpy(r.resp, "HTTP/1.1 503 x", 14);
        snprintf(r.comm, sizeof r.comm, "ruby");
        check_case(&C, &r, "window + wait + head", off, now);

        /* offcpu_ns over the window: the clamp the declaration now performs. */
        r.offcpu_ns = 500000000ULL;
        r.comm[0] = '\0';
        memset(r.resp, 0, sizeof r.resp);
        check_case(&C, &r, "offcpu > window, no comm", off, now);
    }

    /* -------- redis: the channel with no seam, reported rather than skipped
     * silently. Its span is built inline inside the push loop (there is no
     * redis_fill_span), so there is nothing to call without a ringbuf. Two of
     * its eight rules are also declared unexpressible. Both facts are printed so
     * that the coverage of this test is a number a reader can see. */
    {
        int nrule = (int)(sizeof spnl_egress_rules_redis / sizeof spnl_egress_rules_redis[0]);
        int nunexp = 0;
        for (int i = 0; i < nrule; i++) if (!spnl_egress_rules_redis[i].present) nunexp++;
        printf("\n  redis   NOT COMPARED: the span is built inline in spnl_otlp_redis_span_push_obj()\n"
               "          (no redis_fill_span seam to call without a ringbuf). %d rules, %d of them\n"
               "          declared unexpressible.\n", nrule, nunexp);
        for (int i = 0; i < nrule; i++)
            if (!spnl_egress_rules_redis[i].present)
                printf("          %s -> %s\n", spnl_egress_rules_redis[i].key,
                       spnl_egress_rules_redis[i].unexpressible);
    }

    printf("\n[egress] %d checks, %s\n", g_checks, g_fail ? "**FAILURES**" : "all MATCH");
    return g_fail ? 1 : 0;
}
