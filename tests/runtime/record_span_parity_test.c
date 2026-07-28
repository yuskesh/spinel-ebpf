/*
 * record_span_parity_test.c -- host oracle for "the value Ruby sees == the value
 * that lands on the span".
 *
 * Every property of a typed consumer (`on_emit :<ch> do |ev|`) should be the output
 * of the same function, with the same value, as the egress span builder. That is
 * already true property by property for qname, for method/path/status, for
 * peer/direction and for srtt_us, but only srtt_us on the conn channel had been
 * shown end-to-end against a real kernel; the other channels were left as an
 * unaudited boundary.
 *
 * This file mechanises that audit. For one synthetic record it applies BOTH paths:
 *
 *   (1) the path a typed consumer takes : the generated accessor
 *                                         spnl_rec_<ch>_<prop>() (= ev.<prop> in Ruby)
 *   (2) the path onto the wire          : <ch>_fill_span() (the builder shared by the
 *                                         implicit push form and the explicit to_span form)
 *
 * and compares them property by property. The two paths are written independently,
 * so this test never reimplements a value -- it cannot end up agreeing with itself.
 *
 * There are three kinds of correspondence, each its own assertion:
 *   (a) maps directly to a span attribute : ev.<prop> == attr("<key>")
 *   (b) maps to some other part of the span : ev.duration_ns == end-start /
 *       ev.peer == the subject of the span name / ev.status>=500 == is_error
 *   (c) never reaches the span : confirm the value appears in NO attribute (pid / cgid)
 *
 * Why otlp_agent.c is included as a whole translation unit: the builder
 * (<ch>_fill_span) and the holder for drained records (g_rec_<ch>) are both static.
 * They are internal structure -- what guarantees the implicit and explicit forms go
 * through the same builder -- not a production API. Exposing them for the test would
 * add an API that exists only for the test. Including the TU means production code
 * does not change by a single line.
 *
 * No real kernel, probe or collector is needed (the records are synthetic). libbpf
 * only has to be linked because otlp_agent.c uses it for the ringbuf drain; the
 * drain is never called.
 *
 *   sh tests/runtime/run_record_span_parity.sh
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* The unit under test. Included so the static builders and record holders are
 * reachable -- see the note above. */
#include "otlp_agent.c"

/* ------------------------------------------------------------------ test helpers */

static int  g_fail;
static int  g_checks;
static const char *g_ch;      /* channel under test (leftmost table column) */

/* attribute key -> value, or NULL if absent. */
static const char *attr_of(const otlp_kv_t *a, int n, const char *key) {
    for (int i = 0; i < n; i++) if (strcmp(a[i].key, key) == 0) return a[i].val;
    return NULL;
}

/* One table row. The verdict is MATCH or **DIFF**. */
static void row(const char *prop, const char *counterpart,
                const char *ev, const char *span, int ok) {
    g_checks++;
    if (!ok) g_fail = 1;
    printf("  %-5s %-13s %-28s %-22s %-22s %s\n",
           g_ch, prop, counterpart, ev, span, ok ? "MATCH" : "**DIFF**");
}

static void row_str(const char *prop, const char *counterpart,
                    const char *ev, const char *span) {
    row(prop, counterpart, ev ? ev : "(null)", span ? span : "(absent)",
        ev && span && strcmp(ev, span) == 0);
}

static void row_int(const char *prop, const char *counterpart,
                    long ev, const char *span_str) {
    char e[32]; snprintf(e, sizeof e, "%ld", ev);
    row(prop, counterpart, e, span_str ? span_str : "(absent)",
        span_str && strcmp(e, span_str) == 0);
}

/* (c) never reaches the span: the value must appear in no attribute value and not
 * in the span name either. Each case uses a distinctive number that cannot collide
 * with anything else (pid=424242 and so on). */
static void row_absent(const char *prop, const char *why, long v,
                       const otlp_kv_t *a, int n, const char *name) {
    char s[32]; snprintf(s, sizeof s, "%ld", v);
    int leaked = (name && strstr(name, s) != NULL);
    for (int i = 0; i < n && !leaked; i++)
        if (strcmp(a[i].val, s) == 0) leaked = 1;
    row(prop, why, s, "(no attribute)", !leaked);
}

static void hdr(const char *title) {
    printf("\n[parity] %s\n", title);
    printf("  %-5s %-13s %-28s %-22s %-22s %s\n",
           "ch", "ev.<prop>", "span counterpart", "ev value", "span value", "verdict");
}

/* Shared header for the synthetic records. With off=0 the ktime is emitted as the
 * unix time unchanged. */
static void put_hdr(struct spnl_event_hdr *h, uint64_t ktime) {
    memset(h, 0, sizeof *h);
    h->type = 0x0100; h->version = 1; h->timestamp = ktime;
}

/* ------------------------------------------------------------------ dns */

static void case_dns(void) {
    uint64_t seed = 1;
    otlp_generic_span_t s; otlp_kv_t a[8]; char name[160];

    memset(g_rec_dns, 0, sizeof g_rec_dns[0]);
    spnl_rec_dns_t *r = &g_rec_dns[0];
    put_hdr(&r->hdr, 1700000000000000000ULL);
    r->pid = 424242;
    snprintf(r->comm, sizeof r->comm, "%s", "getent");
    r->cgid = 909090;
    r->duration_ns = 51000000ULL;            /* the RTT dns_emit measures */
    /* raw: DNS query header(12B) + length-prefixed labels "example.com" */
    memcpy(r->raw + 12, "\7example\3com\0", 13);
    g_rec_dns_n = 1;

    int nsp = dns_fill_span(r, 0, &seed, &s, a, name, sizeof name);
    if (!nsp) { printf("  FAIL: dns_fill_span returned 0\n"); g_fail = 1; return; }

    g_ch = "dns";
    row_absent("pid", "(c) never an attribute", spnl_rec_dns_pid(0), a, s.nattrs, name);
    row_str("comm", "process.executable.name", spnl_rec_dns_comm(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_DNS_ATTR_PROCESS_EXECUTABLE_NAME));
    row_absent("cgid", "(c) enricher input", spnl_rec_dns_cgid(0), a, s.nattrs, name);
    row_int("duration_ns", "spnl.dns.latency_ns", spnl_rec_dns_duration_ns(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_DNS_ATTR_SPNL_DNS_LATENCY_NS));
    {   /* (b) it is also the span duration itself */
        char span[32]; snprintf(span, sizeof span, "%" PRIu64, s.end_unix_ns - s.start_unix_ns);
        row_int("duration_ns", "(b) span end-start", spnl_rec_dns_duration_ns(0), span);
    }
    row_str("qname", "dns.question.name", spnl_rec_dns_qname(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_DNS_ATTR_DNS_QUESTION_NAME));
    {   /* (b) the subject of the span name */
        char want[192]; snprintf(want, sizeof want, "resolve %s", spnl_rec_dns_qname(0));
        row_str("qname", "(b) span name", want, name);
    }

    /* duration_ns == 0 (the query-only emit path): no attribute is written, and ev
     * reads 0 too, so the two agree. */
    r->duration_ns = 0;
    nsp = dns_fill_span(r, 0, &seed, &s, a, name, sizeof name);
    (void)nsp;
    row("duration_ns", "(cond) 0 -> no attribute", "0",
        attr_of(a, s.nattrs, SPNL_EGRESS_DNS_ATTR_SPNL_DNS_LATENCY_NS) ? "(present)" : "(absent)",
        spnl_rec_dns_duration_ns(0) == 0 &&
        attr_of(a, s.nattrs, SPNL_EGRESS_DNS_ATTR_SPNL_DNS_LATENCY_NS) == NULL);

    /* A QNAME as wide as the source allows. Both sides cap at the declared qname cap
     * SPNL_REC_DERIVED_DNS_QNAME_CAP; feeding the longest value raw[64] permits makes
     * this row fail the moment the two widths diverge again. */
    r->duration_ns = 51000000ULL;
    memset(r->raw + 12, 0, 52);
    {
        int o = 12;
        while (o < 62) { int l = (62 - o - 1 < 9) ? (62 - o - 1) : 9; if (l <= 0) break;
                         r->raw[o++] = (unsigned char)l;
                         for (int k = 0; k < l; k++) r->raw[o++] = 'a' + (unsigned char)(k % 26); }
    }
    dns_fill_span(r, 0, &seed, &s, a, name, sizeof name);
    row_str("qname", "(longest QNAME) dns.question.name", spnl_rec_dns_qname(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_DNS_ATTR_DNS_QUESTION_NAME));
    printf("        (longest QNAME = %zu chars -- the most raw[64] allows)\n",
           strlen(spnl_rec_dns_qname(0)));
}

/* ------------------------------------------------------------------ conn */

static void conn_case(int v6) {
    uint64_t seed = 1;
    otlp_generic_span_t s; otlp_kv_t a[20]; char name[128];

    memset(g_rec_conn, 0, sizeof g_rec_conn[0]);
    spnl_rec_conn_t *r = &g_rec_conn[0];
    put_hdr(&r->hdr, 1700000000000000000ULL);
    r->pid = 424242;
    snprintf(r->comm, sizeof r->comm, "%s", "curl");
    r->dport = 8443;
    r->srtt_us = 296;          /* the kernel's 1/8 us scale -> 37 us */
    r->cgid = 909090;
    r->oldstate = v6 ? 3 : 2;  /* passive / active */
    if (!v6) { r->family = 2; r->daddr = 0x0100007F; }
    else {
        r->family = 10;
        unsigned char v6a[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01};
        memcpy(&r->daddr6_hi, v6a, 8); memcpy(&r->daddr6_lo, v6a + 8, 8);
    }
    g_rec_conn_n = 1;

    if (!conn_fill_span(r, 0, &seed, &s, a, name, sizeof name)) {
        printf("  FAIL: conn_fill_span returned 0\n"); g_fail = 1; return;
    }

    g_ch = v6 ? "conn6" : "conn";
    row_absent("pid", "(c) never an attribute", spnl_rec_conn_pid(0), a, s.nattrs, name);
    row_str("comm", "process.executable.name", spnl_rec_conn_comm(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_CONN_ATTR_PROCESS_EXECUTABLE_NAME));
    row_int("dport", "network.peer.port", spnl_rec_conn_dport(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_PORT));
    row_absent("cgid", "(c) enricher input", spnl_rec_conn_cgid(0), a, s.nattrs, name);
    {   /* (b) ev.peer = "<network.peer.address>:<network.peer.port>", the subject of the span name */
        const char *addr = attr_of(a, s.nattrs, SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_ADDRESS);
        const char *port = attr_of(a, s.nattrs, SPNL_EGRESS_CONN_ATTR_NETWORK_PEER_PORT);
        char want[96]; snprintf(want, sizeof want, "%s:%s", addr ? addr : "?", port ? port : "?");
        row_str("peer", "peer.address + \":\" + port", spnl_rec_conn_peer(0), want);
        char wname[128]; snprintf(wname, sizeof wname, "connect %s", spnl_rec_conn_peer(0));
        row_str("peer", "(b) span name", wname, name);
    }
    row_str("direction", "spnl.conn.direction", spnl_rec_conn_direction(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_CONN_ATTR_SPNL_CONN_DIRECTION));
    row_int("srtt_us", "net.peer.srtt_us", spnl_rec_conn_srtt_us(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_CONN_ATTR_NET_PEER_SRTT_US));
    {   /* The mismatch this guards: the raw field is in 1/8 us. ev is not the raw value. */
        row("srtt_us", "not the raw field", "37", "raw=296 (1/8us)",
            spnl_rec_conn_srtt_us(0) == 37 && r->srtt_us == 296);
    }
}

/* ------------------------------------------------------------------ l7 */

static void case_l7(void) {
    uint64_t seed = 1;
    otlp_generic_span_t s; otlp_kv_t a[10]; char name[128];

    memset(g_rec_l7, 0, sizeof g_rec_l7[0]);
    spnl_rec_l7_t *r = &g_rec_l7[0];
    put_hdr(&r->hdr, 1700000000000000000ULL);
    r->pid = 424242;
    snprintf(r->comm, sizeof r->comm, "%s", "python3");
    r->daddr = 0x0100007F; r->dport = 6379; r->family = 2;
    r->start_ktime = 1700000000000000000ULL;
    r->duration_ns = 508000000ULL;
    r->cgid = 909090;
    g_rec_l7_n = 1;

    if (!l7_fill_span(r, 0, &seed, &s, a, name, sizeof name)) {
        printf("  FAIL: l7_fill_span returned 0\n"); g_fail = 1; return;
    }

    g_ch = "l7";
    row_absent("pid", "(c) never an attribute", spnl_rec_l7_pid(0), a, s.nattrs, name);
    row_str("comm", "process.executable.name", spnl_rec_l7_comm(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_L7_ATTR_PROCESS_EXECUTABLE_NAME));
    row_int("dport", "network.peer.port", spnl_rec_l7_dport(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_L7_ATTR_NETWORK_PEER_PORT));
    row_int("duration_ns", "spnl.l7.latency_ns", spnl_rec_l7_duration_ns(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_L7_ATTR_SPNL_L7_LATENCY_NS));
    {
        char span[32]; snprintf(span, sizeof span, "%" PRIu64, s.end_unix_ns - s.start_unix_ns);
        row_int("duration_ns", "(b) span end-start", spnl_rec_l7_duration_ns(0), span);
    }
    row_absent("cgid", "(c) enricher input", spnl_rec_l7_cgid(0), a, s.nattrs, name);
}

/* ------------------------------------------------------------------ http */

/* Fill req[64] with "<head>", zeroing the rest -- the same shape the kernel's
 * bounded copy produces. */
static void http_put_req(spnl_rec_http_t *r, const char *head) {
    memset(r->req, 0, sizeof r->req);
    size_t n = strlen(head);
    if (n > sizeof r->req) n = sizeof r->req;
    memcpy(r->req, head, n);
}

static void case_http(void) {
    uint64_t seed = 1;
    otlp_generic_span_t s; otlp_kv_t a[14]; char name[96];   /* 13 -> 14 to make room for the latency attribute */

    memset(g_rec_http, 0, sizeof g_rec_http[0]);
    spnl_rec_http_t *r = &g_rec_http[0];
    put_hdr(&r->hdr, 1700000000000000000ULL);
    r->pid = 424242;
    snprintf(r->comm, sizeof r->comm, "%s", "curl");
    r->daddr = 0x0100007F; r->dport = 8080; r->family = 2;
    r->start_ktime = 1700000000000000000ULL;
    r->duration_ns = 305000000ULL;
    r->cgid = 909090;
    http_put_req(r, "GET /health HTTP/1.1\r\n");
    memcpy(r->resp, "HTTP/1.1 503 S", 14);
    g_rec_http_n = 1;

    if (!http_fill_span(r, 0, &seed, &s, a, name, sizeof name)) {
        printf("  FAIL: http_fill_span returned 0\n"); g_fail = 1; return;
    }

    g_ch = "http";
    row_absent("pid", "(c) never an attribute", spnl_rec_http_pid(0), a, s.nattrs, name);
    row_str("comm", "process.executable.name", spnl_rec_http_comm(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_PROCESS_EXECUTABLE_NAME));
    row_int("dport", "network.peer.port", spnl_rec_http_dport(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_NETWORK_PEER_PORT));
    row_absent("cgid", "(c) enricher input", spnl_rec_http_cgid(0), a, s.nattrs, name);
    {   /* Like l7, http carries a latency attribute. Both the span duration
         * (end-start) and that attribute must equal ev.duration_ns. */
        char span[32]; snprintf(span, sizeof span, "%" PRIu64, s.end_unix_ns - s.start_unix_ns);
        row_int("duration_ns", "(b) span end-start", spnl_rec_http_duration_ns(0), span);
        row_int("duration_ns", "spnl.http.latency_ns", spnl_rec_http_duration_ns(0),
                attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_SPNL_HTTP_LATENCY_NS));
    }
    row_str("method", "http.request.method", spnl_rec_http_method(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_HTTP_REQUEST_METHOD));
    row_str("path", "url.path", spnl_rec_http_path(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_URL_PATH));
    row_int("status", "http.response.status_code", spnl_rec_http_status(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_HTTP_RESPONSE_STATUS_CODE));
    {   /* (b) status>=500 becomes Span.status=ERROR (the error axis of RED) */
        row("status", "(b) >=500 -> Span ERROR", "503", s.is_error ? "ERROR" : "OK",
            (spnl_rec_http_status(0) >= 500) == (s.is_error != 0));
    }
    {   /* (b) span name = "<method> <path>" */
        char want[128];
        snprintf(want, sizeof want, "%s %s", spnl_rec_http_method(0), spnl_rec_http_path(0));
        row_str("method+path", "(b) span name", want, name);
    }

    /* The TLS path (daddr==0 && dport==0): no peer attributes are written, and
     * ev.dport reads 0 too, so the two agree. */
    r->daddr = 0; r->dport = 0;
    http_fill_span(r, 0, &seed, &s, a, name, sizeof name);
    row("dport", "(TLS) no attribute + ev=0", "0",
        attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_NETWORK_PEER_PORT) ? "(present)" : "(absent)",
        spnl_rec_http_dport(0) == 0 &&
        attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_NETWORK_PEER_PORT) == NULL);
    r->daddr = 0x0100007F; r->dport = 8080;

    /* A path as wide as the source allows (the longest req[64] permits). The builder
     * hands over path[64]. */
    http_put_req(r, "GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1");
    http_fill_span(r, 0, &seed, &s, a, name, sizeof name);
    row_str("path", "(longest path) url.path", spnl_rec_http_path(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_URL_PATH));
    printf("        (longest path = %zu chars -- the most req[64] allows)\n", strlen(spnl_rec_http_path(0)));

    /* A request head containing no space. The kernel-side filter (spnl_is_http_req)
     * only inspects the first 4 bytes, so "DELE" gets through -- this input is
     * reachable in practice. The method token is then the whole of req[64]. */
    http_put_req(r, "DELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELE");
    http_fill_span(r, 0, &seed, &s, a, name, sizeof name);
    row_str("method", "(no-space head) http.request.method", spnl_rec_http_method(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_HTTP_REQUEST_METHOD));
    printf("        (ev.method = %zu chars / span = %zu chars)\n",
           strlen(spnl_rec_http_method(0)),
           strlen(attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_HTTP_REQUEST_METHOD) ?
                  attr_of(a, s.nattrs, SPNL_EGRESS_HTTP_ATTR_HTTP_REQUEST_METHOD) : ""));
}

/* ------------------------------------------------------------------ offcpu
 *
 * This channel was the last one to get a typed consumer, because three of its
 * egress attributes are not fields at all: one is clamped, one is a difference, and
 * one is a classification computed outside the record via kallsyms. That is exactly
 * what the table below looks at:
 *   - ev.offcpu_ns is the CLAMPED value (min(offcpu_ns, duration_ns)), equal to the attribute
 *   - ev.oncpu_ns  is a COMPUTED value (duration - clamp), equal to the attribute
 *   - ev.wait_kind is the output of the same function that fills spnl.wait.kind
 * The builder takes now_unix: this record carries an elapsed time, so the anchor is
 * "now - dur". */

static void offcpu_put_req(spnl_rec_offcpu_t *r, const char *head) {
    memset(r->req, 0, sizeof r->req);
    size_t n = strlen(head);
    if (n > sizeof r->req) n = sizeof r->req;
    memcpy(r->req, head, n);
}

/* Set up one synthetic record and run the builder over it; callers adjust the
 * values first. */
static const uint64_t OC_NOW = 1700000000000000000ULL;

static void case_offcpu(void) {
    uint64_t seed = 1;
    otlp_generic_span_t s; otlp_kv_t a[13]; char name[96];

    memset(g_rec_offcpu, 0, sizeof g_rec_offcpu[0]);
    spnl_rec_offcpu_t *r = &g_rec_offcpu[0];
    put_hdr(&r->hdr, OC_NOW);
    r->pid = 424242;
    snprintf(r->comm, sizeof r->comm, "%s", "gunicorn");
    r->duration_ns = 310000000ULL;      /* window (recv -> send) */
    r->offcpu_ns   =  90000000ULL;      /* the part of it spent waiting */
    r->wait_stack  = -1;                /* no stack map here, so the "none" path */
    r->cgid = 909090;
    offcpu_put_req(r, "GET /slow HTTP/1.1\r\n");
    memcpy(r->resp, "HTTP/1.1 503 S", 14);
    g_rec_offcpu_n = 1;

    if (!offcpu_fill_span(r, OC_NOW, &seed, &s, a, name, sizeof name)) {
        printf("  FAIL: offcpu_fill_span returned 0\n"); g_fail = 1; return;
    }

    g_ch = "offcp";
    row_absent("pid", "(c) never an attribute", spnl_rec_offcpu_pid(0), a, s.nattrs, name);
    row_str("comm", "process.executable.name", spnl_rec_offcpu_comm(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_PROCESS_EXECUTABLE_NAME));
    row_absent("cgid", "(c) enricher input", spnl_rec_offcpu_cgid(0), a, s.nattrs, name);
    {   /* (b) the window length is the span length. offcpu has no latency attribute --
         * the span duration is the authoritative value. */
        char span[32]; snprintf(span, sizeof span, "%" PRIu64, s.end_unix_ns - s.start_unix_ns);
        row_int("duration_ns", "(b) span end-start", spnl_rec_offcpu_duration_ns(0), span);
    }
    row_str("method", "http.request.method", spnl_rec_offcpu_method(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_HTTP_REQUEST_METHOD));
    row_str("path", "url.path", spnl_rec_offcpu_path(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_URL_PATH));
    row_int("status", "http.response.status_code", spnl_rec_offcpu_status(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_HTTP_RESPONSE_STATUS_CODE));
    row("status", "(b) >=500 -> Span ERROR", "503", s.is_error ? "ERROR" : "OK",
        (spnl_rec_offcpu_status(0) >= 500) == (s.is_error != 0));
    {   /* (b) span name = "<method> <path>", the same shape as http */
        char want[192];
        snprintf(want, sizeof want, "%s %s", spnl_rec_offcpu_method(0), spnl_rec_offcpu_path(0));
        row_str("method+path", "(b) span name", want, name);
    }
    row_int("offcpu_ns", "spnl.offcpu_ns", spnl_rec_offcpu_offcpu_ns(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_SPNL_OFFCPU_NS));
    row_int("oncpu_ns", "spnl.oncpu_ns", spnl_rec_offcpu_oncpu_ns(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_SPNL_ONCPU_NS));
    {   /* (b) the three close structurally: on + off == window */
        char sum[32];
        snprintf(sum, sizeof sum, "%ld", spnl_rec_offcpu_oncpu_ns(0) + spnl_rec_offcpu_offcpu_ns(0));
        row_int("oncpu+offcpu", "(b) == ev.duration_ns", spnl_rec_offcpu_duration_ns(0), sum);
    }
    row_str("wait_kind", "spnl.wait.kind", spnl_rec_offcpu_wait_kind(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_SPNL_WAIT_KIND));
    row("wait_kind", "(value) wait_stack<0 -> \"none\"", spnl_rec_offcpu_wait_kind(0), "none",
        strcmp(spnl_rec_offcpu_wait_kind(0), "none") == 0);

    /* wait_stack >= 0 but there is no stack map (this is a host oracle): both sides go
     * through the same function, so both come out "unknown". Classifying for real needs
     * a live map -- that stays outside this test -- but the invariant that the two paths
     * agree is still visible here. */
    r->wait_stack = 4711;
    offcpu_fill_span(r, OC_NOW, &seed, &s, a, name, sizeof name);
    row_str("wait_kind", "(no stack map) spnl.wait.kind", spnl_rec_offcpu_wait_kind(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_SPNL_WAIT_KIND));
    r->wait_stack = -1;

    /* A record where the clamp bites, which is the whole point: offcpu_ns > duration_ns
     * is representable, because the wait is a sum over sched_switch events while the
     * window is a recv/send pair -- two different measurements. ev is not the raw value
     * but the clamped one, equal to the attribute, and oncpu is 0. Had the raw field
     * been exposed instead, this is the row that would disagree. */
    r->offcpu_ns = 500000000ULL;   /* a wait longer than the 310ms window */
    offcpu_fill_span(r, OC_NOW, &seed, &s, a, name, sizeof name);
    row_int("offcpu_ns", "(clamp) spnl.offcpu_ns", spnl_rec_offcpu_offcpu_ns(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_SPNL_OFFCPU_NS));
    row("offcpu_ns", "not the raw field", "310000000", "raw=500000000",
        spnl_rec_offcpu_offcpu_ns(0) == 310000000L && r->offcpu_ns == 500000000ULL);
    row_int("oncpu_ns", "(clamp) spnl.oncpu_ns", spnl_rec_offcpu_oncpu_ns(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_SPNL_ONCPU_NS));
    r->offcpu_ns = 90000000ULL;

    /* A head as wide as the source allows, the same longest input the http case uses.
     * offcpu shares http's derivation, so it must truncate at exactly the same place. */
    offcpu_put_req(r, "DELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELE");
    offcpu_fill_span(r, OC_NOW, &seed, &s, a, name, sizeof name);
    row_str("method", "(no-space head) http.request.method", spnl_rec_offcpu_method(0),
            attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_HTTP_REQUEST_METHOD));
    printf("        (ev.method = %zu chars / span = %zu chars -- same derivation and cap as the http channel)\n",
           strlen(spnl_rec_offcpu_method(0)),
           strlen(attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_HTTP_REQUEST_METHOD) ?
                  attr_of(a, s.nattrs, SPNL_EGRESS_OFFCPU_ATTR_HTTP_REQUEST_METHOD) : ""));
    {   /* The same head in an http record yields the same value: two channels, one derivation */
        memset(g_rec_http, 0, sizeof g_rec_http[0]);
        spnl_rec_http_t *h = &g_rec_http[0];
        put_hdr(&h->hdr, OC_NOW);
        h->daddr = 0x0100007F; h->dport = 8080; h->family = 2;
        http_put_req(h, "DELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELETEDELE");
        g_rec_http_n = 1;
        row_str("method", "(2 channels) http's ev.method", spnl_rec_offcpu_method(0),
                spnl_rec_http_method(0));
    }
}

/* ------------------------------------------------------- the indirect counterpart of cgid
 *
 * pid and cgid never become span attributes -- case (c) in the table above. But cgid
 * is not irrelevant: it is the input to the userspace enrichers, and once those are
 * enabled the same record grows k8s.* attributes. Whether an enricher is active is
 * decided lazily, once per process, so this has to run as a separate process from the
 * plain table. The cgid is the inode of a fake kubepods hierarchy, so no real k8s is
 * needed. */
static int mode_cgid_enricher(void) {
    char cgroot[] = "/tmp/e377_cg_XXXXXX";
    char uidmap[] = "/tmp/e377_uid_XXXXXX";
    const char *uid = "1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280";
    const char *ctr = "9b763adf6f512b686d81705fe1267700c1de5ab427f527a84ca949b6d7eec866";
    char p[4][512]; struct stat st;

    if (!mkdtemp(cgroot)) { perror("mkdtemp"); return 2; }
    snprintf(p[0], sizeof p[0], "%s/kubepods", cgroot);      mkdir(p[0], 0755);
    snprintf(p[1], sizeof p[1], "%s/burstable", p[0]);       mkdir(p[1], 0755);
    snprintf(p[2], sizeof p[2], "%s/pod%s", p[1], uid);      mkdir(p[2], 0755);
    snprintf(p[3], sizeof p[3], "%s/%s", p[2], ctr);         mkdir(p[3], 0755);
    if (stat(p[3], &st) != 0) { perror("stat"); return 2; }
    { int fd = mkstemp(uidmap); FILE *f = fdopen(fd, "w");
      fprintf(f, "%s kube-system/coredns-ccb96694c-5kpb7\n", uid); fclose(f); }
    setenv("SPNL_K8S_CGROUP_ROOT", cgroot, 1);
    setenv("SPNL_K8S_UIDMAP", uidmap, 1);

    memset(g_rec_dns, 0, sizeof g_rec_dns[0]);
    spnl_rec_dns_t *r = &g_rec_dns[0];
    put_hdr(&r->hdr, 1700000000000000000ULL);
    snprintf(r->comm, sizeof r->comm, "%s", "getent");
    r->cgid = (uint64_t)st.st_ino;         /* the cgroup id the kernel would put here */
    memcpy(r->raw + 12, "\7example\3com\0", 13);
    g_rec_dns_n = 1;

    uint64_t seed = 1;
    otlp_generic_span_t s; otlp_kv_t a[8]; char name[160];
    if (!dns_fill_span(r, 0, &seed, &s, a, name, sizeof name)) return 2;

    printf("[parity] the indirect counterpart of cgid (the userspace enrichers)\n");
    printf("  ev.cgid = %ld (inode of the fake kubepods container)\n", spnl_rec_dns_cgid(0));
    for (int i = 0; i < s.nattrs; i++) printf("    attr %-24s = %s\n", a[i].key, a[i].val);
    const char *pod = attr_of(a, s.nattrs, "k8s.pod.name");
    int ok = pod && strcmp(pod, "coredns-ccb96694c-5kpb7") == 0;
    printf("  VERDICT: %s (cgid never becomes an attribute, yet k8s.* resolves from that same value)\n",
           ok ? "MATCH" : "**FAIL**");
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    /* The userspace enrichers are env-driven. This audit looks at the bare span, so
     * unset them explicitly: with k8s.* present, the (c) "the value did not leak"
     * check would be testing something else. */
    unsetenv("SPNL_K8S_CGROUP_ROOT"); unsetenv("SPNL_K8S_UIDMAP");
    unsetenv("SPNL_K8S_IPMAP"); unsetenv("SPNL_K8S_CRIMAP");

    if (argc > 1 && strcmp(argv[1], "--cgid-enricher") == 0) return mode_cgid_enricher();

    printf("[parity] typed consumer accessor  vs  egress span builder (same record)\n");
    hdr("dns");   case_dns();
    hdr("conn (IPv4 / active)"); conn_case(0);
    hdr("conn (IPv6 / passive)"); conn_case(1);
    hdr("l7");    case_l7();
    hdr("http");  case_http();
    hdr("offcpu (clamp / computed value / kallsyms classification)"); case_offcpu();

    printf("\n[parity] %d checks, %s\n", g_checks, g_fail ? "FAIL" : "all MATCH");
    return g_fail ? 1 : 0;
}
