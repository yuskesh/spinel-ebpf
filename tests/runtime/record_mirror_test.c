/*
 * record_mirror_test.c -- the generated record mirrors read the same bytes the
 * hand-written ones did.
 *
 * The DNS channel was made declarative first; conn / l7 / http / redis / offcpu /
 * l7stream followed, which meant deleting six hand-written `memcpy(p + 32, ...)`
 * ladders from src/runtime/otlp/otlp_agent.c. Nothing in the test suite exercised
 * those ladders, so "the generated unpack agrees with the one it replaced" would
 * otherwise have rested on review alone.
 *
 * This test is the independent oracle. It builds each record's byte image using
 * the offsets EXACTLY AS THEY WERE SPELLED BY HAND in the runtime before the
 * generator existed (copied from that code, kept as literals below and never
 * derived from the schema), then unpacks with the generated spnl_rec_<id>_unpack()
 * and asserts every field. If the schema table and the historical wire ever
 * disagree, the two sides of this file disagree and the test fails.
 *
 * It also pins the append-only READING rule for the one channel that relies on it:
 * an offcpu record from a producer that predates the two trailing fields is
 * shorter, must still be accepted, and must read start_ktime == 0 with hdr_ext
 * all-zero.
 *
 * Host-only: no libbpf, no kernel. `sh tests/runtime/run_record_mirror.sh`.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* record_mirror_gen.h needs the kernel spellings (normally from <bpf/libbpf.h>
 * or <vmlinux.h>); this test is host-only, so provide them from stdint. */
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

#include "record_mirror_gen.h"

#define H 16   /* sizeof(struct spnl_event_hdr) -- fixed by the event header contract */

static int g_fail;
static void ck(int cond, const char *what) {
    if (cond) { printf("  ok: %s\n", what); return; }
    printf("  FAIL: %s\n", what);
    g_fail = 1;
}
#define CKEQ(got, want, what) do { \
    unsigned long long _g = (unsigned long long)(got), _w = (unsigned long long)(want); \
    if (_g == _w) printf("  ok: %s = %llu\n", (what), _g); \
    else { printf("  FAIL: %s = %llu (want %llu)\n", (what), _g, _w); g_fail = 1; } \
} while (0)

/* ---- byte-image builders: HISTORICAL offsets, typed out by hand ------------
 * Each put_* below mirrors one deleted rb_cb. The numbers are the ones that
 * used to appear in otlp_agent.c; they are deliberately NOT computed from the
 * schema, or this test would agree with itself. */

static void hdr_put(uint8_t *b, uint64_t ktime) {
    uint16_t type = 0x0100, ver = 1; uint32_t rsv = 0;
    memcpy(b + 0, &type, 2); memcpy(b + 2, &ver, 2);
    memcpy(b + 4, &rsv, 4);  memcpy(b + 8, &ktime, 8);
}

/* conn_event, as conn_rb_cb read it:
 *   pid(0..4) comm(4..20) daddr(20..24) dport(24..26) family(26..28) pad
 *   srtt(+32) cgid(+40) oldstate(+48) daddr6_hi(+56) daddr6_lo(+64); min H+72 */
static size_t put_conn(uint8_t *b, size_t cap) {
    uint32_t pid = 4242, daddr = 0x0100007F /* 127.0.0.1 be */;
    uint16_t dport = 8080, family = 2;
    int64_t srtt = 296; uint64_t cgid = 178, hi = 0x0102030405060708ULL, lo = 0x090A0B0C0D0E0F10ULL;
    uint32_t oldstate = 2;
    memset(b, 0, cap);
    hdr_put(b, 1234567890ULL);
    uint8_t *p = b + H;
    memcpy(p +  0, &pid, 4);
    memcpy(p +  4, "curl", 5);
    memcpy(p + 20, &daddr, 4);
    memcpy(p + 24, &dport, 2);
    memcpy(p + 26, &family, 2);
    memcpy(p + 32, &srtt, 8);
    memcpy(p + 40, &cgid, 8);
    memcpy(p + 48, &oldstate, 4);
    memcpy(p + 56, &hi, 8);
    memcpy(p + 64, &lo, 8);
    return H + 72;
}

/* l7_event, as l7_rb_cb read it:
 *   pid(0) comm(4) daddr(20) dport(24) family(26) start_ktime(32)
 *   duration_ns(40) cgid(48); min H+56 */
static size_t put_l7(uint8_t *b, size_t cap) {
    uint32_t pid = 777, daddr = 0x0101010A;
    uint16_t dport = 443, family = 2;
    uint64_t start = 900000000ULL, dur = 508000000ULL, cgid = 99;
    memset(b, 0, cap);
    hdr_put(b, 111ULL);
    uint8_t *p = b + H;
    memcpy(p +  0, &pid, 4);
    memcpy(p +  4, "wget", 5);
    memcpy(p + 20, &daddr, 4);
    memcpy(p + 24, &dport, 2);
    memcpy(p + 26, &family, 2);
    memcpy(p + 32, &start, 8);
    memcpy(p + 40, &dur, 8);
    memcpy(p + 48, &cgid, 8);
    return H + 56;
}

/* http_event (and redis_event, same layout), as http_rb_cb read it:
 *   pid(0) comm(4) daddr(20) dport(24) family(26) start_ktime(32)
 *   duration_ns(40) req(48..112) resp(112..128) cgid(128..136); min H+136 */
static size_t put_httpish(uint8_t *b, size_t cap, const char *req, const char *resp) {
    uint32_t pid = 31697, daddr = 0x0100007F;
    uint16_t dport = 80, family = 2;
    uint64_t start = 5ULL, dur = 305000000ULL, cgid = 178;
    memset(b, 0, cap);
    hdr_put(b, 42ULL);
    uint8_t *p = b + H;
    memcpy(p +  0, &pid, 4);
    memcpy(p +  4, "python3", 8);
    memcpy(p + 20, &daddr, 4);
    memcpy(p + 24, &dport, 2);
    memcpy(p + 26, &family, 2);
    memcpy(p + 32, &start, 8);
    memcpy(p + 40, &dur, 8);
    memcpy(p + 48, req, strlen(req));
    memcpy(p + 112, resp, strlen(resp));
    memcpy(p + 128, &cgid, 8);
    return H + 136;
}

/* offcpu_event, as offcpu_rb_cb read it:
 *   pid(0) comm(4) pad duration(24) offcpu(32) wait_stack(40) req(44..108)
 *   resp(108..124) pad cgid(128..136) | start_ktime(136..144) hdr_ext(144..272)
 * min H+136; the last two fields were appended later (H+144 / H+272 guards). */
static size_t put_offcpu(uint8_t *b, size_t cap, int with_window_fields) {   /* with_window_fields: write the two appended fields too */
    uint32_t pid = 1010;
    uint64_t dur = 310000000ULL, off = 305000000ULL, cgid = 7, start = 88888ULL;
    int32_t stack = 14636;
    const char *req = "GET /sleep HTTP/1.1\r\nHost: x\r\ntraceparent: 00-"
                      "4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n";
    memset(b, 0, cap);
    hdr_put(b, 9ULL);
    uint8_t *p = b + H;
    memcpy(p +  0, &pid, 4);
    memcpy(p +  4, "server", 7);
    memcpy(p + 24, &dur, 8);
    memcpy(p + 32, &off, 8);
    memcpy(p + 40, &stack, 4);
    memcpy(p + 44, "GET /sleep HTTP/1.1", 19);
    memcpy(p + 108, "HTTP/1.1 200 OK", 15);
    memcpy(p + 128, &cgid, 8);
    if (!with_window_fields) return H + 136;
    memcpy(p + 136, &start, 8);
    memcpy(p + 144, req, strlen(req));
    return H + 272;
}

/* dns_event, as the hand-written dns_rb_cb read it:
 *   pid(0) comm(4) raw(20..84) cgid(88) duration_ns(96); min H+104 */
static size_t put_dns(uint8_t *b, size_t cap) {
    uint32_t pid = 31697;
    uint64_t cgid = 178, dur = 51000000ULL;
    /* minimal DNS query wire: 12B header then length-prefixed labels */
    static const unsigned char q[] = {
        0,0, 1,0, 0,1, 0,0, 0,0, 0,0,
        7,'e','x','a','m','p','l','e', 3,'c','o','m', 0, 0,1, 0,1
    };
    memset(b, 0, cap);
    hdr_put(b, 77ULL);
    uint8_t *p = b + H;
    memcpy(p +  0, &pid, 4);
    memcpy(p +  4, "python3", 8);
    memcpy(p + 20, q, sizeof q);
    memcpy(p + 88, &cgid, 8);
    memcpy(p + 96, &dur, 8);
    return H + 104;
}

/* l7stream_event, as _spnl_l7stream_cb (bin/spinel-ebpf glue) reads it:
 *   sock(+0) len(+8) raw(+12) */
static size_t put_l7stream(uint8_t *b, size_t cap) {
    uint64_t sock = 0xFFFF8881ABCD0000ULL;
    uint32_t len = 5;
    memset(b, 0, cap);
    hdr_put(b, 3ULL);
    uint8_t *p = b + H;
    memcpy(p + 0, &sock, 8);
    memcpy(p + 8, &len, 4);
    memcpy(p + 12, "GET /", 5);
    return (size_t)SPNL_REC_L7STREAM_SIZE;   /* the kernel always reserves the whole struct */
}

int main(void) {
    static uint8_t buf[1024];

    printf("[mirror] conn (historical offsets)\n");
    {
        spnl_rec_conn_t r;
        size_t n = put_conn(buf, sizeof buf);
        CKEQ(n, SPNL_REC_CONN_SIZE, "hand-written record length == schema size");
        ck(spnl_rec_conn_unpack(buf, n, &r) == 0, "unpack ok");
        CKEQ(r.hdr.timestamp, 1234567890ULL, "hdr.timestamp");
        CKEQ(r.pid, 4242, "pid");
        ck(strcmp(r.comm, "curl") == 0, "comm == \"curl\"");
        CKEQ(r.daddr, 0x0100007Fu, "daddr");
        CKEQ(r.dport, 8080, "dport");
        CKEQ(r.family, 2, "family");
        CKEQ(r.srtt_us, 296, "srtt_us");
        CKEQ(r.cgid, 178, "cgid");
        CKEQ(r.oldstate, 2, "oldstate (direction = active)");
        CKEQ(r.daddr6_hi, 0x0102030405060708ULL, "daddr6_hi");
        CKEQ(r.daddr6_lo, 0x090A0B0C0D0E0F10ULL, "daddr6_lo");
        /* the old callback rejected `size < H + 72`; so must the generated one */
        ck(spnl_rec_conn_unpack(buf, H + 71, &r) == -1, "short record rejected (< H+72)");
    }

    printf("[mirror] l7 (historical offsets)\n");
    {
        spnl_rec_l7_t r;
        size_t n = put_l7(buf, sizeof buf);
        CKEQ(n, SPNL_REC_L7_SIZE, "hand-written record length == schema size");
        ck(spnl_rec_l7_unpack(buf, n, &r) == 0, "unpack ok");
        CKEQ(r.pid, 777, "pid");
        ck(strcmp(r.comm, "wget") == 0, "comm == \"wget\"");
        CKEQ(r.daddr, 0x0101010Au, "daddr");
        CKEQ(r.dport, 443, "dport");
        CKEQ(r.start_ktime, 900000000ULL, "start_ktime");
        CKEQ(r.duration_ns, 508000000ULL, "duration_ns");
        CKEQ(r.cgid, 99, "cgid");
        ck(spnl_rec_l7_unpack(buf, H + 55, &r) == -1, "short record rejected (< H+56)");
    }

    printf("[mirror] http (historical offsets)\n");
    {
        spnl_rec_http_t r;
        size_t n = put_httpish(buf, sizeof buf, "GET /health HTTP/1.1", "HTTP/1.1 404 NF");
        CKEQ(n, SPNL_REC_HTTP_SIZE, "hand-written record length == schema size");
        ck(spnl_rec_http_unpack(buf, n, &r) == 0, "unpack ok");
        CKEQ(r.pid, 31697, "pid");
        ck(strcmp(r.comm, "python3") == 0, "comm == \"python3\"");
        CKEQ(r.dport, 80, "dport");
        CKEQ(r.start_ktime, 5, "start_ktime");
        CKEQ(r.duration_ns, 305000000ULL, "duration_ns");
        ck(memcmp(r.req, "GET /health HTTP/1.1", 20) == 0, "req[64] head");
        ck(memcmp(r.resp, "HTTP/1.1 404 NF", 15) == 0, "resp[16] head");
        CKEQ(r.cgid, 178, "cgid");
        ck(spnl_rec_http_unpack(buf, H + 135, &r) == -1, "short record rejected (< H+136)");
    }

    printf("[mirror] redis (same wire as http, its own contract)\n");
    {
        spnl_rec_redis_t r;
        size_t n = put_httpish(buf, sizeof buf, "*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n", "-ERR x");
        CKEQ(n, SPNL_REC_REDIS_SIZE, "hand-written record length == schema size");
        CKEQ(SPNL_REC_REDIS_SIZE, SPNL_REC_HTTP_SIZE, "redis and http records are the same width");
        ck(spnl_rec_redis_unpack(buf, n, &r) == 0, "unpack ok");
        ck(memcmp(r.req, "*2\r\n$3\r\nGET\r\n", 13) == 0, "req[64] RESP head");
        CKEQ(r.resp[0], '-', "resp[0] == '-' (RESP error -> error.type)");
        CKEQ(r.cgid, 178, "cgid");
    }

    printf("[mirror] offcpu (historical offsets + the append-only read)\n");
    {
        spnl_rec_offcpu_t r;
        size_t n = put_offcpu(buf, sizeof buf, 1);
        CKEQ(n, SPNL_REC_OFFCPU_SIZE, "full record length == schema size");
        ck(spnl_rec_offcpu_unpack(buf, n, &r) == 0, "unpack ok (producer writes the appended fields)");
        CKEQ(r.pid, 1010, "pid");
        ck(strcmp(r.comm, "server") == 0, "comm == \"server\"");
        CKEQ(r.duration_ns, 310000000ULL, "duration_ns");
        CKEQ(r.offcpu_ns, 305000000ULL, "offcpu_ns");
        CKEQ(r.wait_stack, 14636, "wait_stack");
        ck(memcmp(r.req, "GET /sleep HTTP/1.1", 19) == 0, "req[64] head");
        ck(memcmp(r.resp, "HTTP/1.1 200 OK", 15) == 0, "resp[16] head");
        CKEQ(r.cgid, 7, "cgid");
        CKEQ(r.start_ktime, 88888ULL, "start_ktime (appended field)");
        ck(strstr((const char *)r.hdr_ext, "traceparent:") != NULL, "hdr_ext carries the traceparent");

        /* the append-only reading rule: a producer that predates the two trailing
         * fields writes H+136 bytes. That record is still accepted, and the two
         * appended fields read back as zero. */
        size_t old = put_offcpu(buf, sizeof buf, 0);
        CKEQ(old, SPNL_REC_OFFCPU_MIN, "older record length == schema MIN");
        ck(spnl_rec_offcpu_unpack(buf, old, &r) == 0, "unpack ok (older producer)");
        CKEQ(r.duration_ns, 310000000ULL, "duration_ns still read");
        CKEQ(r.cgid, 7, "cgid still read");
        CKEQ(r.start_ktime, 0, "appended start_ktime reads as zero");
        {
            int zero = 1;
            for (size_t i = 0; i < sizeof r.hdr_ext; i++) if (r.hdr_ext[i]) zero = 0;
            ck(zero, "appended hdr_ext reads as all-zero");
        }
        ck(spnl_rec_offcpu_unpack(buf, H + 135, &r) == -1, "shorter than MIN is rejected");
    }

    printf("[mirror] dns (historical offsets -- the first channel converted, unchanged)\n");
    {
        spnl_rec_dns_t r;
        char host[128];
        size_t n = put_dns(buf, sizeof buf);
        CKEQ(n, SPNL_REC_DNS_SIZE, "hand-written record length == schema size");
        ck(spnl_rec_dns_unpack(buf, n, &r) == 0, "unpack ok");
        CKEQ(r.pid, 31697, "pid");
        ck(strcmp(r.comm, "python3") == 0, "comm == \"python3\"");
        CKEQ(r.cgid, 178, "cgid");
        CKEQ(r.duration_ns, 51000000ULL, "duration_ns");
        /* the QNAME walk lives in otlp_agent.c; repeat it minimally to prove raw
         * landed at the right offset (labels start at raw[12]) */
        CKEQ(r.raw[12], 7, "raw[12] = first label length");
        ck(memcmp(r.raw + 13, "example", 7) == 0, "raw[13..] = first label");
        (void)host;
    }

    printf("[mirror] l7stream (historical offsets, glue-side reader)\n");
    {
        spnl_rec_l7stream_t r;
        size_t n = put_l7stream(buf, sizeof buf);
        ck(spnl_rec_l7stream_unpack(buf, n, &r) == 0, "unpack ok");
        CKEQ(r.sock, 0xFFFF8881ABCD0000ULL, "sock");
        CKEQ(r.len, 5, "len");
        ck(memcmp(r.raw, "GET /", 5) == 0, "raw[0..len]");
        /* the glue reader (bin/spinel-ebpf) hard-codes sock@+0 len@+8 raw@+12 */
        CKEQ(SPNL_REC_L7STREAM_OFF_SOCK - H, 0, "glue offset: sock @ payload+0");
        CKEQ(SPNL_REC_L7STREAM_OFF_LEN  - H, 8, "glue offset: len  @ payload+8");
        CKEQ(SPNL_REC_L7STREAM_OFF_RAW  - H, 12, "glue offset: raw  @ payload+12");
    }

    if (g_fail) { printf("FAIL: generated record mirrors disagree with the historical wire\n"); return 1; }
    printf("PASS: every generated mirror reads the bytes its hand-written predecessor read\n");
    return 0;
}
