/* === pure-XDP TCP slice (port 8080, prefix "GET /health ")           === */
/* === plus bpf_timer state cleanup and client-retransmit handling      === */

/* conn_state stored per 4-tuple. state: 1=ESTAB, 2=RESP_SENT, 3=CLOSED.
 * A bpf_timer is embedded for per-state time-to-live cleanup. */
struct spnl_tcp_slice_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct spnl_tcp_slice_state {
    __u32 server_seq;
    __u32 client_seq;
    __u16 mss;
    __u8  state;
    __u8  pad;
    struct bpf_timer timer;   /* per-connection cleanup timer */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct spnl_tcp_slice_key);
    __type(value, struct spnl_tcp_slice_state);
    __uint(max_entries, 65536);
} bpf_conntab SEC(".maps");

/* Observability counters. Names mirror the original proof of concept. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 17);
} bpf_ts_counters SEC(".maps");

/* Per-state time-to-live (nanoseconds). Once the timer fires, the
 * map entry is deleted by spnl_tcp_slice_timeout_cb. State
 * transitions re-arm the timer with the new state's TTL. */
#define SPNL_TS_NS_PER_SEC 1000000000ULL
#define SPNL_TS_TTL_ESTAB  ( 30ULL * SPNL_TS_NS_PER_SEC)
#define SPNL_TS_TTL_RESP   ( 30ULL * SPNL_TS_NS_PER_SEC)
#define SPNL_TS_TTL_CLOSED ( 60ULL * SPNL_TS_NS_PER_SEC)

static __always_inline void spnl_tcp_slice_inc(int k)
{
    __u32 key = k;
    __u64 *v = bpf_map_lookup_elem(&bpf_ts_counters, &key);
    if (v) __sync_fetch_and_add(v, 1);
}

static __always_inline __u16 spnl_tcp_slice_csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static __always_inline __u16 spnl_tcp_slice_csum_tcpudp(__be32 saddr, __be32 daddr,
                                                        __u32 len, __u8 proto, __u32 csum)
{
    __u64 s = csum;
    s += (__u32)saddr;
    s += (__u32)daddr;
    s += bpf_htons(proto + len);
    while (s >> 32) s = (s & 0xffffffff) + (s >> 32);
    return spnl_tcp_slice_csum_fold((__u32)s);
}

static __always_inline int spnl_tcp_slice_recompute_csums(struct iphdr *iph,
                                                          struct tcphdr *tcp,
                                                          __u32 seglen, void *data_end)
{
    __s64 v;
    iph->check = 0;
    v = bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);
    if (v < 0) return -1;
    iph->check = spnl_tcp_slice_csum_fold((__u32)v);
    tcp->check = 0;
    if ((void *)tcp + seglen > data_end) return -1;
    v = bpf_csum_diff(0, 0, (void *)tcp, seglen, 0);
    if (v < 0) return -1;
    tcp->check = spnl_tcp_slice_csum_tcpudp(iph->saddr, iph->daddr, seglen, 6, (__u32)v);
    return 0;
}

static __always_inline void spnl_tcp_slice_swap_mac(struct ethhdr *eth)
{
    __u8 buf[6];
    __builtin_memcpy(buf, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, buf, 6);
}

/* The bpf_timer callback. Fires when a conn_state has been idle
 * for its state-specific TTL; deletes the entry so the LRU slot can
 * be reused by a fresh connection. (The verifier requires the
 * callback signature to match: (void *map, key*, value*).) */
static int spnl_tcp_slice_timeout_cb(void *map,
                                     struct spnl_tcp_slice_key *key,
                                     struct spnl_tcp_slice_state *val)
{
    __u32 ck = 15; /* CNT_TIMER_FIRED */
    __u64 *v = bpf_map_lookup_elem(&bpf_ts_counters, &ck);
    if (v) __sync_fetch_and_add(v, 1);
    bpf_map_delete_elem(map, key);
    return 0;
}

/* (Re-)arm the per-conn cleanup timer. bpf_timer_init is idempotent
 * (-EEXIST on second call) so we always call it; the verifier then
 * lets us set_callback + start. Calling start on an already-armed
 * timer replaces the timeout, which is exactly what we want on each
 * state transition. */
static __always_inline void spnl_tcp_slice_arm(struct spnl_tcp_slice_state *st,
                                               __u64 ttl_ns)
{
    bpf_timer_init(&st->timer, &bpf_conntab, 1 /* CLOCK_MONOTONIC */);
    bpf_timer_set_callback(&st->timer, spnl_tcp_slice_timeout_cb);
    bpf_timer_start(&st->timer, ttl_ns, 0);
}

static __always_inline int spnl_tcp_slice_build_synack(struct ethhdr *eth,
                                                       struct iphdr *iph,
                                                       struct tcphdr *tcp,
                                                       __u32 cookie, __u16 mss,
                                                       void *data_end)
{
    spnl_tcp_slice_swap_mac(eth);
    __be32 t = iph->saddr; iph->saddr = iph->daddr; iph->daddr = t;
    __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;
    __u32 client_seq = bpf_ntohl(tcp->seq);
    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->seq = bpf_htonl(cookie);
    tcp->fin = 0; tcp->syn = 1; tcp->rst = 0;
    tcp->psh = 0; tcp->ack = 1; tcp->urg = 0;
    tcp->ece = 0; tcp->cwr = 0;
    tcp->doff = 6;
    tcp->window = bpf_htons(65535);
    tcp->urg_ptr = 0;
    __u8 *o = (void *)tcp + 20;
    if ((void *)(o + 4) > data_end) return -1;
    o[0] = 2;          /* TCPOPT_MSS */
    o[1] = 4;          /* TCPOLEN_MSS */
    o[2] = (mss >> 8) & 0xff;
    o[3] = mss & 0xff;
    return 0;
}

static const __u8 spnl_tcp_slice_resp_body[41] = {
    0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
    0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
    0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
    0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a,
    0x20, 0x33, 0x0d, 0x0a, 0x0d, 0x0a, 0x4f, 0x4b,
    0x0a
};

static __always_inline int spnl_tcp_slice_build_response(struct ethhdr *eth,
                                                         struct iphdr *iph,
                                                         struct tcphdr *tcp,
                                                         __u32 srv_seq, __u32 cli_seq,
                                                         int kc_slot, void *data_end)
{
    spnl_tcp_slice_swap_mac(eth);
    __be32 t = iph->saddr; iph->saddr = iph->daddr; iph->daddr = t;
    __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;
    tcp->seq = bpf_htonl(srv_seq);
    tcp->ack_seq = bpf_htonl(cli_seq);
    tcp->fin = 1; tcp->syn = 0; tcp->rst = 0;
    tcp->psh = 1; tcp->ack = 1; tcp->urg = 0;
    tcp->ece = 0; tcp->cwr = 0;
    tcp->doff = 5;
    tcp->window = bpf_htons(65535);
    tcp->urg_ptr = 0;
    __u8 *out = (void *)tcp + 20;
    if ((void *)(out + 41) > data_end) return -1;
    (void)kc_slot;
    __builtin_memcpy(out, spnl_tcp_slice_resp_body, 41);
    iph->ihl = 5;
    iph->tot_len = bpf_htons(20 + 20 + 41);
    iph->ttl = 64;
    iph->id = 0;
    return 0;
}

static __always_inline int spnl_tcp_slice_build_finack(struct ethhdr *eth,
                                                       struct iphdr *iph,
                                                       struct tcphdr *tcp,
                                                       __u32 srv_seq, __u32 cli_seq,
                                                       void *data_end)
{
    spnl_tcp_slice_swap_mac(eth);
    __be32 t = iph->saddr; iph->saddr = iph->daddr; iph->daddr = t;
    __be16 p = tcp->source; tcp->source = tcp->dest; tcp->dest = p;
    tcp->seq = bpf_htonl(srv_seq);
    tcp->ack_seq = bpf_htonl(cli_seq);
    tcp->fin = 0; tcp->syn = 0; tcp->rst = 0;
    tcp->psh = 0; tcp->ack = 1; tcp->urg = 0;
    tcp->ece = 0; tcp->cwr = 0;
    tcp->doff = 5;
    tcp->window = bpf_htons(65535);
    tcp->urg_ptr = 0;
    iph->ihl = 5;
    iph->tot_len = bpf_htons(20 + 20);
    iph->ttl = 64;
    iph->id = 0;
    return 0;
}

/* Return the cache slot whose "GET <path> " prefix matches, or -1. */
static __always_inline int spnl_tcp_slice_match_route(const char *p,
                                                      __u32 len, void *data_end)
{
    if (len >= 12 && (void *)(p + 12) <= data_end &&
        p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ' && p[4] == '/' && p[5] == 'h' && p[6] == 'e' && p[7] == 'a' && p[8] == 'l' && p[9] == 't' && p[10] == 'h' && p[11] == ' ') return 0;
    return -1;
}

/* Main state machine entry. Returns XDP_PASS/DROP/TX/ABORTED. */
static __noinline int spnl_tcp_slice_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x0800)) {
        spnl_tcp_slice_inc(11); /* CNT_PASS */
        return XDP_PASS;
    }
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != 6) {
        spnl_tcp_slice_inc(11);
        return XDP_PASS;
    }
    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph) || (void *)iph + ihl > data_end) return XDP_PASS;
    struct tcphdr *tcp = (void *)iph + ihl;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    if (tcp->dest != bpf_htons(8080)) {
        spnl_tcp_slice_inc(11);
        return XDP_PASS;
    }

    /* RST: clean up state, cancelling the timer too -- map_delete
     * implicitly cancels but explicit cancel is safer when both
     * paths (XDP and timer callback) race on the same value. */
    if (tcp->rst) {
        spnl_tcp_slice_inc(13); /* CNT_RST_RX */
        struct spnl_tcp_slice_key kr = {
            .saddr = iph->saddr, .daddr = iph->daddr,
            .sport = tcp->source, .dport = tcp->dest,
        };
        struct spnl_tcp_slice_state *st_rst =
            bpf_map_lookup_elem(&bpf_conntab, &kr);
        if (st_rst) bpf_timer_cancel(&st_rst->timer);
        bpf_map_delete_elem(&bpf_conntab, &kr);
        spnl_tcp_slice_inc(10); /* CNT_DROP */
        return XDP_DROP;
    }

    /* ---- SYN: generate cookie, send SYN-ACK ---- */
    if (tcp->syn && !tcp->ack) {
        spnl_tcp_slice_inc(0); /* CNT_SYN_RX */
        __u32 thl_in = tcp->doff * 4;
        if (thl_in < sizeof(*tcp) || (void *)tcp + thl_in > data_end)
            return XDP_DROP;

        int delta = 60 - thl_in;
        if (bpf_xdp_adjust_tail(ctx, delta) != 0) {
            spnl_tcp_slice_inc(12);
            return XDP_ABORTED;
        }
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_ABORTED;
        iph = (void *)(eth + 1);
        if ((void *)iph + 60 > data_end) return XDP_ABORTED;
        tcp = (void *)iph + iph->ihl * 4;
        if ((void *)tcp + 60 > data_end) return XDP_ABORTED;

        __s64 cookie = bpf_tcp_raw_gen_syncookie_ipv4(iph, tcp, thl_in);
        if (cookie < 0) {
            spnl_tcp_slice_inc(12);
            return XDP_ABORTED;
        }
        __u32 cookie_seq = (__u32)cookie;
        __u16 mss = cookie >> 32;
        if (mss == 0) mss = 1460;

        if (spnl_tcp_slice_build_synack(eth, iph, tcp, cookie_seq, mss, data_end) < 0) {
            spnl_tcp_slice_inc(12);
            return XDP_ABORTED;
        }
        iph->ihl = 5;
        iph->tot_len = bpf_htons(20 + 24);
        iph->ttl = 64;
        iph->id = 0;
        if (spnl_tcp_slice_recompute_csums(iph, tcp, 24, data_end) < 0) {
            spnl_tcp_slice_inc(12);
            return XDP_ABORTED;
        }
        int cur = (long)data_end - (long)data;
        int want = sizeof(*eth) + 20 + 24;
        if (cur != want) {
            if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
                spnl_tcp_slice_inc(12);
                return XDP_ABORTED;
            }
        }
        spnl_tcp_slice_inc(1); /* CNT_SYNACK_TX */
        return XDP_TX;
    }

    if (!(tcp->ack)) return XDP_PASS;

    __u32 thl = tcp->doff * 4;
    if (thl < sizeof(*tcp) || (void *)tcp + thl > data_end) return XDP_DROP;
    __u32 ip_tot = bpf_ntohs(iph->tot_len);
    if (ip_tot < ihl + thl) return XDP_DROP;
    __u32 payload_len = ip_tot - ihl - thl;

    struct spnl_tcp_slice_key k = {
        .saddr = iph->saddr, .daddr = iph->daddr,
        .sport = tcp->source, .dport = tcp->dest,
    };
    struct spnl_tcp_slice_state *st = bpf_map_lookup_elem(&bpf_conntab, &k);

    if (!st) {
        /* Validate cookie and create state. */
        __s64 r = bpf_tcp_raw_check_syncookie_ipv4(iph, tcp);
        if (r < 0) {
            spnl_tcp_slice_inc(3); /* CNT_ACK_INVALID */
            return XDP_PASS;
        }
        spnl_tcp_slice_inc(2); /* CNT_ACK_VALID */
        struct spnl_tcp_slice_state new_st = {
            .server_seq = bpf_ntohl(tcp->ack_seq),
            .client_seq = bpf_ntohl(tcp->seq),
            .mss = 1460, .state = 1, .pad = 0,
        };
        if (bpf_map_update_elem(&bpf_conntab, &k, &new_st, BPF_ANY) == 0)
            spnl_tcp_slice_inc(4); /* CNT_CONN_CREATED */
        st = bpf_map_lookup_elem(&bpf_conntab, &k);
        if (!st) {
            spnl_tcp_slice_inc(10);
            return XDP_DROP;
        }
        /* arm the idle timer for the ESTABLISHED state */
        spnl_tcp_slice_arm(st, SPNL_TS_TTL_ESTAB);
    }

    /* FIN from client.
     *  - state==2 (RESP_SENT): first FIN → build FIN-ACK, transition
     *    to CLOSED.
     *  - state==3 (CLOSED):   a retransmit → rebuild same FIN-ACK
     *    using the stored seqs (client_seq already advanced by FIN).
     *
     * In both cases we send the same packet shape (eth+ip+tcp ACK,
     * doff=5, no payload, no FIN). The client's TCP layer keeps
     * retransmitting its FIN until it sees our ACK or gives up. */
    if (tcp->fin && (st->state == 2 || st->state == 3)) {
        __u32 cli_seq_for_ack;
        if (st->state == 2) {
            spnl_tcp_slice_inc(8); /* CNT_FIN_RX */
            cli_seq_for_ack = bpf_ntohl(tcp->seq) + payload_len + 1;
        } else {
            /* CLOSED → retransmit. state.client_seq already includes
             * the +1 for the original FIN slot. */
            spnl_tcp_slice_inc(16); /* CNT_FIN_RETX */
            cli_seq_for_ack = st->client_seq;
        }
        __u32 srv_seq = st->server_seq;
        if (spnl_tcp_slice_build_finack(eth, iph, tcp, srv_seq,
                                        cli_seq_for_ack, data_end) < 0) {
            spnl_tcp_slice_inc(12);
            return XDP_ABORTED;
        }
        if (spnl_tcp_slice_recompute_csums(iph, tcp, 20, data_end) < 0) {
            spnl_tcp_slice_inc(12);
            return XDP_ABORTED;
        }
        int cur = (long)data_end - (long)data;
        int want = sizeof(*eth) + 20 + 20;
        if (cur != want) {
            if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
                spnl_tcp_slice_inc(12);
                return XDP_ABORTED;
            }
        }
        if (st->state == 2) {
            st->state = 3;
            st->client_seq = cli_seq_for_ack;
        }
        /* re-arm the cleanup timer with the CLOSED time-to-live */
        spnl_tcp_slice_arm(st, SPNL_TS_TTL_CLOSED);
        spnl_tcp_slice_inc(9); /* CNT_FINACK_TX */
        return XDP_TX;
    }

    /* Data path. Two cases handle the same packet shape:
     *  - state==1 (ESTABLISHED): first GET → send response, advance state
     *  - state==2 (RESP_SENT)  : a GET retransmit → re-send response
     *                            using the seqs we already saved
     */
    if (payload_len > 0 && (st->state == 1 || st->state == 2)) {
        const char *payload = (const char *)tcp + thl;
        int kc_slot = spnl_tcp_slice_match_route(payload, payload_len, data_end);
        if (kc_slot >= 0) {
            
            __u32 srv_seq_to_send, cli_seq_after;
            if (st->state == 1) {
                spnl_tcp_slice_inc(5); /* CNT_DATA_GET */
                srv_seq_to_send = st->server_seq;
                cli_seq_after   = bpf_ntohl(tcp->seq) + payload_len;
            } else {
                /* RESP_SENT retransmit: reuse the same seqs we sent
                 * the first time. server_seq was post-incremented by
                 * (41 + 1 for FIN); roll it back to the original.
                 * client_seq was advanced by payload_len. (41 is the
                 * same map-derived value as the first send.) */
                spnl_tcp_slice_inc(14); /* CNT_RESP_RETX */
                srv_seq_to_send = st->server_seq - 41 - 1;
                cli_seq_after   = st->client_seq;
            }
            
            if (spnl_tcp_slice_build_response(eth, iph, tcp, srv_seq_to_send,
                                              cli_seq_after, kc_slot, data_end) < 0) {
                spnl_tcp_slice_inc(12);
                return XDP_ABORTED;
            }
            if (spnl_tcp_slice_recompute_csums(iph, tcp, 20 + 41, data_end) < 0) {
                spnl_tcp_slice_inc(12);
                return XDP_ABORTED;
            }
            int cur = (long)data_end - (long)data;
            int want = sizeof(*eth) + 20 + 20 + 41;
            if (cur != want) {
                if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
                    spnl_tcp_slice_inc(12);
                    return XDP_ABORTED;
                }
            }
            if (st->state == 1) {
                st->server_seq = srv_seq_to_send + 41 + 1;
                st->client_seq = cli_seq_after;
                st->state = 2;
            }
            /* re-arm the cleanup timer with the RESP_SENT time-to-live */
            spnl_tcp_slice_arm(st, SPNL_TS_TTL_RESP);
            spnl_tcp_slice_inc(7); /* CNT_RESPONSE_TX */
            return XDP_TX;
        }
        spnl_tcp_slice_inc(6); /* CNT_DATA_OTHER */
        spnl_tcp_slice_inc(10);
        return XDP_DROP;
    }

    spnl_tcp_slice_inc(10);
    return XDP_DROP;
}
