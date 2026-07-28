/*
 * otlp_xlayer.c -- the L3/L4 half of cross-layer correlation, joined in userspace.
 *
 * On the kernel side, a probe on the inet_sock_set_state tracepoint (see
 * examples/observability/otlp/xlayer_correlate.rb) hashes the 4-tuple of each TCP
 * state transition into a deterministic u64 key and counts per metric into a keyed
 * histogram map. Here, given an accepted client fd, we derive *the same key from
 * the same 4-tuple* and read that map back, yielding the L3/L4 measurements: how
 * many times the connection reached ESTABLISHED, and how many state transitions it
 * made in total.
 *
 * The key derivation must match the probe's arithmetic byte for byte. In the
 * tracepoint, the addresses are raw big-endian 32-bit values -- the same form
 * getsockname and getpeername return in s_addr -- while the ports have already
 * been converted to host order. So userspace keeps the addresses as-is and applies
 * ntohs to the ports:
 *   ci=client ip (raw be32 = getpeername s_addr = tracepoint daddr),
 *   si=server ip (raw be32 = getsockname s_addr = tracepoint saddr),
 *   cp=client port (host = ntohs(getpeername port) = tracepoint dport),
 *   sp=server port (host = ntohs(getsockname port) = tracepoint sport)。
 *
 * Reading a bpf map means this depends on libbpf, so it is linked only on the
 * eBPF build path.
 */
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Hash a 4-tuple into a u64 key. This must match the probe's arithmetic exactly.
 * It chains the 64-bit FNV-1a prime (1099511628211), and separates the metrics
 * into their own key spaces through metric_id. Everything wraps in 64-bit two's
 * complement, so signedness does not matter. */
static uint64_t xlayer_tuple_key(uint32_t ci_be, uint32_t si_be,
                                 uint16_t cp_host, uint16_t sp_host, uint64_t metric_id) {
    uint64_t h = (uint64_t)(ci_be & 0xFFFFFFFFu);
    h = h * 1099511628211ULL + (uint64_t)(si_be & 0xFFFFFFFFu);
    h = h * 1099511628211ULL + (uint64_t)(cp_host & 0xFFFFu);
    h = h * 1099511628211ULL + (uint64_t)(sp_host & 0xFFFFu);
    h = h * 1099511628211ULL + metric_id;
    return h;
}

/* Extract the 4-tuple from an accepted client fd; IPv4 only. Addresses stay
 * big-endian and ports are converted to host order, matching what the tracepoint
 * hashed. Returns 1 on success, 0 for a non-inet socket or an error. */
static int xlayer_tuple_from_fd(int fd, uint32_t *ci_be, uint32_t *si_be,
                                uint16_t *cp_host, uint16_t *sp_host) {
    struct sockaddr_in local, peer;
    socklen_t ll = sizeof local, pl = sizeof peer;
    if (fd < 0) return 0;
    if (getsockname(fd, (struct sockaddr *)&local, &ll) != 0) return 0;
    if (getpeername(fd, (struct sockaddr *)&peer, &pl) != 0) return 0;
    if (local.sin_family != AF_INET || peer.sin_family != AF_INET) return 0;
    *ci_be   = (uint32_t)peer.sin_addr.s_addr;   /* client ip  (raw be = tracepoint daddr) */
    *si_be   = (uint32_t)local.sin_addr.s_addr;  /* server ip  (raw be = tracepoint saddr) */
    *cp_host = ntohs(peer.sin_port);             /* client port(host   = tracepoint dport) */
    *sp_host = ntohs(local.sin_port);            /* server port(host   = tracepoint sport) */
    return 1;
}

/*
 * Look the 4-tuple of an accepted fd up in the keyed histogram map and return the
 * sum over its 64 buckets -- the number of observations for that tuple and metric.
 *   hit  -> zero or more
 *   miss -> -1, meaning nothing was counted for that tuple: either the key does not
 *           match what the kernel wrote, or the probe never fired
 * A non-inet socket or an error also yields -1. Keeping the miss distinguishable is
 * what lets a test prove the join actually happened -- that the key userspace
 * derived really is the key the kernel wrote.
 */
long spnl_otlp_xlayer_l34_count_obj(struct bpf_object *obj, const char *map_name,
                                    int fd, unsigned long long metric_id) {
    if (!obj || !map_name) return -1;
    uint32_t ci = 0, si = 0;
    uint16_t cp = 0, sp = 0;
    if (!xlayer_tuple_from_fd(fd, &ci, &si, &cp, &sp)) return -1;
    uint64_t key = xlayer_tuple_key(ci, si, cp, sp, (uint64_t)metric_id);

    struct bpf_map *m = bpf_object__find_map_by_name(obj, map_name);
    if (!m) return -1;
    int mfd = bpf_map__fd(m);
    if (mfd < 0) return -1;

    /* value = struct spnl_hist_struct { __u64 buckets[64]; } (512B)。 */
    uint64_t buckets[64];
    memset(buckets, 0, sizeof buckets);
    if (bpf_map_lookup_elem(mfd, &key, buckets) != 0) return -1;  /* absent key: a miss */
    uint64_t total = 0;
    for (int i = 0; i < 64; i++) total += buckets[i];
    return (long)total;
}

/* Return the u64 key the lookup above would use for this fd and metric, so a test
 * can assert it equals the key the generated tracepoint writes for the same
 * 4-tuple. Returns 1 on success, 0 on failure. */
int spnl_otlp_xlayer_key_from_fd(int fd, unsigned long long metric_id, unsigned long long *key_out) {
    uint32_t ci = 0, si = 0;
    uint16_t cp = 0, sp = 0;
    if (!key_out || !xlayer_tuple_from_fd(fd, &ci, &si, &cp, &sp)) return 0;
    *key_out = xlayer_tuple_key(ci, si, cp, sp, (uint64_t)metric_id);
    return 1;
}
