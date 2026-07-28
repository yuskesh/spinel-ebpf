/*
 * otlp_xlayer.c — E274: L2–L8 横断相関の L3/L4 ルックアップ (A 方式 = userspace 結合)。
 *
 * eBPF 側 (Ruby DSL の inet_sock_set_state tracepoint、examples/observability/otlp/
 * xlayer_correlate.rb) は TCP 状態遷移の 4-tuple を決定的 u64 キーにハッシュして keyed-hist
 * map (bpf_hist_keyed) に per-metric で計数する。ここでは accept 済み client fd から **同一の
 * 4-tuple → 同一キー導出**でその map を引き、L3/L4 メトリクス値 (ESTABLISHED 数 / 状態遷移数)
 * を返す。
 *
 * キー導出 (xlayer_tuple_key) は DSL 側の算術と byte 一致必須。tracepoint の saddr/daddr は
 * raw be32 (getsockname/getpeername の s_addr と一致)、sport/dport は host order
 * (tracepoint が ntohs 済、E123)。よって userspace は addr は raw be、port は ntohs で合わせる:
 *   ci=client ip (raw be32 = getpeername s_addr = tracepoint daddr),
 *   si=server ip (raw be32 = getsockname s_addr = tracepoint saddr),
 *   cp=client port (host = ntohs(getpeername port) = tracepoint dport),
 *   sp=server port (host = ntohs(getsockname port) = tracepoint sport)。
 *
 * libbpf 依存 (bpf map 読取) のため eBPF ビルド経路でのみリンクされる (bin/spinel-ebpf)。
 */
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* 4-tuple → u64 キー。DSL 側 (xlayer_correlate.rb) の算術と完全一致させること。
 * FNV-1a 64bit プライム (1099511628211) の連鎖。metric_id で per-metric 空間を分離
 * (1=retransmits, 2=server sends)。全て 64bit 二の補数で wrap するので符号は不問。 */
static uint64_t xlayer_tuple_key(uint32_t ci_be, uint32_t si_be,
                                 uint16_t cp_host, uint16_t sp_host, uint64_t metric_id) {
    uint64_t h = (uint64_t)(ci_be & 0xFFFFFFFFu);
    h = h * 1099511628211ULL + (uint64_t)(si_be & 0xFFFFFFFFu);
    h = h * 1099511628211ULL + (uint64_t)(cp_host & 0xFFFFu);
    h = h * 1099511628211ULL + (uint64_t)(sp_host & 0xFFFFu);
    h = h * 1099511628211ULL + metric_id;
    return h;
}

/* accept 済み client fd から 4-tuple を取り出す (IPv4 のみ)。addr は raw be、port は host order
 * (tracepoint の saddr/daddr=be, sport/dport=host に合わせる)。成功 1 / 非 inet・失敗 0。 */
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
 * accept fd の 4-tuple で keyed-hist map (map_name = bpf_hist_keyed) を引き、64 バケットの
 * 総和 (= その 4-tuple・当該 metric_id の観測数) を返す。
 *   hit  -> >=0 (再送数 / 送信数)
 *   miss -> -1  (その 4-tuple の当該メトリクスが未計数 = kernel 側キーと不一致 or 未発火)
 * non-inet / エラーも -1。miss を区別することで「userspace が導いたキーが kernel の書いた
 * キーに実際に当たった」= 4-tuple join の成立を証明できる。
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
    if (bpf_map_lookup_elem(mfd, &key, buckets) != 0) return -1;  /* key 不在 = miss */
    uint64_t total = 0;
    for (int i = 0; i < 64; i++) total += buckets[i];
    return (long)total;
}

/* accept fd + metric_id から lookup が実際に使う u64 キーを返す (E274 join テスト用)。
 * DSL(.bpf.c) の tracepoint が同一 4-tuple・同一算術で書き込むキーと byte 一致する。1/0。 */
int spnl_otlp_xlayer_key_from_fd(int fd, unsigned long long metric_id, unsigned long long *key_out) {
    uint32_t ci = 0, si = 0;
    uint16_t cp = 0, sp = 0;
    if (!key_out || !xlayer_tuple_from_fd(fd, &ci, &si, &cp, &sp)) return 0;
    *key_out = xlayer_tuple_key(ci, si, cp, sp, (uint64_t)metric_id);
    return 1;
}
