/* otlp_peer.c — conn span の宛先 IP を pod/service/外部に解決。詳細は otlp_peer.h。 */
#include "otlp_peer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>       /* getnameinfo (best-effort reverse-DNS) */
#include <sys/socket.h>

/* ---- IP マップ (ip -> {kind, ns, name}) ---- */
typedef struct { char ip[46]; int kind; char ns[128]; char name[256]; } peer_ent_t;

static peer_ent_t *g_map = NULL;
static int         g_map_n = 0;
static uint32_t    g_pod_base = 0, g_pod_mask = 0;   /* host order */
static uint32_t    g_svc_base = 0, g_svc_mask = 0;
static int         g_have_pod_cidr = 0, g_have_svc_cidr = 0;
static int         g_rdns = 0;
static int         g_inited = -1;   /* -1 unknown, 0 off (no IPMAP), 1 on */

/* "a.b.c.d/prefix" -> base(host order) + mask(host order)。成功で 1。 */
static int parse_cidr(const char *s, uint32_t *base, uint32_t *mask) {
    if (!s || !s[0]) return 0;
    char buf[64]; snprintf(buf, sizeof buf, "%s", s);
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
    if (prefix < 0 || prefix > 32) return 0;
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return 0;
    uint32_t m = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    *mask = m;
    *base = ntohl(a.s_addr) & m;
    return 1;
}

/* "::ffff:1.2.3.4" -> "1.2.3.4"。それ以外は addr をそのまま out にコピー。 */
static void unwrap_v4mapped(const char *addr, char *out, size_t cap) {
    if (addr && (strncmp(addr, "::ffff:", 7) == 0 || strncmp(addr, "::FFFF:", 7) == 0)
        && strchr(addr + 7, '.')) {
        snprintf(out, cap, "%s", addr + 7);
    } else {
        snprintf(out, cap, "%s", addr ? addr : "");
    }
}

static int is_loopback(const char *addr) {
    if (!addr) return 0;
    if (strncmp(addr, "127.", 4) == 0) return 1;
    if (strcmp(addr, "::1") == 0) return 1;
    return 0;
}

/* 内部: IP マップ 1 行 "ip kind ns name" を格納。 */
static void map_add(const char *ip, const char *kind, const char *ns, const char *name) {
    peer_ent_t *e = realloc(g_map, sizeof(peer_ent_t) * (g_map_n + 1));
    if (!e) return;
    g_map = e;
    peer_ent_t *p = &g_map[g_map_n];
    memset(p, 0, sizeof *p);
    snprintf(p->ip, sizeof p->ip, "%s", ip);
    p->kind = (!strcmp(kind, "service")) ? SPNL_PEER_SERVICE : SPNL_PEER_POD;
    snprintf(p->ns, sizeof p->ns, "%s", ns);
    snprintf(p->name, sizeof p->name, "%s", name);
    g_map_n++;
}

static void lazy_init(void) {
    if (g_inited >= 0) return;
    const char *ipmap = getenv("SPNL_K8S_IPMAP");
    if (!ipmap || !ipmap[0]) { g_inited = 0; return; }   /* gate: no map -> hard no-op */

    FILE *f = fopen(ipmap, "r");
    if (f) {
        char line[640];
        while (fgets(line, sizeof line, f)) {
            char ip[46], kind[16], ns[128], name[256];
            if (sscanf(line, "%45s %15s %127s %255s", ip, kind, ns, name) == 4)
                map_add(ip, kind, ns, name);
        }
        fclose(f);
    }
    /* CIDR: env 指定が無ければ k3s 既定 (pod 10.42/16, svc 10.43/16)。 */
    const char *pc = getenv("SPNL_K8S_POD_CIDR");
    g_have_pod_cidr = parse_cidr((pc && pc[0]) ? pc : "10.42.0.0/16", &g_pod_base, &g_pod_mask);
    const char *sc = getenv("SPNL_K8S_SVC_CIDR");
    g_have_svc_cidr = parse_cidr((sc && sc[0]) ? sc : "10.43.0.0/16", &g_svc_base, &g_svc_mask);
    const char *rd = getenv("SPNL_K8S_PEER_RDNS");
    g_rdns = (rd && (rd[0] == '1' || rd[0] == 'y' || rd[0] == 'Y' || rd[0] == 't' || rd[0] == 'T')) ? 1 : 0;
    g_inited = 1;
}

/* 外部 IP の逆引き (best-effort、cache 付き)。取れなければ空文字。 */
static const char *rdns_cached(const char *addr) {
    static struct { char ip[46]; char host[256]; } cache[256];
    static int cn = 0;
    for (int i = 0; i < cn; i++) if (!strcmp(cache[i].ip, addr)) return cache[i].host;
    char host[256] = {0};
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, addr, &sa.sin_addr) == 1) {
        if (getnameinfo((struct sockaddr *)&sa, sizeof sa, host, sizeof host, NULL, 0, NI_NAMEREQD) != 0)
            host[0] = '\0';
    }
    if (cn < (int)(sizeof cache / sizeof cache[0])) {
        snprintf(cache[cn].ip, sizeof cache[cn].ip, "%s", addr);
        snprintf(cache[cn].host, sizeof cache[cn].host, "%s", host);
        return cache[cn++].host;
    }
    /* cache 満杯: 一時領域に返す (次呼出で上書き) */
    static char tmp[256]; snprintf(tmp, sizeof tmp, "%s", host); return tmp;
}

int spnl_peer_classify(const char *addr, spnl_peer_t *out) {
    if (!out) return SPNL_PEER_NONE;
    memset(out, 0, sizeof *out);
    lazy_init();
    if (g_inited != 1 || !addr || !addr[0]) return SPNL_PEER_NONE;

    char a[46];
    unwrap_v4mapped(addr, a, sizeof a);
    snprintf(out->address, sizeof out->address, "%s", a);

    if (is_loopback(a)) { out->kind = SPNL_PEER_LOOPBACK; return out->kind; }

    /* IP マップ完全一致 (pod IP / service ClusterIP)。 */
    for (int i = 0; i < g_map_n; i++) {
        if (!strcmp(g_map[i].ip, a)) {
            out->kind = g_map[i].kind;
            snprintf(out->namespace_, sizeof out->namespace_, "%s", g_map[i].ns);
            snprintf(out->name, sizeof out->name, "%s", g_map[i].name);
            return out->kind;
        }
    }

    /* CIDR 判定 (IPv4)。 */
    struct in_addr ia;
    if (inet_pton(AF_INET, a, &ia) == 1) {
        uint32_t h = ntohl(ia.s_addr);
        if ((g_have_pod_cidr && (h & g_pod_mask) == g_pod_base) ||
            (g_have_svc_cidr && (h & g_svc_mask) == g_svc_base)) {
            out->kind = SPNL_PEER_CLUSTER;   /* cluster 内だが名前不明 (node gw 等) */
            return out->kind;
        }
        out->kind = SPNL_PEER_EXTERNAL;
        if (g_rdns) {
            const char *hn = rdns_cached(a);
            if (hn && hn[0]) snprintf(out->hostname, sizeof out->hostname, "%s", hn);
        }
        return out->kind;
    }

    /* IPv4 でない (真の IPv6)。マップ外なら外部扱い。 */
    out->kind = SPNL_PEER_EXTERNAL;
    return out->kind;
}

int spnl_peer_fill_attrs(const spnl_peer_t *p, otlp_kv_t *attrs, int max) {
    if (!p || !attrs) return 0;
    int n = 0;
    #define PUT(k, v) do { if ((v)[0] && n < max) { \
        snprintf(attrs[n].key, sizeof attrs[n].key, "%s", (k)); \
        snprintf(attrs[n].val, sizeof attrs[n].val, "%s", (v)); n++; } } while (0)
    switch (p->kind) {
    case SPNL_PEER_POD:
        PUT("peer.k8s.pod.name",       p->name);
        PUT("peer.k8s.namespace.name", p->namespace_);
        break;
    case SPNL_PEER_SERVICE:
        PUT("peer.k8s.service.name",   p->name);
        PUT("peer.k8s.namespace.name", p->namespace_);
        break;
    case SPNL_PEER_EXTERNAL:
        if (n < max) { snprintf(attrs[n].key, sizeof attrs[n].key, "network.peer.external");
                       snprintf(attrs[n].val, sizeof attrs[n].val, "true"); n++; }
        PUT("peer.hostname", p->hostname);
        break;
    default:  /* NONE / LOOPBACK / CLUSTER: identity 無し = 属性を足さない (正直に no-op) */
        break;
    }
    #undef PUT
    return n;
}

int spnl_peer_enrich_attrs(const char *addr, otlp_kv_t *attrs, int max) {
    if (!attrs || max <= 0) return 0;
    lazy_init();
    if (g_inited != 1 || !addr || !addr[0]) return 0;
    spnl_peer_t p;
    spnl_peer_classify(addr, &p);
    return spnl_peer_fill_attrs(&p, attrs, max);
}
