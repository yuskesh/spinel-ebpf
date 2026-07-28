/* otlp_enrich.c — 層 2 enricher レジストリ (ADR-014、E313 / E315)。詳細は otlp_enrich.h。 */
#include "otlp_enrich.h"
#include "otlp_k8s.h"
#include "otlp_peer.h"
#include "otlp_cri.h"
#include <stdio.h>       /* snprintf */
#include <stdlib.h>      /* getenv */
#include <string.h>
#include <sys/stat.h>    /* stat / S_ISDIR (kubepods 階層の検出) */

/* ---- enricher #1: k8s pod attribution (cgroup_id -> k8s.*、E304) ----
 * cgid を k8s.pod.name / k8s.namespace.name / k8s.pod.uid / k8s.container.name
 * (+ E310: k8s.deployment.name / k8s.service.name) に解決 (otlp_k8s、E302/E304)。
 * kubepods 階層が無いホストでは hard no-op (return 0) = 属性は E304 前と byte 同一。
 * 入力は env (生成 agent 経路には argv が無い):
 *   SPNL_K8S_CGROUP_ROOT  cgroup2 mount (既定 "/sys/fs/cgroup")
 *   SPNL_K8S_UIDMAP       kubectl 由来 "uid ns/name" ファイル (任意)
 * 全 signal に適用 (どの record も process ctx で cgid を持ち得る)。 */
static int k8s_enrich(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap) {
    static int  enabled = -1;   /* -1 unknown, 0 off, 1 on (lazy one-shot) */
    static char root[256];
    static char uidmap[512];
    static int  have_uidmap = 0;
    if (enabled < 0) {
        const char *r = getenv("SPNL_K8S_CGROUP_ROOT");
        snprintf(root, sizeof root, "%s", (r && r[0]) ? r : "/sys/fs/cgroup");
        struct stat st; char probe[300]; int ok = 0;
        snprintf(probe, sizeof probe, "%s/kubepods", root);
        if (stat(probe, &st) == 0 && S_ISDIR(st.st_mode)) ok = 1;
        if (!ok) { snprintf(probe, sizeof probe, "%s/kubepods.slice", root);
                   if (stat(probe, &st) == 0 && S_ISDIR(st.st_mode)) ok = 1; }
        enabled = ok;
        const char *um = getenv("SPNL_K8S_UIDMAP");
        if (um && um[0]) { snprintf(uidmap, sizeof uidmap, "%s", um); have_uidmap = 1; }
    }
    if (enabled != 1 || ctx->cgid == 0 || cap <= 0) return 0;
    return spnl_k8s_enrich_attrs(ctx->cgid, root, have_uidmap ? uidmap : NULL, out, cap);
}

/* ---- enricher #3: CRI container 名解決 (cgroup_id -> 実 container 名、E315) ----
 * otlp_k8s は k8s.container.name に container-id (hex) を載せる。ここは cgid を CRIMAP で
 * 実 container 名 (coredns 等) に引き、**同じ key を last-writer-wins で上書き**して実名にする。
 * SPNL_K8S_CRIMAP 未設定 / cgid がマップに無ければ hard no-op (k8s の id が残る = E304/E310 byte 同一)。
 * 全 signal に適用 (process ctx の cgid を持つ経路すべて。**k8s の後に登録**して後勝ち上書きを成立させる)。 */
static int cri_enrich(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap) {
    if (ctx->cgid == 0 || cap <= 0) return 0;
    return spnl_cri_enrich_attrs(ctx->cgid, out, cap);
}

/* ---- enricher #2: peer resolution (network.peer.address -> peer identity、E310) ----
 * conn span の宛先 IP を pod / service / external に分類 (otlp_peer)。
 * SPNL_K8S_IPMAP 未設定なら hard no-op (span byte 不変)。lazy_init は otlp_peer 側。
 * conn signal のみに適用 (宛先アドレスを持つ経路、registry の signal_mask で宣言)。 */
static int peer_enrich(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap) {
    if (!ctx->peer_addr || !ctx->peer_addr[0] || cap <= 0) return 0;
    return spnl_peer_enrich_attrs(ctx->peer_addr, out, cap);
}

/* レジストリ。**並び順 = enricher 適用順** (k8s -> cri -> peer)。cri は k8s の後に置き、
 * funnel の last-writer-wins で k8s.container.name (id) を実名に後勝ち上書きする。
 * per-signal 適用可否は signal_mask で宣言。 */
static const otlp_enricher_t g_enrichers[] = {
    { "k8s",  OTLP_SIG_ALL,                   k8s_enrich  },   /* E304: 全経路 (container=id) */
    { "cri",  OTLP_SIG_ALL,                   cri_enrich  },   /* E315: 全経路 (container 名を実名に上書き) */
    { "peer", OTLP_SIG_BIT(OTLP_SIGNAL_CONN), peer_enrich },   /* E310: conn のみ */
};
#define OTLP_ENRICH_N ((int)(sizeof g_enrichers / sizeof g_enrichers[0]))

/* out[0..n) から key を線形探索 (無ければ -1)。属性数は高々数個なので線形で十分。 */
static int find_key(const otlp_kv_t *out, int n, const char *key) {
    for (int i = 0; i < n; i++) if (!strcmp(out[i].key, key)) return i;
    return -1;
}

int otlp_enrich_run(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap) {
    if (!ctx || !out || cap <= 0) return 0;
    int n = 0;
    for (int i = 0; i < OTLP_ENRICH_N; i++) {
        if (n >= cap) break;
        const otlp_enricher_t *e = &g_enrichers[i];
        if (!(e->signal_mask & OTLP_SIG_BIT(ctx->signal))) continue;   /* 適用外 signal はスキップ */
        /* 各 enricher の出力を一旦 scratch に取り、**last-writer-wins** で out にマージ。
         * 同一 key が既にあれば後勝ちで置換 (index 不変 = 順序保持)、無ければ末尾 append。
         * key が衝突しない限り append と byte-identical (E304/E310 の後方互換の肝)。 */
        otlp_kv_t scratch[16];
        int room = cap - n; if (room > 16) room = 16;
        int m = e->enrich(ctx, scratch, room);
        for (int j = 0; j < m; j++) {
            int at = find_key(out, n, scratch[j].key);
            if (at >= 0) {
                out[at] = scratch[j];               /* 後勝ち上書き (順序不変) */
            } else if (n < cap) {
                out[n++] = scratch[j];              /* 新規 key は末尾 append */
            }
        }
    }
    return n;
}

int otlp_enrich_count(void) { return OTLP_ENRICH_N; }

const otlp_enricher_t *otlp_enrich_at(int i) {
    return (i >= 0 && i < OTLP_ENRICH_N) ? &g_enrichers[i] : NULL;
}
