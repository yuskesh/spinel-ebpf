/* otlp_enrich.c -- the registry of attribute enrichers. See otlp_enrich.h. */
#include "otlp_enrich.h"
#include "otlp_k8s.h"
#include "otlp_peer.h"
#include "otlp_cri.h"
#include <stdio.h>       /* snprintf */
#include <stdlib.h>      /* getenv */
#include <string.h>
#include <sys/stat.h>    /* stat / S_ISDIR, to detect a kubepods hierarchy */

/* ---- enricher 1: Kubernetes pod attribution, cgroup id -> k8s.* ----
 * Resolves a cgroup id to k8s.pod.name, k8s.namespace.name, k8s.pod.uid and
 * k8s.container.name, plus k8s.deployment.name and k8s.service.name when the uid
 * map supplies them. On a host with no kubepods hierarchy it returns 0 and adds
 * nothing, leaving the attributes exactly as they were.
 * Its inputs come from the environment, because the generated agent has no argv:
 *   SPNL_K8S_CGROUP_ROOT  the cgroup2 mount; defaults to "/sys/fs/cgroup"
 *   SPNL_K8S_UIDMAP       an optional "uid ns/name" file produced from kubectl
 * It applies to every signal: any record taken in a process context can carry a
 * cgroup id. */
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

/* ---- enricher 3: CRI container names, cgroup id -> the real name ----
 * The Kubernetes enricher fills k8s.container.name with a container id in hex.
 * This one looks the cgroup id up in the CRI map and overwrites that same key --
 * last-writer-wins -- with the real name, coredns and the like. With
 * SPNL_K8S_CRIMAP unset, or a cgroup id absent from the map, it adds nothing and
 * the id stays. It applies to every signal, and is registered *after* the
 * Kubernetes enricher so that the overwrite actually happens. */
static int cri_enrich(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap) {
    if (ctx->cgid == 0 || cap <= 0) return 0;
    return spnl_cri_enrich_attrs(ctx->cgid, out, cap);
}

/* ---- enricher 2: peer resolution, network.peer.address -> an identity ----
 * Classifies a connection span's destination as a pod, a Service, or external.
 * With SPNL_K8S_IPMAP unset it adds nothing and the span is unchanged; the lazy
 * initialisation lives in otlp_peer. It applies only to the connection signal,
 * the one that has a destination address, as declared by its signal mask. */
static int peer_enrich(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap) {
    if (!ctx->peer_addr || !ctx->peer_addr[0] || cap <= 0) return 0;
    return spnl_peer_enrich_attrs(ctx->peer_addr, out, cap);
}

/* The registry. Array order is application order: k8s, then cri, then peer. The
 * CRI entry sits after the Kubernetes one so that last-writer-wins replaces the
 * container id in k8s.container.name with the real name. Which signals each one
 * applies to is declared by its signal mask. */
static const otlp_enricher_t g_enrichers[] = {
    { "k8s",  OTLP_SIG_ALL,                   k8s_enrich  },   /* every signal; container name is the id */
    { "cri",  OTLP_SIG_ALL,                   cri_enrich  },   /* every signal; rewrites that to the real name */
    { "peer", OTLP_SIG_BIT(OTLP_SIGNAL_CONN), peer_enrich },   /* connections only */
};
#define OTLP_ENRICH_N ((int)(sizeof g_enrichers / sizeof g_enrichers[0]))

/* Linear search for key in out[0..n), or -1. There are only ever a handful of
 * attributes, so a scan is plenty. */
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
        if (!(e->signal_mask & OTLP_SIG_BIT(ctx->signal))) continue;   /* not for this signal */
        /* Collect each enricher's output into scratch, then merge it into out
         * last-writer-wins: an existing key is replaced in place, keeping its index
         * and so the attribute order, and a new key is appended. As long as keys do
         * not collide the result is byte-identical to a plain append, which is what
         * keeps older probes producing exactly the spans they always did. */
        otlp_kv_t scratch[16];
        int room = cap - n; if (room > 16) room = 16;
        int m = e->enrich(ctx, scratch, room);
        for (int j = 0; j < m; j++) {
            int at = find_key(out, n, scratch[j].key);
            if (at >= 0) {
                out[at] = scratch[j];               /* replace in place, order preserved */
            } else if (n < cap) {
                out[n++] = scratch[j];              /* a new key goes on the end */
            }
        }
    }
    return n;
}

int otlp_enrich_count(void) { return OTLP_ENRICH_N; }

const otlp_enricher_t *otlp_enrich_at(int i) {
    return (i >= 0 && i < OTLP_ENRICH_N) ? &g_enrichers[i] : NULL;
}
