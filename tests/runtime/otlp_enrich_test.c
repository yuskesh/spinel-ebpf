/*
 * otlp_enrich_test.c -- unit test for the userspace enricher registry, the layer
 * that decorates spans after the probe has emitted them.
 *
 * What it checks:
 *  (1) registry introspection: three enrichers are registered (k8s -> cri -> peer)
 *      and each declares which signals it applies to (signal_mask).
 *  (2) no-op: with none of the env vars set, even a CONN record yields 0
 *      attributes (the span bytes are unchanged) -- verified in a forked child,
 *      since the lazy init is one-shot and would otherwise contaminate the parent.
 *  (2b) backward compatibility (the most important gate): with no CRIMAP set,
 *      k8s.container.name stays the raw container id, byte-identical to the output
 *      from before CRI name resolution existed.
 *  (2c) CRI resolution and last-writer-wins: with a CRIMAP set, k8s.container.name
 *      becomes the real name "coredns" and appears exactly once -- the cri
 *      enricher overwrites the id the k8s enricher wrote instead of appending a
 *      second entry, and the other k8s.* attributes survive.
 *  (3) CONN: both k8s (the originating pod) and peer (the destination) apply, and
 *      the k8s attributes are emitted *before* the peer attributes -- the same
 *      byte order as when the runtime called the two resolvers directly.
 *  (4) DNS: even when a peer_addr is supplied, peer is excluded by signal_mask, so
 *      only k8s applies, byte-identical to the behaviour before the registry.
 *  (5) the cap on how many attributes may be written is respected.
 *
 * The test builds a fake kubepods hierarchy under a temp directory and uses the
 * inode of its container directory as the cgid, so no real kernel is needed (this
 * runs on a macOS or Linux host). No libbpf or nanopb dependency. Link against
 * otlp_enrich.c + otlp_k8s.c + otlp_peer.c + otlp_cri.c with
 * cc -I src/runtime/otlp -I include.
 */
#include "otlp_enrich.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

static int fails = 0;
#define CHK(cond, msg) do { if (cond) { printf("  ok: %s\n", msg); } \
    else { printf("  FAIL: %s\n", msg); fails++; } } while (0)

/* Index of key in the attribute array, or -1 if it is absent. */
static int attr_idx(const otlp_kv_t *a, int n, const char *k) {
    for (int i = 0; i < n; i++) if (!strcmp(a[i].key, k)) return i;
    return -1;
}

static const char *POD_UID = "1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280";
static const char *CTR_ID  = "9b763adf6f512b686d81705fe1267700c1de5ab427f527a84ca949b6d7eec866";
static const char *POD_IP  = "10.42.0.20";

int main(void) {
    /* ---- build a fake kubepods hierarchy under a temp dir (container inode = cgid) ---- */
    char cgroot[] = "/tmp/spnl_enrich_cg_XXXXXX";
    if (!mkdtemp(cgroot)) { perror("mkdtemp cgroot"); return 2; }
    char p1[512], p2[512], p3[512], p4[512];
    snprintf(p1, sizeof p1, "%s/kubepods", cgroot);                mkdir(p1, 0755);
    snprintf(p2, sizeof p2, "%s/burstable", p1);                   mkdir(p2, 0755);
    snprintf(p3, sizeof p3, "%s/pod%s", p2, POD_UID);              mkdir(p3, 0755);
    snprintf(p4, sizeof p4, "%s/%s", p3, CTR_ID);                  mkdir(p4, 0755);
    struct stat st;
    if (stat(p4, &st) != 0) { perror("stat container dir"); return 2; }
    uint64_t cgid = (uint64_t)st.st_ino;

    /* uid map / ip map, standing in for what kubectl would supply */
    char uidmap[] = "/tmp/spnl_enrich_uid_XXXXXX";
    { int fd = mkstemp(uidmap); FILE *f = fdopen(fd, "w");
      fprintf(f, "%s kube-system/coredns-ccb96694c-5kpb7\n", POD_UID); fclose(f); }
    char ipmap[] = "/tmp/spnl_enrich_ip_XXXXXX";
    { int fd = mkstemp(ipmap); FILE *f = fdopen(fd, "w");
      fprintf(f, "%s pod default echo-srv\n", POD_IP); fclose(f); }
    /* CRIMAP maps cgid -> real container name; here the container inode -> coredns. */
    char crimap[] = "/tmp/spnl_cri_XXXXXX";
    { int fd = mkstemp(crimap); FILE *f = fdopen(fd, "w");
      fprintf(f, "%llu coredns\n", (unsigned long long)cgid); fclose(f); }

    /* ---- (1) registry introspection (env-independent; does not trigger lazy init) ---- */
    printf("[enrich] (1) registry introspection\n");
    CHK(otlp_enrich_count() == 3, "3 enrichers registered (k8s, cri, peer)");
    const otlp_enricher_t *e0 = otlp_enrich_at(0);
    const otlp_enricher_t *e1 = otlp_enrich_at(1);
    const otlp_enricher_t *e2 = otlp_enrich_at(2);
    CHK(e0 && !strcmp(e0->name, "k8s"),  "slot 0 = k8s (applied first)");
    CHK(e1 && !strcmp(e1->name, "cri"),  "slot 1 = cri (runs after k8s, so it overwrites the container name)");
    CHK(e2 && !strcmp(e2->name, "peer"), "slot 2 = peer (applied last)");
    CHK(e0 && e0->signal_mask == OTLP_SIG_ALL, "k8s: applies to every signal");
    CHK(e1 && e1->signal_mask == OTLP_SIG_ALL, "cri: applies to every signal");
    CHK(e2 && (e2->signal_mask & OTLP_SIG_BIT(OTLP_SIGNAL_CONN)) != 0, "peer: applies to CONN");
    CHK(e2 && (e2->signal_mask & OTLP_SIG_BIT(OTLP_SIGNAL_DNS))  == 0, "peer: does not apply to DNS");
    CHK(e2 && (e2->signal_mask & OTLP_SIG_BIT(OTLP_SIGNAL_HTTP)) == 0, "peer: does not apply to HTTP");
    CHK(otlp_enrich_at(3) == NULL,  "index out of range -> NULL");
    CHK(otlp_enrich_at(-1) == NULL, "negative index -> NULL");

    /* ---- (2) no-op with no env set, checked in a forked child so the one-shot lazy init is not contaminated ---- */
    printf("[enrich] (2) no-op: with no env set even CONN yields 0 attributes (forked child)\n");
    { char empty[] = "/tmp/spnl_enrich_empty_XXXXXX"; (void)mkdtemp(empty);   /* empty root, no kubepods */
      pid_t pid = fork();
      if (pid == 0) {
          unsetenv("SPNL_K8S_IPMAP");            /* peer off */
          unsetenv("SPNL_K8S_CRIMAP");           /* cri off */
          setenv("SPNL_K8S_CGROUP_ROOT", empty, 1);  /* no kubepods -> k8s disabled */
          otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, cgid, POD_IP };   /* the inputs are present ... */
          otlp_kv_t a[16];
          _exit(otlp_enrich_run(&ec, a, 16) == 0 ? 0 : 1);            /* ... yet a total no-op is expected */
      }
      int stt = 0; waitpid(pid, &stt, 0);
      CHK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0, "no env -> 0 attributes even for CONN (span bytes unchanged)");
    }

    /* ---- (2b) backward compatibility, the most important gate: with no CRIMAP,
     * k8s.container.name = container_id ----
     * With no CRIMAP the cri enricher is a no-op, so the id the k8s enricher wrote
     * survives, byte-identical to the output from before CRI resolution existed.
     * Run in a forked child to keep the one-shot lazy init away from the parent
     * (only k8s enabled, CRIMAP unset). */
    printf("[enrich] (2b) no CRIMAP -> k8s.container.name = container_id (byte-identical to before)\n");
    { pid_t pid = fork();
      if (pid == 0) {
          setenv("SPNL_K8S_CGROUP_ROOT", cgroot, 1);
          setenv("SPNL_K8S_UIDMAP", uidmap, 1);
          unsetenv("SPNL_K8S_IPMAP");             /* peer off */
          unsetenv("SPNL_K8S_CRIMAP");            /* cri off = the backward-compatible case */
          otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, cgid, NULL };
          otlp_kv_t a[16]; int n = otlp_enrich_run(&ec, a, 16);
          int ci = attr_idx(a, n, "k8s.container.name");
          int ok = (ci >= 0 && !strcmp(a[ci].val, CTR_ID));   /* still the container id, not the real name */
          if (!ok) printf("  child: k8s.container.name=%s (want id)\n", ci>=0?a[ci].val:"(none)");
          _exit(ok ? 0 : 1);
      }
      int stt = 0; waitpid(pid, &stt, 0);
      CHK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0,
          "no CRIMAP -> k8s.container.name = container_id (byte-identical to before)");
    }

    /* ---- (2c) CRI resolution and last-writer-wins: with a CRIMAP the real name
     * "coredns" appears, with no duplicate ----
     * cri overwrites the container_id that k8s wrote, so k8s.container.name is
     * present exactly once (replaced, not appended). */
    printf("[enrich] (2c) with CRIMAP -> k8s.container.name = coredns (real name, last-writer-wins)\n");
    { pid_t pid = fork();
      if (pid == 0) {
          setenv("SPNL_K8S_CGROUP_ROOT", cgroot, 1);
          setenv("SPNL_K8S_UIDMAP", uidmap, 1);
          unsetenv("SPNL_K8S_IPMAP");             /* peer off, so even CONN gets no peer attributes */
          setenv("SPNL_K8S_CRIMAP", crimap, 1);   /* cri on: cgid -> coredns */
          otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, cgid, NULL };
          otlp_kv_t a[16]; int n = otlp_enrich_run(&ec, a, 16);
          /* k8s.container.name is the real name coredns, and appears exactly once
           * (last-writer-wins, no duplicate append) */
          int cnt = 0, ci = -1;
          for (int i = 0; i < n; i++) if (!strcmp(a[i].key, "k8s.container.name")) { cnt++; ci = i; }
          int ok = (cnt == 1 && ci >= 0 && !strcmp(a[ci].val, "coredns"));
          /* the other k8s.* attributes (pod.name and friends) survive; only container.name is overwritten */
          int keep = attr_idx(a, n, "k8s.pod.name") >= 0;
          if (!ok) printf("  child: cnt=%d val=%s (want 1x coredns)\n", cnt, ci>=0?a[ci].val:"(none)");
          _exit((ok && keep) ? 0 : 1);
      }
      int stt = 0; waitpid(pid, &stt, 0);
      CHK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0,
          "with CRIMAP -> k8s.container.name=coredns (real name) exactly once (last-writer-wins)");
    }

    /* ---- parent: set the env, then run the positive tests (lazy init happens once, on the first enrich call) ---- */
    setenv("SPNL_K8S_CGROUP_ROOT", cgroot, 1);
    setenv("SPNL_K8S_UIDMAP", uidmap, 1);
    setenv("SPNL_K8S_IPMAP", ipmap, 1);
    setenv("SPNL_K8S_POD_CIDR", "10.42.0.0/16", 1);
    setenv("SPNL_K8S_SVC_CIDR", "10.43.0.0/16", 1);
    setenv("SPNL_K8S_PEER_RDNS", "0", 1);

    /* ---- (3) CONN: both k8s and peer apply, and k8s comes before peer ---- */
    printf("[enrich] (3) CONN: k8s (source) + peer (destination), in the order k8s -> peer\n");
    { otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, cgid, POD_IP };
      otlp_kv_t a[16]; int n = otlp_enrich_run(&ec, a, 16);
      int i_k8s_ns   = attr_idx(a, n, "k8s.namespace.name");
      int i_k8s_pod  = attr_idx(a, n, "k8s.pod.name");
      int i_peer_pod = attr_idx(a, n, "peer.k8s.pod.name");
      int i_peer_ns  = attr_idx(a, n, "peer.k8s.namespace.name");
      CHK(i_k8s_ns  >= 0, "k8s.namespace.name added (originating pod)");
      CHK(i_k8s_pod >= 0 && !strcmp(a[i_k8s_pod].val, "coredns-ccb96694c-5kpb7"),
          "k8s.pod.name=coredns-... (cgid resolved to a pod)");
      CHK(i_peer_pod >= 0 && !strcmp(a[i_peer_pod].val, "echo-srv"),
          "peer.k8s.pod.name=echo-srv (destination IP resolved)");
      CHK(i_peer_ns >= 0, "peer.k8s.namespace.name added");
      /* the crux of staying byte-identical: k8s attributes precede peer attributes (registry order) */
      CHK(i_k8s_pod < i_peer_pod, "k8s attributes precede peer attributes (span byte order)");
      CHK(i_k8s_ns  < i_peer_pod, "all of k8s.* comes before peer.*");
    }

    /* ---- (4) DNS: peer does not apply even with a peer_addr (signal_mask); only k8s does ---- */
    printf("[enrich] (4) DNS: peer excluded by the mask even with a peer_addr (byte-identical to before)\n");
    { otlp_enrich_ctx_t ec = { OTLP_SIGNAL_DNS, cgid, POD_IP };   /* deliberately pass a peer_addr */
      otlp_kv_t a[16]; int n = otlp_enrich_run(&ec, a, 16);
      CHK(attr_idx(a, n, "k8s.pod.name") >= 0, "DNS gets k8s.pod.name (k8s applies to every signal)");
      CHK(attr_idx(a, n, "peer.k8s.pod.name") < 0,
          "DNS gets no peer.* (peer is CONN-only; byte-identical to before)");
    }

    /* ---- (5) no-op on missing input, plus the attribute cap ---- */
    printf("[enrich] (5) no-op on missing input, plus the attribute cap\n");
    { otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, 0, NULL };   /* cgid=0 and no peer */
      otlp_kv_t a[16]; int n = otlp_enrich_run(&ec, a, 16);
      CHK(n == 0, "cgid=0 and no peer -> 0 attributes (no-op)"); }
    { otlp_enrich_ctx_t ec = { OTLP_SIGNAL_CONN, cgid, POD_IP };
      otlp_kv_t a[2]; int n = otlp_enrich_run(&ec, a, 2);
      CHK(n <= 2, "never writes past cap=2"); }

    /* best-effort cleanup */
    rmdir(p4); rmdir(p3); rmdir(p2); rmdir(p1); rmdir(cgroot);
    unlink(uidmap); unlink(ipmap); unlink(crimap);

    if (fails == 0) { printf("[enrich] PASS (registry: k8s->cri->peer, per-signal mask, byte-order, CRI last-writer-wins)\n"); return 0; }
    printf("[enrich] FAIL: %d\n", fails); return 1;
}
