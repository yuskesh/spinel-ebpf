/*
 * otlp_k8s_test.c -- unit test for resolving a cgroup_id to a k8s pod.
 *
 * The inputs are real kubepods cgroup paths and a real pod UID map captured from a
 * k3s VM. The test confirms that the cgroup_ids a BPF program observed there, 674
 * and 592, resolve to the coredns and local-path pods and turn into the semconv
 * k8s.* attributes. No libbpf or nanopb dependency, so it runs on a host.
 */
#include "otlp_k8s.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

static int fails = 0;
#define CHECK(cond, msg) do { if (cond) { printf("  ok: %s\n", msg); } \
    else { printf("  FAIL: %s\n", msg); fails++; } } while (0)

/* Observed in a k3s VM: the cgroup path of the coredns container (cgroup_id = inode = 674). */
static const char *COREDNS_PATH =
  "/sys/fs/cgroup/kubepods/burstable/pod1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280/"
  "9b763adf6f512b686d81705fe1267700c1de5ab427f527a84ca949b6d7eec866";
/* Observed: the local-path-provisioner container (cgroup_id = inode = 592). */
static const char *LOCALPATH_PATH =
  "/sys/fs/cgroup/kubepods/besteffort/podbcc002b1-ebe2-4295-97ec-480e0355c126/"
  "522ecf0f0e503390dd52c24268d2ea1e60a8a326ac94c59d6eb2dad9aa931798";
/* For reference: the systemd cgroup-driver form. Not yet seen on a live node here,
 * but the parser handles it already. */
static const char *SYSTEMD_PATH =
  "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/"
  "kubepods-burstable-pod1d0ff866_8ef5_41f5_a2ee_0c1ddcd4c280.slice/"
  "cri-containerd-9b763adf6f512b686d81705fe1267700c1de5ab427f527a84ca949b6d7eec866.scope";

int main(void)
{
    printf("[k8s] parse cgroupfs-form kubepods path (coredns, cgroup_id 674)\n");
    spnl_k8s_pod_t p;
    CHECK(spnl_k8s_parse_kubepods_path(COREDNS_PATH, &p) == 1, "parse returns found");
    CHECK(!strcmp(p.qos, "burstable"), "qos=burstable");
    CHECK(!strcmp(p.pod_uid, "1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280"), "pod_uid extracted");
    CHECK(!strcmp(p.container_id,
          "9b763adf6f512b686d81705fe1267700c1de5ab427f527a84ca949b6d7eec866"),
          "container_id extracted");

    printf("[k8s] parse (local-path, cgroup_id 592)\n");
    spnl_k8s_pod_t q;
    CHECK(spnl_k8s_parse_kubepods_path(LOCALPATH_PATH, &q) == 1, "parse found");
    CHECK(!strcmp(q.qos, "besteffort"), "qos=besteffort");
    CHECK(!strcmp(q.pod_uid, "bcc002b1-ebe2-4295-97ec-480e0355c126"), "pod_uid extracted");

    printf("[k8s] parse systemd-form (slice/scope, underscore UID normalized)\n");
    spnl_k8s_pod_t s;
    CHECK(spnl_k8s_parse_kubepods_path(SYSTEMD_PATH, &s) == 1, "parse found");
    CHECK(!strcmp(s.qos, "burstable"), "qos=burstable (from prefix)");
    CHECK(!strcmp(s.pod_uid, "1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280"), "pod_uid _->- normalized");
    CHECK(!strcmp(s.container_id,
          "9b763adf6f512b686d81705fe1267700c1de5ab427f527a84ca949b6d7eec866"),
          "container_id from cri-containerd-<id>.scope");

    printf("[k8s] non-kubepods path is rejected\n");
    spnl_k8s_pod_t r;
    CHECK(spnl_k8s_parse_kubepods_path("/sys/fs/cgroup/system.slice/sshd.service", &r) == 0,
          "non-kubepods returns 0");

    printf("[k8s] resolve pod_uid -> namespace/name from real uid map\n");
    /* Write the real uid map (from kubectl get pods) to a temp file and resolve against it. */
    char tmpl[] = "/tmp/spnl_uidmap_XXXXXX";
    int fd = mkstemp(tmpl);
    assert(fd >= 0);
    FILE *mf = fdopen(fd, "w");
    fputs("1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280 kube-system/coredns-ccb96694c-5kpb7\n", mf);
    fputs("bcc002b1-ebe2-4295-97ec-480e0355c126 kube-system/local-path-provisioner-5cf85fd84d-2pnmm\n", mf);
    fclose(mf);

    CHECK(spnl_k8s_resolve_name(&p, tmpl) == 1, "coredns uid resolved");
    CHECK(!strcmp(p.namespace_, "kube-system"), "k8s.namespace.name=kube-system");
    CHECK(!strcmp(p.pod_name, "coredns-ccb96694c-5kpb7"), "k8s.pod.name=coredns-...");
    CHECK(spnl_k8s_resolve_name(&q, tmpl) == 1, "local-path uid resolved");
    CHECK(!strcmp(q.pod_name, "local-path-provisioner-5cf85fd84d-2pnmm"), "k8s.pod.name=local-path-...");
    unlink(tmpl);

    printf("[k8s] fill semconv k8s.* attrs (what rides the span)\n");
    otlp_kv_t a[8];
    int n = spnl_k8s_fill_attrs(&p, a, 8);
    CHECK(n == 4, "4 attrs (ns/name/uid/container)");
    int have_ns = 0, have_name = 0, have_uid = 0, have_ctr = 0;
    for (int i = 0; i < n; i++) {
        if (!strcmp(a[i].key, "k8s.namespace.name") && !strcmp(a[i].val, "kube-system")) have_ns = 1;
        if (!strcmp(a[i].key, "k8s.pod.name") && !strcmp(a[i].val, "coredns-ccb96694c-5kpb7")) have_name = 1;
        if (!strcmp(a[i].key, "k8s.pod.uid")) have_uid = 1;
        if (!strcmp(a[i].key, "k8s.container.name")) have_ctr = 1;
    }
    CHECK(have_ns,   "attr k8s.namespace.name present");
    CHECK(have_name, "attr k8s.pod.name present");
    CHECK(have_uid,  "attr k8s.pod.uid present");
    CHECK(have_ctr,  "attr k8s.container.name present");

    if (fails == 0) { printf("[k8s] PASS (BPF cgroup_id 674->coredns, 592->local-path)\n"); return 0; }
    printf("[k8s] FAIL: %d\n", fails); return 1;
}
