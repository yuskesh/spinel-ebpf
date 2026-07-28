/*
 * otlp_k8s_span_test.c -- adds k8s.* attributes to an existing span (a file-audit
 * span of the kind the LSM probes produce), encodes it as OTLP protobuf and writes
 * it to stdout. The run script decodes the wire bytes with protoc --decode and
 * confirms that the real pod name, k8s.pod.name=coredns-..., rides along as a span
 * attribute.
 *
 * The cgroup_id used here is 674, a value a BPF program actually observed in a k3s
 * VM (the cgroup inode of the coredns container). A plain host has no kubepods
 * hierarchy to walk, so instead of spnl_k8s_lookup_by_cgroup_id this test parses
 * the cgroup path the VM reported and runs resolve -> fill_attrs on it directly;
 * the inode walk itself is covered by the end-to-end run inside the VM.
 * This is a userspace-side join: the span builder (otlp_traces_generic_build) is
 * untouched, k8s.* is simply appended to the attribute array.
 */
#include "otlp_traces.h"   /* otlp_generic_span_t, otlp_traces_generic_build */
#include "otlp_k8s.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Observed in a k3s VM: the container cgroup path behind BPF cgroup_id 674. */
static const char *CGID_674_PATH =
  "/sys/fs/cgroup/kubepods/burstable/pod1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280/"
  "9b763adf6f512b686d81705fe1267700c1de5ab427f527a84ca949b6d7eec866";

int main(void)
{
    /* Write the uid map (real kubectl get pods output) to a temp file. */
    char tmpl[] = "/tmp/spnl_uidmap_span_XXXXXX";
    int fd = mkstemp(tmpl);
    FILE *mf = fdopen(fd, "w");
    fputs("1d0ff866-8ef5-41f5-a2ee-0c1ddcd4c280 kube-system/coredns-ccb96694c-5kpb7\n", mf);
    fclose(mf);

    /* cgroup_id 674 -> resolve the pod -> k8s.* attributes. */
    spnl_k8s_pod_t pod;
    spnl_k8s_parse_kubepods_path(CGID_674_PATH, &pod);
    spnl_k8s_resolve_name(&pod, tmpl);
    unlink(tmpl);

    otlp_kv_t attrs[8];
    int n = 0;
    /* Attributes of a file-audit span. */
    snprintf(attrs[n].key, sizeof attrs[n].key, "file.path");
    snprintf(attrs[n].val, sizeof attrs[n].val, "/etc/shadow"); n++;
    snprintf(attrs[n].key, sizeof attrs[n].key, "process.executable.name");
    snprintf(attrs[n].val, sizeof attrs[n].val, "cat"); n++;
    snprintf(attrs[n].key, sizeof attrs[n].key, "verdict");
    snprintf(attrs[n].val, sizeof attrs[n].val, "deny"); n++;
    /* k8s.* enrichment (cgroup_id -> pod). */
    n += spnl_k8s_fill_attrs(&pod, attrs + n, 8 - n);

    otlp_generic_span_t s;
    memset(&s, 0, sizeof s);
    for (int i = 0; i < 16; i++) s.trace_id[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 8; i++)  s.span_id[i]  = (uint8_t)(0xa0 + i);
    s.has_parent = false;
    s.start_unix_ns = 1789000000000000000ULL;
    s.end_unix_ns   = 1789000000001000000ULL;
    s.name = "file_open /etc/shadow";
    s.kind = 0;          /* INTERNAL */
    s.is_error = true;   /* deny -> Span.status=ERROR */
    s.attrs = attrs; s.nattrs = n;

    static uint8_t buf[8192];
    long blen = otlp_traces_generic_build(buf, sizeof buf, "spinel-e302-k8s", "0.1",
                                          "spinel-ebpf", &s);
    if (blen < 0) { fprintf(stderr, "encode failed\n"); return 1; }
    fwrite(buf, 1, (size_t)blen, stdout);
    return 0;
}
