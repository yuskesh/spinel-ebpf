/*
 * otlp_k8s.h -- resolve a cgroup id to the Kubernetes pod that owns it.
 *
 * The kernel side emits bpf_get_current_cgroup_id() -- the inode of the cgroup
 * directory -- through the cgroup_id() builtin. Here userspace turns that into a
 * pod and puts the semconv k8s.* attributes on the span: k8s.pod.uid,
 * k8s.pod.name, k8s.namespace.name and k8s.container.name. That is what makes
 * "which process in which pod did this" searchable in an APM backend.
 *
 * It is a userspace join; no generated code changes. The resolution path is:
 *   cgroup id (inode) --walk /sys/fs/cgroup/kubepods--> .../pod<UID>/<container-id>
 *                     --parse the path-->              {qos, pod_uid, container_id}
 *   pod_uid --uid map, a file of "uid ns/name" lines from `kubectl get pods`-->
 *                                                      {namespace, pod_name}
 *
 * This parses the cgroupfs driver layout, kubepods/<qos>/pod<UID>/<id>, which is
 * what k3s uses by default. The systemd layout
 * (kubepods.slice/...-pod<UID>.slice/cri-containerd-<id>.scope) is not handled
 * here. Resolving a container id to its real name is the CRI enricher's job
 * (otlp_cri.h); on its own this fills k8s.container.name with the id.
 *
 * Pure C with no libbpf dependency, so it can be unit-tested on any host.
 */
#ifndef SPNL_OTLP_K8S_H
#define SPNL_OTLP_K8S_H

#include <stdint.h>
#include "otlp_http.h"   /* otlp_kv_t */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char pod_uid[40];        /* the UID out of pod<UID>, with dashes normalised */
    char container_id[68];   /* the container cgroup directory name (the CRI container id) */
    char qos[16];            /* besteffort / burstable / guaranteed */
    char namespace_[128];    /* from the uid map; empty when unresolved */
    char pod_name[256];      /* from the uid map; empty when unresolved */
    char deployment[256];    /* owning workload (a Deployment, say): uid map column 3, else empty */
    char service[256];       /* the Service selecting this pod: uid map column 4, else empty */
    int  found;              /* 1 when the path parsed as a kubepods pod/container path */
} spnl_k8s_pod_t;

/* Extract {qos, pod_uid, container_id} from a kubepods cgroup path, for example
 * /sys/fs/cgroup/kubepods/burstable/pod<UID>/<container-id>. A pod directory with
 * no container component still returns 1, leaving container_id empty. Returns 0
 * for a path that is not under kubepods. */
int spnl_k8s_parse_kubepods_path(const char *cgroup_path, spnl_k8s_pod_t *out);

/* Walk cgroup_root (normally "/sys/fs/cgroup") looking for the directory whose
 * inode is cgid, then parse that path. Returns 1 when found. Linux only: it needs
 * a mounted cgroup filesystem. */
int spnl_k8s_lookup_by_cgroup_id(uint64_t cgid, const char *cgroup_root, spnl_k8s_pod_t *out);

/* Resolve pod_uid through a uid map file produced from kubectl. Two line formats
 * are accepted, the second a backward-compatible extension of the first:
 *   "<uid> <namespace>/<name>"
 *   "<uid> <namespace>/<name> <deployment> <service>"
 * On a match it fills p->namespace_ and p->pod_name (and deployment/service when
 * present) and returns 1. A third or fourth column of "-" or empty leaves that
 * field empty, and no attribute is added for it. */
int spnl_k8s_resolve_name(spnl_k8s_pod_t *p, const char *uidmap_file);

/* Fill attrs[] with the semconv k8s.* attributes of a resolved pod, skipping
 * empty values, and return how many were written. The keys are k8s.pod.uid,
 * k8s.pod.name, k8s.namespace.name and k8s.container.name, plus
 * k8s.deployment.name and k8s.service.name when the uid map supplied them. */
int spnl_k8s_fill_attrs(const spnl_k8s_pod_t *p, otlp_kv_t *attrs, int max);

/* Convenience wrapper doing lookup, resolve and fill for a single cgroup id, and
 * returning how many attributes were written. cgroup_root and uidmap_file may be
 * NULL: the first defaults to "/sys/fs/cgroup", and a NULL second skips name
 * resolution. */
int spnl_k8s_enrich_attrs(uint64_t cgid, const char *cgroup_root,
                          const char *uidmap_file, otlp_kv_t *attrs, int max);

#ifdef __cplusplus
}
#endif
#endif /* SPNL_OTLP_K8S_H */
