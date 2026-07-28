/*
 * otlp_cri.h -- enricher that resolves a cgroup id to its CRI container name
 *
 * The Kubernetes enricher resolves a cgroup id to a pod, but it has no way to ask
 * the container runtime for a name, so it fills `k8s.container.name` with the raw
 * container id (a hex string). This enricher reads a static snapshot of
 * cgroup-id-to-container-name pairs, collected from crictl when the run starts,
 * and rewrites that attribute to the real name -- coredns, local-path-provisioner,
 * and so on. Attributes are applied last-writer-wins, so this overwrites the id
 * the Kubernetes enricher put there.
 *
 * This is a userspace-only join: no code generation changes, no change to the
 * record layout, and not one character of the probe. When the preconditions are
 * not met -- SPNL_K8S_CRIMAP unset (so, not Kubernetes), no map, or a cgroup id
 * that is absent from it -- it is a complete no-op and `k8s.container.name` keeps
 * the container id, byte for byte what the other enrichers produce on their own.
 *
 * Configuration (environment; a static snapshot taken from crictl at start-up):
 *   SPNL_K8S_CRIMAP  lines of "<cgid> <container_name>", where cgid is the leaf
 *                    cgroup inode in decimal. Its presence is what gates
 *                    resolution, the same way the uid and ip maps gate theirs.
 *
 * It applies to every signal that can carry a cgroup id from a process context;
 * the registry declares that through a signal mask. Pure C with no libbpf
 * dependency, so it can be unit-tested on any host.
 */
#ifndef SPNL_OTLP_CRI_H
#define SPNL_OTLP_CRI_H

#include <stdint.h>
#include "otlp_http.h"   /* otlp_kv_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve cgid to a container name through the CRI map. Returns 1 and fills
 * name_out when found, 0 when not. Always 0 when SPNL_K8S_CRIMAP is unset. */
int spnl_cri_lookup(uint64_t cgid, char *name_out, int cap);

/* Convenience wrapper: fill attrs with k8s.container.name for one cgid, returning
 * how many attributes were written (0 or 1). Returns 0 -- leaving the span
 * unchanged -- when SPNL_K8S_CRIMAP is unset, cgid is 0, the id is absent from the
 * map, or cap is not positive. */
int spnl_cri_enrich_attrs(uint64_t cgid, otlp_kv_t *attrs, int max);

#ifdef __cplusplus
}
#endif
#endif /* SPNL_OTLP_CRI_H */
