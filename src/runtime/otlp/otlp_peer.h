/*
 * otlp_peer.h -- enricher that resolves a connection span's destination
 * (network.peer.address) to a pod, a Service, or something outside the cluster.
 *
 * A connection span only knows the address and port it dialled. Here userspace
 * turns that address into a Kubernetes identity:
 *   - internal pod      in the pod CIDR and present in the IP map ->
 *                       peer.k8s.pod.name / peer.k8s.namespace.name
 *   - internal Service  in the service CIDR and present in the IP map ->
 *                       peer.k8s.service.name / peer.k8s.namespace.name
 *   - external          in no cluster CIDR -> network.peer.external=true, plus a
 *                       best-effort peer.hostname
 *   - loopback, or inside the cluster but unnamed: no identity, and no attributes
 *                       are added -- an honest no-op
 *
 * Measured on a real cluster: for an active connection from a pod to a ClusterIP
 * Service, network.peer.address is the ClusterIP, not the backing pod's address.
 * Resolving that therefore needs the service CIDR and a ClusterIP-to-Service map.
 * Pod-to-pod carries the pod address, and pod-to-outside the raw external one.
 *
 * This is a userspace join: no code generation changes, no change to the
 * connection record layout, and not one character of the probe. Without its
 * preconditions -- SPNL_K8S_IPMAP unset, so not Kubernetes, or no map at all --
 * it is a complete no-op and the span is byte-identical to one produced without
 * any enricher at all.
 *
 * Configuration (environment; a static snapshot taken from kubectl at start-up):
 *   SPNL_K8S_IPMAP     lines of "ip kind ns name", where kind is pod or service.
 *                      Its presence is what gates resolution.
 *   SPNL_K8S_POD_CIDR  for example "10.42.0.0/16"; a k3s default is assumed when unset
 *   SPNL_K8S_SVC_CIDR  for example "10.43.0.0/16"; likewise
 *   SPNL_K8S_PEER_RDNS "1" enables reverse lookup of external addresses into
 *                      peer.hostname. Off by default, and cached when on.
 *
 * Pure C with no libbpf dependency, so it can be unit-tested on any host.
 */
#ifndef SPNL_OTLP_PEER_H
#define SPNL_OTLP_PEER_H

#include <stdint.h>
#include "otlp_http.h"   /* otlp_kv_t */

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SPNL_PEER_NONE     = 0,  /* not classified; no attributes */
    SPNL_PEER_POD      = 1,  /* in the pod CIDR and present in the map */
    SPNL_PEER_SERVICE  = 2,  /* in the service CIDR and present in the map */
    SPNL_PEER_EXTERNAL = 3,  /* outside every cluster CIDR */
    SPNL_PEER_LOOPBACK = 4,  /* 127.0.0.0/8 / ::1 */
    SPNL_PEER_CLUSTER  = 5,  /* inside a cluster CIDR but unnamed in the map (a node gateway, say) */
};

typedef struct {
    int  kind;
    char address[46];      /* the address as text, with any ::ffff: prefix stripped */
    char namespace_[128];  /* namespace of the pod or Service */
    char name[256];        /* pod name, or Service name */
    char hostname[256];    /* external peers only: best-effort reverse lookup, empty on failure */
} spnl_peer_t;

/* Classify a network.peer.address string, returning its kind. Always
 * SPNL_PEER_NONE when SPNL_K8S_IPMAP is unset. */
int spnl_peer_classify(const char *addr, spnl_peer_t *out);

/* Fill attrs[] from a resolved peer, skipping empty values, and return how many
 * were written. */
int spnl_peer_fill_attrs(const spnl_peer_t *p, otlp_kv_t *attrs, int max);

/* Convenience wrapper doing classify and fill for one address, returning how many
 * attributes were written. Returns 0 -- leaving the span unchanged -- when
 * SPNL_K8S_IPMAP is unset or addr is empty. */
int spnl_peer_enrich_attrs(const char *addr, otlp_kv_t *attrs, int max);

#ifdef __cplusplus
}
#endif
#endif /* SPNL_OTLP_PEER_H */
