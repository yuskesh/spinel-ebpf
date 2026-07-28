/*
 * otlp_enrich.h -- the registry of attribute enrichers.
 *
 * After the span push funnel has assembled the attributes for a record, it calls
 * otlp_enrich_run() exactly once, and that applies every registered enricher in
 * turn. Each enricher has the same shape: add attributes if its preconditions
 * hold, otherwise return 0 and change nothing.
 *
 *   otlp_k8s   cgroup id      -> k8s.*                    (every signal)
 *   otlp_cri   cgroup id      -> k8s.container.name        (every signal; overwrites
 *                                                          the id the k8s enricher wrote)
 *   otlp_peer  peer address   -> peer.k8s.* /              (connection signal only,
 *                                network.peer.external      the one with a destination)
 *
 * Which signals an enricher applies to is declared by the signal_mask on its
 * registry entry, because it genuinely differs: the Kubernetes and CRI enrichers
 * apply everywhere, the peer one only where there is a destination address. The
 * funnel checks ctx->signal against the mask before calling.
 *
 * The funnel is last-writer-wins. An enricher that emits a key already present
 * replaces its value in place, keeping the original index and therefore the
 * attribute order; a new key is appended. That is how the CRI enricher can
 * replace the container id the Kubernetes enricher wrote with a real name. As
 * long as keys do not collide, the result is byte-identical to a plain append.
 *
 * Output order follows the order of the registry array (k8s, then cri, then
 * peer), and is kept stable on purpose: reordering attributes changes the bytes
 * on the wire, and the golden tests with them.
 *
 * A future enricher -- cloud metadata, say -- reaches every span path for its
 * signals by adding one line to that array.
 *
 * Pure C with no libbpf dependency, so it can be unit-tested on any host.
 */
#ifndef SPNL_OTLP_ENRICH_H
#define SPNL_OTLP_ENRICH_H

#include <stdint.h>
#include "otlp_http.h"   /* otlp_kv_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Which span path a record came from. Used to decide whether an enricher applies. */
typedef enum {
    OTLP_SIGNAL_CONN   = 0,   /* network connect span */
    OTLP_SIGNAL_DNS    = 1,   /* DNS query span */
    OTLP_SIGNAL_L7     = 2,   /* L7 request/response span */
    OTLP_SIGNAL_HTTP   = 3,   /* HTTP RED span */
    OTLP_SIGNAL_OFFCPU = 4,   /* off-CPU span, and the request-tree parent */
    OTLP_SIGNAL__COUNT = 5,
} otlp_signal_t;

/* The context handed to an enricher: only the inputs it can act on. */
typedef struct {
    otlp_signal_t signal;      /* which span path this came from */
    uint64_t      cgid;        /* cgroup id; 0 means none. Input to the k8s enricher. */
    const char   *peer_addr;   /* network.peer.address; NULL means none. Input to the peer enricher. */
} otlp_enrich_ctx_t;

/* One enricher. Fills out[0..cap) with attributes and returns how many it wrote;
 * 0 when it does not apply. */
typedef int (*otlp_enrich_fn)(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap);

typedef struct {
    const char    *name;         /* "k8s", "peer", ... -- for introspection and debugging */
    uint32_t       signal_mask;  /* bitmask of the signals it applies to (see OTLP_SIG_BIT) */
    otlp_enrich_fn enrich;
} otlp_enricher_t;

#define OTLP_SIG_BIT(s) (1u << (unsigned)(s))
#define OTLP_SIG_ALL    0xFFFFFFFFu

/* Apply every registered enricher to ctx, in order, skipping those whose
 * signal_mask excludes it, appending attributes into out[0..cap). Returns the
 * total number written. */
int otlp_enrich_run(const otlp_enrich_ctx_t *ctx, otlp_kv_t *out, int cap);

/* Introspection, for unit tests: how many are registered, and the i-th one
 * (NULL when i is out of range). */
int                    otlp_enrich_count(void);
const otlp_enricher_t *otlp_enrich_at(int i);

#ifdef __cplusplus
}
#endif
#endif /* SPNL_OTLP_ENRICH_H */
