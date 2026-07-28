/*
 * otlp_metric.h -- OTLP export for generic keyed metrics, independent of --instrument
 *
 * Any probe (including one that watches an existing process through a kprobe or
 * uprobe) can accumulate a per-key log2 latency histogram with
 * `hist_observe_by(key, val)`. Each key can then be labelled freely -- by
 * function, pid, comm, whatever the probe chose -- and exported as OTLP metrics:
 * a Sum for the rate and an ExponentialHistogram for the latency. None of this
 * goes through the auto-instrumentation method registry in otlp_agent.c. Reading
 * the bpf map means this depends on libbpf, so it is for eBPF programs only.
 */
#ifndef SPNL_OTLP_METRIC_H
#define SPNL_OTLP_METRIC_H

#include <stdint.h>

struct bpf_object;

#ifdef __cplusplus
extern "C" {
#endif

/* Attach one label to a series (a histogram key). Call it repeatedly to attach
 * several labels to the same key. Returns 0 on success, -1 on failure. */
int spnl_otlp_series_label(uint64_t key, const char *label_key, const char *label_val);

/* Read the registered series out of hist_map (a keyed histogram map) and push
 * them to endpoint as metric_name (a Sum) plus "<metric_name>_latency_ns" (an
 * ExponentialHistogram). Returns the HTTP status, or -1 on failure. */
int spnl_otlp_metric_push_obj(struct bpf_object *obj, const char *hist_map,
                              const char *metric_name, const char *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_METRIC_H */
