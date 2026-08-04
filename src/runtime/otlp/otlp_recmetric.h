/*
 * otlp_recmetric.h -- from a record channel to OTLP metrics
 *
 * A ringbuf record has always been read one way here: one record is one span. A
 * span is the shape of "what happened this once", not the shape of "how often,
 * and how long did it take". The second shape is a metric, and its declaration
 * is CcRecMetric in src/codegen_c/record_schema.h.
 *
 * This is the runtime side of that declaration:
 *   - spnl_recmetric_observe()        -- fold one drained record into the
 *                                        aggregate (the generated
 *                                        spnl_recmetric_observe_<ch>() calls it)
 *   - spnl_otlp_record_metrics_push() -- send the aggregate as OTLP metrics
 *                                        (reached over FFI from Ruby)
 *
 * The number of series is proven by the declaration. The generator multiplies
 * and sums the series bound of every declared metric, and refuses to compile a
 * set of declarations whose total exceeds SPNL_RECMETRIC_MAX_SERIES, so the
 * array below cannot overflow. Unlike the hand-written accumulator in
 * otlp_httpspan.c -- capped at 64, warning about and discarding the 65th --
 * there is no runtime decision to make about a series that does not fit.
 */
#ifndef SPNL_OTLP_RECMETRIC_H
#define SPNL_OTLP_RECMETRIC_H

#ifdef __cplusplus
extern "C" {
#endif

/* Called by the generated intake. `metric` indexes the generated table
 * spnl_recmetrics[] (the SPNL_RECMETRIC_<CH>_<ID> macros). label_values are the
 * raw renderings in declaration order -- projecting them onto the declared set,
 * so that a value outside it becomes the fallback, happens here and only here. */
void spnl_recmetric_observe(int metric, const char *const *label_values,
                            int nlabels, int has_value, double value);

/* Send the aggregate over OTLP/HTTP (or gRPC, or JSON), one POST per metric.
 * Returns the HTTP status of the last POST, 0 if there was nothing to send, and
 * -1 on failure. */
int spnl_otlp_record_metrics_push(const char *endpoint);

/* How many time series are held right now, for tests and diagnostics. */
int spnl_recmetric_series_count(void);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_RECMETRIC_H */
