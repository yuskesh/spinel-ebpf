/*
 * otlp_logs.h -- turn emitted events into OTLP logs (LogRecord)
 *
 * Each event in an emit ringbuf (spnl_emit writes <unit>_events, spnl_emit_str
 * writes <unit>_str_events) becomes exactly one LogRecord, whose body is either
 * an integer or a string. The encoding here has no libbpf dependency, so it can
 * be unit-tested on any host; draining the ringbuf is otlp_agent's job.
 */
#ifndef SPNL_OTLP_LOGS_H
#define SPNL_OTLP_LOGS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t    time_unix_ns;  /* wall-clock (ktime + offset) */
    int32_t     severity;      /* OTLP SeverityNumber; 0 means the INFO (9) default */
    bool        body_is_str;
    const char *body_str;      /* used when body_is_str */
    int64_t     body_int;      /* used otherwise */
    const char *event_name;    /* omitted when NULL */
} otlp_log_record_t;

/* Build an OTLP ExportLogsServiceRequest from records. Returns the byte count
 * written, or -1 on failure. */
long otlp_logs_build(uint8_t *buf, size_t cap,
                     const char *service_name, const char *service_version,
                     const char *scope_name,
                     const otlp_log_record_t *recs, size_t nrecs);

#ifdef __cplusplus
}
#endif

#endif /* SPNL_OTLP_LOGS_H */
