/*
 * otlp_audit_span_test.c -- wire verification of the audit span
 * (spnl_otlp_audit_file_span). Turns a denied file access into a span, sends it to
 * the endpoint, and lets the mock receiver plus protoc recover the attributes:
 *   span name "file_open /etc/shadow", kind=INTERNAL,
 *   process.executable.path / process.parent.executable.path / file.path / verdict,
 *   deny=1 -> Span.status=STATUS_CODE_ERROR.
 * Usage: otlp_audit_span_test <endpoint>   (the mock receiver asserts on the decode)
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "otlp_httpspan.h"

int main(int argc, char **argv) {
    const char *endpoint = (argc > 1) ? argv[1] : "http://127.0.0.1:4318";
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t t0 = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;

    int st = spnl_otlp_audit_file_span(
        "" /* new trace */,
        "/bin/cat", "/usr/sbin/nginx", "/etc/shadow", "deny", 1 /* deny */,
        t0, t0 + 8000000ull, endpoint);

    printf("audit span HTTP status = %d\n", st);
    return (st == 200) ? 0 : 1;
}
