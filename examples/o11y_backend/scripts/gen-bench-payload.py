#!/usr/bin/env python3
# Generate an ExportLogsServiceRequest textproto for benchmarking: N records
# per request (100 is a realistic OTLP batch), two resources, mixed severities,
# bodies and attributes. Encode with protoc as in gen-test-payload.sh.
#   python3 gen-bench-payload.py 100 > ../tests/payload_bench.textproto
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
services = [("api", 60), ("checkout", 40)]
sevs = [(9, "INFO", "request handled in %d ms"),
        (9, "INFO", "cache hit for key user:%d"),
        (13, "WARN", "slow upstream response %d ms"),
        (17, "ERROR", "connection timeout to db-%d"),
        (21, "FATAL", "payment failed for order %d")]
base = 1700000000_000_000_000

out = []
idx = 0
for svc, cnt in services:
    cnt = n * cnt // 100
    out.append("resource_logs {")
    out.append("  resource { attributes { key: \"service.name\" value { string_value: \"%s\" } }" % svc)
    out.append("             attributes { key: \"host.name\" value { string_value: \"bench-host\" } } }")
    out.append("  scope_logs {")
    for i in range(cnt):
        sev_num, sev_txt, body_fmt = sevs[(idx * 7) % len(sevs)]
        out.append("    log_records {")
        out.append("      time_unix_nano: %d" % (base + idx * 1_000_000))
        out.append("      severity_number: %d" % sev_num)
        out.append("      severity_text: \"%s\"" % sev_txt)
        out.append("      body { string_value: \"%s\" }" % (body_fmt % (idx * 13 % 977)))
        out.append("      attributes { key: \"http.status_code\" value { int_value: %d } }" % (200 + idx % 5))
        out.append("      attributes { key: \"thread.name\" value { string_value: \"worker-%d\" } }" % (idx % 8))
        out.append("    }")
        idx += 1
    out.append("  }")
    out.append("}")
print("\n".join(out))
