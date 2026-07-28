# Send an audit record (verdict, path, lineage) to Splunk Observability Cloud as
# an OTLP span.
#
# Splunk Observability Cloud cannot take OTLP logs directly: it exposes no logs
# endpoint and the native Log Observer was retired. So if you want the audit
# record to go *straight* to Splunk O11y and be visible in APM / Trace Analyzer,
# expressing it as a span (traces) is the only route. This example sends
# "the child Y of parent X opened file Z, with this verdict" as one span.
#
# Where the data comes from in production: the path from emit_path and the
# parent lineage from parent_path_eq / ppid are read in the kernel by the LSM
# file_open hook, and userspace puts those values into span attributes. That is
# a userspace join and needs no codegen change. This example demonstrates the
# wire path only, so it passes representative values in directly; wiring it to
# the drained kernel emit is the same kind of userspace join.
#
# Attributes, with standard and own keys called out:
#   process.executable.path        (semconv v1.37.0) ... the executable that opened it
#   file.path                      (semconv v1.37.0) ... the target file
#   process.parent.executable.path (**own key**; semconv only has
#                                   process.parent_pid) ... the parent
#   verdict                        (**own key**; allow/deny)
# A span with deny=1 gets Span.status=ERROR, which APM colours red.
#
# ── Build & send (straight to Splunk) ────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_span_demo.rb --build -o build/audit_span
#   OTEL_SERVICE_NAME=spinel-audit-span \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_span/audit_span_demo
#   # Then in the APM Trace Analyzer, filter on service.name=spinel-audit-span
#   # and on file.path.

module Otlp
  ffi_func :spnl_otlp_now_unix_ns, [], :int
  # (traceparent, exe, parent_exe, file, verdict, deny, t0, t1, endpoint) -> HTTP status
  ffi_func :spnl_otlp_audit_file_span,
           [:str, :str, :str, :str, :str, :int, :int, :int, :str], :int
end

ep = ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
     ENV["OTLP_ENDPOINT"] ||
     "http://127.0.0.1:4318"

# (1) deny: /bin/cat, a child of /usr/sbin/nginx, tried to open /etc/shadow and
#     was refused -- a deny keyed on the parent's executable path.
t0 = Otlp.spnl_otlp_now_unix_ns
t1 = Otlp.spnl_otlp_now_unix_ns
st1 = Otlp.spnl_otlp_audit_file_span(
  "", "/bin/cat", "/usr/sbin/nginx", "/etc/shadow", "deny", 1, t0, t1, ep)
puts "[audit-span] deny  file_open /etc/shadow (parent=/usr/sbin/nginx) -> HTTP " + st1.to_s

# (2) allow (observe): an ordinary httpd opened /var/www/index.html -- recorded only.
t2 = Otlp.spnl_otlp_now_unix_ns
t3 = Otlp.spnl_otlp_now_unix_ns
st2 = Otlp.spnl_otlp_audit_file_span(
  "", "/usr/sbin/httpd", "/sbin/init", "/var/www/index.html", "allow", 0, t2, t3, ep)
puts "[audit-span] allow file_open /var/www/index.html -> HTTP " + st2.to_s
