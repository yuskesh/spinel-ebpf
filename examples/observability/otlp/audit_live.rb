# Live audit span: send the real path and the real parent of an actual LSM
# file_open straight to Splunk APM.
#
# The sibling audit_span_demo.rb passes representative values in as constants to
# prove out the wire path. This example instead takes the path, the executable
# name and the parent's executable path of a **file_open that really happened**
# from eBPF (the LSM file_open hook), and assembles the span in userspace. Only
# emit_parent_path is new in codegen; the rest is userspace assembly.
#
# In the LSM file_open hook, for opens performed by a process whose comm matches
# the marker "spnlaud" (this probe), three records go into the str ringbuf in a
# fixed order:
#   emit_path(file)     -> file.path                      (semconv, the file opened)
#   emit_comm           -> process.executable.name        (semconv, the process comm)
#   emit_parent_path    -> process.parent.executable.path (own key, real parent path)
# The hook observes only -- it returns allow (0) and records.
#
# Userspace drains the ringbuf with spnl_otlp_audit_span_push and folds each
# triple of records into one span. The span timestamp comes from the real ktime
# in the record header converted to unix time. Passing the timestamp through an
# :int FFI boundary would truncate the nanoseconds and land the span in 1970, so
# the conversion happens in C.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_live.rb --build -o build/audit_live
#   OTEL_SERVICE_NAME=spinel-file-audit \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_live/audit_live
#   # Audit spans for files opened by a process with the marker comm "spnlaud"
#   # appear in APM. In another terminal, running something like
#   # `exec -a spnlaud cat /etc/hostname` turns that real open into a span.

module Otlp
  ffi_func :spnl_otlp_audit_span_push, [:str], :int
end

@events = 0

def lsm__file_open(file, ret)
  if comm_hash == 28276558962520179   # "spnlaud" LE — the comm this probe watches
    @events = @events + 1
    emit_path(file)        # file.path
    emit_comm              # process.executable.name
    emit_parent_path       # process.parent.executable.path
  end
  0                        # observe: allow (record only, never deny)
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-live] LSM file_open (marker comm spnlaud) -> OTLP audit span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_audit_span_push(ep)
  puts "[audit-live] audit spans pushed -> " + ep + " HTTP " + st.to_s
end
