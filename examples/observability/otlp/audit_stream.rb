# Kernel audit stream -> OTLP logs, with Splunk as the SIEM.
#
# Streams security audit events that originate in the kernel, and are therefore
# hard to tamper with, to a SIEM as OTLP logs (LogRecord). Unlike userspace logs,
# these are observed directly by eBPF at a kernel hook, so they are not affected
# by an application dropping or rewriting its own log lines. Two sources are
# funnelled into a single string ringbuffer:
#
#   (a) LSM file_open      ... emit_comm publishes the comm of the process that
#                              opened a file. LSM can enforce as well as observe:
#                              returning a non-zero value denies the open. This
#                              demo is for auditing, so it returns 0 (allow) and
#                              only observes.
#   (b) tracepoint execve  ... spnl_emit_str(filename) publishes the path of the
#                              program being executed. "What was exec'd" is a
#                              low-noise SIEM signal.
#
# Both pile into the per-unit string ringbuffer (<unit>_str_events), and
# spnl_otlp_log_push_str drains it, turns each entry into an OTLP LogRecord with
# a string body, and pushes it.
#
# Note: for LSM file_open to actually fire, the kernel must have been booted with
# bpf in its lsm= list. On a kernel without it the program loads but never fires.
#
# ── Build (inside the container) ─────────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_stream.rb --build -o build/audit
#   SPNL_CGROUP_PATH=/sys/fs/cgroup ./build/audit/audit_stream   # LSM/tracepoint attach automatically
#
# ── Where it sends (OTLP logs) ───────────────────────────────────────────
#   Straight to a standard OTLP Collector (`/v1/logs`): the comm and the exec path
#   arrive in resourceLogs[].logRecords[].body.
#     OTLP_ENDPOINT=http://<collector>:4318  ./build/audit/audit_stream
#
#   Measured: **OTLP logs cannot be sent directly to Splunk Observability Cloud**.
#   Direct ingest there covers traces (/v2/trace/otlp) and metrics
#   (/v2/datapoint/otlp) only; there is no logs endpoint (/v1/logs and the other
#   candidates all return 404), and the native Log Observer was retired in
#   January 2024 (today's Log Observer Connect only *references* logs already in
#   Splunk Platform). Getting logs into Splunk requires an OTel Collector to
#   convert OTLP to HEC and then Splunk Platform HEC -- we only emit OTLP, so a
#   Collector is a prerequisite. If you want the audit to go *straight* to Splunk
#   Observability Cloud, express it as traces (spans) instead; APM displays those.
#   # For now the body is a single value, either the comm or the path. Splitting
#   # the event kind out into an attribute is future work.

module Otlp
  ffi_func :spnl_otlp_log_push_str, [:str], :int
end

# (a) Who (comm) opened which file (full path). Returns allow (0) and only observes.
#     emit_path uses bpf_d_path to resolve the full path from a `struct file *`.
#     Without it only the comm is available, which tells you no more than
#     "cat opened something".
def lsm__file_open(file, ret)
  emit_comm
  emit_path(file)
  0
end

# (b) What was exec'd (the executable path). execve's first argument, filename,
#     is a userspace pointer.
def tracepoint__syscalls__sys_enter_execve(filename, argv, envp)
  spnl_emit_str(filename)
end

ep   = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit] kernel security events (file_open comm + execve path) -> OTLP logs " + ep + " every " + secs.to_s + "s"

loop do
  sleep secs
  st = Otlp.spnl_otlp_log_push_str(ep)
  puts "[audit] audit logs pushed -> " + ep + " HTTP " + st.to_s
end
