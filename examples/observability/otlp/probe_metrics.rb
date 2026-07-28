# Attach an eBPF probe to an already-running process, observe it, and ship the
# result as OTLP metrics.
#
# A kprobe (system-wide here; it can also be filtered by pid) observes the
# latency of do_sys_openat2. Arbitrary labels (function / probe) are attached to
# series key 0 and pushed as OTLP metrics: openat_calls for the rate and
# openat_calls_latency_ns for the latency. This does not depend on --instrument
# -- it uses generic keyed metrics rather than the self-instrumentation method
# registry. Observing a function in a foreign binary with a pid-scoped uprobe
# goes through the same push path.
#
# build: bin/spinel-ebpf compile examples/observability/otlp/probe_metrics.rb --build -o build
# run:   OTLP_ENDPOINT=http://127.0.0.1:4318 PROBE_SECONDS=2 ./build/probe_metrics
module Otlp
  ffi_func :spnl_otlp_series_label, [:int, :str, :str], :int
  ffi_func :spnl_otlp_metric_push,  [:str, :str],       :int
end

def kprobe__do_sys_openat2(dfd, name)
  latency_start
end

def kretprobe__do_sys_openat2(ret)
  hist_observe_by(0, latency_end)
end

ep   = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i

# Labels for series key 0. These are arbitrary -- function, pid, comm, whatever.
Otlp.spnl_otlp_series_label(0, "function", "do_sys_openat2")
Otlp.spnl_otlp_series_label(0, "probe", "kprobe")
puts "[probe] observing do_sys_openat2 -> OTLP " + ep + " every " + secs.to_s + "s"

loop do
  sleep secs
  st = Otlp.spnl_otlp_metric_push("openat_calls", ep)
  puts "[probe] openat_calls pushed -> " + ep + " HTTP " + st.to_s
end
