# A one-shot observation probe for incident response -- uprobe an already-running
# process and send its RED metrics straight to Splunk.
#
# Temporarily inject an eBPF probe into a production process that is misbehaving,
# with no resident agent and no redeploy, and send the call rate and latency (RED)
# of the target function as OTLP metrics. When you have seen enough, Ctrl-C
# removes it. No Collector is needed either -- it can go straight to Splunk
# Observability Cloud.
#
#   uprobe/uretprobe   ... hook the entry and exit of a function in the target
#                          binary (handle_request below). The binary and the PID
#                          are chosen at run time by environment variable:
#                            SPNL_UPROBE_BINARY=/path/to/target  (required)
#                            SPNL_UPROBE_PID=<pid>               (optional,
#                                            default -1 = system-wide)
#                          The function name observed is fixed by the suffix of
#                          uprobe__; watching a different function means
#                          recompiling.
#   latency_start/end  ... entry-to-exit delta, keyed by tid.
#   hist_observe_by(0) ... accumulate the latency in the log2 keyed histogram at
#                          series key 0. Being a histogram, it cannot overflow.
#   spnl_otlp_series_label / spnl_otlp_metric_push ... label series 0 and turn it
#                          into OTLP metrics.
#
# ── Build (inside the container) ─────────────────────────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/incident_probe.rb --build -o build/incident
#
# ── Sending straight to Splunk (in practice: look quickly, then stop) ─────
#   # Build it static, scp it to the target host, and send to the SaaS backend
#   # with no Collector in between:
#   SPNL_STATIC=1 bin/spinel-ebpf compile examples/observability/otlp/incident_probe.rb --build -o build/incident
#   scp build/incident/incident_probe user@prod-host:/tmp/
#   ssh user@prod-host \
#     'SPNL_UPROBE_BINARY=/usr/bin/myapp \
#      OTLP_ENDPOINT=https://ingest.us1.signalfx.com \
#      OTEL_EXPORTER_OTLP_HEADERS="x-sf-token=$SPLUNK_TOKEN" \
#      OTEL_EXPORTER_OTLP_COMPRESSION=gzip \
#      sudo -E /tmp/incident_probe'
#   # incident_calls (a rate) and incident_calls_latency_ns (an
#   # ExponentialHistogram) then flow to Splunk labelled {function, target}.
#   # Put it in place, look, take it away.
#   # For a permanent production deployment, go through a Collector. Sending
#   # directly is meant for short incident investigations.

module Otlp
  ffi_func :spnl_otlp_series_label, [:int, :str, :str], :int
  ffi_func :spnl_otlp_metric_push,  [:str, :str],       :int
end

# Entry and exit of the target function. The demo verifies against a C
# handle_request(). To observe a different function, change the suffix of these
# method names (after uprobe__ / uretprobe__) and recompile.
def uprobe__handle_request(arg0)
  latency_start
end

def uretprobe__handle_request(ret)
  hist_observe_by(0, latency_end)
end

ep     = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
secs   = (ENV["PROBE_SECONDS"] || "2").to_i
target = ENV["SPNL_UPROBE_BINARY"] || "unknown"

# Attach the RED labels to series key 0. They become attributes on the OTLP data point.
Otlp.spnl_otlp_series_label(0, "function", "handle_request")
Otlp.spnl_otlp_series_label(0, "target", target)
puts "[incident] observing handle_request in " + target + " -> OTLP " + ep + " every " + secs.to_s + "s"

loop do
  sleep secs
  st = Otlp.spnl_otlp_metric_push("incident_calls", ep)
  puts "[incident] incident_calls pushed -> " + ep + " HTTP " + st.to_s
end
