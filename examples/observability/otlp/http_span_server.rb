# HTTP server span plus W3C traceparent propagation.
#
# A spinel-compiled HTTP/1.0 server, native and independent of eBPF. On each
# request it:
#   1. extracts traceparent from the incoming headers -- continuing that trace if
#      it is present, starting a new one if it is not
#   2. measures the wall clock either side of the handler
#   3. sends a SERVER span (http.request.method / url.path /
#      http.response.status_code) as OTLP traces
#
# build: bin/spinel-ebpf compile examples/observability/otlp/http_span_server.rb --build -o build
# run:   OTLP_ENDPOINT=http://127.0.0.1:4318 SPINEL_HTTP_PORT=8080 ./build/http_span_server
# test:  curl -H 'traceparent: 00-<32hex>-<16hex>-01' http://127.0.0.1:8080/hello
module Net
  ffi_func :sp_net_listen,    [:int, :int], :int
  ffi_func :sp_net_accept,    [:int],       :int
  ffi_func :sp_net_read_line, [:int],       :str
  ffi_func :sp_net_write_str, [:int, :str], :int
  ffi_func :sp_net_rl_close,  [:int],       :int
end

module Otlp
  ffi_func :spnl_otlp_now_unix_ns,        [],                                                 :int
  # Derives the server and client addresses from the fd, and takes the route
  # (used as the span name and as http.route).
  ffi_func :spnl_otlp_http_span_fd,       [:int, :str, :str, :str, :str, :int, :int, :int, :str], :int
  # Pushes the accumulated http.server.request.duration, in seconds, using the
  # same bucket boundaries as the OpenTelemetry eBPF instrumentation.
  ffi_func :spnl_otlp_http_metrics_push,  [:str],                                             :int
end

# Returns a low-cardinality route, used as the span name, as the http.route
# attribute, and as the key of the duration metric.
def route_for(path)
  if path == "/hello"
    "/hello"
  else
    "/other"
  end
end

def build_response(status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: text/plain\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Connection: close\r\n" +
  "\r\n" +
  body
end

# Reads headers up to the blank line and returns the traceparent value, or ""
# if there is none.
def read_headers_traceparent(fd)
  tp = ""
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
    parts = line.split(": ")
    if parts.length >= 2 && parts[0] == "traceparent"
      tp = parts[1]
    end
  end
  tp
end

port = (ENV["SPINEL_HTTP_PORT"] || "8080").to_i
endpoint = ENV["OTLP_ENDPOINT"] || "http://127.0.0.1:4318"
listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[span-server] listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[span-server] HTTP/1.0 on 127.0.0.1:" + port.to_s + " -> OTLP " + endpoint

loop do
  client = Net.sp_net_accept(listen_fd)
  break if client < 0

  t0 = Otlp.spnl_otlp_now_unix_ns
  line = Net.sp_net_read_line(client)
  parts = line.split(" ")
  verb = parts[0]
  path = parts[1]
  tp = read_headers_traceparent(client)
  route = route_for(path)

  Net.sp_net_write_str(client, build_response("200 OK", "hello\n"))
  t1 = Otlp.spnl_otlp_now_unix_ns

  # Build the span before closing the client, so getsockname/getpeername can
  # still derive the server and client addresses.
  st = Otlp.spnl_otlp_http_span_fd(client, tp, verb, path, route, 200, t0, t1, endpoint)
  Net.sp_net_rl_close(client)
  # Push http.server.request.duration (a cumulative Histogram) once per request.
  Otlp.spnl_otlp_http_metrics_push(endpoint)
  puts "[span-server] " + verb + " " + path + " route=" + route + " tp=[" + tp + "] -> otlp HTTP " + st.to_s
end

Net.sp_net_rl_close(listen_fd)
