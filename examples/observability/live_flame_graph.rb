# Live on-CPU flame graph in the browser. One spinel-ebpf binary
# does everything:
#   1. 99 Hz on-CPU perf_event sampler + stack capture +
#      keyed log2 hist
#   2. HTTP/1.0 server on port 8080
#   3. `GET /folded` returns current folded stacks streamed
#      directly into the client TCP socket
#   4. `GET /` returns an HTML page with d3-flame-graph (loaded from CDN)
#      that polls /folded every 2 seconds and re-renders
#
# Build:
#   bin/spinel-ebpf compile examples/observability/live_flame_graph.rb \
#                   -o build/live --build
# Run:
#   ./build/live/live_flame_graph &
#   # CPU load:
#   for i in 1 2 3 4 5; do
#     dd if=/dev/zero of=/dev/null bs=1M count=200000 &
#   done
#   # open http://localhost:8080/ in a browser

module LiveProfile
  include BPF::EventLoop
  on :perf_event, hz: 99 do
    sid = stack_id
    hist_observe_by(sid, 1) if sid >= 0
  end
end

module Net
  ffi_func :sp_net_listen,     [:int, :int],    :int
  ffi_func :sp_net_accept,     [:int],          :int
  ffi_func :sp_net_read_line,  [:int],          :str
  ffi_func :sp_net_write_str,  [:int, :str],    :int
  ffi_func :sp_net_rl_close,      [:int],          :int
end

module FG
  ffi_func :spnl_dump_folded_to_fd, [:str, :str, :int], :int
end

# The HTML page is a self-contained d3-flame-graph viewer that polls
# /folded every 2 seconds, parses the folded format into a tree, and
# re-renders the flame graph in place. Uses jsdelivr CDN for d3 + the
# flame-graph plugin so no local web asset wrangling.
HTML = <<~HTML
  <!DOCTYPE html>
  <html lang="en">
  <head>
  <meta charset="utf-8">
  <title>spinel-ebpf live flame graph</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.css">
  <style>
    body { font-family: -apple-system, sans-serif; padding: 20px; background: #fafafa; }
    h1 { font-size: 18px; }
    #meta { color: #666; font-size: 12px; margin-bottom: 8px; }
    #chart { background: white; border: 1px solid #ddd; padding: 8px; }
  </style>
  </head>
  <body>
  <h1>spinel-ebpf live on-CPU flame graph</h1>
  <div id="meta">refresh: 2s &middot; <span id="status">loading…</span></div>
  <div id="chart"></div>
  <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.min.js"></script>
  <script>
    function parseFolded(text) {
      const root = { name: "all", value: 0, children: [] };
      for (const raw of text.split("\\n")) {
        const line = raw.trim();
        if (!line) continue;
        const sp = line.lastIndexOf(" ");
        if (sp < 0) continue;
        const frames = line.slice(0, sp).split(";");
        const count = parseInt(line.slice(sp + 1), 10);
        if (!Number.isFinite(count) || count <= 0) continue;
        root.value += count;
        let node = root;
        for (const frame of frames) {
          if (!frame) continue;
          let child = node.children.find(c => c.name === frame);
          if (!child) { child = { name: frame, value: 0, children: [] }; node.children.push(child); }
          child.value += count;
          node = child;
        }
      }
      return root;
    }
    const chart = flamegraph().width(1200).cellHeight(18)
                              .transitionDuration(250).sort(true)
                              .inverted(false);
    let mounted = false;
    async function refresh() {
      const t0 = Date.now();
      try {
        const r = await fetch("/folded", { cache: "no-store" });
        const text = await r.text();
        const tree = parseFolded(text);
        if (!mounted) { d3.select("#chart").datum(tree).call(chart); mounted = true; }
        else { chart.update(tree); }
        const ms = Date.now() - t0;
        document.getElementById("status").textContent =
          "samples=" + tree.value + " stacks=" + tree.children.length +
          " (fetched in " + ms + "ms)";
      } catch (e) {
        document.getElementById("status").textContent = "error: " + e;
      }
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
  </body>
  </html>
HTML

# Minimal HTTP/1.0 request parser — enough for "GET /path HTTP/1.0".
def parse_path(line)
  # line looks like "GET /folded HTTP/1.0"
  parts = line.split(" ")
  if parts.length >= 2
    parts[1]
  else
    "/"
  end
end

def drain_headers(fd)
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
  end
end

def write_status(client, status, content_type, content_length)
  Net.sp_net_write_str(client, "HTTP/1.0 " + status + "\r\n")
  Net.sp_net_write_str(client, "Content-Type: " + content_type + "\r\n")
  if content_length >= 0
    Net.sp_net_write_str(client, "Content-Length: " + content_length.to_s + "\r\n")
  end
  Net.sp_net_write_str(client, "Connection: close\r\n")
  Net.sp_net_write_str(client, "\r\n")
end

port = (ENV["SPINEL_HTTP_PORT"] || "8080").to_i
listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[live_flame_graph] tcp_listen(" + port.to_s + ") failed"
  exit(1)
end
puts "live_flame_graph: open http://127.0.0.1:" + port.to_s + "/ in a browser"

loop do
  client = Net.sp_net_accept(listen_fd)
  if client < 0
    next
  end

  line = Net.sp_net_read_line(client)
  path = parse_path(line)
  drain_headers(client)

  if path == "/folded"
    write_status(client, "200 OK", "text/plain", -1)
    FG.spnl_dump_folded_to_fd("bpf_hist_keyed", "bpf_stacks", client)
  elsif path == "/health"
    body = "ok\n"
    write_status(client, "200 OK", "text/plain", body.length)
    Net.sp_net_write_str(client, body)
  else
    write_status(client, "200 OK", "text/html; charset=utf-8", HTML.length)
    Net.sp_net_write_str(client, HTML)
  end
  Net.sp_net_rl_close(client)
end
