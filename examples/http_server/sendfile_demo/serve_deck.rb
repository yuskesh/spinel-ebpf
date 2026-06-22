# examples/http_server/sendfile_demo/serve_deck.rb
#
# Dogfooding: serve the spinel-ebpf presentation HTML *from the spinel-ebpf
# HTTP server itself*. Same single-process accept loop as the sendfile
# demo, but the static file is served at `GET /` with `Content-Type:
# text/html` so a browser renders it (the deck is a self-expanding bundle,
# decompressed client-side). Body bytes go file page cache -> socket via
# sendfile(2); HTTP framing stays in Ruby.
#
# Run: SPINEL_HTTP_PORT=8080 SPINEL_STATIC_FILE=/tmp/deck.html ./server

require_relative "http_parser"

module Net
  ffi_func :sp_net_listen,     [:int, :int],    :int
  ffi_func :sp_net_accept,     [:int],          :int
  ffi_func :sp_net_read_line,  [:int],          :str
  ffi_func :sp_net_write_str,  [:int, :str],    :int
  ffi_func :sp_net_rl_close,      [:int],          :int
  ffi_func :sp_net_file_size,  [:str],          :int
  ffi_func :sp_net_sendfile,   [:int, :str],    :int
end

def build_response(status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: text/plain\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Connection: close\r\n" +
  "\r\n" +
  body
end

# Serve `path` as an HTML page: header via write, body via sendfile.
def serve_html(client, path)
  sz = Net.sp_net_file_size(path)
  if sz < 0
    Net.sp_net_write_str(client, build_response("404 Not Found", "Not Found\n"))
    return
  end
  header = "HTTP/1.0 200 OK\r\n" +
           "Content-Type: text/html; charset=utf-8\r\n" +
           "Content-Length: " + sz.to_s + "\r\n" +
           "Connection: close\r\n" +
           "\r\n"
  Net.sp_net_write_str(client, header)   # header: ordinary write
  Net.sp_net_sendfile(client, path)      # body:   kernel zero-copy
end

def drain_headers(fd)
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
  end
end

# ---- main ----

port  = (ENV["SPINEL_HTTP_PORT"]  || "8080").to_i
deck  = ENV["SPINEL_STATIC_FILE"] || "/tmp/deck.html"

listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[deck] tcp_listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[deck] spinel HTTP/1.0 serving deck on 0.0.0.0:" + port.to_s + " file=" + deck

loop do
  client = Net.sp_net_accept(listen_fd)
  if client < 0
    puts "[deck] accept failed"
    break
  end

  line = Net.sp_net_read_line(client)
  req  = parse_request_line(line)
  drain_headers(client)

  if req.valid == 1 && req.verb == "GET" && req.path == "/health"
    Net.sp_net_write_str(client, build_response("200 OK", "OK\n"))
  elsif req.valid == 1 && req.verb == "GET"
    # any GET path serves the single-page deck
    serve_html(client, deck)
  else
    Net.sp_net_write_str(client, build_response("405 Method Not Allowed", "Method Not Allowed\n"))
  end
  Net.sp_net_rl_close(client)
end

Net.sp_net_rl_close(listen_fd)
