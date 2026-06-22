# examples/http_server/sendfile_demo/serve_deck_pty.rb
#
# Dogfooding showcase: the HTTP server compiled with spinel-ebpf provides a
# browser-usable **interactive terminal** (WebSocket + PTY; vi/top/less work).
#
#   GET  /            -> deck.html        (sendfile, text/html)
#   GET  /pty-term    -> pty_terminal.html (xterm.js page)
#   GET  /dual        -> dual_terminal.html (top = interactive terminal /
#                                            bottom = eBPF visualization, auto-started)
#   GET  /pty         -> WebSocket upgrade -> forkpty(bash) -> bidirectional pump
#   POST /api/exec    -> sp_net_shell_capture(body) RAW shell (LAN-only / RCE)
#   GET  /health      -> "OK\n"
#
# Both the WebSocket handshake and the frame handling (parse/unmask/build/mask)
# are written entirely in Ruby (spinel subset). The FFI :binstr type carries the
# NUL bytes of masked frames, so the old sp_ws_pump_* C shims are no longer
# needed. The only remaining C primitives are PTY operations (sp_pty_spawn /
# read / write / set_winsize) — the pty master is not a socket, so send/recv
# cannot be used and read/write are required. Ruby handles the handshake,
# framing, poll, and session lifecycle.
#
# Run: SPINEL_HTTP_PORT=8080 SPINEL_STATIC_FILE=/tmp/deck.html \
#      SPINEL_PTY_TERM_FILE=/tmp/pty_terminal.html ./serve_deck_pty

require_relative "http_parser"

module Crypto
  ffi_func :sp_crypto_websocket_accept, [:str],          :str
end

module Net
  ffi_func :sp_net_listen,        [:int, :int],    :int
  ffi_func :sp_net_accept,        [:int],          :int
  ffi_func :sp_net_read_line,     [:int],          :str
  ffi_func :sp_net_write_str,     [:int, :str],    :int
  ffi_func :sp_net_rl_close,         [:int],          :int
  ffi_func :sp_net_file_size,     [:str],          :int
  ffi_func :sp_net_sendfile,      [:int, :str],    :int
  ffi_func :sp_net_rl_recv_some,     [:int, :int],    :binstr   # binary-safe (NUL-safe) read
  ffi_func :sp_net_write_bytes,      [:int, :str, :int], :int   # explicit length, NUL-safe
  ffi_func :sp_net_shell_capture, [:str, :int],    :str
  ffi_func :sp_net_poll_reset,    [],              :int
  ffi_func :sp_net_poll_add,      [:int, :int],    :int
  ffi_func :sp_net_poll_run,      [:int],          :int
  ffi_func :sp_net_poll_ready,    [:int],          :int
  ffi_func :sp_pty_spawn,            [:str, :int, :int], :int
  ffi_func :sp_pty_set_winsize,      [:int, :int, :int], :int
  ffi_func :sp_pty_read,             [:int, :int],       :binstr  # read(2): pty master isn't a socket
  ffi_func :sp_pty_write,            [:int, :str, :int], :int     # write(2)
  ffi_func :sp_net_fork,             [],                 :int
  ffi_func :sp_net_exit,             [:int],             :int
  ffi_func :sp_net_reap_nb,          [],                 :int
  ffi_func :sp_net_autoreap_on,      [],                 :int
  ffi_func :sp_net_wait_any,         [],                 :int
end

def build_response(ctype, status, body)
  "HTTP/1.0 " + status + "\r\n" +
  "Content-Type: " + ctype + "\r\n" +
  "Content-Length: " + body.length.to_s + "\r\n" +
  "Cache-Control: no-store\r\n" +
  "Connection: close\r\n" +
  "\r\n" +
  body
end

def serve_html(client, path)
  sz = Net.sp_net_file_size(path)
  if sz < 0
    Net.sp_net_write_str(client, build_response("text/plain", "404 Not Found", "Not Found\n"))
    return
  end
  header = "HTTP/1.0 200 OK\r\n" +
           "Content-Type: text/html; charset=utf-8\r\n" +
           "Content-Length: " + sz.to_s + "\r\n" +
           "Cache-Control: no-store\r\n" +
           "Connection: close\r\n" +
           "\r\n"
  Net.sp_net_write_str(client, header)
  Net.sp_net_sendfile(client, path)
end

# Read headers to the end; return the Sec-WebSocket-Key if present ("" = non-WS).
def read_headers_wskey(fd)
  key = ""
  loop do
    line = Net.sp_net_read_line(fd)
    break if line.length == 0
    parts = line.split(": ", 2)
    if parts.length == 2 && parts[0] == "Sec-WebSocket-Key"
      key = parts[1]
    end
  end
  key
end

# ---- WebSocket frame handling (all Ruby; :binstr makes the binary read NUL-safe) ----

# Read exactly n bytes from the client socket. Requests only the remaining count
# per recv, so it never overshoots the current frame (no leftover to carry across
# poll iterations). Returns an n-byte String, or "" if the peer closed mid-read.
def read_exact(client, n)
  s = ""
  while s.bytesize < n
    more = Net.sp_net_rl_recv_some(client, n - s.bytesize)
    return "" if more.bytesize == 0
    s = s + more
  end
  s
end

# Build + send one unmasked server frame (FIN=1, given opcode), 7/16/64-bit length.
def send_frame(client, opcode, payload)
  n = payload.bytesize
  b0 = 0x80 | opcode
  frame = b0.chr
  if n < 126
    frame = frame + n.chr
  elsif n < 65536
    frame = frame + 126.chr
    frame = frame + ((n >> 8) & 0xff).chr
    frame = frame + (n & 0xff).chr
  else
    frame = frame + 127.chr
    frame = frame + 0.chr + 0.chr + 0.chr + 0.chr
    frame = frame + ((n >> 24) & 0xff).chr
    frame = frame + ((n >> 16) & 0xff).chr
    frame = frame + ((n >> 8) & 0xff).chr
    frame = frame + (n & 0xff).chr
  end
  frame = frame + payload
  Net.sp_net_write_bytes(client, frame, frame.bytesize)
end

# Text control frame "R:cols,rows" -> resize the pty.
def handle_resize(pty, payload)
  parts = payload.split(":", 2)
  if parts.length == 2 && parts[0] == "R"
    cr = parts[1].split(",", 2)
    if cr.length == 2
      Net.sp_pty_set_winsize(pty, cr[1].to_i, cr[0].to_i)
    end
  end
end

# Read one client frame, unmask it, and act: close -> -1, ping -> pong,
# text -> resize control, binary -> keystrokes to pty. >=0 continue, -1 end.
def pump_client_to_pty(client, pty)
  h = read_exact(client, 2)
  return -1 if h.bytesize < 2
  opcode = h.getbyte(0) & 0x0f
  masked = (h.getbyte(1) & 0x80) != 0
  len    = h.getbyte(1) & 0x7f
  if len == 126
    e = read_exact(client, 2)
    return -1 if e.bytesize < 2
    len = (e.getbyte(0) << 8) | e.getbyte(1)
  elsif len == 127
    e = read_exact(client, 8)
    return -1 if e.bytesize < 8
    len = (e.getbyte(4) << 24) | (e.getbyte(5) << 16) | (e.getbyte(6) << 8) | e.getbyte(7)
  end
  mask = ""
  if masked
    mask = read_exact(client, 4)
    return -1 if mask.bytesize < 4
  end
  payload = ""
  if len > 0
    raw = read_exact(client, len)
    return -1 if raw.bytesize < len
    i = 0
    while i < len
      b = raw.getbyte(i)
      if masked
        b = b ^ mask.getbyte(i % 4)
      end
      payload = payload + b.chr
      i = i + 1
    end
  end
  if opcode == 0x8
    return -1                          # close
  elsif opcode == 0x9
    send_frame(client, 0xA, payload)   # ping -> pong
    return 0
  elsif opcode == 0xA
    return 0                           # pong (ignore)
  elsif opcode == 0x1
    handle_resize(pty, payload)        # text control "R:cols,rows"
    return 0
  else
    if len > 0
      Net.sp_pty_write(pty, payload, payload.bytesize)  # binary keystrokes
    end
    return 1
  end
end

# Read pty output and forward it to the client as one binary frame.
def pump_pty_to_client(pty, client)
  data = Net.sp_pty_read(pty, 65000)
  return -1 if data.bytesize == 0      # EOF: shell exited
  send_frame(client, 0x2, data)
  data.bytesize
end

# WebSocket upgrade -> forkpty(bash) -> bidirectional client<->pty pump (all framing in Ruby)
def handle_ws_pty(client, wskey)
  accept = Crypto.sp_crypto_websocket_accept(wskey)
  resp = "HTTP/1.1 101 Switching Protocols\r\n" +
         "Upgrade: websocket\r\n" +
         "Connection: Upgrade\r\n" +
         "Sec-WebSocket-Accept: " + accept + "\r\n" +
         "\r\n"
  Net.sp_net_write_str(client, resp)

  pty = Net.sp_pty_spawn("/bin/bash", 24, 80)
  if pty < 0
    return
  end

  loop do
    Net.sp_net_poll_reset
    cs = Net.sp_net_poll_add(client, 1)
    ps = Net.sp_net_poll_add(pty, 1)
    ready = Net.sp_net_poll_run(120000)
    break if ready < 0
    if ready > 0
      if (Net.sp_net_poll_ready(cs) & 1) != 0
        r = pump_client_to_pty(client, pty)
        break if r < 0
      end
      if (Net.sp_net_poll_ready(ps) & 1) != 0
        r2 = pump_pty_to_client(pty, client)
        break if r2 < 0
      end
    end
  end
  Net.sp_net_rl_close(pty)   # end of session: close the PTY master -> SIGHUP to bash
  Net.sp_net_wait_any     # reap bash (this handler's child); PID 1 (sleep) does not reap orphans
end

# ---- main ----

port      = (ENV["SPINEL_HTTP_PORT"]     || "8080").to_i
deck      = ENV["SPINEL_STATIC_FILE"]    || "/tmp/deck.html"
pty_term  = ENV["SPINEL_PTY_TERM_FILE"]  || "/tmp/pty_terminal.html"
dual      = ENV["SPINEL_DUAL_FILE"]      || "/tmp/dual_terminal.html"

listen_fd = Net.sp_net_listen(port, 0)
if listen_fd < 0
  puts "[pty] tcp_listen(" + port.to_s + ") failed"
  exit(1)
end
puts "[pty] deck + /pty-term (WebSocket+PTY) + /api/exec on 0.0.0.0:" + port.to_s

# Reap finished session children immediately via SIGCHLD (no zombies even while
# blocked in accept).
Net.sp_net_autoreap_on

loop do
  Net.sp_net_reap_nb               # safety net (autoreap is primary; this is belt-and-suspenders)
  client = Net.sp_net_accept(listen_fd)
  if client < 0
    puts "[pty] accept failed"
    break
  end

  line  = Net.sp_net_read_line(client)
  req   = parse_request_line(line)
  wskey = read_headers_wskey(client)

  if req.valid == 1 && req.verb == "GET" && req.path == "/pty" && wskey.length > 0
    # Multi-session: fork per session. The child owns its own bash/PTY, and the
    # parent returns to accept immediately (each session is a separate process,
    # so static buffers are not shared).
    pid = Net.sp_net_fork
    if pid == 0
      Net.sp_net_rl_close(listen_fd)        # child: listen fd not needed
      handle_ws_pty(client, wskey)
      Net.sp_net_rl_close(client)
      Net.sp_net_exit(0)                 # child does not return to the accept loop
    elsif pid < 0
      handle_ws_pty(client, wskey)       # on fork failure, degrade to inline handling
    end
    # parent (pid > 0) falls through to the shared close below and continues
  elsif req.valid == 1 && req.verb == "POST" && req.path == "/api/exec"
    cmd = Net.sp_net_rl_recv_some(client, 65000)
    out = Net.sp_net_shell_capture(cmd, 65000)
    Net.sp_net_write_str(client, build_response("text/plain; charset=utf-8", "200 OK", out))
  elsif req.valid == 1 && req.verb == "GET" && req.path == "/pty-term"
    serve_html(client, pty_term)
  elsif req.valid == 1 && req.verb == "GET" && req.path == "/dual"
    serve_html(client, dual)
  elsif req.valid == 1 && req.verb == "GET" && req.path == "/health"
    Net.sp_net_write_str(client, build_response("text/plain", "200 OK", "OK\n"))
  elsif req.valid == 1 && req.verb == "GET"
    serve_html(client, deck)
  else
    Net.sp_net_write_str(client, build_response("text/plain", "405 Method Not Allowed", "Method Not Allowed\n"))
  end
  Net.sp_net_rl_close(client)
end

Net.sp_net_rl_close(listen_fd)
