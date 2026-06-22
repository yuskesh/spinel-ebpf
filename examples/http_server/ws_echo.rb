# examples/http_server/ws_echo.rb
#
# WebSocket echo server, **frame handling written entirely in Ruby** (spinel
# subset) — no sp_ws_* C shims. This is the payoff of `:binstr`: client WS
# frames are masked binary and routinely contain 0x00 bytes, so the frame
# read MUST be binary-safe. `sp_net_rl_recv_some` declared `:binstr` builds the
# String from sp_net_bin_len bytes (not strlen), so embedded NULs survive; the
# echo is written with `sp_net_write_bytes` (explicit length, NUL-safe). With
# the old `:str` mode the frame would truncate at the first NUL.
#
# This is the first stage of the WebSocket+PTY terminal plan: prove the WS layer
# (RFC 6455 handshake + frame parse/unmask/build/mask) in Ruby before adding PTY.
#
#   GET / (Upgrade: websocket) -> 101 -> echo every text/binary frame back
#   ping -> pong, close -> close (then drop the connection)
#
# build: bin/spinel-ebpf compile examples/http_server/ws_echo.rb --native-only --build -o build
# run:   SPINEL_HTTP_PORT=8090 ./build/ws_echo
#   then connect with wscat -c ws://127.0.0.1:8090/ (or a raw masked frame)

module Crypto
  ffi_func :sp_crypto_websocket_accept, [:str],       :str
end

module Net
  ffi_func :sp_net_listen,        [:int, :int], :int
  ffi_func :sp_net_accept,        [:int],       :int     # TCP_NODELAY set automatically
  ffi_func :sp_net_read_line,     [:int],       :str
  ffi_func :sp_net_write_str,     [:int, :str], :int
  ffi_func :sp_net_write_bytes,   [:int, :str, :int], :int   # explicit length, NUL-safe
  ffi_func :sp_net_rl_recv_some,  [:int, :int], :binstr  # binary-safe (NUL-safe) read
  ffi_func :sp_net_rl_close,      [:int],       :int
end

# Read request headers to end-of-headers; return the Sec-WebSocket-Key ("" = non-WS).
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

# Accumulate at least `need` bytes into buf via binary-safe recv. Returns buf
# (possibly longer than need); if it returns shorter than need the peer closed.
def recv_until(client, buf, need)
  while buf.bytesize < need
    more = Net.sp_net_rl_recv_some(client, 65000)
    if more.bytesize == 0
      return buf
    end
    buf = buf + more
  end
  buf
end

# Build a server (unmasked) WS frame: FIN=1, given opcode, payload, then send it.
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

# Handshake then loop: parse one client frame, unmask it, echo/pong/close.
def handle_ws_echo(client, wskey)
  accept = Crypto.sp_crypto_websocket_accept(wskey)
  resp = "HTTP/1.1 101 Switching Protocols\r\n" +
         "Upgrade: websocket\r\n" +
         "Connection: Upgrade\r\n" +
         "Sec-WebSocket-Accept: " + accept + "\r\n" +
         "\r\n"
  Net.sp_net_write_str(client, resp)

  buf = ""
  loop do
    # 2-byte minimal header
    buf = recv_until(client, buf, 2)
    break if buf.bytesize < 2
    b0 = buf.getbyte(0)
    b1 = buf.getbyte(1)
    opcode = b0 & 0x0f
    masked = (b1 & 0x80) != 0
    len = b1 & 0x7f
    hdr = 2

    if len == 126
      buf = recv_until(client, buf, 4)
      break if buf.bytesize < 4
      len = (buf.getbyte(2) << 8) | buf.getbyte(3)
      hdr = 4
    elsif len == 127
      buf = recv_until(client, buf, 10)
      break if buf.bytesize < 10
      # only the low 32 bits are honored (PoC; frames are tiny)
      len = (buf.getbyte(6) << 24) | (buf.getbyte(7) << 16) | (buf.getbyte(8) << 8) | buf.getbyte(9)
      hdr = 10
    end

    maskoff = hdr
    if masked
      buf = recv_until(client, buf, hdr + 4)
      break if buf.bytesize < hdr + 4
      hdr = hdr + 4
    end

    total = hdr + len
    buf = recv_until(client, buf, total)
    break if buf.bytesize < total

    # extract + unmask the payload
    payload = ""
    i = 0
    while i < len
      b = buf.getbyte(hdr + i)
      if masked
        b = b ^ buf.getbyte(maskoff + (i % 4))
      end
      payload = payload + b.chr
      i = i + 1
    end

    if opcode == 0x8
      send_frame(client, 0x8, payload)   # close -> echo close, then stop
      break
    elsif opcode == 0x9
      send_frame(client, 0xA, payload)   # ping -> pong
    else
      send_frame(client, opcode, payload) # text/binary -> echo
    end

    # keep any bytes past this frame for the next iteration
    rest = ""
    j = total
    while j < buf.bytesize
      rest = rest + buf.getbyte(j).chr
      j = j + 1
    end
    buf = rest
  end

  Net.sp_net_rl_close(client)
end

port = (ENV["SPINEL_HTTP_PORT"] || "8090").to_i
fd = Net.sp_net_listen(port, 0)
if fd < 0
  puts "listen failed"
  exit(1)
end
puts "ws_echo on 127.0.0.1:" + port.to_s

loop do
  client = Net.sp_net_accept(fd)
  if client >= 0
    wskey = read_headers_wskey(client)
    if wskey.length == 0
      Net.sp_net_write_str(client, "HTTP/1.0 400 Bad Request\r\nConnection: close\r\n\r\n")
      Net.sp_net_rl_close(client)
    else
      handle_ws_echo(client, wskey)
    end
  end
end
