# Shared HTTP/1.x reading and writing, one request per call:
#
#   head = http_read_head(fd)      # nil means the connection ended (EOF)
#   body = http_read_body(fd, head.clen)
#   http_respond(fd, "200 OK", "application/json", body, head.keep)
#
# Keepalive policy (HTTP/1.1 defaults to persistent, HTTP/1.0 needs the
# Connection header) is decided here and carried on the head.

class HttpHead
  attr_reader :line, :clen, :keep, :encoding

  def initialize(line, clen, keep, encoding)
    @line = line
    @clen = clen
    @keep = keep
    @encoding = encoding   # Content-Encoding ("" = identity)
  end
end

# Read the request line and headers. nil when the connection is closed.
def http_read_head(fd)
  line = Net.sp_net_read_line(fd)
  return nil if line.length == 0
  clen = 0
  keep = false
  encoding = ""
  loop do
    h = Net.sp_net_read_line(fd)
    break if h == ""
    hl = h.downcase
    clen = h[15..-1].strip.to_i if hl.start_with?("content-length:")
    keep = true if hl == "connection: keep-alive"
    encoding = hl[17..-1].strip if hl.start_with?("content-encoding:")
  end
  keep = true if line.end_with?("HTTP/1.1")
  HttpHead.new(line, clen, keep, encoding)
end

# Read Content-Length bytes, binary-safe. May return fewer on early EOF --
# length validation is the caller's job, and a mismatch is answered with a
# loud 400 rather than a silent partial ingest.
def http_read_body(fd, clen)
  body = ""
  while body.length < clen
    chunk = Net.sp_net_rl_recv_some(fd, clen - body.length)
    break if chunk.length == 0
    body = body + chunk
  end
  body
end

def http_respond(fd, status, ctype, body, keep)
  txt = "HTTP/1.1 #{status}\r\n" \
        "Content-Type: #{ctype}\r\n" \
        "Content-Length: #{body.length}\r\n"
  txt = txt + "Connection: Keep-Alive\r\n" if keep
  Net.sp_net_write_str(fd, txt + "\r\n" + body)
end

def http_json(fd, status, json, keep)
  http_respond(fd, status, "application/json", json, keep)
end

def http_json_error(fd, status, msg, keep)
  http_json(fd, status, "{\"error\":\"" + json_escape(msg) + "\"}", keep)
end

def json_escape(s)
  out = ""
  i = 0
  while i < s.length
    c = s[i]
    if c == "\"" || c == "\\"
      out = out + "\\" + c
    elsif c == "\n"
      out = out + "\\n"
    elsif c == "\r"
      out = out + "\\r"
    elsif c == "\t"
      out = out + "\\t"
    else
      out = out + c
    end
    i += 1
  end
  out
end

# ---- TLS variants: same semantics over TLS.otls_*. Maintain in step with the
# plaintext versions above. ----

def https_read_head(fd)
  line = TLS.otls_read_line(fd)
  return nil if line.length == 0
  clen = 0
  keep = false
  encoding = ""
  loop do
    h = TLS.otls_read_line(fd)
    break if h == ""
    hl = h.downcase
    clen = h[15..-1].strip.to_i if hl.start_with?("content-length:")
    keep = true if hl == "connection: keep-alive"
    encoding = hl[17..-1].strip if hl.start_with?("content-encoding:")
  end
  keep = true if line.end_with?("HTTP/1.1")
  HttpHead.new(line, clen, keep, encoding)
end

def https_read_body(fd, clen)
  body = ""
  while body.length < clen
    chunk = TLS.otls_recv_some(fd, clen - body.length)
    break if chunk.length == 0
    body = body + chunk
  end
  body
end

def https_respond(fd, status, ctype, body, keep)
  txt = "HTTP/1.1 #{status}\r\n" \
        "Content-Type: #{ctype}\r\n" \
        "Content-Length: #{body.length}\r\n"
  txt = txt + "Connection: Keep-Alive\r\n" if keep
  txt = txt + "\r\n" + body
  TLS.otls_write_bytes(fd, txt, txt.length)
end

def https_json(fd, status, json, keep)
  https_respond(fd, status, "application/json", json, keep)
end

def https_json_error(fd, status, msg, keep)
  https_json(fd, status, "{\"error\":\"" + json_escape(msg) + "\"}", keep)
end
