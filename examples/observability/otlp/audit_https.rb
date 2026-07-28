# TLS plaintext span: span the contents of encrypted HTTPS traffic without
# decrypting anything.
#
# All this does is feed **the plaintext seen by SSL_write/SSL_read uprobes** into
# the same HTTP parser used for cleartext HTTP. HTTPS from an OpenSSL-based
# application such as curl lands in Splunk APM as method, path, status and
# duration, **without changing a line of the application and without keys or
# decryption** -- the technique `sslsniff` uses. On the TCP path, port 443 shows
# only ciphertext; that contrast is exactly why the SSL uprobe is needed.
#
# How it works, reusing the same machinery and changing only the hooks and the key:
#   1. SSL_write(ssl, buf, num) uprobe: buf is **the plaintext before encryption**,
#      i.e. the request. ssl_req_start reuses http_pending and spnl_is_http_req
#      unchanged, recording under the **SSL* pointer** as the key rather than a sock.
#   2. SSL_read(ssl, buf, num) uprobe entry: the decrypted plaintext only lands in
#      buf **after the function returns**, so ssl_resp_stash stashes {ssl, buf} by
#      tid -- the same trap as with recvmsg.
#   3. SSL_read uretprobe: ssl_emit reads the stash, correlates by SSL*, and emits
#      one span into the same http_events ringbuffer.
#   Parsing the method, path and status uses the same userspace parser, since by
#   this point it is plain HTTP either way.
#
# semconv: the same as the cleartext HTTP example (`http.request.method` /
#   `url.path` / `http.response.status_code`) plus **`url.scheme=https`**, which is
#   inferred from there being no sock -- the mark of TLS. status >= 500 becomes
#   ERROR. The span is named "<METHOD> <path>" with kind=CLIENT.
#
# * No sensitive data goes into the span: only method, path and status. **Request
#   bodies, authorization headers and cookies are never put in a span.** Even
#   though the plaintext is right there, the design reads only the leading request
#   line and status line and never the body, so no secret leaks into an audit trail.
#
# ── Build & send (straight to Splunk, self-attaching) ────────────────────
#   bin/spinel-ebpf compile examples/observability/otlp/audit_https.rb --build -o build/audit_https
#   SPNL_UPROBE_BINARY=/usr/lib/aarch64-linux-gnu/libssl.so.3 \   # OpenSSL's libssl
#   OTEL_SERVICE_NAME=spinel-https-red \
#   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp \
#   OTEL_EXPORTER_OTLP_HEADERS="X-SF-Token=$(cat ~/.spinel_splunk_token)" \
#     ./build/audit_https/audit_https
#   # In another terminal, `curl https://<host>/path` (OpenSSL) produces a span
#   # carrying GET /path, the status and the duration even though the traffic is
#   # encrypted, with url.scheme=https.
#
# Limits:
#   - **Go's crypto/tls does not use OpenSSL** -- the same situation as Go's native
#     DNS resolver -- so it is not caught by the SSL_read/write uprobes.
#     BoringSSL, rustls and GnuTLS export different symbols too. **This targets
#     OpenSSL-based software**: curl, wget, python-requests over openssl,
#     nginx built against openssl, and so on.
#   - HTTP/2 multiplexing and pipelining are not handled, the same scope as the
#     cleartext HTTP example.

module Otlp
  ffi_func :spnl_otlp_http_span_push, [:str], :int
end

def uprobe__SSL_write(ssl, buf, num)
  ssl_req_start(ssl, buf)   # the plaintext request before encryption (method/path)
  0
end

def uprobe__SSL_read(ssl, buf, num)
  ssl_resp_stash(ssl, buf)  # stash the receive buffer; the decrypted bytes are read in the uretprobe
  0
end

def uretprobe__SSL_read(ret)
  ssl_emit(ret)             # read the decrypted response (status), correlate -> one span
  0
end

ep   = ENV["OTLP_ENDPOINT"] || ENV["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] ||
       "http://127.0.0.1:4318"
secs = (ENV["PROBE_SECONDS"] || "2").to_i
puts "[audit-https] TLS plaintext L7 RED (SSL_write/SSL_read uprobe) -> OTLP span " + ep

loop do
  sleep secs
  st = Otlp.spnl_otlp_http_span_push(ep)
  puts "[audit-https] https spans pushed -> " + ep + " HTTP " + st.to_s
end
