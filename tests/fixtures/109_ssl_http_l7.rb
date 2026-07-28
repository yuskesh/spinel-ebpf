# TLS plaintext span. Read the plaintext of HTTPS via SSL_write/SSL_read uprobes (OpenSSL),
# reusing the plain-TCP HTTP parser -- the encrypted HTTPS body is never decrypted by us; we
# read the plaintext the app hands to / gets from OpenSSL, before/after encryption.
#
#   SSL_write(ssl, buf, num) uprobe: buf is the plaintext BEFORE encryption = the request.
#     ssl_req_start reuses the http_pending map + spnl_is_http_req, keyed by SSL* (not sock).
#   SSL_read(ssl, buf, num) uprobe entry: the decrypted plaintext lands in buf only AFTER
#     SSL_read returns, so ssl_resp_stash stashes {ssl, buf} by tid (the same trap the plain-TCP
#     tcp_recvmsg path hits).
#   SSL_read uretprobe: ssl_emit reads the stashed buffer (response), correlates with the pending
#     request by SSL*, and emits ONE span into the shared http_events channel
#     (method/path/status/duration).
#
# Target binary is OpenSSL's libssl (env SPNL_UPROBE_BINARY). Go crypto/tls / BoringSSL / rustls
# use different symbols and are NOT captured (documented limit). method/path/status only -- request
# bodies / auth headers are NOT put in spans (secrets must not leak into the audit trail).
def uprobe__SSL_write(ssl, buf, num)
  ssl_req_start(ssl, buf)
  0
end

def uprobe__SSL_read(ssl, buf, num)
  ssl_resp_stash(ssl, buf)
  0
end

def uretprobe__SSL_read(ret)
  ssl_emit(ret)
  0
end
