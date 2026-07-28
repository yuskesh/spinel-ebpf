# go_tls_write -- Go crypto/tls.(*Conn).Write plaintext -> HTTP request span.
# The Go slice arg (b []byte) decomposes to ptr/len; on arm64 PT_REGS_PARM reads them.
# Reads min(len, 64) plaintext and if HTTP emits ONE request-only http_event (no sock -> url.scheme=https).
module GoTlsFix
  include BPF::EventLoop

  on :uprobe, "/opt/app/goclient:crypto/tls.(*Conn).Write" do |conn, ptr, len|
    go_tls_write(conn, ptr, len)
  end
end
