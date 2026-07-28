# Go-native robust full RED. go_tls_req (len-bound request stash, conn key) +
# go_tls_resp_stash (recv stash keyed by the g register = goroutine, survives M migration) +
# go_tls_emit (g lookup + conn correlate + full RED span). go_tls_resp_stash/emit read ctx->regs[28]
# so ctx is forwarded to the uprobe inner (uses_go_gptr).
module GoTlsNative
  include BPF::EventLoop
  on :uprobe,  "/opt/app/goclient:crypto/tls.(*Conn).Write" do |conn, ptr, len| go_tls_req(conn, ptr, len) end
  on :uprobe,  "/opt/app/goclient:crypto/tls.(*Conn).Read"  do |conn, ptr, len| go_tls_resp_stash(conn, ptr) end
  on :go_uret, "/opt/app/goclient:crypto/tls.(*Conn).Read"  do |ret|            go_tls_emit(ret) end
end
