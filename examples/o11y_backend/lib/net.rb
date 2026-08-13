# Shared socket / epoll / fork FFI declarations (upstream sp_net plus the
# rl_ shims from src/runtime/sp_net_ext.c).
#
# The sp_net_rl_* variants drain the read_line buffer before reading, so a
# binary body that was partially pulled into the line buffer is not lost.
# sp_net_ext.c is linked into every binary by bin/spinel-ebpf, which is why
# ingestd/queryd are built with that CLI (see the README).

module Net
  ffi_func :sp_net_listen,         [:int, :int], :int   # (port, reuseport) -- the 2nd arg is NOT a backlog
  ffi_func :sp_net_accept,         [:int],       :int   # upstream sets TCP_NODELAY on accept
  ffi_func :sp_net_read_line,      [:int],       :str   # CRLF stripped; "" is a blank line or EOF
  ffi_func :sp_net_write_str,      [:int, :str], :int
  ffi_func :sp_net_rl_recv_some,   [:int, :int], :binstr
  ffi_func :sp_net_rl_close,       [:int],       :int
  ffi_func :sp_net_fork,           [],           :int
  ffi_func :sp_net_getpid,         [],           :int
  ffi_func :sp_net_epoll_create,   [],           :int
  ffi_func :sp_net_epoll_add,      [:int, :int], :int
  ffi_func :sp_net_epoll_del,      [:int, :int], :int
  ffi_func :sp_net_epoll_wait_one, [:int],       :int
end
