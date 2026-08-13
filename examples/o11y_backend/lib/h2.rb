# HTTP/2 (h2c) + gRPC unary receive, FFI surface.
#
# The implementation is native/o11y_h2.c: nghttp2's callbacks, HPACK and flow
# control all live on the C side, and Ruby only sees "take a completed
# request / send a response". See serve_h2 in ingestd.rb for usage.

module H2
  ffi_lib "nghttp2"
  ffi_cflags "native/o11y_h2.c"
  ffi_func :h2_open,         [:int], :int
  ffi_func :h2_is_open,      [:int], :int
  ffi_func :h2_feed,         [:int], :int          # <0 = connection over (epoll_del + h2_close)
  ffi_func :h2_next_stream,  [:int], :int          # stream id at the head of the completed queue, or -1
  ffi_func :h2_req_path,     [:int], :str
  ffi_func :h2_req_encoding, [:int], :str   # grpc-encoding header ("" = absent)
  ffi_func :h2_req_body,     [:int], :binstr       # raw body, gRPC 5-byte prefix included
  ffi_func :h2_req_pop,      [:int], :void
  ffi_func :h2_respond_grpc, [:int, :int, :int, :str], :int
  ffi_func :h2_close,        [:int], :void
end

# gRPC status values (sent in the grpc-status trailer)
GRPC_OK               = 0
GRPC_INVALID_ARGUMENT = 3
GRPC_INTERNAL         = 13
GRPC_UNIMPLEMENTED    = 12
