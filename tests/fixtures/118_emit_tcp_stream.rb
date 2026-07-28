# emit_tcp_stream -- sock-keyed, length-bounded L7 stream capture from tcp_sendmsg.
# The sock-aware upgrade of emit_tcp_payload, which emits 128B to a str ringbuf with
# NO sock and NO length, so userspace cannot tell which connection a fragment belongs to
# (multi-connection interleaving breaks reassembly). emit_tcp_stream emits a PACKED
# record {sock, len, raw[128]} so userspace can group fragments per-connection (by sock ptr)
# and reassemble byte-exactly (bounded by the real send length). raw is length-bounded and
# NOT NUL-terminated; userspace reads exactly `len` bytes (hex-printed to avoid CRLF/NUL mangling).
def kprobe__tcp_sendmsg(sk, msg, size)
  emit_tcp_stream(sk, msg, size)
end
