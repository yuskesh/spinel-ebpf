# A (bool signature support): spinel infers `bool` for comparison results.
# `is_big` returns a bool; `both` takes that bool as a parameter and returns it.
# Before bool was an eligible eBPF signature type in the C codegen these fell
# back to native; now bool lowers to __s32 (Ruby SPINEL_TYPE_TO_C["bool"]) and
# stays eBPF, byte-identical to the Ruby oracle. Both are called in the kprobe's
# condition (expression-context BPF-to-BPF calls), so the bodies stay non-empty.
def is_big(size)
  size > 256
end
def both(flag)
  flag
end
def kprobe__tcp_sendmsg(sk, msg, size)
  if both(is_big(size))
    spnl_emit(size)
  end
end
