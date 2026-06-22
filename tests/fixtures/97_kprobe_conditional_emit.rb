# regression: a kprobe handler whose body is `if … end` without an
# `else`. spinel widens the inferred return to `int?` (the implicit nil
# branch). That must NOT disqualify the method from eBPF (nil -> 0 / __s64),
# and codegen must keep the inner non-void/return consistent so clang does
# not reject it with -Wreturn-mismatch.
def kprobe__tcp_sendmsg(sk, msg, size)
  if size > 256
    spnl_emit(size)
  end
end
