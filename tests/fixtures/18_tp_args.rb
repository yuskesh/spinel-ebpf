def spnl_emit(x)
  # placeholder
end

# Tracepoint method with positional params — codegen extracts ctx->args[i].
# For sys_enter_openat: args[0] = dfd, args[1] = filename ptr,
#                      args[2] = flags, args[3] = mode.
# We declare just `dfd` so spinel can infer it as int.
def tracepoint__syscalls__sys_enter_openat(dfd)
  spnl_emit(dfd)
end
