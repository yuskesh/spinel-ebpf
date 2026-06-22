# trace — print a kernel event, filtered by a predicate (bcc trace equivalent).
#
# bcc trace's signature is the *filter*: "trace -p PID 'sys_enter_openat \"%s\",
# filename'" prints only the chosen process's opens. Here the predicate is
# comm == "trycat", so only that process's openat() filenames stream; every
# other process is dropped in-kernel. Swap the probe / predicate / emitted value
# to trace anything — any kprobe/uprobe/tracepoint arg or builtin can be emitted.
#
#   cp /bin/cat /tmp/trycat
#   bin/spinel-ebpf compile tools/trace.rb --build -o build/trace
#   sudo ./build/trace/trace &
#   /tmp/trycat /etc/passwd     # streams; plain `cat` is filtered out
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def tracepoint__syscalls__sys_enter_openat(dfd, filename)
  # 0x746163797274 = comm "trycat" (first 8 bytes, little-endian s64).
  if comm_hash == 127961629553268
    spnl_emit_str(filename)
  end
  0   # trailing int keeps the handler's inferred return type int (not int?),
      # so partition keeps it on the eBPF side.
end

puts "[trace] openat() filenames for comm=trycat only:"
Stream.spnl_stream(0)
