# log2 histogram of write(2) syscall size.
#
# tracepoint__syscalls__sys_enter_write provides the (fd, buf, count) args,
# of which we bin `count` into a log2 histogram. The result shows the
# distribution of write sizes across the entire system.
#
# Build:
#   bin/spinel-ebpf compile examples/observability/write_size_hist.rb \
#                   -o build/write_hist --build
#
# Run:
#   ./build/write_hist/write_size_hist &
#   # exercise with varied write sizes:
#   for s in 1 4 16 64 256 1024 4096; do
#     dd if=/dev/zero of=/dev/null bs=$s count=10 2>/dev/null
#   done
#   sleep 1
#   bpftool map dump name bpf_hist
#
# The Ruby host program can dump the histogram via the runtime API:
#   spnl_runtime_print_log2_hist(rt, "bpf_hist", "bytes", stderr);

def tracepoint__syscalls__sys_enter_write(fd, buf, count)
  hist_observe(count)
end

puts "write_size_hist loaded — exercise with varied write(2) sizes"
sleep 3600
