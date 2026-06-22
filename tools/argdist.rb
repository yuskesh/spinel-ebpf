# argdist — distribution of an expression's value at a probe (bcc argdist -C).
#
# bcc: argdist -C 't:syscalls:sys_enter_write():u64:count' builds a frequency
# table of write() sizes. Here path_counter_inc(count) keys a HASH by the write
# size, so bpf_path_counts becomes {size -> occurrences}. Scoped to comm "dd" so
# the table is deterministic (dd issues exactly `count` writes of size `bs`).
# Swap the probe / keyed expression to tabulate any arg or builtin value.
# (The -H histogram mode is hist_observe(value); see tools/funclatency.rb.)
#
#   bin/spinel-ebpf compile tools/argdist.rb --build -o build/argdist
#   sudo ./build/argdist/argdist &
#   dd if=/dev/zero of=/dev/null bs=64   count=50 status=none
#   dd if=/dev/zero of=/dev/null bs=4096 count=20 status=none
#   bpftool map dump name bpf_path_counts     # {64:50, 4096:20}
def tracepoint__syscalls__sys_enter_write(fd, buf, count)
  if comm_hash == 25700        # comm "dd" (first 8 bytes, little-endian s64)
    path_counter_inc(count)    # count keyed by the write size
  end
  0
end

puts "[argdist] tabulating write() sizes for comm=dd (8s)..."
sleep 8
