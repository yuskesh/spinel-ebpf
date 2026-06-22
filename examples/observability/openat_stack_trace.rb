# Capture the kernel call stack at do_sys_openat2 entry, bin by
# stack id (so identical stacks share one slot). Userspace dumps each
# unique stack with kallsyms-symbolized PC list.
#
# Build:
#   bin/spinel-ebpf compile examples/observability/openat_stack_trace.rb \
#                   -o build/stack --build
# Run:
#   ./build/stack/openat_stack_trace &
#   for i in $(seq 1 50); do cat /etc/hostname > /dev/null; done
#
# Inspect:
#   bpftool map dump name bpf_hist_keyed   — count per stack id
#   bpftool map dump name bpf_stack_traces — PC list per stack id

def kprobe__do_sys_openat2(dfd, filename)
  ksid = stack_id
  if ksid >= 0
    # count occurrences per (stack id)
    hist_observe_by(ksid, 1)
  end
end

puts "openat_stack_trace loaded — exercise then dump bpf_stack_traces"
sleep 3600
