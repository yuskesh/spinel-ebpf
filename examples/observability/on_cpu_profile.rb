# On-CPU profiler (equivalent to bcc profile.py).
#
# Samples CPU clock at 99 Hz on every online CPU. Each sample captures the
# kernel call stack (via stack_id), and bins by stack — so the top stack
# (by hit count) shows where CPU time is being spent kernel-side.
#
# Build:
#   bin/spinel-ebpf compile examples/observability/on_cpu_profile.rb \
#                   -o build/oncpu --build
# Run:
#   ./build/oncpu/on_cpu_profile &
#
#   # Generate some CPU load:
#   dd if=/dev/zero of=/dev/null bs=1M count=20000 &
#
#   sleep 5
#   # Top stacks by hit count:
#   bpftool map dump name bpf_hist_keyed | jq -c '.[]|{k:.key,n:.value.buckets|add}'
#   # Symbolicate one stack (replace 12345 with a real stack_id):
#   # spnl_dump_stack via ffi_func from inside the demo binary, or:
#   bpftool map lookup name bpf_stacks key 39 30 00 00

module OnCpuProfile
  include BPF::EventLoop

  on :perf_event, hz: 99 do
    sid = stack_id
    hist_observe_by(sid, 1) if sid >= 0
  end
end

puts "on_cpu_profile loaded — 99 Hz CPU clock sampling"
sleep 3600
