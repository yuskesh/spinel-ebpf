# examples/profiling/fib_flamegraph/user_profile.rb
#
# On-CPU USER-stack profiler, written in spinel-ebpf's own DSL. This is the
# dogfooded counterpart to the standard `perf` flow: the same fib(38) flame
# graph, produced by spinel-ebpf instead of perf.
#
# It samples the CPU clock at 99 Hz on every CPU, grabs the user-space call
# stack (user_stack_id), and bins by (process, stack). The histogram key packs
# the process id in the high 32 bits so the host can symbolize each stack
# against the right /proc/<pid> address space:
#
#     key = (tgid << 32) | user_stack_id
#
# After PROFILE_SECS the host dumps folded USER stacks (flamegraph.pl format)
# to stderr via spnl_dump_folded_user, symbolizing with spnl_sym_user (which
# falls back to /usr/lib/debug/.build-id/... so stripped statics like libruby's
# vm_exec_core resolve). The profiled process must still be alive at dump time
# (its maps are read then), so run the workload in a loop that outlives the dump.
#
# SPNL_SYM_PID: under a nested pid namespace (inside a container) the kernel
# records the init-namespace pid, which doesn't match this process's /proc view.
# Set SPNL_SYM_PID to the namespace-local pid of the workload (the one `ps`
# shows) so its stacks resolve; the dominant on-CPU process is the workload, so
# symbolizing everything against it is accurate. Leave unset (-1) when the
# profiler and targets share the kernel's pid namespace (system-wide).
#
# Build:
#   bin/spinel-ebpf compile examples/profiling/fib_flamegraph/user_profile.rb \
#                   -o build/uprof --build
# Run (profile a specific pid for PROFILE_SECS, then emit folded to stderr):
#   FIB_LOOPS=60 ./fib_spinel & WL=$!
#   SPNL_SYM_PID=$WL PROFILE_SECS=8 ./build/uprof/user_profile 2> folded.txt
#   flamegraph.pl < folded.txt > flame.svg

module UserProfile
  include BPF::EventLoop

  on :perf_event, hz: 99 do
    sid = user_stack_id
    if sid >= 0
      key = (tgid << 32) | sid
      hist_observe_by(key, 1)
    end
  end
end

module FG
  ffi_func :spnl_dump_folded_user, [:str, :str, :int], :int
end

secs = (ENV["PROFILE_SECS"]  || "8").to_i
pid  = (ENV["SPNL_SYM_PID"]  || "-1").to_i
puts "[user_profile] user on-CPU profiler — sampling 99 Hz for " + secs.to_s + "s (sym pid=" + pid.to_s + ")"
sleep secs
FG.spnl_dump_folded_user("bpf_hist_keyed", "bpf_stacks", pid)
