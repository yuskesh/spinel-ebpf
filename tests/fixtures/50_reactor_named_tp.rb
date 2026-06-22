# reactor + named-field tracepoint block params.
# Verifies that param names matching TRACEPOINT_FIELDS resolve via
# extract_named_tracepoint_args (the named-field tracepoint path).

module ReactorNamedTp
  include BPF::EventLoop

  on :tracepoint, "sched", "sched_switch" do |prev_pid, next_pid|
    @switches = @switches + 1
    @last_prev = prev_pid
    @last_next = next_pid
  end
end

@switches = 0
@last_prev = 0
@last_next = 0
