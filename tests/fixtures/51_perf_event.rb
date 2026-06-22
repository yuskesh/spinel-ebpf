# perf_event sampling fixture (reactor form).
# Samples CPU at 99 Hz, captures kernel stack id, bins by stack id.

module PerfSample
  include BPF::EventLoop

  on :perf_event, hz: 99 do
    sid = stack_id
    hist_observe_by(sid, 1) if sid >= 0
  end
end
