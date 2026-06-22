# Reactor per-handler PID smoke fixture.

module ReactorPid
  include BPF::EventLoop

  on :uprobe, "/usr/bin/bash:readline", pid: 12345 do |prompt|
    @hits = @hits + 1
  end

  on :usdt, "/usr/lib/aarch64-linux-gnu/libstdc++.so.6", "libstdcxx", "throw", pid: 67890 do |obj, tinfo, dest|
    @throws = @throws + 1
  end
end

@hits = 0
@throws = 0
