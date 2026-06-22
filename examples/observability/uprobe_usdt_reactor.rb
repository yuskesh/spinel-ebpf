# Reactor-form uprobe / uretprobe / USDT — per-handler binary path
# specified inline (no need for SPNL_*_BINARY env vars), multiple targets
# in one module.
#
# Build:
#   bin/spinel-ebpf compile examples/observability/uprobe_usdt_reactor.rb \
#                   -o build/uudt_reactor --build
# Run:
#   ./build/uudt_reactor/uprobe_usdt_reactor &
#   # exercise:
#   bash -c 'echo hi'                 # readline + bash internals
#   for i in $(seq 1 5); do /tmp/throw_loop 3; done   # libstdc++ throws
#
# Inspect counters:
#   bpftool map dump name uprobe_usdt_re

module UprobeUsdtReactor
  include BPF::EventLoop

  on :uprobe, "/usr/bin/bash:readline" do
    @bash_readline = @bash_readline + 1
  end

  on :uretprobe, "/usr/bin/bash:readline" do
    @bash_readline_ret = @bash_readline_ret + 1
  end

  on :usdt, "/usr/lib/aarch64-linux-gnu/libstdc++.so.6", "libstdcxx", "throw" do
    @cxx_throws = @cxx_throws + 1
  end

  on :usdt, "/usr/lib/aarch64-linux-gnu/libstdc++.so.6", "libstdcxx", "catch" do
    @cxx_catches = @cxx_catches + 1
  end
end

@bash_readline = 0
@bash_readline_ret = 0
@cxx_throws = 0
@cxx_catches = 0

puts "uprobe_usdt_reactor loaded — exercise bash + throw_loop"
sleep 3600
