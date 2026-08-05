# uprobe + uretprobe attach demo.
#
# Counts calls to readline() in bash (or any binary exporting the symbol).
# The target binary path comes from $SPNL_UPROBE_BINARY at runtime;
# $SPNL_UPROBE_PID restricts attach to a single process (default -1 = all).
#
# Build:
#   bin/spinel-ebpf compile examples/observability/uprobe_demo.rb \
#                   -o build/uprobe_demo --build
#
# Run:
#   SPNL_UPROBE_BINARY=/usr/bin/bash ./build/uprobe_demo/uprobe_demo &
#   bash -c 'echo "hello"; echo "world"'   # generates 2 readline calls
#
# Inspect:
#   # The kernel keeps only the first 15 characters of a map name, so these
#   # two both appear as `uprobe_demo_top` and cannot be told apart by name.
#   # Look them up by id instead:
#   bpftool map show | grep uprobe_demo_top
#   bpftool map dump id <the id printed above>

@calls = 0
@returns = 0

def uprobe__readline(prompt)
  @calls = @calls + 1
end

def uretprobe__readline(ret)
  @returns = @returns + 1
end

puts "uprobe_demo loaded — set SPNL_UPROBE_BINARY=/usr/bin/bash and trigger readline"
sleep 3600
