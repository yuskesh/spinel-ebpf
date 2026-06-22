# syscount — count syscalls system-wide (bcc syscount equivalent).
# Uses the raw sys_enter tracepoint (one count per syscall entry).
#
#   bin/spinel-ebpf compile tools/syscount.rb --build -o build/syscount
#   ./build/syscount/syscount &
#   bpftool map dump name syscount_top_c   # @count = total syscalls so far
@count = 0
def raw_tp__sys_enter
  @count = @count + 1
end
puts "[syscount] counting all syscalls (raw sys_enter). Inspect @count via:"
puts "  bpftool map dump name syscount_top_c"
sleep 3600
