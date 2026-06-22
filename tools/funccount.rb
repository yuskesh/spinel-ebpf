# funccount — count calls to a kernel function (bcc funccount equivalent).
# Edit the kprobe method name to count any function reachable by a kprobe.
#
#   bin/spinel-ebpf compile tools/funccount.rb --build -o build/funccount
#   ./build/funccount/funccount &
#   bpftool map dump name funccount_top_c   # @count = call count so far
@count = 0
def kprobe__do_sys_openat2(dfd)
  @count = @count + 1
end
puts "[funccount] counting do_sys_openat2 calls. Inspect @count via:"
puts "  bpftool map dump name funccount_top_c"
sleep 3600
