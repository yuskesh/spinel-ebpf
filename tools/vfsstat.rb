# vfsstat — count core VFS operations (bcc vfsstat equivalent).
# kprobes on vfs_read / vfs_write / vfs_open keep per-op counters.
#
#   bin/spinel-ebpf compile tools/vfsstat.rb --build -o build/vfsstat
#   ./build/vfsstat/vfsstat &
#   bpftool map dump name vfsstat_top_re   # @reads
#   bpftool map dump name vfsstat_top_wr   # @writes
#   bpftool map dump name vfsstat_top_op   # @opens
@reads  = 0
@writes = 0
@opens  = 0
def kprobe__vfs_read(file)
  @reads = @reads + 1
end
def kprobe__vfs_write(file)
  @writes = @writes + 1
end
def kprobe__vfs_open(path)
  @opens = @opens + 1
end
puts "[vfsstat] counting vfs_read / vfs_write / vfs_open. Inspect via bpftool map dump."
sleep 3600
