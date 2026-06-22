# filelife — lifespan of short-lived files (bcc filelife equivalent).
#
# security_inode_create stamps a per-dentry timer (the new file's dentry);
# vfs_unlink reads it back (same cached dentry) and emits the file's lifetime
# in ns. Keyed by the dentry pointer via the arbitrary-key latency helper.
#
#   bin/spinel-ebpf compile tools/filelife.rb --build -o build/filelife
#   sudo ./build/filelife/filelife    # streams: <ktime> <lifetime_ns>
module Stream
  ffi_func :spnl_stream, [:int], :int
end

def kprobe__security_inode_create(dir, dentry)
  lat_start(dentry)
  0
end

def kprobe__vfs_unlink(idmap, dir, dentry)
  d = lat_end(dentry)
  if d > 0
    spnl_emit(d)
  end
  0
end

puts "[filelife] ktime  lifetime_ns (create -> unlink):"
Stream.spnl_stream(0)
