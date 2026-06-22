# cachestat — page cache hit/miss statistics (bcc cachestat equivalent).
#
# Counts page-cache events into bpf_path_counts (one map, keyed 0/1/2 to dodge
# truncated ivar-map name collisions):
#   key 0 = folio_mark_accessed  (total accesses)
#   key 1 = filemap_add_folio     (pages brought in = misses)
#   key 2 = mark_buffer_dirty     (dirties)
# hits = accesses - misses; ratio = hits / accesses (bcc's approximation).
#
#   bin/spinel-ebpf compile tools/cachestat.rb --build -o build/cachestat
#   sudo ./build/cachestat/cachestat ; bpftool map dump name bpf_path_counts
def kprobe__folio_mark_accessed
  path_counter_inc(0)
  0
end

def kprobe__filemap_add_folio
  path_counter_inc(1)
  0
end

def kprobe__mark_buffer_dirty
  path_counter_inc(2)
  0
end

puts "[cachestat] counting page-cache events for 5s (key0=access key1=miss key2=dirty)..."
sleep 5
