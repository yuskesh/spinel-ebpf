# deadlock — detect potential lock-order inversions (bcc deadlock equivalent).
#
# Uprobes pthread_mutex_lock/unlock. Per thread we remember the last-held lock
# (task_swap, per-task storage); when a thread holds A and acquires B we record
# the edge A->B in bpf_lock_edges. If both A->B and B->A are ever observed
# (across threads) that is a lock-order inversion = potential AB-BA deadlock,
# which spnl_dump_deadlocks flags. Scoped to comm "dldemo" (bcc deadlock's -p):
# change the comm literal / SPNL_UPROBE_BINARY for another target.
#
# MVP: tracks the immediately-preceding held lock (1-deep), so it catches the
# classic 2-lock AB-BA inversion; deeper nesting (3+ held locks) is future work.
#
#   export SPNL_UPROBE_BINARY=/lib/aarch64-linux-gnu/libc.so.6
#   bin/spinel-ebpf compile tools/deadlock.rb --build -o build/deadlock
#   sudo -E ./build/deadlock/deadlock &
#   ./dldemo                                  # AB-BA pattern across two threads
module DL
  ffi_func :spnl_dump_deadlocks, [:str, :int], :int
end

def uprobe__pthread_mutex_lock(mutex)
  if comm_hash == 122515643198564     # comm "dldemo"
    prev = task_swap(mutex)
    if prev != 0
      lock_edge(prev, mutex)
    end
  end
  0
end

def uprobe__pthread_mutex_unlock(mutex)
  if comm_hash == 122515643198564
    task_store(0)
  end
  0
end

puts "[deadlock] watching pthread_mutex_lock order (comm=dldemo) for 8s..."
sleep 8
DL.spnl_dump_deadlocks("bpf_lock_edges", 20)
