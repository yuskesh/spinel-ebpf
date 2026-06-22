# lock-order inversion detection (bcc deadlock). Per thread we
# remember the last-held lock (task_swap) and record an edge to the next lock
# acquired (lock_edge); userspace flags A->B + B->A cycles as deadlocks.
def uprobe__pthread_mutex_lock(mutex)
  prev = task_swap(mutex)
  if prev != 0
    lock_edge(prev, mutex)
  end
  0
end

def uprobe__pthread_mutex_unlock(mutex)
  task_store(0)
  0
end
