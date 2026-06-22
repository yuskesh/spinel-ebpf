# QUEUE (FIFO) + STACK (LIFO) maps. fentry pushes a marker into each;
# fexit pops from the FIFO. Since every pushed value is 42, @last_popped ends
# up 42, proving the FIFO round-trips. The STACK fills with 7s (push only).
@last_popped = 0
def fentry__do_sys_openat2(dfd)
  fifo_push(42)
  lifo_push(7)
end
def fexit__do_sys_openat2(dfd, ret)
  @last_popped = fifo_pop()
end
