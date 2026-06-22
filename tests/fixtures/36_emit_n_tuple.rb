# spnl_emit3 / spnl_emit4 smoke fixture.
# A kprobe handler emitting a (pid, syscall_nr, arg0) 3-tuple
# and a (pid, syscall_nr, arg0, arg1) 4-tuple per call.

def kprobe__do_sys_openat2(dfd, filename, how)
  spnl_emit3(dfd, 1, 2)
  spnl_emit4(dfd, 1, 2, 3)
end
