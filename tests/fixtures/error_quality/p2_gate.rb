def kprobe__do_sys_openat2(dfd, file)
  emit_path(file)
end
