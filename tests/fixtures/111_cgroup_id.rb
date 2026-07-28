# cgroup_id() smoke fixture -- emit the current cgroup id (kernfs id /
# cgroup-dir inode) for k8s pod correlation. In a k3s pod the value equals the
# inode of .../kubepods/.../pod<UID>/<container-id>, which userspace maps to the pod.

def kprobe__do_sys_openat2(dfd, filename)
  spnl_emit(cgroup_id)
end
