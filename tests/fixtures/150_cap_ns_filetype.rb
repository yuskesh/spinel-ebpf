# has_cap / ns_id / in_host_ns / file_type -- the three selectors Tetragon has
# and this codegen did not (matchCapabilities / matchNamespaces / FileType).
#
# kfield could already REACH all three: cred, nsproxy and i_mode are ordinary
# CO-RE chains. What it cannot supply is what the value means, and all three are
# cases where the raw value CANNOT BE COMPARED CORRECTLY BY HAND:
#
#   cap_effective  a 64-bit bit set. `caps & CAP_SYS_ADMIN` tests bits 0/2/4 and
#                  returns 21 whether or not the process has it (measured: the
#                  same 21 in both runs, while the correct bit test flips).
#   ns inode       means nothing alone; "is this the host" needs a number from
#                  outside the task, and /proc/1/ns is the CONTAINER's init
#                  when the probe is in a container.
#   i_mode         type bits packed with permission bits. `== S_IFREG` is false
#                  for every regular file; `& S_IFDIR` is TRUE for a socket --
#                  the wrong type, not no type.
#
# The first three read the CURRENT TASK and are refused outside process context:
# measured, the identical call in XDP reported a CPU burner's capabilities for
# packets sent by another machine. file_type reads the pointer the hook hands
# it, so it is ungated exactly like kfield.
@denied = 0
@host_opens = 0
@dirs = 0

def lsm__file_open(file, ret)
  # AOT: the capability number is known at compile time, so this is a shift and
  # a mask, not a lookup in a value set (which is what Tetragon needs, because
  # its selectors arrive as YAML after the program was built).
  if has_cap(CAP::SYS_ADMIN) == 0 && file_type(file) == FileType::REG
    @denied = @denied + 1
  end
  if in_host_ns(:mnt) == 1
    @host_opens = @host_opens + 1
  end
  if file_type(file) == FileType::DIR
    @dirs = @dirs + 1
  end
  0
end

# The value forms: for reporting, not for testing. spnl_emit4 carries the whole
# capability set plus three namespace inodes out to userspace, which is what the
# raw numbers are actually good for.
def kprobe__do_sys_openat2
  spnl_emit4(cap_effective, ns_id(:mnt), ns_id(:pid), ns_id(:user))
  spnl_emit_pair(has_cap_permitted(CAP::NET_ADMIN), has_cap_inheritable(CAP_SYS_PTRACE))
end
