# NEGATIVE fixture: filter_by in a unit that also has a hook the filter cannot
# cover.
#
# The codegen refuses this whole unit rather than filtering the kprobe and
# leaving the XDP handler open.
#
# Two independent reasons, either one sufficient:
#   * XDP is not process context. bpf_get_current_pid_tgid() there reports
#     whichever task happens to be on the CPU when the packet arrives, so the
#     filter would not be wrong so much as meaningless.
#   * the wrapper's return value is a verdict. "Skip this event" would have to be
#     `return 0`, which for XDP is XDP_ABORTED, and for lsm/fmod_ret is "allow".
#     Discarding an event must never be spelled the same way as a decision.
#
# The refusal is the design, not a limitation: a partly-applied filter produces
# exactly the artefact this feature exists to prevent -- a probe that looks
# narrowed and is not. A unit that needs both writes two probes.
filter_by :pid

def kprobe__do_sys_openat2(dfd)
  @opens += 1
  0
end

def xdp__main
  @rx += 1
  2
end
