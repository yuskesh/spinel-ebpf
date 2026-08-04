# examples/observability/attach_multi_demo.rb
#
# One definition, many attach points.
#
#   on :kprobe, %w[vfs_read vfs_write vfs_open] do ... end
#
# One body rides three kernel functions. **Which lowering is used is invisible
# from the body** -- expanded (N programs) or kprobe_multi (one program plus a
# per-symbol cookie), "which symbol am I on" is spelled exactly one way, through
# `attached_symbol_eq("...")` / `attached_index`. The list can grow and the
# codegen can switch mechanisms without the body changing by a character.
#
# `via: :expand` / `via: :multi` names the mechanism explicitly. That is not for
# the body's sake but for **deployment**: kprobe_multi raises the kernel floor to
# 5.18, so a host that cannot be raised needs the expanded form to be reachable.
#
# filter_by :comm is here to make the measurement deterministic -- it keeps
# vfs_* from processes unrelated to this probe out of the counts.
#
# Build:
#   spinel-ebpf compile examples/observability/attach_multi_demo.rb \
#       -o build/attach_multi_demo --build
# Run:
#   SPNL_FILTER_COMM=cat ./build/attach_multi_demo/attach_multi_demo &
#   cat /etc/hostname > /dev/null
#   bpftool map dump name bpf_path_counts   # key = attached_index (0/1/2)
#   bpftool map dump name attach_multi_de   # @reads (the attached_symbol_eq path)

filter_by :comm

@reads = 0

module VfsAudit
  include BPF::EventLoop

  on :kprobe, %w[vfs_read vfs_write vfs_open] do
    # Two ways to ask "which symbol am I on". Both lower to the same single
    # value (__spnl_sym in the inner), so the meaning survives a change of
    # mechanism.
    #
    #   index form -- for putting in the output (describe publishes the
    #                 index -> name table)
    path_counter_inc(attached_index)
    #   name form  -- for deciding on (survives reordering the list; a typo is a
    #                 compile error)
    if attached_symbol_eq("vfs_read")
      @reads = @reads + 1
    end
  end
end

puts "VfsAudit loaded (one body, three symbols)"
sleep 3600
