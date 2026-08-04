# Module + include attach -- the Ruby-correct spelling of the class form (a
# class that is never instantiated is a module). `include BPF::XDP` binds every
# method of the module to the XDP attach kind.
#
# ALL NINE module+include surfaces were measured dead, including the three
# struct_ops ones the class form still supported: a module has no superclass, so
# the `cls_parents` field the IR build keyed on was empty and there was nothing
# to bind. Every one compiled to SEC("syscall").
#
# Fixed by binding both surfaces in one post-pass over the IR
# (cc_bind_dsl_class_attach), which renames the members to the flat
# `<prefix><member>` form -- i.e. makes the claimed equivalence true by
# construction instead of by two code paths agreeing.
XDP_PASS = 2

module ProtoCounter
  include BPF::XDP

  def count
    n = pkt_l4_proto
    if n == IPPROTO_TCP
      @tcp = @tcp + 1
    end
    XDP_PASS
  end
end
