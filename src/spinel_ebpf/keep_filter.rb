# frozen_string_literal: true
#
# The declarative userspace consumer filter.
#
# A typed consumer drains a packed record and turns it into a span. `keep_if`
# says, once per channel, which records get that far:
#
#     on_emit :dns do |ev|
#       send_otlp(to_span(ev), @ep)
#     end
#     keep_if :dns, qname: :contains        # SPNL_KEEP_DNS_QNAME
#
# The consumer transform (src/spinel_ebpf/consumer.rb) lowers that into the head
# of the generated handler:
#
#     def __spnl_consume_rec_dns(ev)
#       __spnl_keep_dns_qname = ENV["SPNL_KEEP_DNS_QNAME"] || ""
#       if __spnl_keep_dns_qname != ""
#         return 0 unless SpnlRecDns.spnl_rec_dns_qname(ev).include?(__spnl_keep_dns_qname)
#       end
#       ...
#
# WHY A DECLARATION AND NOT `next unless ev.qname.include?(...)`
#
# Not for type-checking: `ev.<prop>` is ALREADY checked (`ev.typo` is rejected
# with the real property list), so the hand-written form has that too. What it
# cannot have is:
#
#   1. POSITION. The guard is hoisted to the head of the handler by
#      construction. A hand-written `next` sitting one line below `send_otlp`
#      compiles, runs, sends everything, and looks filtered -- the within-handler
#      version of the partial application that made the in-kernel filter a
#      declaration too.
#   2. A NAME THE PROGRAM DOES NOT OWN. The env var is derived from the channel
#      and the property, so the loader can sweep the environment and refuse a
#      SPNL_KEEP_* nobody declared -- the same sweep `param` and `filter_by` get,
#      extended here. Hand-written `ENV["SPNL_KEEP_DNS_QNMAE"] || ""` is a filter
#      that silently never fires.
#   3. A CHECKABLE RELATION TO THE KERNEL-SIDE FILTER. Because the declaration
#      names the property, the transform can look up whether `filter_by` selects
#      on the same value and refuse the redundant, more expensive spelling.
#      Arbitrary Ruby gets no such answer -- see `kfilter` in
#      src/codegen_c/record_schema.h for why that is per field and not per name.
#   4. VISIBILITY WITHOUT READING THE BODY. `describe` can say what a probe drops
#      -- and, more importantly, say that a probe drops NOTHING. That is the
#      in-kernel filter's lesson repeated: the reading that is most often missing
#      is the absent one.
#
# Split of duties, the same one common_filter.rb documents: this module owns the
# VOCABULARY (operators, env names, the guard text) and the source scan. The
# refusals live in consumer.rb, which is the thing that already fails a build for
# `ev.typo` and so speaks with one voice about one record's properties.
require_relative "capabilities"
require_relative "common_filter"

module SpinelEbpf
  module KeepFilter
    class Error < StandardError; end

    # The closed operator set. Deliberately small: every operator is a spelling a
    # reader has to learn and a shape the generator has to be able to emit for
    # both Ruby types, and the ones below are what a narrowing actually needs
    # (an identity, its negation, a threshold in each direction, a substring).
    #
    # `types` is which Ruby exposure the operator accepts. `qname: :ge` is a
    # compile error rather than a string comparison nobody meant, and `pid:
    # :contains` likewise -- the record contract already says which is which
    # (`expose` in record_schema.h), so the check costs nothing to author.
    Op = Struct.new(:name, :types, :reads, :note, keyword_init: true)

    OPS = [
      Op.new(name: "eq",       types: %w[int str], reads: "==",
             note: "keep records whose value equals the environment's"),
      Op.new(name: "ne",       types: %w[int str], reads: "!=",
             note: "keep records whose value differs (the in-kernel filter has no negation)"),
      Op.new(name: "ge",       types: %w[int],     reads: ">=",
             note: "keep records at or above a threshold (`duration_ns: :ge` = only the slow ones)"),
      Op.new(name: "le",       types: %w[int],     reads: "<=",
             note: "keep records at or below a threshold"),
      Op.new(name: "contains", types: %w[str],     reads: "includes",
             note: "keep records whose string contains the environment's (substring, case-sensitive)"),
    ].freeze

    OPS_BY_NAME = OPS.to_h { |o| [o.name, o] }.freeze

    module_function

    def op(name) ; OPS_BY_NAME[name.to_s] ; end
    def ops_for(expose) ; OPS.select { |o| o.types.include?(expose.to_s) } ; end

    def env_name(chan, prop) ; "SPNL_KEEP_#{chan.to_s.upcase}_#{prop.to_s.upcase}" ; end
    ENV_PREFIX = "SPNL_KEEP_"

    # The local the generated handler binds the environment value to. Prefixed so
    # it cannot collide with anything the author wrote, and named after the
    # predicate so the generated Ruby reads as the declaration does.
    def local_name(chan, prop) ; "__spnl_keep_#{chan}_#{prop}" ; end

    # --- source scan ----------------------------------------------------------
    #
    # `describe` reads raw source and must work on a file that does not compile,
    # so the scan reports and never refuses (same rule as CommonFilter.scan_source).
    # An unknown channel / property / operator comes back verbatim and the caller
    # decides whether that is a warning (describe) or a build failure (consumer).
    # The predicate list is optional in the PATTERN so that `keep_if :dns` (the
    # natural half-written form) is recognised as a declaration and refused for
    # having no predicates, instead of sliding past as an unknown top-level call
    # and dying in spinel about something else.
    DECL_RE = /\A\s*keep_if\s+:([A-Za-z_]\w*)\s*(?:,\s*(.+?))?\s*(?:#.*)?\z/.freeze
    PRED_RE = /\A([A-Za-z_]\w*)\s*:\s*:([A-Za-z_]\w*)\z/.freeze

    # [{ line:, channel:, preds: [{ prop:, op: }], bad: [text,...] }] in source order.
    def scan_source(source)
      source.each_line.with_index(1).filter_map do |line, i|
        m = DECL_RE.match(line.chomp)
        next unless m
        preds = []
        bad   = []
        m[2].to_s.split(",").each do |chunk|
          text = chunk.strip
          next if text.empty?     # trailing comma -> "no predicates", not "bad predicate"
          p = PRED_RE.match(text)
          p ? preds << { prop: p[1], op: p[2] } : bad << text
        end
        { line: i, channel: m[1], preds: preds, bad: bad }
      end
    end

    def present?(source)
      source.each_line.any? { |line| DECL_RE.match?(line.chomp) }
    end

    # Remove the declarations line-for-line. The consumer transform has already
    # turned them into guards, and spinel's native codegen refuses an unknown
    # top-level call. Replacing rather than deleting keeps every later line number
    # honest (Param / CommonFilter do the same, and for the same reason).
    def strip_declarations(source)
      source.each_line.map { |l| DECL_RE.match(l.chomp) ? "# (keep_if lowered into the consumer)\n" : l }.join
    end

    # What the loader glue needs to know about a declaration: the env var to
    # sweep for and how to validate its value. Flattened to one row per
    # predicate, since that is what an operator sets one of.
    # [{ channel:, prop:, op:, expose:, env: }]
    def loader_declarations(source)
      scan_source(source).flat_map do |d|
        d[:preds].filter_map do |p|
          prop = SpinelEbpf::Capabilities.record_properties(d[:channel])
                                         .find { |x| x[:name].to_s == p[:prop] }
          next unless prop
          { channel: d[:channel], prop: p[:prop], op: p[:op],
            expose: prop[:expose].to_s, env: env_name(d[:channel], p[:prop]) }
        end
      end
    end

    # A property worth showing in an example / a hint: prefer a derivation, since
    # that is the case this filter exists for (the kernel cannot see it at all),
    # and never one whose `:eq` the transform would refuse. One implementation so
    # that the error messages and `describe` suggest the same thing.
    def example_predicate(chan)
      props = SpinelEbpf::Capabilities.record_properties(chan)
      p = props.find { |x| x[:kind].to_s == "derived" && kernel_key(chan, x[:name]).nil? } ||
          props.find { |x| kernel_key(chan, x[:name]).nil? } || props.first
      return nil unless p
      ops = ops_for(p[:expose])
      op = ops.find { |o| o.name == "contains" } || ops.find { |o| o.name == "ge" } || ops.first
      { prop: p[:name].to_s, op: op.name }
    end

    # --- lowering -------------------------------------------------------------

    # The Ruby a predicate becomes, as an array of lines (no trailing newline),
    # given the accessor expression for the property. `acc` is exactly what
    # `ev.<prop>` lowers to, so the filter and the body read the same value
    # through the same generated accessor -- there is no second way to get at it.
    #
    # The unset test is a comparison against "" rather than a nil check: the
    # environment value is bound with `|| ""` so the local has ONE type, and an
    # empty value is refused by the loader anyway (see the glue in bin/spinel-ebpf),
    # so "" can only mean "not set".
    #
    # The DROP condition is spelled positively (`return 0 if <not kept>`) so the
    # generated Ruby has no `!`, which keeps it inside the subset a reader can
    # hand-write. `contains` is the one that needs `unless`, because String#include?
    # is the predicate and there is no "excludes".
    LOWERING = {
      %w[eq int]       => "return 0 if %<acc>s != %<k>s.to_i",
      %w[ne int]       => "return 0 if %<acc>s == %<k>s.to_i",
      %w[ge int]       => "return 0 if %<acc>s < %<k>s.to_i",
      %w[le int]       => "return 0 if %<acc>s > %<k>s.to_i",
      %w[eq str]       => "return 0 if %<acc>s != %<k>s",
      %w[ne str]       => "return 0 if %<acc>s == %<k>s",
      %w[contains str] => "return 0 unless %<acc>s.include?(%<k>s)",
    }.freeze

    def guard_lines(chan, prop, opname, expose, acc, indent: "  ")
      k = local_name(chan, prop)
      tmpl = LOWERING[[opname.to_s, expose.to_s]] or
        raise Error, "no lowering for #{opname} on a #{expose} property"
      ["#{indent}#{k} = ENV[#{env_name(chan, prop).inspect}] || \"\"",
       "#{indent}if #{k} != \"\"",
       "#{indent}  #{format(tmpl, acc: acc, k: k)}",
       "#{indent}end"]
    end

    # --- the line between here and the in-kernel filter ------------------------
    #
    # `kfilter` on a published property (record_schema.h) names the `filter_by`
    # key that selects the SAME value in the kernel. Where one exists, `:eq` is
    # the one predicate the two surfaces both express -- and the kernel's is
    # strictly better, because the record is never created. Everything else
    # (negation, thresholds, substrings) the in-kernel filter cannot express at
    # all, so it stays here even on a property that has a kernel key.
    def kernel_key(chan, prop)
      p = SpinelEbpf::Capabilities.record_properties(chan).find { |x| x[:name].to_s == prop.to_s }
      k = p && p[:kfilter].to_s
      k.nil? || k.empty? ? nil : k
    end

    # Why a given predicate has to run in userspace -- one of three answers, and
    # the reason `describe` can state it as a fact instead of a hope.
    #   :derived            the value does not exist until userspace computes it
    #   :no_kernel_key      the kernel wrote the bytes, but the common filter's
    #                       vocabulary is fixed and has no key for them
    #   :operator           the kernel has the key but not this comparison
    def placement(chan, prop, opname)
      p = SpinelEbpf::Capabilities.record_properties(chan).find { |x| x[:name].to_s == prop.to_s }
      return :derived if p && p[:kind].to_s == "derived"
      kernel_key(chan, prop) ? :operator : :no_kernel_key
    end

    PLACEMENT_NOTE = {
      derived:       "userspace-only: a derived value does not exist until userspace computes it " \
                     "(walking a DNS QNAME in the kernel blows up verifier state, which is why " \
                     "it is a derivation)",
      no_kernel_key: "userspace-only: the kernel wrote this field, but the in-kernel common filter's " \
                     "vocabulary is fixed (pid tid uid gid cgroup_id comm) and has no key for it",
      operator:      "userspace: `filter_by` has this key but not this comparison " \
                     "(the in-kernel filter is equality-AND only)",
    }.freeze
  end
end
