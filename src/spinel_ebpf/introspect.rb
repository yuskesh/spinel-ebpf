# frozen_string_literal: true
#
# `spinel-ebpf describe` — emit/consumer introspection.
#
# What `on_emit` actually receives is only knowable from the code's convention
# (positional __s64 values whose meaning is the emit call's arguments). This
# module scans the source, matches emit sites (kind/arity/call text) against
# consumers (kind/block params), and lists the bindings, arity mismatches, and
# missing producers/consumers (a machine-readable alternative).
require_relative "consumer"

module SpinelEbpf
  module Introspect
    module_function

    NAMED_EMIT_RE     = /\A\s*emit\s+:(\w+)\s*,\s*(.+?)\s*(?:#.*)?\z/.freeze
    NAMED_CONSUMER_RE = /\A\s*on_emit\s+:(\w+)\s+do\s*\|\s*(\w+)\s*\|/.freeze

    # [{ line:, name:, text: }] for `emit :NAME, expr` producer sites
    def named_emits(source)
      source.each_line.with_index(1).filter_map do |line, n|
        m = NAMED_EMIT_RE.match(line.chomp)
        m && { line: n, name: m[1], text: line.strip }
      end
    end

    # [{ line:, name:, param: }] for `on_emit :NAME do |v|` consumer sites
    def named_consumers(source)
      source.each_line.with_index(1).filter_map do |line, n|
        m = NAMED_CONSUMER_RE.match(line.strip)
        m && { line: n, name: m[1], param: m[2] }
      end
    end

    # emit builtin -> { kind(consumer suffix), arity, consumer name }
    EMITS = {
      "spnl_emit_pair" => { kind: "_pair", arity: 2, consumer: "on_emit_pair" },
      "spnl_emit3"     => { kind: "3",     arity: 3, consumer: "on_emit3" },
      "spnl_emit4"     => { kind: "4",     arity: 4, consumer: "on_emit4" },
      "spnl_emit_str"  => { kind: "_str",  arity: 1, consumer: "on_emit_str" },
      "spnl_emit"      => { kind: "",      arity: 1, consumer: "on_emit" },
    }.freeze
    # longest first so spnl_emit_pair matches before spnl_emit
    EMIT_ORDER = EMITS.keys.sort_by { |k| -k.length }.freeze
    ON_EMIT_RE = /\Aon_emit(_pair|_str|3|4)?\s+do\s*\|([^|]*)\|/.freeze

    # [{ line:, name:, kind:, arity:, text: }]
    def emits(source)
      source.each_line.with_index(1).filter_map do |line, n|
        body = line.chomp.sub(/#.*\z/, "")  # drop trailing comment (naive; chomp so \z matches)
        name = EMIT_ORDER.find { |e| body =~ /(?<![\w.])#{Regexp.escape(e)}\s*\(/ }
        next unless name
        { line: n, name: name, kind: EMITS[name][:kind], arity: EMITS[name][:arity], text: line.strip }
      end
    end

    # [{ line:, kind:, consumer:, nparams: }]
    def consumers(source)
      source.each_line.with_index(1).filter_map do |line, n|
        m = ON_EMIT_RE.match(line.strip)
        next unless m
        suffix = m[1] || ""
        params = m[2].split(",").map(&:strip).reject(&:empty?)
        { line: n, kind: suffix, consumer: "on_emit#{suffix}", nparams: params.length, params: params }
      end
    end

    def kind_label(k)
      { "" => ":int", "_pair" => ":pair", "_str" => ":str", "3" => ":tuple3", "4" => ":tuple4" }[k] || k
    end

    # Human-readable report (String). path is shown in the header.
    def report(source, path)
      es = emits(source)
      cs = consumers(source)
      out = +"spinel-ebpf describe: #{path}\n\n"

      out << "emit sites (kernel -> ringbuf):\n"
      out << "  (none)\n" if es.empty?
      es.each { |e| out << format("  L%-4d %-15s arity %d  %s  %s\n", e[:line], e[:name], e[:arity], kind_label(e[:kind]), e[:text]) }

      out << "\nconsumers (ringbuf -> Ruby):\n"
      out << "  (none)\n" if cs.empty?
      cs.each { |c| out << format("  L%-4d %-13s |%s|  %s\n", c[:line], c[:consumer], c[:params].join(", "), kind_label(c[:kind])) }

      out << "\nbinding (matched by kind; payload is positional __s64, meaning is the emit args):\n"
      kinds = (es.map { |e| e[:kind] } + cs.map { |c| c[:kind] }).uniq
      warnings = []
      kinds.each do |k|
        ek = es.select { |e| e[:kind] == k }
        ck = cs.select { |c| c[:kind] == k }
        prod = ek.map { |e| "#{e[:name]}@L#{e[:line]}" }.join(", ")
        cons = ck.map { |c| "#{c[:consumer]}@L#{c[:line]}" }.join(", ")
        mark = (!ek.empty? && !ck.empty?) ? "OK" : "!!"
        out << format("  %-7s producers[%s] -> consumers[%s]  %s\n", kind_label(k), prod, cons, mark)
        warnings << "#{kind_label(k)}: emit has no matching on_emit#{k}" if !ek.empty? && ck.empty?
        warnings << "#{kind_label(k)}: on_emit#{k} has no matching emit" if ek.empty? && !ck.empty?
        ck.each do |c|
          want = EMITS.values.find { |v| v[:kind] == k }&.dig(:arity)
          warnings << "L#{c[:line]} on_emit#{k}: block params #{c[:nparams]} != emit arity #{want}" if want && c[:nparams] != want
        end
        warnings << "#{kind_label(k)}: #{ek.length} emit sites of the same kind -> indistinguishable at the consumer (no per-site tag support)" if ek.length > 1 && !ck.empty?
      end

      # Named events (emit :NAME / on_emit :NAME), bound by name+tag.
      ne = named_emits(source)
      nc = named_consumers(source)
      unless ne.empty? && nc.empty?
        out << "\nnamed events (bound by name; tag in pair field-a):\n"
        names = (ne.map { |e| e[:name] } + nc.map { |c| c[:name] }).uniq
        tags = {}
        names.each do |nm|
          tag = SpinelEbpf::Consumer.name_tag(nm)
          ep = ne.select { |e| e[:name] == nm }
          cp = nc.select { |c| c[:name] == nm }
          prod = ep.map { |e| "emit@L#{e[:line]}" }.join(", ")
          cons = cp.map { |c| "on_emit@L#{c[:line]}" }.join(", ")
          mark = (!ep.empty? && !cp.empty?) ? "OK" : "!!"
          out << format("  :%-12s tag=%#x  producers[%s] -> consumers[%s]  %s\n", nm, tag, prod, cons, mark)
          warnings << ":#{nm}: emit has no matching on_emit :#{nm}" if !ep.empty? && cp.empty?
          warnings << ":#{nm}: on_emit :#{nm} has no matching emit" if ep.empty? && !cp.empty?
          (tags[tag] ||= []) << nm
        end
        tags.each_value { |ns| warnings << "tag collision: #{ns.map { |x| ":#{x}" }.join(', ')} share the same tag" if ns.length > 1 }
      end

      out << "\nwarnings:\n"
      out << "  (none)\n" if warnings.empty?
      warnings.each { |w| out << "  - #{w}\n" }
      out
    end
  end
end
