# frozen_string_literal: true
#
# `spinel-ebpf describe` -- introspection over emitters and consumers.
#
# What actually arrives at an `on_emit` block is otherwise only knowable by
# convention: positional __s64 values whose meaning is whatever the emit call
# passed. This module scans the source, pairs each emit site (its kind, arity and
# call text) with each consumer (its kind and block parameters), and reports the
# matches, the arity mismatches and the missing halves.
require_relative "consumer"
require_relative "capabilities"

module SpinelEbpf
  module Introspect
    module_function

    # Scan the source for capability builtins and group the
    # hits by domain. Text-based (like emits/consumers), best-effort: drop trailing
    # comments per line, then whole-word match each registered builtin. The
    # lookbehind (?<![\w.]) keeps `path_eq` from matching inside `parent_path_eq`
    # (preceded by `_`) or a `sk.foo` receiver. Returns {domain => [builtin(sorted)]}.
    def builtin_domains(source)
      code = source.each_line.map { |l| l.chomp.sub(/#.*\z/, "") }.join("\n")
      names = SpinelEbpf::Capabilities.all_builtins.select do |b|
        code =~ /(?<![\w.])#{Regexp.escape(b)}(?![\w])/
      end
      SpinelEbpf::Capabilities.domains_used(names)
    end

    # Collect the packed-record emit sites, with line numbers. Unlike the scalar
    # emits, these builtins -- emit_dns and the like -- write a *typed record* into
    # a ringbuf. Which channel each one writes is part of the record contract that
    # capabilities reports; the offsets are computed by the generator.
    # [{ line:, name:, channel: }]
    def record_emits(source)
      prods = SpinelEbpf::Capabilities.record_producers
      return [] if prods.empty?
      source.each_line.with_index(1).flat_map do |line, n|
        body = line.chomp.sub(/#.*\z/, "")
        prods.filter_map do |p|
          next unless body =~ /(?<![\w.])#{Regexp.escape(p)}\s*\(/
          ch = SpinelEbpf::Capabilities.record_channel_for(p)
          { line: n, name: p, channel: ch[:id] }
        end
      end
    end

    NAMED_EMIT_RE     = /\A\s*emit\s+:(\w+)\s*,\s*(.+?)\s*(?:#.*)?\z/.freeze
    NAMED_CONSUMER_RE = /\A\s*on_emit\s+:(\w+)\s+do\s*\|\s*(\w+)\s*\|/.freeze

    # [{ line:, name:, text: }] for `emit :NAME, expr` producer sites
    def named_emits(source)
      source.each_line.with_index(1).filter_map do |line, n|
        m = NAMED_EMIT_RE.match(line.chomp)
        m && { line: n, name: m[1], text: line.strip }
      end
    end

    # [{ line:, name:, param: }] for `on_emit :NAME do |v|` consumer sites.
    # `on_emit :<record channel>` is a *typed record* consumer, not a named
    # event -- same syntax, different binding -- so it is reported by
    # record_consumers below and excluded here (otherwise every typed consumer
    # draws a bogus "no matching emit :dns" warning).
    def named_consumers(source)
      ids = SpinelEbpf::Capabilities.typed_record_channel_ids   # typed channels only
      source.each_line.with_index(1).filter_map do |line, n|
        m = NAMED_CONSUMER_RE.match(line.strip)
        m && !ids.include?(m[1]) && { line: n, name: m[1], param: m[2] }
      end
    end

    # [{ line:, channel:, param:, props: [name,...] }] for
    # `on_emit :<channel> do |ev|` typed record consumers. `props` is which
    # declared properties the block actually reads (`ev.qname` -> "qname"),
    # scanned the same best-effort way as the rest of describe.
    #
    # a program may consume several channels, and two blocks may even share
    # the parameter name (`ev`), so "which properties does this consumer read" is
    # scanned **inside the block** (indentation-delimited, the same boundary
    # Consumer#transform_record uses) instead of over the whole file. Scanning the
    # file would credit the dns consumer with `ev.status` from the http block.
    def record_consumers(source)
      chans = SpinelEbpf::Capabilities.typed_record_channel_ids   # typed channels only
      return [] if chans.empty?
      lines = source.each_line.map { |l| l.chomp.sub(/#.*\z/, "") }
      sites = []
      cur = nil
      lines.each_with_index do |line, i|
        if (m = NAMED_CONSUMER_RE.match(line.strip)) && chans.include?(m[1])
          cur = { line: i + 1, channel: m[1], param: m[2], indent: line[/\A\s*/].length, body: +"" }
          sites << cur
          next
        end
        if cur
          if line =~ /\A\s{#{cur[:indent]}}end\s*\z/
            cur = nil
          else
            cur[:body] << line << "\n"
          end
        end
      end
      sites.each do |s|
        s[:props] = s[:body].scan(/(?<![\w.@:])#{Regexp.escape(s[:param])}\.(\w+)/).flatten.uniq.sort
        s.delete(:body)
        s.delete(:indent)
      end
      sites
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
          warnings << "L#{c[:line]} on_emit#{k}: #{c[:nparams]} block params, but emit has arity #{want}" if want && c[:nparams] != want
        end
        warnings << "#{kind_label(k)}: #{ek.length} emit sites of the same kind -- a consumer cannot tell them apart (there are no per-site tags)" if ek.length > 1 && !ck.empty?
      end

      # named events (emit :NAME / on_emit :NAME), bound by name+tag.
      ne = named_emits(source)
      nc = named_consumers(source)
      unless ne.empty? && nc.empty?
        out << "\nnamed events (bound by name; the tag travels in field a of the pair):\n"
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
        tags.each_value { |ns| warnings << "tag collision: #{ns.map { |x| ":#{x}" }.join(', ')} share one tag" if ns.length > 1 }
      end

      # The packed-record channels: the bytes this probe writes into a ringbuf, and
      # the span -- and semconv attributes -- those bytes eventually become. This is
      # what makes a probe reviewable: it is the one view that follows a record all
      # the way to what leaves the host, without reading any generated C.
      res = record_emits(source)
      rcs = record_consumers(source)
      unless res.empty? && rcs.empty?
        out << "\nrecord channels (the ringbuf byte layout, and the span it becomes):\n"
        (res.group_by { |r| r[:channel] }.keys | rcs.map { |c| c[:channel] }).each do |cid|
          sites = res.select { |r| r[:channel] == cid }
          c = SpinelEbpf::Capabilities.record_channel(cid)
          prod = sites.map { |s| "#{s[:name]}@L#{s[:line]}" }.join(", ")
          out << format("  %-5s %s (%d B, map %s) <- %s\n", cid, c[:record_struct], c[:record_bytes],
                        c[:ringbuf_map], prod.empty? ? "(no producer in this unit)" : prod)
          c[:fields].each do |f|
            type = f[:count].to_i > 0 ? "#{f[:ctype]}[#{f[:count]}]" : f[:ctype]
            out << format("    @%-4d %-14s %-22s %s\n", f[:offset], f[:name], type, f[:note])
          end
          # When a typed consumer is present, report which of the record's
          # properties its block actually reads -- that is, what information has
          # crossed into Ruby.
          typed = rcs.select { |r| r[:channel] == cid }
          typed.each do |t|
            props = SpinelEbpf::Capabilities.record_properties(cid)
            out << format("    consumer: on_emit :%s do |%s|@L%d  (%s)\n", cid, t[:param], t[:line],
                          props.map { |p| "#{t[:param]}.#{p[:name]}" }.join(" "))
            used = Array(t[:props])
            out << format("      reads: %s\n",
                          used.empty? ? "(reads nothing yet)" : used.map { |p| "#{t[:param]}.#{p}" }.join(" "))
          end
          e = c[:egress]
          next unless e
          out << format("    egress: %s -> span \"%s\" (SpanKind %s)\n",
                        e[:push_fn], e[:span_name], e[:span_kind])
          e[:attributes].each do |a|
            out << format("      %-24s %-8s <- %s  [%s]\n", a[:key], a[:stability], a[:source], a[:condition])
          end
          unless Array(e[:enrichers]).empty?
            out << format("      + enrichers (environment-gated, no probe change): %s\n", Array(e[:enrichers]).join(", "))
          end
          # A whole class of bug: the kernel only accumulates records. Without a
          # drain in userspace, the program compiles and the verifier is happy and
          # not one span comes out. There are two ways to drain, and either will do:
          # the short form calls the push FFI, the explicit form receives the
          # records in an `on_emit :<channel>` block.
          drained = source =~ /(?<![\w.])#{Regexp.escape(e[:push_fn])}(?![\w])/ || !typed.empty?
          unless drained
            warnings << "#{cid}: neither #{e[:push_fn]} nor `on_emit :#{cid} do |ev|` appears in " \
                        "the source, so nothing drains the records and no span is produced"
          end
          # The same hole in reverse: a consumer with no producer drains nothing.
          if sites.empty? && !typed.empty?
            warnings << "#{cid}: `on_emit :#{cid}` is present, but this unit calls none of the " \
                        "builtins that write the record (#{Array(c[:producers]).join(' / ')}), so none will arrive"
          end
          # The explicit form has the same hole: writing the block but never calling
          # `consume_records(t)` means the drain loop never runs.
          if !typed.empty? && source !~ /(?<![\w.])consume_records\s*\(/
            warnings << "#{cid}: `on_emit :#{cid}` is present but consume_records(timeout_ms) is " \
                        "never called, so the handler never runs and no span is produced"
          end
        end
      end

      # Which capability domains does this unit touch?
      doms = builtin_domains(source)
      out << "\ncapability domains:\n"
      out << "  (none)\n" if doms.empty?
      doms.each do |dom, blts|
        out << format("  %-14s %s\n", dom, blts.join(" "))
        gated = blts.filter_map { |b| g = SpinelEbpf::Capabilities.gate_for(b); [b, g] if g }
        gated.each do |b, g|
          out << format("    ! %s is only usable in: %s\n", b, g[:valid_secs].join(" | "))
        end
      end

      out << "\nwarnings:\n"
      out << "  (none)\n" if warnings.empty?
      warnings.each { |w| out << "  - #{w}\n" }
      out
    end
  end
end
