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
require_relative "param"
require_relative "common_filter"
require_relative "keep_filter"

module SpinelEbpf
  module Introspect
    module_function

    # Scan the source for capability builtins and group the
    # hits by domain. Text-based (like emits/consumers), best-effort: drop trailing
    # comments per line, then whole-word match each registered builtin. The
    # lookbehind (?<![\w.]) keeps `path_eq` from matching inside `parent_path_eq`
    # (preceded by `_`) or a `sk.foo` receiver. Returns {domain => [builtin(sorted)]}.
    # The multi-symbol `on` forms in this source.
    #
    # Text-scanned, like every other section of `describe` -- the point of the
    # command is to answer questions about a file without building it, so it
    # never runs the codegen. The consequence is that the mechanism reported here
    # is what the codegen WOULD pick from the same two inputs (list length,
    # `via:`); SPNL_ATTACH_MULTI is a measurement knob and deliberately not
    # consulted, since describing an environment variable's effect on a file
    # would make the description depend on who is reading it.
    def multi_attach_sets(source)
      source.scan(/^\s*on\s+:(\w+)\s*,\s*%w\[([^\]]*)\]([^\n]*)/).map do |kind, body, rest|
        via = rest[/via:\s*:(\w+)/, 1]
        { kind: kind, syms: body.split(/\s+/).reject(&:empty?), via: via }
      end
    end

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

    # For this channel's type-driven properties (the ones with a `value_map`):
    # the CLOSED SET of values, and where the names come from (the authority).
    # This is the surface that answers "what can end up in `spnl.conn.tcp_state`"
    # without running anything.
    #
    # And: that this channel's records also become metrics, and WHAT THAT COSTS.
    # A metric's cost is not in its value, it is in its labels -- get the
    # cardinality wrong and the spans stay correct, the exit status stays 0, and
    # only the bill moves. So describe always prints the bound on the number of
    # series and where in the declaration that bound comes from.
    # Nothing is printed for a probe that never pushes metrics (a probe that emits
    # no metrics should not be made to talk about metrics), and that decision is
    # made here rather than by the caller.
    def metric_lines(cid)
      c = SpinelEbpf::Capabilities.record_channel(cid)
      ms = c && Array(c[:metrics])
      return [] if ms.nil? || ms.empty?
      lines = []
      ms.each do |m|
        val = m[:value_from].to_s.empty? ? "records" : "#{m[:value_from]} [#{m[:value_unit]} -> #{m[:unit]}]"
        lines << format("    metric: %s (%s, unit %s, value %s)  series <= %d\n",
                        m[:name], m[:kind], m[:unit], val, m[:series_bound])
        Array(m[:labels]).each do |l|
          how = l[:bound_from] == "declared_set" ?
                "declared set (#{Array(l[:values]).length}) + #{l[:fallback].inspect}; " \
                "anything outside the set folds into the fallback = **declared coarsening** " \
                "(the span still carries the exact value)" :
                "value map `#{l[:value_map]}` is closed (no coarsening)"
          lines << format("      label %-26s <- ev.%-12s bound %-4d %s\n", l[:key], l[:from], l[:bound], how)
        end
        lines << format("      push: spnl_otlp_record_metrics_push(endpoint)%s\n",
                        m[:kind] == "histogram" ? "   buckets #{m[:bounds]}" : "")
      end
      lines
    end

    def value_map_lines(cid)
      props = SpinelEbpf::Capabilities.record_properties(cid).select { |p| p[:value_map] }
      return [] if props.empty?
      lines = []
      props.each do |p|
        m = SpinelEbpf::Capabilities.record_value_map(p[:value_map])
        next unless m
        names = Array(m[:values]).map { |v| "#{v[:value]}=#{v[:name]}" }
        lines << format("    values: ev.%s <- %s  (value map `%s`: %d values, anything else \"%s\")\n",
                        p[:name], p[:source].to_s.sub(/\s*->.*\z/, ""), m[:id],
                        names.length, m[:unknown])
        names.each_slice(6) { |sl| lines << "      #{sl.join('  ')}\n" }
        lines << format("      authority: %s\n", m[:authority].to_s.split(/(?<=\.)\s/).first.to_s)
      end
      lines
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

    # `# @intent` / `# @expect` -- what the author says the probe records.
    # **Never checked.**
    #
    # Whether a probe measures the thing it was meant to measure cannot be
    # decided mechanically, and there is a measurement behind that claim: an
    # audit probe emitting two of its three str records per event balanced
    # perfectly -- the channel report read `in 30 out 30` -- while the spans it
    # produced carried the process name in the position that is documented to
    # hold the file path. Counts agreeing is not evidence that meanings agree.
    #
    # So this is not a place to add a check. It is a place to put the author's
    # claim next to the attributes the probe actually emits, and leave the
    # comparison to whoever reads them -- a person or a model. Presenting it as
    # a check is the dangerous way for this feature to break: it would be read
    # as "writing @intent makes the probe safe".
    ANNOTATION_RE = /^\s*#\s*@(intent|expect)\b[:：]?\s*(.*)$/.freeze
    # A continuation line must be indented at least four spaces past the `#`.
    # Requiring the indent keeps an ordinary comment that happens to follow an
    # annotation from being swallowed into it: showing something the author did
    # not write as the author's intent is as bad as dropping what they did.
    ANNOTATION_CONT_RE = /^\s*#\s{4,}(\S.*)$/.freeze

    def annotations(source)
      out  = []
      prev = -1   # last line taken (annotation or continuation); continuations must be adjacent
      source.each_line.with_index(1) do |ln, i|
        if (m = ANNOTATION_RE.match(ln))
          text = m[2].strip
          next if text.empty?
          out << { line: i, tag: m[1], text: text }
          prev = i
        elsif !out.empty? && i == prev + 1 && (c = ANNOTATION_CONT_RE.match(ln))
          out.last[:text] = "#{out.last[:text]} #{c[1].strip}"
          prev = i
        end
      end
      out
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
          # The CLOSED SET behind a type-driven derivation. Without printing it
          # here, the only way to learn what an attribute's value can be is to run
          # the probe and look at one -- the same position as being handed
          # `error=2` and left to work out the rest.
          value_map_lines(cid).each { |l| out << l }
          metric_lines(cid).each { |l| out << l }
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

      # One definition, several attach points. The purpose of this section is to
      # SAY WHICH LOWERING WAS CHOSEN. It is invisible from the body -- that is
      # the design -- but it is very much visible from the deployment, because
      # kprobe_multi raises the kernel floor to 5.18. So rather than "invisible,
      # therefore not worth writing down", the rule is: kept out of the body, and
      # named here. The index-to-symbol table is printed too, because the output
      # of a probe that emits `attached_index` cannot be read without it.
      multis = multi_attach_sets(source)
      unless multis.empty?
        out << "\nmulti-symbol attach (one definition -> several attach points):\n"
        multis.each do |m|
          picked = m[:via] || (m[:syms].length >= SpinelEbpf::Capabilities::ATTACH_MULTI_THRESHOLD ? "multi" : "expand")
          why = if m[:via]
                  "stated with `via: :#{m[:via]}`"
                else
                  "auto (#{m[:syms].length} #{m[:syms].length >= SpinelEbpf::Capabilities::ATTACH_MULTI_THRESHOLD ? '>=' : '<'} " \
                  "threshold #{SpinelEbpf::Capabilities::ATTACH_MULTI_THRESHOLD})"
                end
          out << format("  on :%s, %d symbols  ->  %s  (%s)\n", m[:kind], m[:syms].length, picked, why)
          if picked == "multi"
            out << "    one SEC(\"kprobe.multi\") plus a per-symbol cookie. " \
                   "**This raises the kernel floor to 5.18** (expanding keeps it at 5.2) --\n" \
                   "    `via: :expand` is there for targets that cannot go that high.\n"
          else
            out << "    expanded into #{m[:syms].length} SEC(\"kprobe/<func>\") programs (N programs, N attach fds).\n"
          end
          out << "    attached_index maps to:\n"
          m[:syms].each_with_index { |s, i| out << format("      %-3d %s\n", i, s) }
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
        # Gates that turn on the attach kind rather than on a SEC allowlist --
        # "is this a hook where the current task is the subject of the event", and
        # the like. A builtin with a SEC gate was already printed above, so it is
        # not printed twice.
        blts.each do |b|
          next if SpinelEbpf::Capabilities.gate_for(b)
          next unless SpinelEbpf::Capabilities::CONTEXT_REQUIREMENTS[b]
          ctx = SpinelEbpf::Capabilities.context_strings(b)
          out << format("    ! %s is only usable in: %s (the codegen enforces this at compile time)\n", b, ctx.join(" ")) if ctx
        end
        # Units and byte order of a return value. Only the values that would pass
        # silently when misread appear here -- the same job describe does for a
        # packed record's notes, done for a builtin.
        blts.each do |b|
          sem = SpinelEbpf::Capabilities.value_semantics_for(b)
          out << format("    = %s -> %s\n", b, sem) if sem
        end
      end

      # What this probe can be narrowed by WITHOUT RECOMPILING. This tends to be
      # the most useful section for a model: knowing that the same binary can be
      # narrowed through the environment means not proposing a fresh .rb for a
      # probe that already has a `param`.
      prms = SpinelEbpf::Param.scan_source(source)
      unless prms.empty?
        out << "\nruntime parameters (written into .rodata before load; no recompile):\n"
        prms.each do |p|
          e = SpinelEbpf::Param::Entry.new(name: p[:name], default: p[:default])
          out << format("  L%-4d %-16s default %-8d %s\n", p[:line], p[:name], p[:default], e.env_name)
          unless SpinelEbpf::Param.referenced?(source, p[:name])
            warnings << "no handler appears to read param :#{p[:name]} -- setting " \
                        "#{e.env_name} changes nothing (the codegen rejects this at compile time)"
          end
        end
        out << "  ^ the value is fixed at load time (.rodata is frozen). Left at its default,\n"
        out << "    the branch that reads it is folded away by the verifier and **disappears**.\n"
      end

      # The common filter. A single declaration is injected at the head of every
      # handler, so **reading a handler body will not show it** -- printing it here
      # is the price of that implicit change of meaning. And what a reader wants to
      # know first is not "what can this probe be narrowed by" but "is it narrowed
      # at all", so one line is printed even when there is no declaration.
      fkeys = SpinelEbpf::CommonFilter.scan_source(source)
      handlers = source.scan(/^\s*def\s+([a-z_0-9]+__[A-Za-z_0-9]*)/).flatten
      out << "\nin-kernel common filter (one declaration, injected at the head of every attach handler):\n"
      if fkeys.empty?
        out << "  (none) this probe is **not narrowed** -- events from every process and every cgroup come out.\n"
        out << "         To narrow it, put `filter_by :pid, :comm` (or similar) at the top level. Keys: " \
               "#{SpinelEbpf::CommonFilter::KEYS.map(&:name).join(' ')}.\n"
      else
        fkeys.each do |f|
          known, unknown = f[:keys].partition { |k| SpinelEbpf::CommonFilter::KEYS_BY_NAME.key?(k) }
          out << format("  L%-4d filter_by %s\n", f[:line], f[:keys].map { |k| ":#{k}" }.join(", "))
          known.each do |k|
            e = SpinelEbpf::CommonFilter::KEYS_BY_NAME[k]
            out << format("        %-12s %-22s unset=%-4s %s\n",
                          k, e.env_name, e.unset.to_s.empty? ? '""' : e.unset.to_s, e.desc)
          end
          unless unknown.empty?
            warnings << "unknown filter_by key #{unknown.map { |k| ":#{k}" }.join(' ')} -- " \
                        "the keys are #{SpinelEbpf::CommonFilter::KEYS.map(&:name).join(' ')} " \
                        "(the codegen rejects this at compile time)"
          end
        end
        out << "  ^ only events matching **every** key that is set survive (AND). An unset key does not\n"
        out << "    constrain, and the verifier folds that decision away along with the helper call.\n"
        out << "    Applied to these attach handlers:\n"
        out << (handlers.empty? ? "      (no attach handler found in this source)\n"
                                : "      #{handlers.join(' ')}\n")
      end

      # The userspace consumer filter. Where the section above answers "is it
      # narrowed in the kernel", this one answers "**is it thrown away after being
      # drained**". It is printed when there is either a typed consumer or a
      # declaration -- a probe with no consumer is not made to talk about
      # consumers. One line when there is no declaration, for the same reason as
      # above: what a reader wants first is whether anything is being dropped.
      keeps = SpinelEbpf::KeepFilter.scan_source(source)
      unless keeps.empty? && rcs.empty?
        out << "\nuserspace consumer filter (dropped after the drain, before the send; span contents unchanged):\n"
        if keeps.empty?
          ex = rcs.map { |r| r[:channel] }.uniq.first
          exp = ex && SpinelEbpf::KeepFilter.example_predicate(ex)
          out << "  (none) this consumer **sends every record it drains**.\n"
          if exp
            out << format("         To narrow it, put `keep_if :%s, %s: :%s` (or similar) at the top level " \
                          "(properties are ev.<name>; operators: %s).\n",
                          ex, exp[:prop], exp[:op], SpinelEbpf::KeepFilter::OPS.map(&:name).join(" "))
          end
        else
          keeps.each do |d|
            out << format("  L%-4d keep_if :%s, %s\n", d[:line], d[:channel],
                          d[:preds].map { |p| "#{p[:prop]}: :#{p[:op]}" }.join(", "))
            props = SpinelEbpf::Capabilities.record_properties(d[:channel])
            unless SpinelEbpf::Capabilities.typed_record_channel_ids.include?(d[:channel])
              warnings << "keep_if :#{d[:channel]} -- this channel publishes no typed consumer " \
                          "(the codegen rejects this at compile time)"
              next
            end
            # Declared, but with no consumer: a filter wired to nothing. Compiling
            # rejects it, but describe also runs on sources that do not compile, so
            # it is said here too -- the same hole as code that is written and never
            # called.
            if rcs.none? { |r| r[:channel] == d[:channel] }
              warnings << "keep_if :#{d[:channel]} is present but `on_emit :#{d[:channel]} do |ev|` is " \
                          "not -- the channel is never drained, so it narrows nothing " \
                          "(the codegen rejects this at compile time)"
            end
            d[:preds].each do |pr|
              p = props.find { |x| x[:name].to_s == pr[:prop] }
              unless p
                warnings << "unknown property `#{pr[:prop]}` in keep_if :#{d[:channel]} -- " \
                            "the properties are #{props.map { |x| x[:name] }.join(' ')} (the codegen rejects this at compile time)"
                next
              end
              op = SpinelEbpf::KeepFilter.op(pr[:op])
              unless op && op.types.include?(p[:expose].to_s)
                warnings << "keep_if :#{d[:channel]}, #{pr[:prop]}: :#{pr[:op]} -- " \
                            "that operator does not apply to a #{p[:expose]} property (the codegen rejects this at compile time)"
                next
              end
              where = SpinelEbpf::KeepFilter.placement(d[:channel], pr[:prop], pr[:op])
              out << format("        %-16s %-26s %-9s unset=keeps everything\n",
                            pr[:prop], SpinelEbpf::KeepFilter.env_name(d[:channel], pr[:prop]), op.name)
              out << format("          %s\n", SpinelEbpf::KeepFilter::PLACEMENT_NOTE[where])
            end
            unless d[:bad].empty?
              warnings << "not a predicate in keep_if :#{d[:channel]}: #{d[:bad].map(&:inspect).join(' ')} " \
                          "(the codegen rejects this at compile time)"
            end
          end
          out << "  ^ only records matching **every** predicate that is set become spans (AND -- the same\n"
          out << "    rule as the in-kernel filter). What is dropped is the record, not part of the span:\n"
          out << "    a record that passes becomes the span the declaration describes, byte for byte,\n"
          out << "    because the egress declaration is what defines it.\n"
        end
        out << "  * \"stop after the first K\" is a **different** thing = SPNL_MAX_EVENTS. keep_if only\n"
        out << "    changes which records are sent and is not a count limit; setting both gives you\n"
        out << "    \"the first K that pass the filter\"; sort/top-N is not implemented.\n"
      end

      # Put the author's claim right next to the attributes that actually go out.
      # Reconciling the two stays a reader's job -- deliberately not a warning,
      # because a warning would make writing the annotation look like passing a
      # check.
      anns = annotations(source)
      out << "\nstated intent (material to compare against; **not checked**):\n"
      if anns.empty?
        out << "  (none) writing `# @intent <what this probe records>` and\n"
        out << "         `# @expect <what should come out, in one line>` puts the\n"
        out << "         claim beside the egress attributes above. Neither is checked.\n"
      else
        anns.each { |a| out << format("  L%-4d @%-6s %s\n", a[:line], a[:tag], a[:text]) }
        out << "  ^ compare these against the egress attributes of the record channels\n"
        out << "    above. Counts agreeing is not evidence that meanings agree: a probe\n"
        out << "    whose str triples were split still balanced at in == out while\n"
        out << "    putting the process name where the file path belongs.\n"
      end

      out << "\nwarnings:\n"
      out << "  (none)\n" if warnings.empty?
      warnings.each { |w| out << "  - #{w}\n" }
      out
    end
  end
end
