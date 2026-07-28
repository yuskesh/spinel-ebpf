# frozen_string_literal: true
#
# userspace consumer DSL — source transform.
#
# spinel's native `-c` rejects unknown top-level calls, so spinel-ebpf rewrites
# the DSL into plain Ruby before handing the source to spinel.
#
# Two styles (a program uses one):
#
#  (A) raw, matched by kind/arity (S1-S5):
#        on_emit do |v|            -> def __spnl_consume_int(v)
#        on_emit_pair do |a, b|    -> def __spnl_consume_pair(a, b)
#        on_emit_pair do |a, b, ts|-> +timestamp
#
#  (B) NAMED (distinguishes emit *sources* by name; subsumes per-site
#      tags). Producer/consumer bound by name; lowered onto the pair ringbuf with
#      the name's stable tag in field-a, value in field-b:
#        emit :http_open, dur      -> spnl_emit_pair(<tag>, (dur))     [kernel]
#        on_emit :http_open do |v| -> def __spnl_named_http_open(v)    [userspace]
#      The driver drains the pair ringbuf and dispatches each record to the
#      handler whose tag matches field-a. (`on_emit :sym` is distinct from the
#      reactor's `on :kind` kernel-handler DSL, so no namespace clash.)
#
#  (C) TYPED RECORD -- the packed-record channels: dns, and so on. The symbol
#      is a *record channel id* from the record contract (S1-S3,
#      src/codegen_c/record_schema.h), not a user-chosen event name:
#        on_emit :dns do |ev|      -> def __spnl_consume_rec_dns(ev)
#          ev.qname                ->   SpnlRecDns.spnl_rec_dns_qname(ev)
#          send_otlp(to_span(ev),e)->   SpnlRecSink.spnl_otlp_span_send(
#                                         SpnlRecDns.spnl_rec_dns_to_span(ev), e)
#        end
#      `ev` is an opaque handle (the record's index in the drain); the bytes stay
#      in C and every property is read through a generated accessor, so the field
#      set has one author (the schema table) and `ev.typo` is a compile error.
#      consume_records(t) drains, dispatches each record to the block, and flushes
#      the send batch. The concise form (`spnl_otlp_dns_span_push(ep)`) still
#      works and goes through the same span builder -- it is the sugar for
#      "to_span + send_otlp every record".
#
#      MULTI-CHANNEL. One program may consume several typed
#      channels. `to_span` stays ONE generic verb (layer 1 does not grow a name per
#      channel); which channel it means is resolved from the block it is
#      written in:
#        on_emit :dns  do |ev| send_otlp(to_span(ev), @ep) end   # -> dns builder
#        on_emit :http do |ev| send_otlp(to_span(ev), @ep) end   # -> http builder
#      The rule is exactly: inside `on_emit :<ch>`, a `to_span` applied to THAT
#      block's own block parameter binds to <ch>. A program with a single typed
#      channel also resolves anywhere. Anything else -- a
#      handle copied into another variable, a `to_span` in a helper method, two
#      channels in one scope -- is NOT guessed: it is a compile error naming the
#      reason, with the escape hatch spelled out:
#        send_otlp(dns_span(ev), @ep)   # `<channel>_span(ev)` = explicit form
#      The escape hatch exists for the cases the scope rule cannot reach; it is not
#      the main way to write this.
#
#  consume_events(t)             -> __spnl_consume_events(t)
#  consume_records(t)            -> __spnl_consume_records(t)      (C)
#
# Generated __spnl_* methods are forced :native by partition and excluded from
# the eBPF IR (cc_is_consumer_fn). MVP named: 1 value per event; don't mix named
# events with raw on_emit_pair (both use the pair ringbuf).
require_relative "capabilities"

module SpinelEbpf
  module Consumer
    # Loud, actionable rejection: a typed consumer that reads a
    # property the record does not have is a compile error naming the real set,
    # not a link error or a silent zero.
    class Error < StandardError; end

    module_function

    DRIVER_FN = "__spnl_consume_events"
    RECORD_DRIVER_FN = "__spnl_consume_records"

    KINDS = {
      ""      => { fn: "__spnl_consume_int",  count: "spnl_consume_count_int",  varity: 1,
                  getters: %w[spnl_cget],                         ts_getter: "spnl_cget_ts" },
      "_pair" => { fn: "__spnl_consume_pair", count: "spnl_consume_count_pair", varity: 2,
                  getters: %w[spnl_cget_pair_a spnl_cget_pair_b], ts_getter: "spnl_cget_pair_ts" },
    }.freeze

    ON_EMIT_RE       = /\A(\s*)on_emit(_pair)?\s+do\s*\|\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*\|\s*(?:#.*)?\z/.freeze
    ON_EMIT_NAMED_RE = /\A(\s*)on_emit\s+:(\w+)\s+do\s*\|\s*([A-Za-z_]\w*)\s*\|\s*(?:#.*)?\z/.freeze
    EMIT_NAMED_RE    = /\A(\s*)emit\s+:(\w+)\s*,\s*(.+?)\s*(?:#.*)?\z/.freeze
    CONSUME_CALL_RE  = /\bconsume_events\b/.freeze
    CONSUME_REC_RE   = /\bconsume_records\b/.freeze

    # Stable name -> tag (FNV-1a 32-bit, mapped to a positive int32 the pair
    # field-a getter (an `int`) can carry). Producer + consumer compute it the
    # same way, so no registry is needed.
    def name_tag(name)
      h = 2166136261
      name.to_s.each_byte { |b| h = ((h ^ b) * 16777619) & 0xFFFFFFFF }
      (h % 0x7FF00000) + 0x10000
    end

    # named consumer sites: { name => param }
    def named(source)
      source.each_line.each_with_object({}) do |l, h|
        m = ON_EMIT_NAMED_RE.match(l.chomp)
        h[m[2]] ||= m[3] if m
      end
    end

    # raw kinds: { suffix => nparams }
    def present(source)
      source.each_line.each_with_object({}) do |l, h|
        m = ON_EMIT_RE.match(l.chomp)
        h[m[2] || ""] ||= m[3].split(",").map(&:strip).reject(&:empty?).length if m
      end
    end

    def present?(source)
      !named(source).empty? || !present(source).empty? || !record_consumers(source).empty?
    end

    def native_method_name?(name)
      name == DRIVER_FN || name.start_with?("__spnl_consume_", "__spnl_named_")
    end

    def transform(source)
      rec = record_consumers(source)
      return transform_record(source, rec) unless rec.empty?

      nm = named(source)
      return transform_named(source, nm) unless nm.empty?

      kinds = present(source)
      return source if kinds.empty?
      out = rewrite_lines(source) { |line| line }
      out + driver_prelude(kinds)
    end

    # ---- raw (kind-based) path ----

    def rewrite_lines(source)
      source.each_line.map do |line|
        if (m = ON_EMIT_RE.match(line.chomp))
          "#{m[1]}def #{KINDS[m[2] || ''][:fn]}(#{m[3]})\n"
        else
          yield line.gsub(CONSUME_CALL_RE, DRIVER_FN)
        end
      end.join
    end

    def driver_prelude(kinds)
      ffi = [["spnl_consume_poll", "[:int]", ":int"]]
      kinds.each do |suffix, nparams|
        info = KINDS[suffix]
        ffi << [info[:count], "[]", ":int"]
        info[:getters].each { |g| ffi << [g, "[:int]", ":int"] }
        ffi << [info[:ts_getter], "[:int]", ":long"] if nparams > info[:varity]
      end
      ffi_decls = ffi.uniq.map { |sym, a, r| "  ffi_func :#{sym}, #{a}, #{r}" }.join("\n")
      blocks = kinds.each_with_index.map { |(suffix, np), idx| drain_block(KINDS[suffix], np, idx) }.join("\n")
      driver_module(ffi_decls, blocks)
    end

    def drain_block(info, nparams, idx)
      cnt = "n#{idx}"; ix = "i#{idx}"
      args = info[:getters].map { |g| "SpnlConsumeFFI.#{g}(#{ix})" }
      args << "SpnlConsumeFFI.#{info[:ts_getter]}(#{ix})" if nparams > info[:varity]
      ["  #{cnt} = SpnlConsumeFFI.#{info[:count]}", "  #{ix} = 0",
       "  while #{ix} < #{cnt}", "    #{info[:fn]}(#{args.join(', ')})",
       "    #{ix} = #{ix} + 1", "  end"].join("\n")
    end

    # ---- named path ----

    def transform_named(source, names)
      out = source.each_line.map do |line|
        body = line.chomp
        if (m = ON_EMIT_NAMED_RE.match(body))
          "#{m[1]}def __spnl_named_#{m[2]}(#{m[3]})\n"
        elsif (m = EMIT_NAMED_RE.match(body))
          "#{m[1]}spnl_emit_pair(#{name_tag(m[2])}, (#{m[3]}))\n"  # tag in field-a, value in field-b
        else
          line.gsub(CONSUME_CALL_RE, DRIVER_FN)
        end
      end.join
      out + named_prelude(names)
    end

    def named_prelude(names)
      ffi_decls = [
        "  ffi_func :spnl_consume_poll, [:int], :int",
        "  ffi_func :spnl_consume_count_pair, [], :int",
        "  ffi_func :spnl_cget_pair_a, [:int], :int",
        "  ffi_func :spnl_cget_pair_b, [:int], :int",
      ].join("\n")
      dispatch = names.keys.map { |n| "    __spnl_named_#{n}(v) if tag == #{name_tag(n)}" }.join("\n")
      <<~RUBY

        # --- generated named-consumer driver (do not edit) ---
        module SpnlConsumeFFI
        #{ffi_decls}
        end
        def #{DRIVER_FN}(t)
          SpnlConsumeFFI.spnl_consume_poll(t)
          n = SpnlConsumeFFI.spnl_consume_count_pair
          i = 0
          while i < n
            tag = SpnlConsumeFFI.spnl_cget_pair_a(i)
            v = SpnlConsumeFFI.spnl_cget_pair_b(i)
        #{dispatch}
            i = i + 1
          end
        end
      RUBY
    end

    # ---- the typed record path ----
    #
    # The distinguishing rule: `on_emit :<sym>` is a TYPED RECORD consumer when
    # <sym> is a record channel id declared by the record contract, and a named
    # named event otherwise. Channel ids are a small closed set that comes from
    # the schema table, so the classification is data-driven rather than a
    # heuristic -- and the one ambiguous case (a program that also produces an
    # named event of the same name) is rejected loudly below.

    # Only channels that PUBLISH a typed consumer count here. A channel
    # can be declarative (schema + generated mirror) without offering `ev` -- and
    # for those, `on_emit :<id>` must keep meaning a named event, or adding a
    # declaration would silently change what an existing program does.
    def record_channel_ids
      SpinelEbpf::Capabilities.typed_record_channel_ids
    end

    # { channel id => block param name } for `on_emit :<channel> do |ev|` sites.
    def record_consumers(source)
      ids = record_channel_ids
      return {} if ids.empty?
      source.each_line.each_with_object({}) do |l, h|
        m = ON_EMIT_NAMED_RE.match(l.chomp)
        h[m[2]] ||= m[3] if m && ids.include?(m[2])
      end
    end

    # channel id -> the generated Ruby module holding its FFI ("dns" -> SpnlRecDns)
    def record_module(chan)
      "SpnlRec" + chan.split(/[^A-Za-z0-9]/).map(&:capitalize).join
    end

    SINK_MODULE = "SpnlRecSink"

    def record_properties(chan)
      c = SpinelEbpf::Capabilities.record_channel(chan)
      Array(c && c.dig(:consumer, :properties))
    end

    # Split a source line into (code, comment). `#` only starts a comment when it
    # is at the start or preceded by whitespace *and* not inside a string literal
    # (an even number of quotes precedes it) -- the rewrites below must not touch
    # comment text, but must not mistake `"a # b"` for one either.
    def split_comment(line)
      idx = nil
      i = 0
      while (i = line.index("#", i))
        prev = i.zero? ? " " : line[i - 1]
        if (prev == " " || prev == "\t" || i.zero?) &&
           line[0...i].count('"').even? && line[0...i].count("'").even?
          idx = i
          break
        end
        i += 1
      end
      idx ? [line[0...idx], line[idx..]] : [line, ""]
    end

    def transform_record(source, recs)
      # Ambiguity guard: a named producer `emit :dns, v` plus `on_emit :dns`
      # (typed consumer) cannot both be meant. Reject rather than pick one.
      recs.each_key do |chan|
        next unless source =~ /^\s*emit\s+:#{Regexp.escape(chan)}\s*,/
        raise Error, "`on_emit :#{chan}` is a typed record consumer (channel `#{chan}` of the " \
                     "ringbuf record contract), but this program also has `emit :#{chan}, ...`, " \
                     "which declares a named event of the same name. Rename the named event " \
                     "(`emit :#{chan}_x, ...` / `on_emit :#{chan}_x`) so the two do not collide."
      end
      unless present(source).empty?
        raise Error, "this program mixes a typed record consumer (`on_emit :#{recs.keys.first}`) with a " \
                     "raw `on_emit`/`on_emit_pair` consumer. They drain different ringbufs through " \
                     "different drivers; use one style per program (S4 boundary)."
      end

      # param name -> [channel, ...]. Two blocks MAY share a parameter name (`ev`
      # in both): inside each block that name is unambiguous. It only becomes
      # ambiguous outside them, and that is where we refuse to guess.
      by_param = recs.each_with_object({}) { |(chan, param), h| (h[param] ||= []) << chan }

      out = +""
      blk = nil                        # { chan:, param:, indent: } — enclosing on_emit block
      lineno = 0
      source.each_line do |line|
        lineno += 1
        body = line.chomp
        if (m = ON_EMIT_NAMED_RE.match(body)) && recs.key?(m[2])
          blk = { chan: m[2], param: m[3], indent: m[1].length }
          out << "#{m[1]}def __spnl_consume_rec_#{m[2]}(#{m[3]})\n"
          next
        end
        if blk && body =~ /\A\s{#{blk[:indent]}}end\s*\z/
          blk = nil
          out << line
          next
        end
        code, comment = split_comment(body)
        # `next` inside the block: the block became a method, so the block-local
        # jump has to become the method-local one (`next if x` -> `return 0 if x`).
        code = code.sub(/\A(\s*)next\b/, '\1return 0') if blk
        code = rewrite_record_calls(code, recs, by_param, blk, lineno)
        out << code << comment << "\n"
      end
      out + record_prelude(recs)
    end

    # ev.<prop> / to_span(...) / <ch>_span(...) / send_otlp(...) / consume_records(...)
    # lowering for ONE source line. `blk` is the enclosing `on_emit :<ch>` block
    # (nil at top level) -- the scope the resolution rules below read.
    #
    # Only a receiver whose name is a typed consumer's block param is treated as a
    # record handle, so an unrelated `req.pid` is left alone; an unknown property
    # ON a handle is an error naming the real set (that is what "typed" buys).
    def rewrite_record_calls(code, recs, by_param, blk, lineno)
      # --- (1) ev.<prop> ------------------------------------------------------
      # Inside a block only THAT block's parameter is a handle: the other blocks'
      # parameters are not in scope there (each block became its own method), and
      # they may even share the name. Outside every block a parameter name still
      # resolves when exactly one block uses it -- that is what lets a helper
      # method take a handle, as in `def hot?(ev) ; ev.duration_ns > n ; end`.
      vars = blk ? [blk[:param]] : by_param.keys
      vars.each do |var|
        chans = blk ? [blk[:chan]] : by_param[var]
        code = code.gsub(/(?<![\w.@:])#{Regexp.escape(var)}\.(\w+)/) do
          prop = Regexp.last_match(1)
          raise Error, ambiguous_handle_msg(var, prop, chans, lineno) if chans.length > 1
          chan  = chans.first
          names = record_properties(chan).map { |p| p[:name].to_s }
          unless names.include?(prop)
            raise Error, "`#{var}.#{prop}` (line #{lineno}) — the `#{chan}` record has no property " \
                         "`#{prop}`. Available: #{names.map { |n| "#{var}.#{n}" }.join(', ')} " \
                         "(see `spinel-ebpf capabilities --json` -> channels[#{chan}].consumer)."
          end
          "#{record_module(chan)}.spnl_rec_#{chan}_#{prop}(#{var})"
        end
      end

      # --- (2) `<channel>_span(ev)` — the explicit escape hatch --
      # Named per channel, so it is never ambiguous. Reserved for the cases the
      # scope rule below cannot reach; writing it for a channel the program does
      # not consume is a compile error rather than a link error.
      record_channel_ids.each do |ch|
        next unless code =~ /(?<![\w.])#{Regexp.escape(ch)}_span\s*\(/
        unless recs.key?(ch)
          raise Error, "`#{ch}_span(...)` (line #{lineno}) names the record channel `#{ch}`, but this " \
                       "program has no `on_emit :#{ch} do |ev| ... end` block, so no #{ch} record is " \
                       "ever drained. Consume the channel first, or use " \
                       "#{recs.empty? ? 'the channel you do consume' : recs.keys.map { |c| "`#{c}_span(ev)`" }.join(' / ')}."
        end
        code = code.gsub(/(?<![\w.])#{Regexp.escape(ch)}_span\s*\(/,
                         "#{record_module(ch)}.spnl_rec_#{ch}_to_span(")
      end

      # --- (3) `to_span(...)` — resolved from the block scope -----
      # (a) inside `on_emit :<ch>`, applied to that block's own parameter -> <ch>.
      if blk
        code = code.gsub(/(?<![\w.])to_span\s*\(\s*#{Regexp.escape(blk[:param])}\s*\)/,
                         "#{record_module(blk[:chan])}.spnl_rec_#{blk[:chan]}_to_span(#{blk[:param]})")
      end
      # (b) whatever is left: a single-channel program is still unambiguous
      #     Anything else is refused, loudly.
      if code =~ /(?<![\w.])to_span\s*\(/
        raise Error, unresolved_to_span_msg(recs, blk, lineno) if recs.length != 1
        chan = recs.keys.first
        code = code.gsub(/(?<![\w.])to_span\s*\(/, "#{record_module(chan)}.spnl_rec_#{chan}_to_span(")
      end

      code = code.gsub(/(?<![\w.])send_otlp\s*\(/, "#{SINK_MODULE}.spnl_otlp_span_send(")
      code.gsub(CONSUME_REC_RE, RECORD_DRIVER_FN)
    end

    # Refuse to pick a channel by luck. The message says
    # WHERE (line), WHY the scope rule did not reach, and HOW to spell it instead.
    def unresolved_to_span_msg(recs, blk, lineno)
      where =
        if blk
          "written inside `on_emit :#{blk[:chan]}` but applied to something other than that block's " \
          "own parameter `#{blk[:param]}` (a handle copied into another variable, or passed through a " \
          "helper, cannot be traced back to its channel)"
        else
          "written outside every `on_emit :<channel>` block, so there is no channel in scope"
        end
      hatch = recs.keys.map { |c| "#{c}_span(ev)" }.join(" / ")
      "`to_span(...)` (line #{lineno}) — cannot tell which record channel this span comes from. " \
        "This program consumes #{recs.length} typed record channels (#{recs.keys.join(', ')}), and " \
        "`to_span` is resolved from the `on_emit :<channel>` block it appears in, applied to that " \
        "block's own block parameter:\n" \
        "    on_emit :#{recs.keys.first} do |ev|\n" \
        "      send_otlp(to_span(ev), @ep)   # resolves to #{recs.keys.first}\n" \
        "    end\n" \
        "Here it is #{where}. Either move the call into the block and apply it to the block parameter, " \
        "or name the channel explicitly (escape hatch): #{hatch}."
    end

    # Same refusal for a handle whose channel cannot be told apart: two blocks
    # named their parameter the same and it is being read outside both of them.
    def ambiguous_handle_msg(var, prop, chans, lineno)
      "`#{var}.#{prop}` (line #{lineno}) — `#{var}` is the block parameter of #{chans.length} typed " \
        "consumers (#{chans.map { |c| "on_emit :#{c}" }.join(', ')}), so outside those blocks there is " \
        "no way to tell which record it is. Give the blocks distinct parameter names " \
        "(e.g. `on_emit :#{chans.first} do |#{chans.first}_ev|`), or read the property inside the block " \
        "that receives it."
    end

    def record_prelude(recs)
      mods = recs.keys.map do |chan|
        decls = ["  ffi_func :spnl_rec_#{chan}_drain, [:int], :int"]
        record_properties(chan).each do |p|
          decls << "  ffi_func :#{p[:ffi]}, [:int], #{p[:ffi_ret]}"
        end
        decls << "  ffi_func :spnl_rec_#{chan}_to_span, [:int], :int"
        "module #{record_module(chan)}\n#{decls.join("\n")}\nend"
      end.join("\n")
      drains = recs.keys.each_with_index.map do |chan, idx|
        cnt = "n#{idx}"; ix = "i#{idx}"
        ["  #{cnt} = #{record_module(chan)}.spnl_rec_#{chan}_drain(t)",
         "  #{ix} = 0",
         "  while #{ix} < #{cnt}",
         "    __spnl_consume_rec_#{chan}(#{ix})",
         "    #{ix} = #{ix} + 1",
         "  end"].join("\n")
      end.join("\n")
      <<~RUBY

        # --- generated typed record-consumer driver (do not edit) ---
        # ev.<prop> accessors are generated from src/codegen_c/record_schema.h
        # (see src/runtime/otlp/record_mirror_gen.h); the record bytes never cross
        # this boundary — `ev` is the record's index in the drain.
        #{mods}
        module #{SINK_MODULE}
          ffi_func :spnl_otlp_span_send, [:int, :str], :int
          ffi_func :spnl_otlp_span_flush, [], :int
        end
        def #{RECORD_DRIVER_FN}(t)
        #{drains}
          #{SINK_MODULE}.spnl_otlp_span_flush
        end
      RUBY
    end

    def driver_module(ffi_decls, blocks)
      <<~RUBY

        # --- generated userspace consumer driver (do not edit) ---
        module SpnlConsumeFFI
        #{ffi_decls}
        end
        def #{DRIVER_FN}(t)
          SpnlConsumeFFI.spnl_consume_poll(t)
        #{blocks}
        end
      RUBY
    end
  end
end
