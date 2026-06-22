# frozen_string_literal: true
#
# Userspace consumer DSL — source transform.
#
# spinel's native `-c` rejects unknown top-level calls, so spinel-ebpf rewrites
# the DSL into plain Ruby before handing the source to spinel.
#
# Two styles (a program uses one):
#
#  (A) raw, matched by kind/arity:
#        on_emit do |v|            -> def __spnl_consume_int(v)
#        on_emit_pair do |a, b|    -> def __spnl_consume_pair(a, b)
#        on_emit_pair do |a, b, ts|-> +timestamp
#
#  (B) NAMED (distinguishes emit *sources* by name; subsumes per-site tags).
#      Producer/consumer bound by name; lowered onto the pair ringbuf with
#      the name's stable tag in field-a, value in field-b:
#        emit :http_open, dur      -> spnl_emit_pair(<tag>, (dur))     [kernel]
#        on_emit :http_open do |v| -> def __spnl_named_http_open(v)    [userspace]
#      The driver drains the pair ringbuf and dispatches each record to the
#      handler whose tag matches field-a. (`on_emit :sym` is distinct from the
#      reactor's `on :kind` kernel-handler DSL, so no namespace clash.)
#
#  consume_events(t)             -> __spnl_consume_events(t)
#
# Generated __spnl_* methods are forced :native by partition and excluded from
# the eBPF IR (cc_is_consumer_fn). MVP named: 1 value per event; don't mix named
# events with raw on_emit_pair (both use the pair ringbuf).
module SpinelEbpf
  module Consumer
    module_function

    DRIVER_FN = "__spnl_consume_events"

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
      !named(source).empty? || !present(source).empty?
    end

    def native_method_name?(name)
      name == DRIVER_FN || name.start_with?("__spnl_consume_", "__spnl_named_")
    end

    def transform(source)
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
