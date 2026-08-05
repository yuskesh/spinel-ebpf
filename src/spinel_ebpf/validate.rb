# frozen_string_literal: true
#
# Loud, actionable rejection at compile time. When the author -- often a machine --
# writes Ruby that cannot work, this says what is wrong, why, where, and how to fix
# it, so the next attempt can be better. The affordance data is what you read
# before writing; this is what corrects you afterwards.
#
# It closes the gaps that fall between partitioning and code generation, in Ruby,
# *before* the generator runs, so the same loud error comes out of the CLI whichever
# generator is in use:
#
#   1. An attach handler that falls back to native, which is a silent no-op. A
#      `def kprobe__x` containing a float, a regex or file I/O is not eligible for
#      eBPF, so nothing ever fires it -- and the program still exits 0, the worst
#      possible outcome. A method with an attach prefix that is ineligible is a hard
#      error, with the reason spelled out.
#
#   2. A typo in an attach name -- the worst of the bunch. Write
#      `def kprobe_do_sys_openat2` with one underscore instead of two and it matches
#      no attach pattern at all, so it silently becomes an orphan syscall program:
#      partitioning, code generation, clang and the verifier are all happy, and the
#      handler is attached to nothing and never fires. A name that would be a valid
#      attach with a doubled underscore is treated as a typo and rejected with a
#      suggestion.
#
#   3. Arguments passed to a builtin that takes none, such as `latency_start(1)`.
#      The generator checks arity for the one-argument siblings but silently drops
#      extra arguments to the zero-argument ones. This removes that asymmetry.
#
#   4. An unknown builtin, usually a typo: `hist_observ(x)`. The generator would
#      fail with something cryptic about a node it cannot lower; this offers a
#      suggestion instead, using an edit distance computed here with no dependency.
#
#   5. An incomplete set of calls -- writing `http_req_start` without `http_emit`,
#      say. That yields a program that is quietly broken: no span comes out, and it
#      still exits 0. The required sets in the capability data catch it.
#
#   6. A `kernel_cache` declaration, which the production generator never implemented.
#      This one had the worst silence of the lot: partitioning announced an eBPF
#      method for it, the generator emitted a .bpf.c with no programs in it, the
#      build succeeded, and the binary printed "BPF loaded and attached" and served
#      nothing -- exit 0 all the way through.
#
# It also rejects enumerable blocks such as `[1,2,3].map { }`, which cannot run in
# eBPF and which partitioning does not catch.
#
# What it deliberately does not do: change one byte of the code generated for a
# probe that compiles. Only the error paths get smarter. Nor is it eager to reject:
# a good probe must still pass.

require "set"
require_relative "capabilities"
require_relative "codegen_bpf"
require_relative "param"
require_relative "kernel_cache"   # check (6) needs the declaration parser

module SpinelEbpf
  module Validate
    # A rejection is an immediate error; the CLI rescues it and aborts with
    # `error: <message>`.
    class Error < StandardError; end

    module_function

    # The authoritative set of builtins: the generator's own list, plus dynptr.
    BUILTINS = (CodegenBpf::BUILTIN_NAMES + CodegenBpf::DYNPTR_BUILTINS).uniq.to_set.freeze

    # The only iteration with a receiver the subset allows is `n.times { }`. Any
    # other enumerable block iterates the heap, which eBPF cannot do. Only calls
    # *with a block* are considered, so a dot-field read like `t.min` or an
    # accessor like `sk.snd_cwnd` is not mistaken for one.
    ENUMERABLE_BLOCK_METHODS = %w[
      map collect select filter reject filter_map
      reduce inject each each_with_object each_with_index each_pair
      flat_map find detect find_all group_by partition
      sort_by min_by max_by sum count chunk_while zip
    ].to_set.freeze

    # Receiverless control forms, kept here so they are never mistaken for typos.
    CONTROL_NAMES = %w[times loop lambda proc].to_set.freeze

    # The known attach-kind words. They are derived mechanically from the method
    # prefixes in the capability data -- the identifier before the first `__` -- so
    # that the affordances an author reads and the detection here cannot disagree.
    # For example "kprobe__<func>" yields "kprobe", and "xdp__<name>"
    # -> "xdp"、"xdp_tail__<name>" -> "xdp_tail"、"sk_skb__verdict__<name>" ->
    # "sk_skb". The timer is the one prefix written as "on :timer, ...", a
    # synthesised name no author types, and it drops out naturally because it does
    # not start with an identifier. Longest first, so "xdp_tail" is preferred over
    # "xdp" and the suggestion is the better one.
    ATTACH_WORDS = Capabilities::ATTACH_KINDS
                   .filter_map { |a| a[:method_prefix][/\A([a-z0-9_]+?)__/, 1] }
                   .uniq
                   .sort_by { |w| -w.length }
                   .freeze

    # The zero-argument builtins whose one-argument siblings do check arity, while
    # the generator silently discards arguments to these. Rejecting the extra
    # argument here removes the asymmetry. They take none because they derive the
    # thread id internally.
    ZERO_ARG_STRICT = %w[latency_start latency_end].to_set.freeze

    # Run every check, raising on the first violation.
    #   ast    -- ParseSpinelAst
    #   result -- a Partition::Result, with tags already assigned
    def validate!(ast, result)
      return if result.nil? || ast.nil?
      check_attach_handlers_are_ebpf!(result)              # (1)
      check_attach_name_typos!(result)                     # (2)
      used, unknown = scan_ebpf_calls(ast, result)         # both, in one walk
      check_heap_iteration!(ast, result)                   # +heap
      check_zero_arg_builtins!(ast, result)                # (3)
      check_unknown_builtins!(unknown)                     # (4)
      check_required_sets!(used)                           # (5)
      check_kernel_cache_unported!(ast)                    # (6)
      nil
    end

    # (6) `kernel_cache "/path", body` -- a top-level directive that reaches NOTHING.
    # It was built in the retired Ruby generator; the port to C never carried it, and
    # the later re-port of the TCP-slice bundle did not include the kernel_cache
    # branch either. Measured before this check existed:
    #
    #   partitioning  says `ebpf  xdp__tcp_slice__kernel_cache`
    #   generation    emits an EMPTY .bpf.c ("ebpf-eligible methods: 0")
    #   --build       succeeds; the binary prints "BPF loaded and attached"
    #   running it    `bpftool prog show` = 0 programs, curl on :8080 refused, exit 0
    #
    # The three orphaned map lookups (bpf_kc_resp and its two companions) were once
    # recorded in the loader contract on the argument that the hole was loud, because
    # sp_kc_set returns -2. It is loud only if the caller LOOKS: the shipped demo
    # discarded the value and printed a success message. So the hole was silent in
    # exactly the shape this file exists to forbid, and it is closed here -- at the
    # layer that can still see the word the author wrote, rather than at a
    # `find_map_by_name` that returns NULL.
    def check_kernel_cache_unported!(ast)
      decls = SpinelEbpf::KernelCache.declarations(ast)
      return if decls.empty?
      paths = decls.map { |d| d.path.inspect }.join(", ")
      raise Error,
            "`kernel_cache` is not implemented by the production codegen (#{decls.length} " \
            "declaration(s): #{paths}).\n" \
            "  Why: it was built in the retired Ruby generator only. The C codegen never " \
            "carried it, and the later re-port of the pure-XDP TCP slice did not include the " \
            "kernel_cache branch. Measured: the generated .bpf.c contains zero programs, the " \
            "build succeeds, the binary prints \"BPF loaded and attached\", and nothing is " \
            "ever served.\n" \
            "  Fix: serve the route from userspace (examples/http_server/), or write the fast " \
            "path yourself with `def xdp__tcp_slice__<name>` (one fixed response) -- that one " \
            "IS in the production codegen.\n" \
            "  Not a silent no-op any more: the three orphaned map lookups (bpf_kc_resp and " \
            "its length and checksum companions) have been removed, and this refuses instead."
    end

    # (1) Reject an attach handler that fell back to native because it cannot run
    # in eBPF. An attach point has no native execution path, so falling back means
    # it never fires at all. The partition table does say why, but the process still
    # exits 0, and an author -- especially a machine -- reads that as success.
    def check_attach_handlers_are_ebpf!(result)
      result.methods.each do |mi|
        next unless mi.tag == :native
        next unless mi.scope == :top_level
        # Only when ineligibility is the cause; a forced-native method, an internal
        # one, or main are all excluded.
        next unless mi.flags && mi.flags.ebpf_impossible?
        attach = CodegenBpf.detect_attach(mi.method_name)
        next unless attach
        reasons = mi.flags.reasons.join("; ")
        raise Error,
              "attach handler `def #{mi.method_name}` (#{attach[:sec]}) can't be lowered to eBPF: " \
              "#{reasons}. An attach handler MUST be eBPF — there is no native execution path for a " \
              "#{attach[:kind]} hook, so this probe would silently never fire. Rewrite the body to the " \
              "eBPF subset (integers + builtins only; see `spinel-ebpf capabilities`)."
      end
    end

    # (2) The most consequential check: a one-character typo in an attach name,
    # `kprobe_x` with a single underscore where `kprobe__x` was meant.
    #
    # A single underscore matches no attach pattern, so the method becomes an orphan
    # syscall program: partitioning, code generation, clang and the verifier are all
    # green, and the handler is attached to nothing and never fires. The verifier
    # only asks whether a program is safe, so it cannot catch this. The name rule
    # can, and with high confidence.
    #
    # It is careful not to over-reject: a name the attach detector already accepts
    # is left alone, and a name is only flagged when doubling that one underscore
    # would produce a valid attach -- which the suggestion helper verifies through
    # the detector itself. Measured against a corpus of 403 method names, it rejects
    # none of them wrongly.
    def check_attach_name_typos!(result)
      result.methods.each do |mi|
        next unless mi.tag == :ebpf
        next unless mi.scope == :top_level
        name = mi.method_name
        next if name.nil? || name.empty?
        next if CodegenBpf.detect_attach(name)     # already a valid attach name
        hit = attach_name_typo_suggestion(name)
        next unless hit
        word, suggestion = hit
        raise Error,
              "method `#{name}` looks like an attach handler but uses a single underscore after " \
              "the attach kind `#{word}`; did you mean `#{suggestion}`? A single `_` here is NOT a " \
              "valid attach prefix, so it lowers to an orphaned SEC(\"syscall\") program that is never " \
              "attached to any kernel event and never fires — yet partition/codegen/clang/verifier all " \
              "stay green. Use the double-underscore form `#{word}__<target>`, or rename it if this is " \
              "intentionally a plain (BPF-to-BPF) helper."
      end
    end

    # If name is an attach word followed by a single underscore and a remainder, and
    # doubling that underscore would make it a valid attach, return [word,
    # suggestion]; otherwise nil. Only typos that one such fix resolves are
    # considered -- a remainder already starting with an underscore is the valid form
    # -- and longer words are tried first so the suggestion is the best one.
    def attach_name_typo_suggestion(name)
      ATTACH_WORDS.each do |w|
        prefix = "#{w}_"
        next unless name.start_with?(prefix)
        rest = name[prefix.length..]
        next if rest.nil? || rest.empty? || rest.start_with?("_")
        candidate = "#{w}__#{rest}"
        return [w, candidate] if CodegenBpf.detect_attach(candidate)
      end
      nil
    end

    # (3) Reject arguments passed to a builtin that takes none. The one-argument
    # siblings do check their arity while the generator silently discards arguments
    # to these, and this removes that asymmetry. A probe that was already correct
    # passes none, so nothing changes for it.
    def check_zero_arg_builtins!(ast, result)
      each_ebpf_body(result) do |mi, body_id|
        walk_calls(body_id, ast) do |nid|
          next unless ast.receiver_of(nid) < 0   # receiverless builtin calls only
          name = ast.name_of(nid)
          next unless ZERO_ARG_STRICT.include?(name)
          n = call_arg_count(ast, nid)
          next if n.zero?
          raise Error,
                "`#{name}` expects no arguments but got #{n} in `#{mi.method_name}` — it captures the " \
                "tid key automatically, so it takes 0 args. Its siblings `lat_start`/`lat_end` take a " \
                "key argument, but `latency_start`/`latency_end` do not. Remove the argument(s)."
        end
      end
    end

    # How many arguments a call node actually has; 0 when it has no arguments node.
    def call_arg_count(ast, nid)
      aid = ast.arguments_of(nid)
      return 0 if aid < 0
      an = ast.node(aid)
      return 0 unless an && an.type == "ArgumentsNode"
      an.arrays.fetch("arguments", []).length
    end

    # Reject an enumerable block call in the body of an eBPF method: it iterates the
    # heap, which eBPF cannot do.
    def check_heap_iteration!(ast, result)
      each_ebpf_body(result) do |mi, body_id|
        walk_calls(body_id, ast) do |nid|
          name = ast.name_of(nid)
          next unless ENUMERABLE_BLOCK_METHODS.include?(name)
          next if ast.ref(nid, "block", default: -1) < 0   # calls with a block only
          raise Error,
                "`.#{name} { ... }` in `#{mi.method_name}` is heap/enumerable iteration, which is " \
                "eBPF-illegal (no heap, no dynamic allocation in BPF). The only bounded loop in the " \
                "eBPF subset is `n.times { |i| ... }`. Rewrite the iteration with `n.times`."
        end
      end
    end

    # (4) Reject an unknown builtin, offering the nearest name as a suggestion.
    def check_unknown_builtins!(unknown)
      return if unknown.empty?
      u = unknown.first
      name, method = u[:name], u[:method]
      best, dist = nearest_builtin(name)
      # Suggest the closest builtin when there is one; the threshold loosens with
      # the length of the name.
      threshold = [2, (name.length / 3.0).ceil].max
      if best && dist <= threshold
        sig = Capabilities.signature_for(best)
        hint = sig[:params] ? "(#{sig[:params].join(', ')})" : "(#{sig[:arity]} args)"
        raise Error,
              "unknown builtin `#{name}` in `#{method}` — did you mean `#{best}`#{hint}? " \
              "#{sig[:summary]} (run `spinel-ebpf capabilities --json` for all #{BUILTINS.size} builtins)."
      end
      raise Error,
            "unknown builtin/method `#{name}` in `#{method}` — not a known builtin, defined method, or " \
            "eBPF construct. Run `spinel-ebpf capabilities` (#{BUILTINS.size} builtins) or define it."
    end

    # (5) Reject an incomplete set of required calls.
    def check_required_sets!(used)
      gaps = Capabilities.missing_companions(used.keys)
      return if gaps.empty?
      g = gaps.first
      if g[:mode] == :all
        raise Error,
              "incomplete builtin set `#{g[:name]}` (#{g[:experiment]}): you use " \
              "#{g[:present].join(', ')} but not #{g[:missing].join(', ')}. These builtins only work " \
              "as a set — #{g[:why]} Add the missing hook(s), or remove the ones you have."
      else
        raise Error,
              "`#{g[:trigger]}` (#{g[:experiment]}) needs #{g[:missing].join(', ')} to have any effect — " \
              "#{g[:why]} Add #{g[:missing].join(', ')}, or remove `#{g[:trigger]}`."
      end
    end

    # ---------- internal helpers ----------

    # Walk every eBPF method once, collecting (a) the builtins in use, mapped to the
    # methods using them, and (b) the unknown receiverless calls.
    #
    # The base of a chain accessor -- the `pkt` in `pkt.l4.proto` -- is a
    # receiverless call that is itself the receiver of another call, and the
    # generator's accessor handling deals with it. A builtin or a typo is always a
    # leaf call, receiver of nothing, so calls in receiver position are excluded
    # from the unknown check rather than rejecting a legitimate chain.
    def scan_ebpf_calls(ast, result)
      known = method_name_set(result)
      # A declared `param :x` is read as a bare name, which prism gives us as a
      # receiver-less CallNode -- indistinguishable from a typo unless we know the
      # declarations. Read from the same AST the codegen reads, so "known here"
      # and "lowerable there" cannot drift.
      known.merge(SpinelEbpf::Param.declarations(ast).map(&:name))
      used = Hash.new { |h, k| h[k] = [] }
      candidates = []          # [{ nid:, name:, method: }] receiver-less unknowns
      receiver_ids = Set.new   # node ids that are the receiver of another call
      each_ebpf_body(result) do |mi, body_id|
        walk_calls(body_id, ast) do |nid|
          rid = ast.receiver_of(nid)
          receiver_ids << rid if rid >= 0
          next unless rid < 0                      # builtins and BPF-to-BPF calls have no receiver
          name = ast.name_of(nid)
          next if name.nil? || name.empty?
          if BUILTINS.include?(name)
            used[name] << mi.method_name
          elsif known.include?(name) || CONTROL_NAMES.include?(name) || BINARY_OP_NAMES.include?(name)
            # A defined method, a control form, or a binary operator: known, ignore
          else
            candidates << { nid: nid, name: name, method: mi.method_name }
          end
        end
      end
      # Exclude the base of a chain accessor, which sits in receiver position.
      unknown = candidates.reject { |c| receiver_ids.include?(c[:nid]) }
      [used, unknown]
    end

    BINARY_OP_NAMES = CodegenBpf::MethodEmitter::BINARY_OPS.to_set.freeze

    # Every method name in the result, both bare and original DSL spellings, used to
    # resolve BPF-to-BPF calls. It is deliberately permissive: missing a suggestion
    # is safer than rejecting a legitimate call.
    def method_name_set(result)
      s = Set.new
      result.methods.each do |m|
        s << m.method_name if m.method_name
        s << m.dsl_orig_name if m.dsl_orig_name
      end
      s
    end

    def each_ebpf_body(result)
      result.methods.each do |mi|
        next unless mi.tag == :ebpf
        next if mi.body_id.nil? || mi.body_id < 0
        yield mi, mi.body_id
      end
    end

    # Yield the call nodes under body_id, without descending into a nested def,
    # class or module -- the same guard partitioning uses.
    def walk_calls(body_id, ast, &blk)
      visited = {}
      stack = [body_id]
      until stack.empty?
        nid = stack.pop
        next if nid.nil? || !nid.is_a?(Integer) || nid < 0
        next if visited[nid]
        visited[nid] = true
        node = ast.node(nid)
        next unless node
        case node.type
        when "DefNode", "ClassNode", "ModuleNode"
          next   # analysed as its own method; do not count it twice
        when "CallNode"
          blk.call(nid)
        end
        # Follow only integer refs, so that an IntegerNode whose value is 0 is not
        # mistaken for node 0.
        node.refs.each_value { |c| stack << c if c.is_a?(Integer) && c >= 0 }
        node.arrays.each_value { |arr| arr.each { |c| stack << c if c.is_a?(Integer) && c >= 0 } }
      end
    end

    # Edit distance, computed here so this module needs no dependency.
    def levenshtein(a, b)
      return b.length if a.empty?
      return a.length if b.empty?
      prev = (0..b.length).to_a
      a.each_char.with_index do |ca, i|
        cur = [i + 1]
        b.each_char.with_index do |cb, j|
          cost = ca == cb ? 0 : 1
          cur << [cur[j] + 1, prev[j + 1] + 1, prev[j] + cost].min
        end
        prev = cur
      end
      prev[b.length]
    end

    # Return the closest builtin to name and its distance, as [best, dist]; when
    # there are no builtins, [nil, infinity].
    def nearest_builtin(name)
      best = nil
      best_d = Float::INFINITY
      BUILTINS.each do |b|
        d = levenshtein(name, b)
        if d < best_d
          best_d = d
          best = b
        end
      end
      [best, best_d]
    end
  end
end
