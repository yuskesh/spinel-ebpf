# frozen_string_literal: true
#
# Runtime parameters.
#
# A top-level `param :name, default: N` declares one knob the operator may turn
# without recompiling. The eBPF codegen turns it into
#
#     volatile const __s64 spnl_param_<name> = N;
#
# which libbpf places in a read-only map; the loader assigns it between the
# skeleton's __open() and __load() and the kernel then BPF_MAP_FREEZEs it, so the
# verifier folds reads of it as constants. Unset therefore does not mean "the
# guard runs and passes" -- it means the guard is not in the accepted program.
#
# This module is the Ruby-side reader of the SAME declaration the C codegen
# reads. Two readers of one declaration is a drift risk, so the split is by role,
# not by convenience:
#
#   * the C codegen (src/codegen_c/spinel_ebpf_cc.c, cc_scan_params) OWNS the
#     contract -- it validates the shape and is the only thing that can refuse a
#     build. Errors live there so that tools/golden.rb, which never runs any Ruby,
#     still exercises them.
#   * this module is for the parts that never reach the codegen: emitting the
#     loader's assignments (bin/spinel-ebpf) and telling a reader what the probe
#     can be narrowed by (`describe`). It is deliberately permissive -- it reports
#     what it sees and lets the codegen do the refusing, so a malformed
#     declaration produces the codegen's message rather than two different ones.
#
# AST shape (from `spinel --dump-ast`):
#   ProgramNode -> StatementsNode body[] -> CallNode(name="param", receiver=-1)
#     -> ArgumentsNode arguments[] -> [SymbolNode(name), KeywordHashNode?]
#          KeywordHashNode -> elements[] -> AssocNode(key: SymbolNode "default",
#                                                     value: IntegerNode)

module SpinelEbpf
  module Param
    Entry = Struct.new(:name, :default, keyword_init: true) do
      # The C identifier in the .bpf.c, and therefore the field name in the
      # skeleton's `rodata` struct that the loader assigns to.
      def c_symbol ; "spnl_param_#{name}" ; end

      # The environment variable that sets it. Uppercased name, one fixed prefix:
      # every other runtime switch in this project is an env var
      # (SPNL_XDP_IFACE / SPNL_MAX_EVENTS / SPNL_K8S_*), and env is what the
      # one-shot injection paths already carry -- both `kubectl debug` and the
      # prebuilt probe image set env, and neither can rewrite an argv.
      def env_name ; "SPNL_PARAM_#{name.upcase}" ; end
    end

    # `param :x` with no keyword, i.e. default 0. Written out rather than
    # inferred so the reason survives: 0 is the value that makes a guard on the
    # parameter disappear from the verified program, so "not declared" and
    # "off" are the same state on purpose.
    IMPLICIT_DEFAULT = 0

    module_function

    # Array<Entry> for every top-level `param :name[, default: N]`.
    def declarations(ast)
      out = []
      stmts = ast.statements_of(ast.root_id)
      return out if stmts.nil? || stmts < 0
      ast.body_array_of(stmts).each do |sid|
        n = ast.node(sid)
        next unless n && n.type == "CallNode"
        next unless ast.str_attr(sid, "name") == "param"
        next unless ast.ref(sid, "receiver") == -1          # bare call, not recv.param
        args = ast.ref(sid, "arguments")
        next if args < 0
        items = ast.array(args, "arguments")
        next if items.empty? || items.length > 2
        sym = ast.node(items[0])
        next unless sym && sym.type == "SymbolNode"
        name = ast.str_attr(items[0], "value").to_s
        next if name.empty?
        out << Entry.new(name: name, default: items.length == 2 ? keyword_default(ast, items[1]) : IMPLICIT_DEFAULT)
      end
      out
    end

    # Array<Entry> read straight from a `.ast` file (what bin/spinel-ebpf has on
    # hand at glue-generation time, the same way kernel_cache paths are read).
    def declarations_from_ast_file(path)
      return [] unless File.exist?(path)
      declarations(SpinelEbpf::ParseSpinelAst.parse_file(path))
    end

    # `default: <int literal>` -> Integer. Anything else -> IMPLICIT_DEFAULT: the
    # codegen refuses those shapes with a message of its own, and guessing a
    # second answer here would only compete with it.
    def keyword_default(ast, kw_id)
      kw = ast.node(kw_id)
      return IMPLICIT_DEFAULT unless kw && kw.type == "KeywordHashNode"
      ast.array(kw_id, "elements").each do |aid|
        a = ast.node(aid)
        next unless a && a.type == "AssocNode"
        key = ast.ref(aid, "key")
        kn = key >= 0 ? ast.node(key) : nil
        next unless kn && kn.type == "SymbolNode" && ast.str_attr(key, "value") == "default"
        val = ast.ref(aid, "value")
        vn = val >= 0 ? ast.node(val) : nil
        return Integer(ast.int_attr(val, "value")) if vn && vn.type == "IntegerNode"
      end
      IMPLICIT_DEFAULT
    end

    # --- source-text scan (describe) -----------------------------------------
    #
    # `describe` reads raw source, never an AST (it must work on a file that does
    # not compile). Same rule as above: report, do not refuse.
    DECL_RE = /\A\s*param\s+:([A-Za-z_]\w*)\s*(?:,\s*default:\s*(-?\d+)\s*)?(?:#.*)?\z/.freeze

    # [{ line:, name:, default: }] in source order.
    def scan_source(source)
      out = []
      source.each_line.with_index(1) do |line, i|
        m = DECL_RE.match(line.chomp)
        next unless m
        out << { line: i, name: m[1], default: m[2] ? Integer(m[2]) : IMPLICIT_DEFAULT }
      end
      out
    end

    # Is `name` referenced anywhere outside its own declaration line? Used by
    # `describe` to say "declared but nothing reads it" without compiling. The
    # codegen makes that case a hard error; here it is only a warning, because
    # describe also runs on sources that are mid-edit.
    def referenced?(source, name)
      re = /(?<![\w:])#{Regexp.escape(name)}(?![\w:])/
      source.each_line.any? { |line| !DECL_RE.match(line.chomp) && re.match?(line.sub(/#.*/, "")) }
    end

    # Line-for-line neutralisation for spinel's NATIVE codegen (`-c`), which
    # refuses an unknown top-level call ("unsupported call: CallNode `param`").
    # The eBPF passes (--dump-ast / --ir) keep the declaration -- that is where
    # the codegen reads it from -- so this is applied to the native pass only,
    # unlike Plugin.strip_declarations which strips before anything parses.
    # Replacing rather than deleting keeps every later line number honest.
    def strip_declarations(source)
      source.each_line.map { |line| DECL_RE.match(line.chomp) ? "# (param stripped for native codegen)\n" : line }.join
    end

    def present?(source)
      source.each_line.any? { |line| DECL_RE.match?(line.chomp) }
    end
  end
end
