# frozen_string_literal: true
#
# The in-kernel common filter.
#
# A top-level `filter_by :pid, :comm` declares, once, what this probe may be
# narrowed by. The eBPF codegen turns it into
#
#     volatile const __s64 spnl_filter_pid  = 0;
#     volatile const char  spnl_filter_comm[16] = {};
#     static __always_inline int spnl_filter_discard(void) { ... }
#
# and injects `if (spnl_filter_discard()) return 0;` at the head of EVERY attach
# handler in the unit. The loader assigns the .rodata between the skeleton's
# __open() and __load(); the kernel then freezes it, so a key nobody sets is
# folded away by the verifier along with the helper call it would have needed.
#
# Why a declaration and not a builtin the handler calls: a probe narrowed in four
# of its five handlers is still a probe that reports everything, and that failure
# passes every gate this project has. A declaration has no fifth handler to
# forget.
#
# The split of duties mirrors src/spinel_ebpf/param.rb exactly, and for the same
# reason:
#
#   * the C codegen (src/codegen_c/spinel_ebpf_cc.c, cc_scan_common_filter +
#     cc_filter_gate) OWNS the contract -- it validates the keys, refuses a unit it
#     cannot cover in full, and is the only thing that can fail a build. The
#     errors live there so tools/golden.rb, which runs no Ruby at all, exercises
#     them.
#   * this module is for the parts that never reach the codegen: emitting the
#     loader's .rodata assignments (bin/spinel-ebpf) and telling a reader what the
#     probe can be narrowed by (`describe`). It reports; it does not refuse.
#
# AST shape (from `spinel --dump-ast`):
#   ProgramNode -> StatementsNode body[] -> CallNode(name="filter_by", receiver=-1)
#     -> ArgumentsNode arguments[] -> [SymbolNode, SymbolNode, ...]

module SpinelEbpf
  module CommonFilter
    # The fixed vocabulary. Mirrors CC_FILTER_KEYS in spinel_ebpf_cc.c, in the
    # same order (emission order = the order `describe` prints); a unit test
    # compares the two so the two tables cannot drift apart.
    #
    # `unset` is per key on purpose. 0 is not a free value everywhere: uid 0 is
    # root and has to be selectable, so uid/gid use -1. pid/tid 0 is the idle
    # task and cgroup id 0 does not exist, so those can use 0.
    Key = Struct.new(:name, :unset, :desc, keyword_init: true) do
      def env_name ; "SPNL_FILTER_#{name.upcase}" ; end
      def c_symbol ; "spnl_filter_#{name}" ; end
      def string?  ; name == "comm" ; end
    end

    KEYS = [
      Key.new(name: "pid",       unset: 0,  desc: "thread-group id (what userspace calls the pid)"),
      Key.new(name: "tid",       unset: 0,  desc: "kernel thread id"),
      Key.new(name: "uid",       unset: -1, desc: "effective uid (unset is -1: uid 0 is root)"),
      Key.new(name: "gid",       unset: -1, desc: "effective gid (unset is -1: gid 0 is root)"),
      Key.new(name: "cgroup_id", unset: 0,  desc: "cgroup id (= cgroup-dir inode; one container/pod)"),
      Key.new(name: "comm",      unset: "", desc: "task comm, exact match, max 15 chars"),
    ].freeze

    KEYS_BY_NAME = KEYS.to_h { |k| [k.name, k] }.freeze

    # The kernel's TASK_COMM_LEN. 15 visible characters plus the NUL the kernel
    # always writes; a longer value could never match anything, so the loader
    # refuses it rather than truncating into a filter that silently never fires.
    COMM_LEN = 16

    module_function

    # Array<Key> for the top-level `filter_by :a, :b`, in declaration order.
    # Unknown keys are dropped here (the codegen names them); duplicates collapse.
    def declarations(ast)
      out = []
      stmts = ast.statements_of(ast.root_id)
      return out if stmts.nil? || stmts < 0
      ast.body_array_of(stmts).each do |sid|
        n = ast.node(sid)
        next unless n && n.type == "CallNode"
        next unless ast.str_attr(sid, "name") == "filter_by"
        next unless ast.ref(sid, "receiver") == -1          # bare call, not recv.filter_by
        args = ast.ref(sid, "arguments")
        next if args < 0
        ast.array(args, "arguments").each do |aid|
          a = ast.node(aid)
          next unless a && a.type == "SymbolNode"
          k = KEYS_BY_NAME[ast.str_attr(aid, "value").to_s]
          out << k if k && !out.include?(k)
        end
      end
      out
    end

    # Array<Key> read straight from a `.ast` file (what bin/spinel-ebpf has on
    # hand when it generates the glue).
    def declarations_from_ast_file(path)
      return [] unless File.exist?(path)
      declarations(SpinelEbpf::ParseSpinelAst.parse_file(path))
    end

    # --- source-text scan (describe) -----------------------------------------
    #
    # `describe` reads raw source, never an AST (it must work on a file that does
    # not compile). Same rule as above: report, do not refuse -- so an unknown key
    # comes back as a string and the caller can say so without competing with the
    # codegen's message.
    DECL_RE = /\A\s*filter_by\s+(:[A-Za-z_]\w*(?:\s*,\s*:[A-Za-z_]\w*)*)\s*(?:#.*)?\z/.freeze

    # [{ line:, keys: ["pid", "comm"] }] in source order.
    def scan_source(source)
      out = []
      source.each_line.with_index(1) do |line, i|
        m = DECL_RE.match(line.chomp)
        next unless m
        out << { line: i, keys: m[1].split(",").map { |s| s.strip.delete_prefix(":") } }
      end
      out
    end

    # Line-for-line neutralisation for spinel's NATIVE codegen (`-c`), which
    # refuses an unknown top-level call. Same treatment, and the same reason, as
    # Param.strip_declarations: the eBPF passes (--dump-ast / --ir) must keep the
    # declaration, because that is where the codegen reads it from. Replacing
    # rather than deleting keeps every later line number honest.
    def strip_declarations(source)
      source.each_line.map { |line| DECL_RE.match(line.chomp) ? "# (filter_by stripped for native codegen)\n" : line }.join
    end

    def present?(source)
      source.each_line.any? { |line| DECL_RE.match?(line.chomp) }
    end
  end
end
