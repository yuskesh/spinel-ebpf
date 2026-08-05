#!/usr/bin/env ruby
# frozen_string_literal: true
#
# partition_id_check.rb — every AST node id the partition walks must be the body
# of the thing the partition says it is.
#
# WHY THIS EXISTS
#
# The partition consumes TWO artifacts produced by TWO different spinel
# invocations: the `.ast` from the upstream binary (`spinel --dump-ast`) and the
# `.ir` from the in-process codegen binary (`spinel-ebpf-cc --ir`). Node ids are
# only comparable across them while both parses were handed the same source
# text — and that is not guaranteed, because a plain `require` resolves relative
# to the RUNNING EXECUTABLE (/proc/self/exe). Measured on a real program: the
# upstream binary spliced 1216 nodes of its own `packages/set/set.rb` that the
# in-process binary could not find, so `@meth_body_ids` named nodes 1216 short
# of the real bodies. The partition then walked the SPLICED LIBRARY for every
# method and produced classifications that happened to look plausible.
#
# Types cannot catch that: both sides are Array<Integer>. What catches it is
# asking, of every id actually walked, "whose body is this?" — a question with a
# single right answer that the AST can settle on its own.
#
# THE CHECK
#
# For each method the partition enumerates, with body_id >= 0:
#
#   owned   the node's parent is a DefNode whose `name` is the method's source
#           name, or a BlockNode (reactor `on :kind do … end` handlers, whose
#           body is the block's), or the ProgramNode's StatementsNode (<main>)
#   orphan  the id is not a node in this AST at all
#   foreign the node exists but is owned by something else — this is the
#           id-space failure above, and the report names the owner so the cause
#           is readable
#
# USAGE
#
#   ruby tools/partition_id_check.rb                 # gate over the corpus
#   ruby tools/partition_id_check.rb --legacy-ids    # same sweep, but resolving
#                                                    # bodies the OLD way
#                                                    # (straight from the IR)
#   ruby tools/partition_id_check.rb --corpus DIR    # reuse a generated corpus
#
# The sweep needs both frontends, because the failure only exists when the two
# disagree; with committed fixtures alone it could never see one. When a binary
# is missing the tool ABORTS rather than passing — a gate that goes green
# because it could not run is worse than no gate (the lesson from
# affordance_gate.rb's wrong-platform abort).
#
# SELF-CHECK (always run, cannot be skipped)
#
# Before reporting anything the tool corrupts one body id in memory (+1) and
# requires the checker to call it out. If the checker stays quiet, the tool
# aborts: "broken=0" from a checker that cannot detect a broken id means
# nothing. This control depends on no corpus file and cannot silently become
# vacuous.

require "fileutils"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
$LOAD_PATH.unshift File.join(ROOT, "src")
require "spinel_ebpf/parse_spinel_ir"
require "spinel_ebpf/parse_spinel_ast"
require "spinel_ebpf/partition"

SPINEL_DIR = ENV["SPINEL_DIR"] || File.join(ROOT, "deps/spinel")

def die(msg)
  warn "partition_id_check: ABORT: #{msg}"
  exit 2
end

def spinel_bin
  [ENV["SPINEL_C_BIN"],
   File.join(SPINEL_DIR, "bin/spinel"),
   File.join(SPINEL_DIR, "build/spinel")].compact.find { |p| File.executable?(p) }
end

def cc_bin
  p = ENV["SPNL_INPROC_BIN"] || File.join(ROOT, "build/codegen_c/spinel-ebpf-cc")
  File.executable?(p) ? p : nil
end

# ---------- corpus ----------

def corpus_programs
  Dir.chdir(ROOT) do
    (Dir["tests/fixtures/**/*.rb"] + Dir["examples/**/*.rb"]).sort
  end
end

# Generate <key>.ast / <key>.ir for every program. Returns [[path, ast, ir], ...].
def generate_corpus(dir)
  sp = spinel_bin or die "upstream spinel not built (looked in #{SPINEL_DIR}); " \
                         "build it with `make -C #{SPINEL_DIR}`"
  cc = cc_bin     or die "in-process codegen binary missing " \
                         "(build/codegen_c/spinel-ebpf-cc); build it with " \
                         "`sh scripts/regen-fixtures.sh` or bin/spinel-ebpf"
  out = []
  corpus_programs.each do |rel|
    key = rel.tr("/", "_").sub(/\.rb\z/, "")
    ast = File.join(dir, "#{key}.ast")
    ir  = File.join(dir, "#{key}.ir")
    Dir.chdir(ROOT) do
      next unless system(sp, "--dump-ast", "--no-line-map", rel,
                         out: ast, err: File::NULL)
      next unless system(cc, rel, key, "--ir", out: ir, err: File::NULL)
    end
    out << [rel, ast, ir]
  end
  out
end

def load_corpus(dir)
  idx = File.join(dir, "index.txt")
  die "no index.txt in #{dir}" unless File.exist?(idx)
  File.readlines(idx).map do |line|
    key, rel = line.split(" ", 2).map(&:strip)
    [rel, File.join(dir, "#{key}.ast"), File.join(dir, "#{key}.ir")]
  end
end

# ---------- the invariant ----------

# The name a method's DefNode should carry. For the DSL forms the partition
# renames the method (`xdp__` prefixes, `uprobe__react0`), and stashes the
# original in dsl_orig_name; reactor handlers have no DefNode at all.
def expected_def_names(mi)
  names = []
  names << mi.dsl_orig_name if mi.dsl_orig_name && !mi.dsl_orig_name.start_with?("on_")
  names << mi.method_name
  names.uniq
end

Finding = Struct.new(:program, :method, :kind, :detail, keyword_init: true)

def check_program(rel, ast, methods)
  parent = {}
  ast.nodes.each do |id, n|
    n.refs.each_value { |c| parent[c] = id if c.is_a?(Integer) && c >= 0 }
    n.arrays.each_value { |a| a.each { |c| parent[c] = id if c.is_a?(Integer) && c >= 0 } }
  end
  root_stmts = ast.root_id ? ast.ref(ast.root_id, "statements", default: -1) : -1

  findings = []
  methods.each do |mi|
    bid = mi.body_id
    next if bid.nil? || bid < 0            # kernel_cache slice: no body by design
    unless ast.node(bid)
      findings << Finding.new(program: rel, method: mi.qualified_name,
                              kind: "orphan", detail: "id #{bid} is not a node in this AST")
      next
    end
    if mi.scope == :main
      unless bid == root_stmts
        findings << Finding.new(program: rel, method: mi.qualified_name, kind: "foreign",
                                detail: "<main> body is #{bid}, program statements are #{root_stmts}")
      end
      next
    end
    owner_id = parent[bid]
    owner = owner_id ? ast.node(owner_id) : nil
    unless owner
      findings << Finding.new(program: rel, method: mi.qualified_name, kind: "foreign",
                              detail: "node #{bid} has no owner (unreachable from the root)")
      next
    end
    # Being a CHILD of a DefNode is not enough — the parameters list is a child
    # too, and an id was measured landing on the ParametersNode of a
    # same-named method in a spliced library. It has to be the `body` ref.
    is_body = owner.refs.fetch("body", -1) == bid
    case owner.type
    when "BlockNode"
      # reactor `on :kind do … end` — the handler body IS the block's body.
      next if is_body
      findings << Finding.new(program: rel, method: mi.qualified_name, kind: "foreign",
                              detail: "node #{bid} is a BlockNode's #{owner.refs.key(bid) || 'child'}, not its body")
    when "DefNode"
      got = owner.attrs.fetch("name", "")
      next if is_body && expected_def_names(mi).include?(got)
      findings << Finding.new(program: rel, method: mi.qualified_name, kind: "foreign",
                              detail: is_body ? "node #{bid} is the body of `def #{got}`"
                                              : "node #{bid} is `def #{got}`'s " \
                                                "#{owner.refs.key(bid) || 'child'}, not its body")
    else
      findings << Finding.new(program: rel, method: mi.qualified_name, kind: "foreign",
                              detail: "node #{bid} is a #{owner.type}'s child, not a method body")
    end
  end
  findings
end

# Rebuild the OLD body ids (straight from the IR tables) so the sweep can be
# run both ways. Only used by --legacy-ids; the point is to show the check has
# teeth on the code it replaced.
def apply_legacy_ids!(ir, methods)
  names  = (ir.sa("@meth_names") || []).flat_map { |s| s.split(";", -1) }.reject(&:empty?)
  bodies = ir.ia("@meth_body_ids") || []
  map = {}
  names.zip(bodies).each { |n, b| map[[:top_level, nil, n]] = b if b && b >= 0 }
  cls_names  = ir.sa("@cls_names") || []
  cls_mnames = ir.sa("@cls_meth_names") || []
  cls_bodies = ir.sa("@cls_meth_bodies") || []
  cls_names.each_with_index do |cn, i|
    next if cn.empty?
    mn = (cls_mnames[i] || "").split(";", -1)
    mb = (cls_bodies[i] || "").split(";", -1).map { |s| s.empty? ? -1 : Integer(s) }
    mn.zip(mb).each { |m, b| map[[:class, cn, m]] = b if m && !m.empty? && b && b >= 0 }
  end
  methods.each do |mi|
    v = map[[mi.scope, mi.class_name, mi.method_name]]
    mi.body_id = v if v
  end
end

# ---------- self-check ----------

def self_check!(rel, ast, methods)
  victim = methods.find { |m| m.scope != :main && m.body_id && m.body_id >= 0 }
  die "self-check has no method to corrupt (empty corpus?)" unless victim
  saved = victim.body_id
  victim.body_id = saved + 1
  findings = check_program(rel, ast, methods)
  victim.body_id = saved
  hit = findings.find { |f| f.method == victim.qualified_name }
  unless hit
    die "self-check FAILED: shifting #{rel} #{victim.qualified_name} " \
        "body #{saved} -> #{saved + 1} was not detected — the checker has no teeth, " \
        "so a green result would mean nothing"
  end
  "self-check=#{hit.kind} (#{rel} #{victim.qualified_name} #{saved}->#{saved + 1})"
end

# ---------- main ----------

legacy = ARGV.include?("--legacy-ids")
corpus_dir = (i = ARGV.index("--corpus")) ? ARGV[i + 1] : nil

Dir.mktmpdir("spnl-idcheck") do |tmp|
  progs = corpus_dir ? load_corpus(corpus_dir) : generate_corpus(tmp)
  die "corpus is empty" if progs.empty?

  checked = 0
  refused = []
  findings = []
  selfcheck_line = nil
  progs.each do |rel, ast_path, ir_path|
    next unless File.exist?(ast_path) && File.exist?(ir_path)
    ast = SpinelEbpf::ParseSpinelAst.parse_file(ast_path)
    ir  = SpinelEbpf::ParseSpinelIR.parse_file(ir_path)
    # The partition now REFUSES a program that declares a handler it
    # cannot realise (negative fixtures do this on purpose). Such a program has
    # no MethodInfos, so there are no body ids to check -- not a finding, not
    # applicable. Counted and printed rather than skipped quietly: if the corpus
    # ever started refusing wholesale, `programs=` alone would just shrink.
    begin
      methods = SpinelEbpf::Partition.classify(ir, ast).methods
    rescue SpinelEbpf::Partition::PartitionError => e
      refused << [rel, e.message.lines.first.to_s.strip]
      next
    end
    apply_legacy_ids!(ir, methods) if legacy
    selfcheck_line ||= self_check!(rel, ast, methods) unless legacy
    findings.concat(check_program(rel, ast, methods))
    checked += 1
  end

  by_kind = findings.group_by(&:kind).transform_values(&:size)
  findings.each do |f|
    puts "FAIL #{f.kind}\t#{f.program}\t#{f.method}\t#{f.detail}"
  end
  refused.sort.each { |rel, why| puts "REFUSED (no ids to check)\t#{rel}\t#{why}" }
  puts "partition_id_check: programs=#{checked} refused=#{refused.size} findings=#{findings.size} " \
       "#{by_kind.inspect}#{legacy ? ' [--legacy-ids]' : ''}"
  puts "partition_id_check: #{selfcheck_line}" if selfcheck_line
  exit(findings.empty? ? 0 : 1)
end
