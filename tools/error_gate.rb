#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Is every error the product can show an author actually ACTIONABLE?
#
# The claim under test is a sentence about the whole surface ("every error
# carries reason + citation + how to fix it"), and until now the only thing
# measuring it was tests/spinel_ebpf/error_quality_test.rb, which pins 21 hand
# picked cases. 21 out of a surface nobody had counted.
#
# WHY A LABEL CHECK WOULD BE WORTHLESS ----------------------------------------
# The obvious gate -- "does the message contain the word Fix:" -- is satisfied by
# boilerplate, so it measures nothing. The syntax-vocabulary audit named this trap
# (`needle_not_bearing`: a needle the twin already satisfies is not load bearing)
# and this gate inherits it: two self-checks REWRITE the whole corpus into
# maximally decorated boilerplate and demand that the score does NOT go up.
#
# WHAT IS MEASURED ------------------------------------------------------------
# Every site in the product that can stop a compile with a message:
#
#   C   src/codegen_c/spinel_ebpf_cc.c        die(msg, detail)
#   rb  src/spinel_ebpf/*.rb (product path)   raise <Class>, "..."
#   rb  bin/spinel-ebpf                       abort "..."
#
# src/spinel_ebpf/codegen_bpf.rb is EXCLUDED: it is the retired Ruby oracle
# (tools/cgen_oracle.rb), reached only when the in-process C codegen cannot be
# built -- the state tools/reach_gate.rb refuses to run in. Its messages are not
# product surface. Counting them would inflate the denominator with text no user
# of a working install can see.
#
# Each site is given an AUDIENCE by a rule over what its guard tests:
#
#   infra     an allocation / file / formatting failure (oom, short read).
#             Not an authoring mistake; no remedy exists.
#   internal  an invariant of the AST/IR that upstream spinel produced, or a
#             capacity of our own data structures. An author writing valid Ruby
#             cannot reach it; reaching it is our bug, not theirs.
#   user      everything else -- the denominator this gate defends.
#
# and, if user-facing, three independent components:
#
#   subject   can the reader find the offending text in THEIR file?  The runtime
#             detail must be something they wrote (a name, a literal, a key) --
#             an AST node type is not ("node type not yet ported: IfNode").
#   remedy    does the message name a DIFFERENT concrete spelling to write next?
#             A pointer to the whole vocabulary ("run spinel-ebpf capabilities")
#             is the null remedy and does not count.
#   source    a citation (a kernel artifact, an experiment name). Reported, but see
#             the note on SOURCE below: this one IS boilerplate-satisfiable, which
#             is exactly why the headline number is subject && remedy.
#
#   ruby tools/error_gate.rb                # gate
#   ruby tools/error_gate.rb --self-check   # just the self-checks
#   ruby tools/error_gate.rb --list         # every site, classified (TSV)
#   ruby tools/error_gate.rb --update       # move the debt baseline (REVIEW IT)
require "json"
require "set"

ROOT = File.expand_path("..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "src"))
require "spinel_ebpf/capabilities"

CC       = File.join(ROOT, "src/codegen_c/spinel_ebpf_cc.c")
CLI      = File.join(ROOT, "bin/spinel-ebpf")
RB_DIR   = File.join(ROOT, "src/spinel_ebpf")
BASELINE = File.join(ROOT, "tests/golden/error_actionability.tsv")

# The retired Ruby oracle. Not product surface -- see the header.
RB_EXCLUDE = ["codegen_bpf.rb"].freeze

# ---------------------------------------------------------------------------
# vocabulary: what an author can actually write. Read from the affordance, never
# restated here: the gate holds no expectations of its own.
# ---------------------------------------------------------------------------
CAPS = SpinelEbpf::Capabilities
AFF  = JSON.parse(CAPS.affordance_json)

BUILTINS = AFF["builtins"].map { |b| b["name"] }.to_set.freeze
RELATED  = AFF["builtins"].to_h { |b| [b["name"], (b["related"] || []).to_set] }.freeze
# `def kprobe__…` / `on :xdp` — the spellings that name an attach point.
ATTACH_WORDS = AFF["attach_kinds"].map { |k| k["kind"] }.to_set.freeze
# Declaration keywords: everything the author types that is not a builtin call.
# Taken from the affordance's own surfaces so it cannot drift.
DECL_WORDS = (
  AFF["runtime_params"].to_a.flat_map { |p| p.is_a?(Hash) ? [p["name"]] : [] } +
  (AFF["consumer_dsl"] || []).map { |c| c.is_a?(Hash) ? c["name"] : c } +
  %w[param filter_by keep_if on_emit use_plugin emit]
).compact.map(&:to_s).to_set.freeze
# Constructs, not identifiers: `.times` is a remedy ("rewrite the iteration with
# n.times") and no amount of builtin vocabulary can express it. Derived from the
# syntax claims so it moves when they do.
SYNTAX_CALLS = (AFF["syntax"] || []).flat_map { |c| c["syntax"].to_s.scan(/\.[a-z_]+\b/) }
                                    .uniq.reject { |m| m.length < 4 }.freeze

VOCAB = (BUILTINS + ATTACH_WORDS + DECL_WORDS).freeze

# A generic pointer is not a remedy: it sends the author back to the whole list.
NULL_REMEDIES = [
  /spinel-ebpf capabilities/i,
  /capabilities --json/i,
  /`spinel-ebpf describe`/i,
].freeze

# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------
def strip_c_comments(src)
  res = +""; i = 0; instr = false; esc = false
  while i < src.length
    c = src[i]
    if instr
      res << c
      if esc then esc = false elsif c == "\\" then esc = true elsif c == '"' then instr = false end
      i += 1; next
    end
    if c == '"' then instr = true; res << c; i += 1; next end
    if c == "/" && src[i + 1] == "*"
      j = (src.index("*/", i + 2) || (src.length - 2)) + 2
      res << src[i...j].gsub(/[^\n]/, " "); i = j; next
    end
    if c == "/" && src[i + 1] == "/"
      j = src.index("\n", i) || src.length
      res << src[i...j].gsub(/[^\n]/, " "); i = j; next
    end
    res << c; i += 1
  end
  res
end

def balanced(txt, from)
  depth = 1; j = from; instr = false; esc = false
  while j < txt.length && depth.positive?
    c = txt[j]
    if instr
      if esc then esc = false elsif c == "\\" then esc = true elsif c == '"' then instr = false end
    else
      case c
      when '"' then instr = true
      when "(" then depth += 1
      when ")" then depth -= 1
      end
    end
    j += 1
  end
  [txt[from...(j - 1)], j]
end

def litjoin(s)
  out = +""
  s.scan(/"((?:[^"\\]|\\.)*)"/m) { |m| out << m[0] }
  out.gsub('\\"', '"').gsub('\\n', "\n").gsub("\\t", "\t").gsub("\\\\", "\\")
end

def split_top(s)
  parts = []; depth = 0; instr = false; esc = false; cur = +""
  s.each_char do |c|
    if instr
      cur << c
      if esc then esc = false elsif c == "\\" then esc = true elsif c == '"' then instr = false end
      next
    end
    case c
    when '"' then instr = true; cur << c
    when "(", "[", "{" then depth += 1; cur << c
    when ")", "]", "}" then depth -= 1; cur << c
    when "," then depth.zero? ? (parts << cur; cur = +"") : cur << c
    else cur << c
    end
  end
  parts << cur
  parts.map(&:strip)
end

# die(msg, detail) — msg is a literal, an msprintf(...), a ternary of literals,
# or a local built just above by msprintf/snprintf.
def c_sites
  raw  = File.read(CC)
  txt  = strip_c_comments(raw)
  out  = []
  i = 0
  while (i = txt.index(/\bdie\s*\(/, i))
    m = txt.match(/\bdie\s*\(/, i)
    args, j = balanced(txt, m.end(0))
    line = txt[0...i].count("\n") + 1
    i = j
    next if line < 45   # the definition of die() itself
    a = split_top(args)
    msgx = a[0].to_s
    msg =
      if msgx.start_with?('"', "msprintf") || msgx.include?("?") then litjoin(msgx)
      else
        name = msgx.strip
        before = txt[0...(txt.index(/\bdie\s*\(/, 0) ? 0 : 0)] # placeholder, replaced below
        before = txt[0...(m.begin(0))]
        fstart = before.rindex(/^\}/m) || 0
        body   = before[fstart..]
        if (sn = body.rindex(/snprintf\s*\(\s*#{Regexp.escape(name)}\s*,/m))
          o = body.index("(", sn) + 1
          litjoin(balanced(body, o)[0])
        elsif (as = body.rindex(/(?:char|const char)\s*\*\s*#{Regexp.escape(name)}\s*=\s*/m))
          tail = body[as..]
          if tail =~ /=\s*msprintf\s*\(/
            o = tail.index("(", tail.index("msprintf")) + 1
            litjoin(balanced(tail, o)[0])
          else
            litjoin(tail[0, 4000])
          end
        else
          ""
        end
      end
    out << { id: "cc:#{line}", file: "src/codegen_c/spinel_ebpf_cc.c", line: line,
             msg: msg, detail: a[1].to_s, guard: guard_line(raw, line),
             # what fills the runtime slots: the die() call and the ~30 lines
             # above it, where the msprintf that built the message lives.
             filler: guard_line(raw, line + 1) + " " +
                     raw.lines[[line - 30, 0].max...line].join(" ") }
  end
  out
end

# The 3 lines above the site: what the guard tested is what decides the audience.
def guard_line(src, line)
  ls = src.lines
  ls[[line - 4, 0].max...(line)].join(" ").gsub(/\s+/, " ")
end

# Ruby sites are parsed, not grepped: `raise Error,` with the message on the
# next four lines is the house style, and a line-oriented scanner reads those as
# empty messages -- an extractor that silently reports "no text" would make the
# surface look better than it is.
def ruby_sites
  require "prism"
  out = []
  files = Dir[File.join(RB_DIR, "*.rb")].reject { |f| RB_EXCLUDE.include?(File.basename(f)) }.sort
  (files + [CLI]).each do |f|
    rel = f.sub("#{ROOT}/", "")
    src = File.read(f)
    root = Prism.parse(src).value
    defs = {}
    collect_defs(root, defs)
    # A `def` whose only job is to raise (or to build the string a raise uses) is
    # a TEMPLATE, not a site: its text is the same for every caller and the part
    # that differs -- the part the author has to read -- is at the call. Counting
    # the template as one site would score five distinct diagnostics as one.
    templates = defs.select { |_n, d| raiser_template?(d) }
    walk_ruby(root, src, rel, File.basename(f), out, defs, templates.keys.to_set)
  end
  out
end

def collect_defs(node, acc)
  return unless node.is_a?(Prism::Node)
  acc[node.name] = node if node.is_a?(Prism::DefNode)
  node.compact_child_nodes.each { |c| collect_defs(c, acc) }
end

# A template is a def whose ENTIRE body is one raise/abort built from its own
# parameters. Anything looser catches ordinary methods that happen to abort
# somewhere (the CLI's `run`), and every call to those would be scored as a
# diagnostic -- measured: it invented 12 sites whose "message" was a clang
# command line.
def raiser_template?(d)
  return false unless d.parameters && !d.parameters.requireds.empty?
  body = d.body
  return false unless body.is_a?(Prism::StatementsNode) && body.body.size == 1

  stmt = body.body.first
  return false unless stmt.is_a?(Prism::CallNode) && %i[raise abort].include?(stmt.name)

  names = d.parameters.requireds.map { |p| p.respond_to?(:name) ? p.name.to_s : "" }
  names.any? { |n| stmt.slice =~ /\#\{#{Regexp.escape(n)}\b/ }
end

# The template's own frame ("Why: ", "Fix: ") is part of what the reader sees, so
# the call site's text is the frame with the parameters substituted.
def template_message(d, call)
  stmt = d.body.body.first
  msgarg = stmt.arguments.arguments.find do |a|
    !a.is_a?(Prism::ConstantReadNode) && !a.is_a?(Prism::ConstantPathNode)
  end
  frame, = ruby_message(msgarg)
  names = d.parameters.requireds.map { |p| p.respond_to?(:name) ? p.name.to_s : "" }
  args  = call.arguments ? call.arguments.arguments : []
  det = []
  names.each_with_index do |n, i|
    lit, dd = args[i] ? ruby_message(args[i]) : ["", ""]
    det << dd
    frame = frame.gsub("\#{#{n}}", lit)
  end
  [frame, det.join(" ")]
end

# The literal text a reader sees, with the interpolations left in place as
# markers. Dropping them made every Ruby diagnostic look like a stub ("`keep_if
# :` (line ) -- the `` record has no property ``"), which would have scored the
# best messages in the tree as the worst: the remedy in those is IN the slot.
def ruby_message(node)
  lit = +""
  det = []
  emit = lambda do |n|
    case n
    when Prism::StringNode then lit << n.unescaped
    when Prism::EmbeddedStatementsNode, Prism::EmbeddedVariableNode
      src = n.slice.sub(/\A\#[\{@$]?/, "").sub(/\}\z/, "")
      det << src
      lit << "\#{#{src}}"
    when Prism::InterpolatedStringNode then n.parts.each { |p| emit.call(p) }
    when Prism::CallNode
      if %i[+ * concat <<].include?(n.name)
        emit.call(n.receiver) if n.receiver
        n.arguments&.arguments&.each { |a| emit.call(a) }
      else
        det << n.slice
      end
    when Prism::Node then n.compact_child_nodes.each { |c| emit.call(c) }
    end
  end
  emit.call(node)
  [lit, det.join(" ")]
end

def walk_ruby(node, src, rel, base, out, defs, template_names)
  return unless node.is_a?(Prism::Node)
  if node.is_a?(Prism::CallNode) && node.arguments
    line = node.location.start_line
    mk = lambda do |lit, det, slice|
      return if lit.strip.empty? && det.strip.empty?
      out << { id: "#{base}:#{line}", file: rel, line: line, msg: lit, detail: det,
               guard: src.lines[[line - 4, 0].max...(line - 1)].join(" ").gsub(/\s+/, " "),
               filler: "#{det} #{slice}" }
    end
    if %i[raise abort].include?(node.name)
      args = node.arguments.arguments
      msgarg = args.find { |a| !a.is_a?(Prism::ConstantReadNode) && !a.is_a?(Prism::ConstantPathNode) }
      if msgarg
        # `raise Error, build_message(...)` -- the text lives in the builder.
        if msgarg.is_a?(Prism::CallNode) && msgarg.receiver.nil? && defs.key?(msgarg.name) &&
           !template_names.include?(msgarg.name)
          lit, det = ruby_message(defs[msgarg.name])
          mk.call(lit, det, msgarg.slice)
        else
          lit, det = ruby_message(msgarg)
          mk.call(lit, det, msgarg.slice)
        end
      end
    elsif template_names.include?(node.name) && node.receiver.nil?
      # a call to a raise-template: the text the reader sees is HERE.
      lit, det = template_message(defs[node.name], node)
      mk.call(lit, det, node.slice)
    end
  end
  # do not descend into a template's own body: its raise is the frame, not a site
  return if node.is_a?(Prism::DefNode) && template_names.include?(node.name)

  node.compact_child_nodes.each { |c| walk_ruby(c, src, rel, base, out, defs, template_names) }
end

# ---------------------------------------------------------------------------
# D0: audience
# ---------------------------------------------------------------------------
INFRA_RE = /\b(oom|short read|cannot open|vsnprintf|out of memory)\b/i

# Artifacts that exist only inside the compiler: the author never typed one and
# cannot make upstream spinel produce a malformed one by writing valid Ruby.
COMPILER_ARTIFACT_NOUN = /
  \b[A-Z][A-Za-z]+Node\b            # prism AST node types
  | \b[SIRA]-field\b | \bSpNode\b   # our own AST record caps
  | \bC\ binop\b                    # the codegen's own operator table
  | \bROOT\ record\b | \bSPINEL-IR\ header\b | \brecord\ missing\ field\b
  | \bnode\b | \boperand\b | \breceiver\b | \bpredicate\b
  | \bfield\ schema\b | \btag\b | \bAST\ text\b | \bSA\/IA\b | \bplugin\ manifest\b | \btracepoint\ ipv6\ param\b
/x
# An INVARIANT violation ("this should have been here and is not"), as opposed to
# an unimplemented feature ("not yet ported"), which IS something an author
# reaches by writing valid Ruby. The distinction is the whole rule; getting it backwards
# would move ~20 genuinely non-actionable messages out of the denominator.
INVARIANT_RE = /\b(missing|malformed|out\ of\ order|overflow|unknown|expected|needs|empty)\b|\bnot\ [A-Z][A-Za-z]*Node\b/xi

# A precondition of the ENVIRONMENT, not of the program: a missing clang, an
# unreadable path, a subprocess that failed. User-facing, but the remedy is
# outside the language, so it does not belong in the denominator of a claim
# about authoring diagnostics (D0: do not inflate).
# NOTE the word boundaries. Without the one before `on PATH` this pattern
# matched "no native executi|on path|" and moved two of the best diagnostics in
# the tree out of the denominator -- an instrument bug that made the score
# BETTER, which is the direction nobody notices.
ENVIRONMENT_RE = /\bnot\ found\b|\bnot\ executable\b|\bnot\ in\ PATH\b|\bon\ PATH\b|
                  \bcommand\ failed\b|\bgeneration\ failed\b|\bdump\ failed\b|
                  \bgen\ skeleton\ failed\b|\bneeds\ clang\b|\bneeds\ bpftool\b|
                  \bneeds\ the\ micro-bpf\b|\bonly\ supported\ on\ Linux\b|
                  \bcannot\ satisfy\ a\ static\ link\b|\bhas\ no\ libelf\b|
                  --dump-ast\ failed|\bbinary\ unavailable\b|\bIR\ emit\ failed\b|
                  \bcodegen\ step\ did\ not\ run\b/xi

# A relay: the site contributes no text of its own, it prints somebody else's
# message (`abort "error: #{e.message}"`). Grading it would score one diagnostic
# twice -- once where it is written and once where it is printed -- and the
# second score would always be zero, which is an artefact of the plumbing rather
# than a fact about the surface.
def forwarded?(s)
  bare = s[:msg].to_s.gsub(/\#\{[^}]*\}/, "").gsub(/\berror:\s*/, "").strip
  bare.empty? && s[:msg].to_s.include?("\#{")
end

def audience(s)
  m = s[:msg].to_s
  return "infra" if m =~ INFRA_RE
  return "forwarded" if forwarded?(s)
  return "environment" if m =~ ENVIRONMENT_RE
  # `abort parser.help` — the usage text, not a diagnostic.
  return "environment" if m.strip.empty? && s[:detail].to_s =~ /help|usage/
  # A message that calls itself internal is taken at its word.
  return "internal" if m.start_with?("internal:")
  return "internal" if m =~ INVARIANT_RE && m =~ COMPILER_ARTIFACT_NOUN && m !~ /not yet ported/
  "user"
end

# ---------------------------------------------------------------------------
# D1: the three components
# ---------------------------------------------------------------------------
# A runtime detail is the AUTHOR'S spelling unless it evaluates to an artifact of
# the compiler: an AST node type, a C type name, a SEC string we synthesised.
COMPILER_ARTIFACT_RE = /->type|nt_type|ty_legacy_name|\btypes\[|\bty\b|so_member/

def tokens(name)
  name.to_s.downcase.split(/[^a-z0-9]+/).reject { |t| t.empty? || t.length < 3 }
end

# The vocabulary identifiers the message mentions.
def mentioned(msg)
  words = msg.scan(/[A-Za-z_][A-Za-z0-9_]*/).to_set
  VOCAB & words
end

# The subject is what the message OPENS by naming -- the first vocabulary word
# in its first sentence. Scanning the whole text instead let a pasted "See also:"
# tail become the subject of a message that had none, and then the pasted names
# were each other's "related alternative": measured, that turned 78 sites
# actionable for free (self-check 2). The subject has to be identified
# independently of the candidates, or the candidates can invent one.
def subject_of(s)
  head = s[:msg].to_s.split(/(?<=[.!?])\s|\n/, 2).first.to_s
  head.scan(/[A-Za-z_][A-Za-z0-9_]*/).find { |w| VOCAB.include?(w) }
end

def names_subject?(s)
  return true if subject_of(s)
  # A message whose FIRST token is a slot names the author's spelling with it
  # ("%s expects exactly one namespace key" is filled with `who`). Refusing to
  # credit that scored six shared helpers as unable to say what went wrong, which
  # is the opposite of what they do.
  return true if s[:msg].to_s.lstrip.start_with?("%s", '#{')
  d = s[:detail].to_s
  return false if d.empty? || d == "NULL"
  return false if d =~ COMPILER_ARTIFACT_RE
  # a dynamic detail that is not a compiler artifact is the author's spelling
  true
end

# The four ways a message can say "write this instead". Each names something the
# author can put in their file; none of them is a label.
#
#   shape        the required call form ("expects 2 args (index, value)",
#                "must be a string literal", "takes no arguments")
#   context      an attach spelling to move the code into (`def lsm__file_open`,
#                "only available inside xdp__ or tc__* methods")
#   alternative  a different vocabulary identifier RELATED to the subject
#   enumeration  a runtime-filled list, credited only when the filler enumerates
#                a table (see (d))
SHAPE_RE = /
  \bexpects\b [^.\n]* \( |                  # expects 2 args (index, value)
  \bexpects\ (?:no\ arg|exactly|at\ least|\d+\ arg) |
  \btakes\ no\ (?:arguments|args)\b |
  \bmust\ be\ an?\ [a-z\ -]*literal\b |     # must be a string or symbol literal
  \bmust\ (?:start\ with|be\ lowercase|be\ positive)\b |
  \bwrite\ it\ as\b | \bspell\ it\b | \be\.g\.\ `?[a-z_@]+[ (:`]
/xi

def remedy_of(s)
  msg  = s[:msg]
  subj = subject_of(s)
  body = msg.dup
  NULL_REMEDIES.each { |re| body = body.gsub(re, " ") }
  # Strip citations BEFORE looking for a remedy. Measured: without this, adding a
  # parenthesised citation to a message that already said "expects" satisfied the
  # shape arm -- the parenthesis of the citation stood in for the parameter list.
  # That is the citation buying actionability, which is the exact confusion this
  # gate exists to take apart (self-check 3).
  body = body.gsub(/\((?:see|measured|Measured)[^)]*\)/, " ")

  # (a) a call shape. It does not need a subject in the vocabulary: `skb_load_*`
  #     is a family glob, not a builtin name, and "expects 1 arg (offset)" is
  #     still the thing the author has to type.
  return ["shape", "#{subj}(...)"] if subj && body =~ /#{Regexp.escape(subj)}\s*\([^)]/
  return ["shape", body[SHAPE_RE].to_s.strip] if body =~ SHAPE_RE
  # (b) an attach-handler spelling to move the code into. Both the `def` form and
  #     the bare prefix ("only available inside xdp__ or tc__* methods") count --
  #     the prefix is what the author edits.
  if (m = body[/\bdef\s+[a-z_]+__[a-z_<>]*/])
    return ["context", m.strip]
  end
  if (m = body.scan(/\b([a-z_]+)__[a-z_*<>]*/).flatten.find { |w| ATTACH_WORDS.include?(w) })
    return ["context", "#{m}__"]
  end
  # the reactor spelling of the same thing (`on :kprobe, %w[a b c] do ... end`)
  if (m = body[/\bon\s+:([a-z_]+)/, 1]) && ATTACH_WORDS.include?(m)
    return ["context", "on :#{m}"]
  end
  # a run of attach kinds offered as places to move the code
  # ("Add a process-context handler (kprobe/tracepoint/fentry/...)"). Two or more,
  # because one bare word is as likely to be part of a sentence as a list.
  kinds = body.scan(/\b[a-z_]+\b/).select { |w| ATTACH_WORDS.include?(w) }.uniq
  return ["context", kinds.first(2).join("/")] if kinds.size >= 2
  # (c) another vocabulary identifier, related to the subject.
  others = mentioned(body) - [subj].compact
  unless others.empty?
    return nil if subj.nil?

    rel = RELATED[subj] || Set.new
    hit = others.find { |o| rel.include?(o) || (tokens(o) & tokens(subj)).any? }
    return ["alternative", hit] if hit
    # A vocabulary word with nothing in common with the subject is noise, not a
    # remedy (error_quality_test pins this: unrelated candidates train the reader
    # to skip the line).
  end
  # (c') a sugar spelling (`pkt.l4.dport`) or an advertised construct (`n.times`)
  #      — copyable, and not a bare identifier, so `mentioned` cannot see it.
  if (m = body[/\b(?:pkt|sk)\.[a-z_]+(?:\.[a-z_]+)*/])
    return ["alternative", m]
  end
  if (m = SYNTAX_CALLS.find { |c| body.include?(c) })
    return ["alternative", "<n>#{m}"]
  end
  # (c'') two or more literal alternatives spelled out (`:expand or :multi`,
  #       `raise|wrap|promote`) — the author copies one of them verbatim.
  syms = body.scan(/(?<![A-Za-z_]):[a-z_]{2,}\b/).uniq
  return ["alternative", syms.first(2).join(" | ")] if syms.size >= 2

  # (c''') a command-line spelling the author can pass (`--native-only`).
  if (m = body[/\s(--[a-z][a-z0-9-]{2,})/, 1])
    return ["alternative", m]
  end
  # (d) an ENUMERATION the message fills at runtime. The text alone cannot be
  #     graded -- a slot could hold anything -- so this arm credits it only when
  #     the expression that FILLS the slot enumerates a table (a cc_*_str()
  #     helper in C, a `.join`/`.map` over a Capabilities collection in Ruby).
  #     A decorated template cannot satisfy this: it has no filler. Self-check 5
  #     ("fake-enumeration") pins that a slot with a constant filler stays 0.
  if body =~ /%s/ && body =~ ENUM_FRAME_RE && s[:filler].to_s =~ ENUM_FILLER_RE
    return ["enumeration", "table"]
  end
  # (e) the Ruby form of (d). Slots carry their own expression, so the test is
  #     sharper: the frame phrase must be followed by a slot whose expression
  #     DIFFERS from the one identifying the subject. "`#{name}` is unknown, did
  #     you mean `#{name}`?" does not pass; "did you mean `#{best}`" does. That
  #     difference is what makes the message compute something the author does
  #     not already have.
  slots = body.scan(/\#\{([^}]*)\}/).flatten
  if slots.size > 1
    subject_slot = slots.first
    body.to_enum(:scan, ENUM_FRAME_RE).each do
      after = body[Regexp.last_match.end(0), 120].to_s
      nxt = after[/\#\{([^}]*)\}/, 1]
      return ["enumeration", nxt] if nxt && nxt != subject_slot
    end
  end
  nil
end

# Prose that frames a slot as "here are the things you may write instead".
ENUM_FRAME_RE = /\b(accepted|keys:|supported:|contexts\ that\ can\ supply\ it|available|
                   only\ slots|declared:|did\ you\ mean|but\ not|instead|choose|one\ of|
                   valid:|operators:|share\ a\ name\ part|expected|write\ it\ as|
                   channels\ with|to\ have\ any\ effect|so\ it\ accepts|use\ )/xi
# Evidence that the slot is filled from a table rather than a constant.
ENUM_FILLER_RE = /cc_[a-z0-9_]*_str\s*\(|\.join\b|\.map\b|\.keys\b|_keys_str|_units_str|
                  buf_printf|CC_[A-Z0-9_]+\[|Capabilities|CAP::/x

# What counts as a citation here. This tree carries no internal document numbers
# by policy, so the forms left are the ones a reader can actually follow: a kernel
# artifact, or the word that says somebody ran it.
SOURCE_RE = /\bbtf_allowlist|\bBPF_[A-Z_]+\b|\b[Mm]easured\b/

ARITY = AFF["builtins"].to_h { |b| [b["name"], b["arity"]] }.freeze
NUM = { "no" => 0, "zero" => 0, "one" => 1, "two" => 2, "three" => 3, "four" => 4 }.freeze

# The `shape` arm is the biggest one, so it is also the easiest to fake: a pass
# that pastes "expects 1 arg" everywhere would raise the score while lying. It
# cannot, because the stated arity is CHECKED against the affordance signature --
# the same discipline applied to every hand-written table here. A message that
# contradicts the registry is reported as a defect in its own right, not as a
# missing remedy.
def arity_disagreement(r, s)
  return nil unless r[:remedy_kind] == "shape"

  subj = subject_of(s)
  want = ARITY[subj]
  return nil if want.nil?

  # The arity claim has to be ADJACENT to the subject. Measured with a 40-character
  # window: "kptr field read takes no args" was read as a claim about the `kptr`
  # builtin (arity 2) and reported as a contradiction that is not there. That is
  # the instrument inventing a defect -- the opposite direction from the
  # ENVIRONMENT_RE bug above, and just as invisible without reading the row.
  m = s[:msg].to_s[/#{Regexp.escape(subj)}\s*(?:\([^)]*\))?\s*(?:expects|takes)\s+(no|zero|one|two|three|four|\d+)\s*(?:arg|argument)/i, 1]
  return nil unless m

  got = NUM.fetch(m.downcase) { m.to_i }
  got == want ? nil : "says #{got}, the affordance says #{want}"
end

# A message can deliver its remedy through a runtime slot whose filler this
# static rule cannot verify ("Contexts that can supply it:%s", "Fix: %s"). Those
# are NOT counted as actionable -- the whole point of the exercise is to stop
# accepting claims -- but they are not the same thing as a message with no remedy
# at all, and lumping them together would send someone to "fix" a message that is
# already good. Reported and recorded as their own class.
def dynamic_claim?(s)
  body = s[:msg].to_s
  (body =~ /%s|\#\{/ && (body =~ ENUM_FRAME_RE || body.include?("Fix:"))) ? true : false
end

def classify(s)
  aud = audience(s)
  row = { id: s[:id], file: s[:file], line: s[:line], audience: aud,
          subject: false, remedy: nil, remedy_kind: nil, source: false,
          msg: s[:msg].to_s.gsub(/\s+/, " ").strip }
  return row unless aud == "user"
  row[:subject] = names_subject?(s)
  if (r = remedy_of(s))
    row[:remedy_kind] = r[0]
    row[:remedy] = r[1]
  end
  row[:source] = !(s[:msg] =~ SOURCE_RE).nil?
  row[:arity_bad] = arity_disagreement(row, s)
  row[:dynamic] = row[:remedy_kind].nil? && dynamic_claim?(s)
  row
end

def raw_sites
  @raw_sites ||= c_sites + ruby_sites
end

def all_rows(mutator = nil)
  sites = raw_sites
  sites = sites.map { |s| mutator.call(s) } if mutator
  sites.map { |s| classify(s) }
end

def actionable?(r) = r[:audience] == "user" && r[:subject] && !r[:remedy_kind].nil?

# What is missing, in the terms someone fixing it would use.
def debt_class(r)
  parts = []
  parts << "subject" unless r[:subject]
  parts << (r[:dynamic] ? "remedy-claimed-in-slot" : "remedy") if r[:remedy_kind].nil?
  parts.join("+")
end

# ---------------------------------------------------------------------------
# self-checks: can the definition be satisfied by boilerplate?
# ---------------------------------------------------------------------------
# Each returns [name, got, want]. A gate whose definition a template can satisfy
# measures nothing, so these run every time and abort.
def self_checks(base)
  base_n = base.count { |r| actionable?(r) }
  out = []

  # (1) DECORATION. Rewrite every message into the maximally decorated template a
  #     label check would accept. It names no alternative spelling, so nothing
  #     here is actionable.
  boiler = lambda do |s|
    s.merge(msg: "this is not supported here.\n  Why: it is not supported.\n" \
                 "  Fix: run `spinel-ebpf capabilities` and pick something else.\n" \
                 "  cited: BPF_PROG_TEST_RUN")
  end
  n = all_rows(boiler).count { |r| actionable?(r) }
  out << ["decoration", n.zero? ? "0" : n.to_s, "0"]

  # (2) NOISE. Keep every message and append three unrelated builtin names. A
  #     candidate with nothing in common with the subject is noise; if pasting
  #     names raised the score, the definition would reward noise.
  noise = lambda do |s|
    subj = subject_of(s)
    # mutually unrelated, so the pasted list cannot read as a coherent
    # "did you mean" set on its own.
    picks = []
    BUILTINS.each do |b|
      next if b == subj
      next if subj && ((RELATED[subj] || Set.new).include?(b) || (tokens(b) & tokens(subj)).any?)
      next if picks.any? { |q| (RELATED[q] || Set.new).include?(b) || (tokens(q) & tokens(b)).any? }
      picks << b
      break if picks.size == 3
    end
    s.merge(msg: "#{s[:msg]}\n  See also: #{picks.join(' ')}.")
  end
  n2 = all_rows(noise).count { |r| actionable?(r) }
  out << ["noise", n2 <= base_n ? "no-gain" : "GAINED #{n2 - base_n}", "no-gain"]

  # (3) CITATION. Appending an E-number must move `source` and NOT `actionable` —
  #     this is the measurement that says why the headline is subject && remedy
  #     and not "has a citation".
  # A citation with no parentheses, on purpose: a parenthesised one would also
  # feed the `shape` arm's "expects ... (list)" pattern, and then this check would
  # be measuring its own punctuation.
  cite = ->(s) { s.merge(msg: "#{s[:msg]} cited: BPF_PROG_TEST_RUN") }
  cr   = all_rows(cite)
  src_gain = cr.count { |r| r[:source] } - base.count { |r| r[:source] }
  act_gain = cr.count { |r| actionable?(r) } - base_n
  out << ["citation-is-free", (src_gain.positive? && act_gain.zero?) ? "source-only" : "leaked", "source-only"]

  # (4) DETECTION. Strip the remedy from one message that has one and demand the
  #     verdict flips. A gate that cannot say no reports broken=0 forever.
  victim = base.find { |r| actionable?(r) }
  if victim
    strip = lambda do |s|
      next s unless s[:id] == victim[:id]
      # the same error, said uselessly: subject kept, remedy gone.
      s.merge(msg: "`#{subject_of(s) || 'it'}` cannot be used here.", filler: "")
    end
    got = all_rows(strip).find { |r| r[:id] == victim[:id] }
    out << ["detection", actionable?(got) ? "still-actionable" : "flipped", "flipped"]
  else
    out << ["detection", "no-victim", "flipped"]
  end

  # (5) FAKE ENUMERATION. A slot framed as a list but filled by a constant is not
  #     a remedy; only a slot filled from a table is. Without this arm, arm (d)
  #     would credit `"... Accepted: %s", "nothing"`.
  fake = ->(s) { s.merge(msg: "#{s[:msg]} Accepted: %s", filler: '"nothing"') }
  n5 = all_rows(fake).count { |r| actionable?(r) }
  out << ["fake-enumeration", n5 <= base_n ? "no-gain" : "GAINED #{n5 - base_n}", "no-gain"]

  # (6) FABRICATED SHAPE. The `shape` arm is the biggest, so it must not reward a
  #     pass that pastes an arity everywhere: the stated number is checked against
  #     the affordance. Claim one arg for every builtin and demand disagreements
  #     appear (base has none).
  lie = ->(s) { s.merge(msg: "#{s[:msg]} #{subject_of(s)} expects 1 arg (x)") }
  n6 = all_rows(lie).count { |r| r[:arity_bad] }
  out << ["fabricated-shape", n6.positive? ? "caught" : "blind", "caught"]
  out
end

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
mode = ARGV[0]
# Loaded as a library by the corpus-firing script -- stop after the definitions
# so the two never keep separate copies of the extractor.
return if mode == "--extract-only"

rows = all_rows

if mode == "--list"
  puts "id\tfile\taudience\tsubject\tremedy\tsource\tmessage"
  rows.each do |r|
    puts [r[:id], r[:file], r[:audience], r[:subject] ? 1 : 0,
          r[:remedy_kind] || "-", r[:source] ? 1 : 0, r[:msg][0, 200]].join("\t")
  end
  exit 0
end

sc = self_checks(rows)
if mode == "--self-check"
  sc.each { |(n, got, want)| puts "self-check #{n}: #{got}#{got == want ? '' : " (WANTED #{want})"}" }
  exit(sc.all? { |(_n, g, w)| g == w } ? 0 : 1)
end

users = rows.select { |r| r[:audience] == "user" }
debt  = users.reject { |r| actionable?(r) }.sort_by { |r| r[:id] }

if mode == "--update"
  File.open(BASELINE, "w") do |f|
    f.puts <<~HDR
      # spinel-ebpf error-actionability debt.
      #
      # The RULE is universal and lives in tools/error_gate.rb: every user-facing
      # error site must name the SUBJECT (what in the author's file went wrong)
      # and a REMEDY (a different concrete spelling to write next). This file is
      # not an inventory of the surface -- it is the list of sites that do not
      # meet the rule yet. A new error site that fails the rule fails the gate;
      # it does not quietly join a census.
      #
      # missing: subject | remedy | subject+remedy
      # note is prose, is NOT compared, and is REQUIRED: an entry with no note
      # cannot be told from one nobody remembers (same rule as product_reach.tsv).
      #
      # Refresh: ruby tools/error_gate.rb --update   (and review the diff.)
      #
      # id\tfile\tmissing\tnote
    HDR
    existing = {}
    if File.exist?(BASELINE)
      File.foreach(BASELINE) do |l|
        next if l.start_with?("#") || l.strip.empty?
        a = l.chomp.split("\t", 4)
        existing[a[0]] = a[3].to_s
      end
    end
    debt.each do |r|
      f.puts [r[:id], r[:file], debt_class(r), existing[r[:id]].to_s].join("\t")
    end
  end
  puts "error_gate: wrote #{File.basename(BASELINE)} — #{debt.size} sites — REVIEW THE DIFF"
  exit 0
end

want = {}
notes = {}
if File.exist?(BASELINE)
  File.foreach(BASELINE) do |l|
    next if l.start_with?("#") || l.strip.empty?
    id, file, miss, note = l.chomp.split("\t", 4)
    want[id] = miss
    notes[id] = note.to_s
    _ = file
  end
end

problems = []
debt.each do |r|
  miss = debt_class(r)
  unless want.key?(r[:id])
    problems << "NOT ACTIONABLE    #{r[:id]}  (missing: #{miss})\n" \
                "               #{r[:msg][0, 120]}\n" \
                "               Every user-facing error must name what the author wrote and a\n" \
                "               different concrete spelling to write next. Fix the message, or\n" \
                "               record the debt with a note: ruby tools/error_gate.rb --update"
    next
  end
  problems << "CHANGED           #{r[:id]}  #{want[r[:id]]} -> #{miss}" if want[r[:id]] != miss
end
(want.keys - debt.map { |r| r[:id] }).sort.each do |id|
  problems << "FIXED (or gone)   #{id}  — no longer in the debt list; drop it: ruby tools/error_gate.rb --update"
end
debt.each do |r|
  next unless notes[r[:id]].to_s.strip.empty?
  next if problems.any? { |p| p.include?(r[:id]) }
  problems << "NOTE MISSING      #{r[:id]}  — say why this message cannot name a remedy yet."
end

byaud = rows.group_by { |r| r[:audience] }.transform_values(&:size)
act   = users.count { |r| actionable?(r) }
puts "-" * 72
puts "error surface: #{rows.size} sites  (#{byaud.sort.map { |k, v| "#{k}=#{v}" }.join('  ')})"
puts "user-facing:   #{users.size}"
puts "  subject      #{users.count { |r| r[:subject] }}"
puts "  remedy       #{users.count { |r| r[:remedy_kind] }}   " \
     "(#{users.group_by { |r| r[:remedy_kind] }.reject { |k, _| k.nil? }.sort_by { |_, v| -v.size }
             .map { |k, v| "#{k}:#{v.size}" }.join(' ')})"
puts "  citation     #{users.count { |r| r[:source] }}   (boilerplate-satisfiable — see self-check 3)"
dyn = users.count { |r| r[:dynamic] }
puts "  ACTIONABLE   #{act} / #{users.size}  (#{(100.0 * act / users.size).round(1)}%)   [subject && remedy, verified statically]"
puts "  claim-only   #{dyn}   (a remedy in a runtime slot this rule cannot verify — not counted above)"
bad_arity = users.select { |r| r[:arity_bad] }
puts "  arity vs affordance: #{bad_arity.empty? ? 'agree' : bad_arity.map { |r| "#{r[:id]} #{r[:arity_bad]}" }.join(', ')}"
puts "  debt         #{debt.size}"
sc.each { |(n, got, w)| puts "self-check #{n}: #{got}#{got == w ? '' : " (WANTED #{w})"}" }
unless problems.empty?
  puts
  problems.each { |p| puts "  #{p}" }
end
sc_bad = sc.reject { |(_n, g, w)| g == w }
unless sc_bad.empty?
  abort "\nerror_gate: self-check failed (#{sc_bad.map(&:first).join(', ')}).\n" \
        "  The definition of `actionable` can now be satisfied by boilerplate, so the\n" \
        "  number above means nothing. Fix the gate before trusting this run."
end
exit(problems.empty? ? 0 : 1)
