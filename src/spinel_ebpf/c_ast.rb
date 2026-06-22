# frozen_string_literal: true

# C-AST — Phase 0 (minimal foundation for structured codegen).
#
# The current codegen_bpf.rb works by expanding Ruby AST into C string
# templates, so expression values flow as strings (no types attached, defensive
# parens written by hand, blurry boundary between expressions and statements).
# This is a staged migration toward a "typed C-AST + explicit type/ownership IR".
#
# This file provides Phase 0 = a thin C-AST of **expressions (CExpr) only**,
# plus the single printer `CPrinter` (precedence -> automatic parens).
# Statements (CStmt) and declarations (CDecl) come in later phases.
#
# Design principles:
# - **byte-identical safety net**: Phase 0 reproduces the existing output
#   byte-for-byte. The "defensive outer parens" the current code carries are
#   modelled *explicitly* with `CParen` to reproduce them (a later deliberate
#   phase drops redundant parens based on precedence).
# - **automatic-paren capability proven separately**: `CPrinter` implements
#   minimal precedence-based parenthesization and is unit-tested in
#   c_ast_test.rb. Phase 0 integration uses `CParen` to stay byte-identical.
# - **escape hatch `CRaw`**: embeds a C string returned by not-yet-migrated
#   lowering directly into the tree.
# - **node-id attachment**: each node can carry its originating Ruby node-id in
#   `nid` (the basis for naming a verifier reject / boundary ABI violation as
#   `foo.rb:42`; unused in Phase 0).

module SpinelEbpf
  module CodegenBpf
    module CAst
      # Operator precedence (higher binds tighter). CPrinter uses it for minimal
      # parenthesization. Primary expressions (CLit/CId/CCall/CParen/CField/CRaw)
      # need no parens at PRIMARY_PREC.
      BINOP_PREC = {
        "||" => 20, "&&" => 25, "|" => 30, "^" => 35, "&" => 40,
        "==" => 45, "!=" => 45,
        "<" => 50, "<=" => 50, ">" => 50, ">=" => 50,
        "<<" => 55, ">>" => 55,
        "+" => 60, "-" => 60,
        "*" => 70, "/" => 70, "%" => 70
      }.freeze

      CAST_PREC    = 80
      UNARY_PREC   = 80
      POSTFIX_PREC = 90
      PRIMARY_PREC = 100

      # Base class for expressions. `nid` is the originating Ruby node-id
      # (nil for synthesized expressions).
      class CExpr
        attr_reader :nid
        def initialize(nid: nil)
          @nid = nid
        end

        # Stringify to C with the default printer (the integration point;
        # downstream receives strings).
        def to_c
          CPrinter.new.expr(self)
        end

        # Precedence the parent uses to decide whether parens are needed.
        def prec
          PRIMARY_PREC
        end
      end

      # Integer literal / token emitted verbatim (e.g. "32" / "TCP_FLAG_RST").
      class CLit < CExpr
        attr_reader :text
        def initialize(text, nid: nil)
          super(nid: nid)
          @text = text.to_s
        end
      end

      # Identifier (local variable / map name / etc.).
      class CId < CExpr
        attr_reader :name
        def initialize(name, nid: nil)
          super(nid: nid)
          @name = name.to_s
        end
      end

      # Escape hatch: embed an already-stringified C fragment as a primary
      # expression. Used in Phase 0 to put not-yet-migrated lowering return
      # values into the tree.
      class CRaw < CExpr
        attr_reader :text
        def initialize(text, nid: nil)
          super(nid: nid)
          @text = text.to_s
        end
      end

      # Function call callee(args...). Postfix = high precedence.
      class CCall < CExpr
        attr_reader :callee, :args
        def initialize(callee, args = [], nid: nil)
          super(nid: nid)
          @callee = callee.to_s
          @args = args
        end

        def prec
          POSTFIX_PREC
        end
      end

      # C cast (type)operand. Prefix = cast precedence.
      class CCast < CExpr
        attr_reader :type, :operand
        def initialize(type, operand, nid: nil)
          super(nid: nid)
          @type = type.to_s
          @operand = operand
        end

        def prec
          CAST_PREC
        end
      end

      # Unary prefix <op>operand (e.g. "!" / "-" / "~").
      class CUnary < CExpr
        attr_reader :op, :operand
        def initialize(op, operand, nid: nil)
          super(nid: nid)
          @op = op.to_s
          @operand = operand
        end

        def prec
          UNARY_PREC
        end
      end

      # Binary lhs <op> rhs (left-associative in C).
      class CBinop < CExpr
        attr_reader :op, :lhs, :rhs
        def initialize(op, lhs, rhs, nid: nil)
          super(nid: nid)
          raise ArgumentError, "unknown C binop #{op.inspect}" unless BINOP_PREC.key?(op.to_s)

          @op = op.to_s
          @lhs = lhs
          @rhs = rhs
        end

        def prec
          BINOP_PREC.fetch(@op)
        end
      end

      # Member access recv.field / recv->field. Postfix = high precedence.
      class CField < CExpr
        attr_reader :recv, :field, :arrow
        def initialize(recv, field, arrow: false, nid: nil)
          super(nid: nid)
          @recv = recv
          @field = field.to_s
          @arrow = arrow
        end

        def prec
          POSTFIX_PREC
        end
      end

      # Explicit grouping parens. Always prints "(inner)". Used in Phase 0 to
      # reproduce the current code's defensive parens byte-identically (a later
      # phase removes the redundant ones).
      class CParen < CExpr
        attr_reader :inner
        def initialize(inner, nid: nil)
          super(nid: nid)
          @inner = inner
        end
      end

      # ---- statements (CStmt) — Phase 2. One statement = one line (indentation
      # is handled by the caller / the CBlock of a later phase). CPrinter#stmt
      # returns a single line including the trailing `;`.
      class CStmt
        attr_reader :nid
        def initialize(nid: nil)
          @nid = nid
        end

        def to_c
          CPrinter.new.stmt(self)
        end
      end

      # An already-stringified single line (including a trailing `;`/`{`/`}`/etc.).
      # Escape hatch for not-yet-migrated lowering.
      class CRawStmt < CStmt
        attr_reader :text
        def initialize(text, nid: nil)
          super(nid: nid)
          @text = text.to_s
        end
      end

      # Expression statement `<expr>;`. e.g. a side-effecting builtin call.
      class CExprStmt < CStmt
        attr_reader :expr
        def initialize(expr, nid: nil)
          super(nid: nid)
          @expr = expr
        end
      end

      # Declaration `<type> <name>;` or `<type> <name> = <init>;`.
      class CDecl < CStmt
        attr_reader :type, :name, :init
        def initialize(type, name, init = nil, nid: nil)
          super(nid: nid)
          @type = type.to_s
          @name = name.to_s
          @init = init
        end
      end

      # `return <expr>;` or `return;`.
      class CReturn < CStmt
        attr_reader :expr
        def initialize(expr = nil, nid: nil)
          super(nid: nid)
          @expr = expr
        end
      end

      # A sequence of statements (block body). `CPrinter#block_lines(block, depth)`
      # expands it into multiple lines with depth-appropriate indentation. A
      # vessel for replacing after-the-fact string indentation (`"    " + line`)
      # with *structural* indentation.
      class CBlock < CStmt
        attr_reader :stmts
        def initialize(stmts = [], nid: nil)
          super(nid: nid)
          @stmts = stmts
        end
      end

      # `if (cond) { then } [else { else }]`. then/else are CBlock. CPrinter
      # indents structurally based on depth (no after-the-fact indentation).
      class CIf < CStmt
        attr_reader :cond, :then_block, :else_block
        def initialize(cond, then_block, else_block = nil, nid: nil)
          super(nid: nid)
          @cond = cond
          @then_block = then_block
          @else_block = else_block
        end
      end

      # Bare scope block `{ <body> }` (body is a CBlock). Used for ringbuf
      # scopes like spnl_emit. CPrinter indents structurally by depth.
      class CBraceBlock < CStmt
        attr_reader :body
        def initialize(body, nid: nil)
          super(nid: nid)
          @body = body
        end
      end

      # The single printer. Expressions: precedence -> minimal parens.
      # Statements: a single line with a trailing `;`. Indentation not handled here.
      class CPrinter
        def expr(node)
          case node
          when CLit   then node.text
          when CId    then node.name
          when CRaw   then node.text
          when CParen then "(#{expr(node.inner)})"
          when CCall  then "#{node.callee}(#{node.args.map { |a| expr(a) }.join(', ')})"
          when CField then "#{operand(node.recv, POSTFIX_PREC)}#{node.arrow ? '->' : '.'}#{node.field}"
          when CCast  then "(#{node.type})#{cast_operand(node.operand)}"
          when CUnary then "#{node.op}#{operand(node.operand, UNARY_PREC)}"
          when CBinop then binop(node)
          else raise ArgumentError, "CPrinter: unknown node #{node.class}"
          end
        end

        # Print a statement as a single line with a trailing `;` (no indentation).
        def stmt(node)
          case node
          when CRawStmt  then node.text
          when CExprStmt then "#{val(node.expr)};"
          when CReturn   then node.expr.nil? ? "return;" : "return #{val(node.expr)};"
          when CDecl
            node.init.nil? ? "#{node.type} #{node.name};" : "#{node.type} #{node.name} = #{val(node.init)};"
          else raise ArgumentError, "CPrinter: unknown stmt #{node.class}"
          end
        end

        INDENT = "    "

        # Expand a block into multiple lines (Array<String>) with depth-based
        # indentation.
        def block_lines(block, depth)
          block.stmts.flat_map { |s| stmt_lines(s, depth) }
        end

        # Expand one statement (or nested block/if/brace) into multiple lines at
        # depth indentation.
        def stmt_lines(node, depth)
          case node
          when CIf         then if_lines(node, depth)
          when CBlock      then block_lines(node, depth)
          when CBraceBlock then brace_lines(node, depth)
          else "#{INDENT * depth}#{stmt(node)}".split("\n", -1)
          end
        end

        private

        def if_lines(node, depth)
          pad = INDENT * depth
          out = ["#{pad}if (#{val(node.cond)}) {"]
          out.concat(block_lines(node.then_block, depth + 1))
          if node.else_block
            out << "#{pad}} else {"
            out.concat(block_lines(node.else_block, depth + 1))
          end
          out << "#{pad}}"
          out
        end

        def brace_lines(node, depth)
          pad = INDENT * depth
          ["#{pad}{"] + block_lines(node.body, depth + 1) + ["#{pad}}"]
        end

        # Print if a CExpr, otherwise use the value as-is (allows return strings
        # from not-yet-migrated lowering).
        def val(x)
          x.is_a?(CExpr) ? expr(x) : x.to_s
        end

        def binop(node)
          p = node.prec
          # Left-associative: parenthesize the left child when its precedence is
          # strictly lower, the right child when it is lower or equal. This keeps
          # a-b-c flat and a-(b-c) parenthesized.
          ls = paren_if(node.lhs, node.lhs.prec < p)
          rs = paren_if(node.rhs, node.rhs.prec <= p)
          "#{ls} #{node.op} #{rs}"
        end

        # Cast operand: cast/unary/postfix/primary are >= so they need no parens;
        # only a binary (weaker) operand is parenthesized.
        def cast_operand(operand)
          paren_if(operand, operand.prec < CAST_PREC)
        end

        def operand(child, parent_prec)
          paren_if(child, child.prec < parent_prec)
        end

        def paren_if(child, cond)
          cond ? "(#{expr(child)})" : expr(child)
        end
      end

      module_function

      # --- concise builders (for assembling trees readably from builtins) ---

      def lit(text, nid: nil)
        CLit.new(text, nid: nil)
      end

      def id(name, nid: nil)
        CId.new(name, nid: nil)
      end

      def raw(text, nid: nil)
        CRaw.new(text, nid: nil)
      end

      def call(callee, *args, nid: nil)
        CCall.new(callee, args, nid: nil)
      end

      def cast(type, operand, nid: nil)
        CCast.new(type, operand, nid: nil)
      end

      def binop(op, lhs, rhs, nid: nil)
        CBinop.new(op, lhs, rhs, nid: nil)
      end

      def paren(inner, nid: nil)
        CParen.new(inner, nid: nil)
      end

      # The frequently-used defensive cast ((__s64) x) in one place. Reproduces
      # byte-identically the outer parens the current code uses when embedding a
      # builtin return value into a larger expression.
      def s64(operand)
        paren(cast("__s64", operand))
      end

      # --- statement builders ---

      def raw_stmt(text, nid: nil)
        CRawStmt.new(text, nid: nil)
      end

      def expr_stmt(expr, nid: nil)
        CExprStmt.new(expr, nid: nil)
      end

      def decl(type, name, init = nil, nid: nil)
        CDecl.new(type, name, init, nid: nil)
      end

      def ret(expr = nil, nid: nil)
        CReturn.new(expr, nid: nil)
      end

      def block(stmts = [], nid: nil)
        CBlock.new(stmts, nid: nil)
      end

      def cif(cond, then_block, else_block = nil, nid: nil)
        CIf.new(cond, then_block, else_block, nid: nil)
      end

      def brace_block(body, nid: nil)
        CBraceBlock.new(body, nid: nil)
      end

      # Expand a block into Array<String> with depth indentation (structural).
      def render_block(block, depth = 0)
        CPrinter.new.block_lines(block, depth)
      end

      # Expand one statement (incl. CBlock/CIf/CBraceBlock) into Array<String>
      # with depth indentation.
      def render_stmt(stmt, depth = 0)
        CPrinter.new.stmt_lines(stmt, depth)
      end

      # --- Phase 4: linear-use / ownership analysis (the first pass that
      # consumes the structure) ---
      #
      # Verifies the bpf_ringbuf reserve->submit discipline from the C-AST
      # structure. Same "a resource you acquire must be released" = linear-use
      # principle as aya's `RingBufEntry #[must_use]` or an skb ref leak. If a
      # local bound to the return value of `bpf_ringbuf_reserve` is not released
      # by `bpf_ringbuf_submit` / `bpf_ringbuf_discard` within the same tree, it
      # is reported as a **leak** (return value = array of leaked local names,
      # empty = OK). Foundation mechanism for the boundary ABI (own/borrow,
      # linear-use).
      RINGBUF_ACQUIRE = "bpf_ringbuf_reserve"
      RINGBUF_RELEASE = %w[bpf_ringbuf_submit bpf_ringbuf_discard].freeze

      def ringbuf_leaks(stmt)
        reserved = []   # [name] declared from bpf_ringbuf_reserve
        released = []   # [name] passed to submit/discard
        walk_stmts(stmt) do |s|
          case s
          when CDecl
            reserved << strip_declarator(s.name) if calls?(s.init, RINGBUF_ACQUIRE)
          when CExprStmt
            e = s.expr
            if e.is_a?(CCall) && RINGBUF_RELEASE.include?(e.callee) && e.args.first
              released << expr_text(e.args.first)
            end
          end
        end
        reserved.uniq - released
      end

      # Walk the CStmt tree (recursing into CBlock/CBraceBlock/CIf), yielding
      # each statement.
      def walk_stmts(node, &blk)
        case node
        when CBlock      then node.stmts.each { |s| walk_stmts(s, &blk) }
        when CBraceBlock then walk_stmts(node.body, &blk)
        when CIf
          blk.call(node)
          walk_stmts(node.then_block, &blk)
          walk_stmts(node.else_block, &blk) if node.else_block
        when CStmt then blk.call(node)
        end
      end

      def calls?(expr, callee)
        expr.is_a?(CCall) && expr.callee == callee
      end

      # Returns the local name `p` for either `*p` or `p` declarators.
      def strip_declarator(name)
        name.to_s.sub(/\A\*+/, "")
      end

      def expr_text(expr)
        expr.is_a?(CExpr) ? expr.to_c : expr.to_s
      end
    end
  end
end
