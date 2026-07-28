# frozen_string_literal: true

# A C abstract syntax tree -- the minimum structure a code generator needs.
#
# The generator started out expanding Ruby AST nodes into C string templates, so
# the value of an expression travelled as text: no type rode along with it,
# defensive parentheses were written by hand, and the line between an expression
# and a statement was blurry. This file is the first step away from that.
#
# What is here is a thin tree of expressions (CExpr) and statements (CStmt), plus
# the single printer `CPrinter`, which adds parentheses from operator precedence.
#
# The design follows a few rules:
# - **Reproduce the existing output byte for byte.** The defensive outer
#   parentheses the old code emits are modelled explicitly with `CParen` so the
#   output does not shift while the tree is being introduced. Dropping the
#   redundant ones is a deliberate later change, not a side effect of this one.
# - **Automatic parenthesisation is proven separately.** `CPrinter` implements
#   minimal parenthesisation from precedence and is unit-tested for it; the
#   integration path uses `CParen` so the bytes stay identical.
# - **`CRaw` is the escape hatch.** Lowering code that has not moved to the tree
#   yet returns a C string, and `CRaw` carries it through untouched.
# - **Nodes carry a source id.** Each node can hold the Ruby node id it came from
#   in `nid`, which is what will eventually let a verifier rejection or a boundary
#   violation name `foo.rb:42`. Nothing reads it yet.

module SpinelEbpf
  module CodegenBpf
    module CAst
      # Operator precedence; a larger number binds tighter. CPrinter uses this to
      # add the fewest parentheses it can. Primary expressions (CLit, CId, CCall,
      # CParen, CField, CRaw) sit at PRIMARY_PREC and never need any.
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

      # The base of every expression. `nid` is the Ruby node id it came from, and
      # is nil for an expression the generator synthesised itself.
      class CExpr
        attr_reader :nid
        def initialize(nid: nil)
          @nid = nid
        end

        # Render to C with the default printer. This is the seam: everything
        # downstream still receives a string.
        def to_c
          CPrinter.new.expr(self)
        end

        # The precedence a parent consults to decide whether to parenthesise this.
        def prec
          PRIMARY_PREC
        end
      end

      # An integer literal, or any token emitted verbatim ("32", "TCP_FLAG_RST").
      class CLit < CExpr
        attr_reader :text
        def initialize(text, nid: nil)
          super(nid: nid)
          @text = text.to_s
        end
      end

      # An identifier: a local variable, a map name, and so on.
      class CId < CExpr
        attr_reader :name
        def initialize(name, nid: nil)
          super(nid: nid)
          @name = name.to_s
        end
      end

      # The escape hatch: embed an already-rendered C fragment as a primary
      # expression. It is how lowering code that has not moved to the tree yet gets
      # its result into one.
      class CRaw < CExpr
        attr_reader :text
        def initialize(text, nid: nil)
          super(nid: nid)
          @text = text.to_s
        end
      end

      # A call, callee(args...). Postfix, so it binds tightly.
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

      # A cast, (type)operand.
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

      # A prefix unary operator: "!", "-", "~".
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

      # A binary operator, lhs <op> rhs. These associate to the left in C.
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

      # Member access, recv.field or recv->field. Postfix, so it binds tightly.
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

      # Explicit grouping: always prints "(inner)". This is what reproduces the old
      # code's defensive parentheses exactly; removing the redundant ones is a
      # separate, deliberate change.
      class CParen < CExpr
        attr_reader :inner
        def initialize(inner, nid: nil)
          super(nid: nid)
          @inner = inner
        end
      end

      # ---- statements. One statement is one line; indentation belongs to the
      # caller, or to CBlock. CPrinter#stmt returns that line including its
      # trailing semicolon.
      class CStmt
        attr_reader :nid
        def initialize(nid: nil)
          @nid = nid
        end

        def to_c
          CPrinter.new.stmt(self)
        end
      end

      # An already-rendered line, including whatever it ends with -- a semicolon, a
      # brace. The statement-level escape hatch.
      class CRawStmt < CStmt
        attr_reader :text
        def initialize(text, nid: nil)
          super(nid: nid)
          @text = text.to_s
        end
      end

      # An expression statement, `<expr>;` -- a call to a builtin for its effect.
      class CExprStmt < CStmt
        attr_reader :expr
        def initialize(expr, nid: nil)
          super(nid: nid)
          @expr = expr
        end
      end

      # A declaration, `<type> <name>;` or `<type> <name> = <init>;`.
      class CDecl < CStmt
        attr_reader :type, :name, :init
        def initialize(type, name, init = nil, nid: nil)
          super(nid: nid)
          @type = type.to_s
          @name = name.to_s
          @init = init
        end
      end

      # `return <expr>;`, or bare `return;`.
      class CReturn < CStmt
        attr_reader :expr
        def initialize(expr = nil, nid: nil)
          super(nid: nid)
          @expr = expr
        end
      end

      # A sequence of statements: the body of a block. `CPrinter#block_lines(block,
      # depth)` expands it to lines indented for that depth, which removes the need
      # to bolt indentation on afterwards (`"    " + line`) and
      # replaces it with indentation that comes from the structure itself.
      class CBlock < CStmt
        attr_reader :stmts
        def initialize(stmts = [], nid: nil)
          super(nid: nid)
          @stmts = stmts
        end
      end

      # `if (cond) { then } [else { else }]`, where each arm is a CBlock. CPrinter
      # indents them from the nesting depth, so nothing has to be indented after
      # the fact.
      class CIf < CStmt
        attr_reader :cond, :then_block, :else_block
        def initialize(cond, then_block, else_block = nil, nid: nil)
          super(nid: nid)
          @cond = cond
          @then_block = then_block
          @else_block = else_block
        end
      end

      # A bare scope, `{ <body> }`, whose body is a CBlock. It is what gives an
      # emit its own ringbuf scope. Indented from depth like everything else.
      class CBraceBlock < CStmt
        attr_reader :body
        def initialize(body, nid: nil)
          super(nid: nid)
          @body = body
        end
      end

      # The one printer. Expressions get the fewest parentheses precedence allows;
      # a statement becomes one line ending in a semicolon. It does not indent.
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

        # Print a statement as a single line ending in a semicolon, unindented.
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

        # Expand a block into an array of lines, indented for the given depth.
        def block_lines(block, depth)
          block.stmts.flat_map { |s| stmt_lines(s, depth) }
        end

        # Expand one statement -- or a nested block, if, or brace -- into lines at
        # the given depth.
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

        # Print a CExpr; pass anything else through, which is what allows lowering
        # code that still returns a string.
        def val(x)
          x.is_a?(CExpr) ? expr(x) : x.to_s
        end

        def binop(node)
          p = node.prec
          # Left associative: the left child needs parentheses only when its
          # precedence is strictly lower, the right child also when it is equal.
          # That keeps a-b-c flat while preserving the parentheses in a-(b-c).
          ls = paren_if(node.lhs, node.lhs.prec < p)
          rs = paren_if(node.rhs, node.rhs.prec <= p)
          "#{ls} #{node.op} #{rs}"
        end

        # The operand of a cast: casts, unary, postfix and primary all bind at
        # least as tightly and need nothing; only a binary operand is parenthesised.
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

      # --- terse builders, so a builtin can assemble a tree readably ---

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

      # The defensive cast ((__s64) x), which appears everywhere, in one place. It
      # reproduces exactly the outer parentheses the old code puts around a
      # builtin's result when embedding it in a larger expression.
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

      # Expand a block to an array of lines, indented from its depth.
      def render_block(block, depth = 0)
        CPrinter.new.block_lines(block, depth)
      end

      # Expand one statement -- including a CBlock, CIf or CBraceBlock -- to lines
      # at the given depth.
      def render_stmt(stmt, depth = 0)
        CPrinter.new.stmt_lines(stmt, depth)
      end

      # --- linear use, the first analysis that consumes the tree's structure ---
      #
      # Checks the reserve-then-submit discipline of a ringbuf from the shape of the
      # C-AST. It is the same rule as `#[must_use]` on a ring buffer entry in other
      # eBPF frameworks, and the same rule the verifier applies to a leaked socket
      # buffer reference: a resource you acquire must be released. A local bound to
      # the result of `bpf_ringbuf_reserve` that is never passed to
      # `bpf_ringbuf_submit` or `bpf_ringbuf_discard` anywhere in the same tree is
      # reported as a leak. The return value is the list of leaked local names, so
      # an empty array means the tree is clean.
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

      # Walk the statement tree, recursing into blocks, braces and conditionals,
      # and yield each statement.
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

      # Return the local's name, `p`, from either declarator form: `*p` or `p`.
      def strip_declarator(name)
        name.to_s.sub(/\A\*+/, "")
      end

      def expr_text(expr)
        expr.is_a?(CExpr) ? expr.to_c : expr.to_s
      end
    end
  end
end
