# frozen_string_literal: true
#
# spinel-ebpf — dispatch shim emitter.
#
# Scope (MVP): for each top-level :ebpf method that has neither an attach
# pattern (kprobe__/tracepoint__/...) nor a builtin name (spnl_emit*), emit a
# native C `sp_<name>(...)` shim whose body invokes the corresponding
# SEC("syscall") BPF program via bpf_prog_test_run().
#
# The shim's symbol/signature is byte-for-byte compatible with what spinel
# would have emitted if the method's body had been left in place. This relies
# on the spinel hook (SPINEL_EXTERN_METHODS), which makes spinel emit
# only `extern <rt> sp_<name>(<params>);` for those methods, so the linker
# resolves to *our* shim instead.
#
# Boundary ABI (see BOUNDARY_* below):
#   - top-level methods only (class methods → future work)
#   - params: int (__s64) + bool (__s32) cross as ctx fields, multi-arg OK
#   - return: only `int` returns a value (32-bit retval, sign-extended);
#     bool/void/nil return as void (aligned with spinel's extern decl)
#   - anything else (string / float / array / 64-bit return) is a
#     BoundaryError, not a silent truncation

require_relative "codegen_bpf"

module SpinelEbpf
  module DispatchShim
    # The spinel<->eBPF boundary ABI for transparent dispatch as a first-class,
    # validated contract. A native call to a dispatched :ebpf method crosses as:
    #   - params: integer ctx-struct fields whose layout MUST mirror the BPF
    #     side (CodegenBpf.emit_ctx_struct via SPINEL_TYPE_TO_C: int->__s64,
    #     bool->__s32). The signature always passes `mrb_int lv_<name>` (spinel's
    #     extern), and the ctx field narrows as needed.
    #   - return: only a concrete `int` comes back as a value (the 32-bit
    #     bpf_prog_test_run retval, sign-extended to mrb_int). `bool`/`void`/`nil`
    #     return as void — matching spinel's extern decl (the canonical
    #     value ABI), which widens only a concrete int to mrb_int. Keeping the
    #     shim's return aligned with the extern decl avoids an ABI mismatch.
    # Anything outside these scalars cannot cross the value boundary and is a
    # BoundaryError (value/copy boundary, pointers don't cross).
    # Deferred: 64-bit return via ctx out-param, Result/option tagged emit,
    # borrow/own handle typing.
    BOUNDARY_PARAM_TYPES  = %w[int bool].freeze
    BOUNDARY_RETURN_TYPES = %w[int bool void nil].freeze

    # Raised when a dispatched method's signature has a type that cannot cross
    # the spinel<->eBPF value boundary.
    class BoundaryError < StandardError; end

    module_function

    # ctx-struct C type for a crossing param (mirrors the BPF side exactly), or
    # BoundaryError naming the offending param.
    def boundary_ctx_ctype!(meth_name, pname, type)
      unless BOUNDARY_PARAM_TYPES.include?(type)
        raise BoundaryError,
              "boundary ABI: cannot dispatch `sp_#{meth_name}` — parameter " \
              "`#{pname}` has type #{type.inspect}, which does not cross the " \
              "spinel<->eBPF boundary (only #{BOUNDARY_PARAM_TYPES.join('/')} are " \
              "carried as ctx fields). Keep the method :native, or pass the value " \
              "via a shared map / ringbuf."
      end
      CodegenBpf::SPINEL_TYPE_TO_C[type]
    end

    # Validate a crossing return type (only `int` returns a value).
    def boundary_check_return!(meth_name, type)
      return if BOUNDARY_RETURN_TYPES.include?(type)

      raise BoundaryError,
            "boundary ABI: cannot dispatch `sp_#{meth_name}` — return type " \
            "#{type.inspect} does not cross the spinel<->eBPF boundary " \
            "(only #{BOUNDARY_RETURN_TYPES.join('/')}; non-int returns as void)."
    end

    # Returns the list of :ebpf top-level method names eligible for transparent
    # dispatch (= the value to set in SPINEL_EXTERN_METHODS).
    def eligible_method_names(partition_result)
      partition_result.methods
        .select { |m| eligible?(m) }
        .map(&:method_name)
    end

    # Returns the dispatch.c text, or nil if no eligible methods.
    # ir/ast/partition_result are the same objects fed to CodegenBpf.emit.
    # base_name matches the unit name (file basename without .rb).
    def emit(ir, ast, partition_result, base_name:)
      eligible = partition_result.methods.select { |m| eligible?(m) }
      return nil if eligible.empty?

      skel_name = CodegenBpf.sanitize_identifier(base_name)
      # Build a fake ctx just enough for the helpers we reuse from CodegenBpf
      # (method_params / method_return_type). They only read ir/partition.
      ctx = CodegenBpf::EmitContext.new(
        ir: ir, ast: ast, partition: partition_result,
        base_name: base_name, unit_name: skel_name,
        uses_ringbuf: false, uses_str_ringbuf: false, uses_pair_ringbuf: false,
        ebpf_methods_by_name: {}, loop_counter: 0, deferred_functions: [],
        pkt_builtins_used: nil,
        uses_blocklist: false,
        uses_path_counter: false,
        uses_reuseport_sockarray: false,
        uses_xdp_health_match: false,
        uses_xdp_health_reply: false,
      )

      ctx_structs = eligible.map { |mi| emit_ctx_struct_decl(ctx, mi) }
      shims       = eligible.map { |mi| emit_one(ctx, mi, skel_name) }

      <<~DISPATCH
        /* SPDX-License-Identifier: MIT OR Apache-2.0
         * GENERATED by spinel-ebpf. Transparent native -> eBPF dispatch.
         *
         * spinel emits `extern mrb_int sp_<name>(...)` for each method listed
         * in SPINEL_EXTERN_METHODS; the shims below provide the body
         * and forward the call to the corresponding SEC("syscall") BPF program
         * loaded by the auto-generated glue (constructor in <base>_glue.c).
         */
        #include <stdint.h>
        #include <stdio.h>
        #include <string.h>
        #include <errno.h>
        #include <linux/types.h>     /* __s64 */
        #include <bpf/libbpf.h>
        #include <bpf/bpf.h>
        #include "#{base_name}.skel.h"

        typedef int64_t mrb_int;

        /* Defined in <base>_glue.c. Holds the loaded + attached skeleton. */
        extern struct #{skel_name} *_spnl_skel;

        /* ctx structs mirroring the BPF-side definitions (kept in sync with
         * codegen_bpf.emit_ctx_struct). userspace fills these before invoking
         * bpf_prog_test_run. */
        #{ctx_structs.join("\n")}

        #{shims.join("\n")}
      DISPATCH
    end

    # Mirror of CodegenBpf.emit_ctx_struct, emitted into dispatch.c so the
    # native side has the struct layout (the BPF skeleton header doesn't
    # re-export it).
    def emit_ctx_struct_decl(ctx, mi)
      params = CodegenBpf.method_params(ctx, mi)
      return "" if params.empty?
      func = CodegenBpf.method_func_name(mi)
      fields = params.map do |name, type|
        "    #{boundary_ctx_ctype!(mi.method_name, name, type)} #{name};"
      end
      "struct #{func}_ctx {\n#{fields.join("\n")}\n};"
    end

    def eligible?(mi)
      return false unless mi.tag == :ebpf
      return false unless mi.scope == :top_level
      return false if CodegenBpf::BUILTIN_NAMES.include?(mi.method_name)
      return false if CodegenBpf.detect_attach(mi.method_name)
      true
    end

    def emit_one(ctx, mi, skel_name)
      name        = mi.method_name
      func        = CodegenBpf.method_func_name(mi)
      params      = CodegenBpf.method_params(ctx, mi)
      return_type = CodegenBpf.method_return_type(ctx, mi)

      # Boundary ABI: int/bool params cross as ctx fields; only `int` returns a
      # value (bool/void/nil -> void shim, matching spinel's extern decl).
      params.each { |(pn, pt)| boundary_ctx_ctype!(name, pn, pt) }
      boundary_check_return!(name, return_type)

      sig_params =
        if params.empty?
          "void"
        else
          params.map { |n, _| "mrb_int lv_#{n}" }.join(", ")
        end

      c_return = (return_type == "int") ? "mrb_int" : "void"

      ctx_init =
        if params.empty?
          "        /* no ctx (no params) */"
        else
          assigns = params.map { |n, _| "            .#{n} = (int64_t)lv_#{n}," }.join("\n")
          "        struct #{func}_ctx ctx = {\n#{assigns}\n        };"
        end

      ctx_args =
        if params.empty?
          ".ctx_in = NULL, .ctx_size_in = 0"
        else
          ".ctx_in = &ctx, .ctx_size_in = sizeof(ctx)"
        end

      return_stmt =
        if return_type == "int"
          # SEC("syscall") return is __u32; sign-extend back to mrb_int (int64_t).
          "        return (mrb_int)(int32_t)opts.retval;"
        else
          "        return;"
        end

      fallback_stmt =
        if return_type == "int"
          "            return 0;"
        else
          "            return;"
        end

      <<~SHIM
        /* sp_#{name}: transparent dispatch into SEC("syscall") int #{func}(...). */
        #{c_return} sp_#{name}(#{sig_params})
        {
        #{ctx_init}
            if (!_spnl_skel) {
                fprintf(stderr, "[spinel-ebpf] sp_#{name}: skeleton not loaded\\n");
        #{fallback_stmt}
            }
            int prog_fd = bpf_program__fd(_spnl_skel->progs.#{func});
            if (prog_fd < 0) {
                fprintf(stderr, "[spinel-ebpf] sp_#{name}: prog fd lookup failed\\n");
        #{fallback_stmt}
            }
            LIBBPF_OPTS(bpf_test_run_opts, opts,
                #{ctx_args});
            int err = bpf_prog_test_run_opts(prog_fd, &opts);
            if (err) {
                fprintf(stderr, "[spinel-ebpf] sp_#{name}: bpf_prog_test_run failed: %s\\n",
                        strerror(-err));
        #{fallback_stmt}
            }
        #{return_stmt}
        }
      SHIM
    end
  end
end
