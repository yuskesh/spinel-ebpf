/* In-process codegen driver: emit the eBPF .bpf.c / the
 * SPINEL-IR v1 .ir for a .rb via the IN-PROCESS path — parse + analyze the
 * program to an upstream Compiler, then call spnl_ebpf_codegen_str
 * (fill_ir_from_compiler -> emitter) and/or cc_build_ir_text, with NO text
 * round-trip and NO `--emit-ir`. This is the production replacement for the
 * `build/spinel --emit-ir` + Stage-1 text codegen chain; tools/stage2_verify.sh
 * diffs its output against that chain to prove byte-identity over every fixture.
 *
 * Builds by #include-ing the codegen TU with SPNL_INPROCESS (so the text
 * parsers/main drop out and the Compiler-direct entry compiles in), then links
 * the upstream compiler objects (minus main.o) + the parse lib:
 *
 *   cc -DSPNL_INPROCESS -I deps/spinel/src \
 *      tools/spinel_ebpf_inproc.c <spinel objs minus main.o> \
 *      deps/spinel/build/libprism.a -lm -o build/codegen_c/spinel-ebpf-cc
 */
#define SPNL_INPROCESS
#include "../src/codegen_c/spinel_ebpf_cc.c"

/* upstream entry points (declared here to avoid extra include-path coupling). */
char *sp_parse_file_to_text(const char *source_file, const char *argv0);
void  analyze_program(Compiler *c);

/* usage: spinel-ebpf-cc <file.rb> <base> [--ir]
 *   default : print the in-process .bpf.c (fill_ir_from_compiler -> emitter)
 *   --ir    : print the relocated SPINEL-IR v1 text (cc_build_ir_text), to diff
 *             against `build/spinel --emit-ir` (proves the --emit-ir patch can
 *             be removed). */
int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) { fprintf(stderr, "usage: %s <file.rb> <base> [--ir]\n", argv[0]); return 1; }
  int want_ir = (argc == 4 && !strcmp(argv[3], "--ir"));
  char *text = sp_parse_file_to_text(argv[1], argv[0]);
  if (!text) { fprintf(stderr, "stage2_verify: parse failed for '%s'\n", argv[1]); return 1; }
  /* Two loads of the same parse: nt_ast stays pristine for the codegen's AST
   * reads; nt_an is mutated by analyze_program (block-param alpha-rename). Same
   * source text => identical node ids, so the Compiler's body_id/node refs
   * index correctly into the pristine AST. The .ir is built from the analyzed
   * compiler (matching upstream build_ir_text, which also runs post-analyze). */
  NodeTable *nt_ast = nt_load_text(text);
  NodeTable *nt_an  = nt_load_text(text);
  free(text);
  if (!nt_ast || !nt_an) { fprintf(stderr, "stage2_verify: AST load failed\n"); return 1; }
  Compiler *c = comp_new(nt_an);
  analyze_program(c);
  char *out = want_ir ? cc_build_ir_text(c) : spnl_ebpf_codegen_str(c, nt_ast, argv[2]);
  fputs(out, stdout);
  return 0;
}
