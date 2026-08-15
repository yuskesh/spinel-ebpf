/* gen_builtin_schema.c -- render builtin_schema.h as JSON for the Ruby side.
 *
 * Three axes today: the declared-arity table, the per-target builtin existence
 * table, and the per-target syntax table (empty here -- see the header).
 * Committed derived artifact: `make -C src/codegen_c builtin-schema`
 * regenerates src/spinel_ebpf/builtin_schema_gen.json; tools/builtin_gate.rb
 * refuses a stale or hand-edited copy. Consumers: target_profile.rb
 * (call_allowlist per target) and capabilities.rb (valid_targets on each
 * builtin entry). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/codegen_c/builtin_schema.h"

static void js(const char *s) {
  if (strchr(s, '"') || strchr(s, '\\')) {
    fprintf(stderr, "gen_builtin_schema: string needs JSON escaping: %s\n", s);
    exit(1);
  }
  printf("\"%s\"", s);
}

int main(void) {
  printf("{\n  \"default_targets\": [\"linux\"],\n");
  printf("  \"declared_arity\": [\n");
  for (int i = 0; i < CC_N_DECLARED_ARITY; i++) {
    printf("    { \"name\": "); js(cc_declared_arity[i].name);
    printf(", \"arity\": %d }%s\n", cc_declared_arity[i].arity,
           i + 1 < CC_N_DECLARED_ARITY ? "," : "");
  }
  printf("  ],\n  \"targets\": [\n");
  for (int i = 0; i < CC_N_BUILTIN_TARGETS; i++) {
    unsigned t = cc_builtin_targets[i].targets;
    if (t == 0) { fprintf(stderr, "gen_builtin_schema: %s has an empty target set\n",
                          cc_builtin_targets[i].name); return 1; }
    if (t == CC_TGT_LINUX) {
      fprintf(stderr, "gen_builtin_schema: %s declares plain {linux} -- that is the "
                      "default; a row for it buries the exceptions (scope rule)\n",
              cc_builtin_targets[i].name);
      return 1;
    }
    printf("    { \"name\": "); js(cc_builtin_targets[i].name);
    printf(", \"targets\": [");
    int first = 1;
    if (t & CC_TGT_LINUX) { printf("%s\"linux\"", first ? "" : ", "); first = 0; }
    if (t & CC_TGT_AMP)   { printf("%s\"amp\"", first ? "" : ", "); first = 0; }
    printf("] }%s\n", i + 1 < CC_N_BUILTIN_TARGETS ? "," : "");
  }
  printf("  ],\n  \"syntax_targets\": [\n");
  for (int i = 0; i < CC_N_SYNTAX_TARGETS; i++) {
    unsigned t = cc_syntax_targets[i].targets;
    if (t == 0 || t == CC_TGT_LINUX) {
      fprintf(stderr, "gen_builtin_schema: syntax %s: target set %s\n",
              cc_syntax_targets[i].name,
              t == 0 ? "is empty"
                     : "is plain {linux} -- linux has no allowlist, the row is dead");
      return 1;
    }
    printf("    { \"name\": "); js(cc_syntax_targets[i].name);
    printf(", \"targets\": [");
    int first = 1;
    if (t & CC_TGT_LINUX) { printf("%s\"linux\"", first ? "" : ", "); first = 0; }
    if (t & CC_TGT_AMP)   { printf("%s\"amp\"", first ? "" : ", "); first = 0; }
    printf("] }%s\n", i + 1 < CC_N_SYNTAX_TARGETS ? "," : "");
  }
  printf("  ]\n}\n");
  return 0;
}
