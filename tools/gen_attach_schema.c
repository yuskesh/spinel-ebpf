/* gen_attach_schema.c -- render attach_schema.h as JSON for the Ruby side.
 *
 * The attach vocabulary is declared once in src/codegen_c/attach_schema.h;
 * cc_detect_attach() walks it directly and the Ruby side (capabilities.rb)
 * reads the JSON this program prints, so the machine half of ATTACH_KINDS
 * (kind set, sec, ctx_type, kname, facets) cannot drift from the codegen.
 * Committed derived artifact: `make -C src/codegen_c attach-schema` regenerates
 * src/spinel_ebpf/attach_schema_gen.json; tools/attach_gate.rb refuses a stale
 * or hand-edited copy.
 *
 * The generator also VALIDATES the one derivable column: `sec_mode` must equal
 * what `sec_pattern` implies (no '<' = fixed, one placeholder = template, two =
 * split2, NULL = none). A mismatch is a contradiction inside the declaration
 * itself, so it exits 1 here rather than letting two readers disagree later. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/codegen_c/attach_schema.h"

static void js(const char *s) {
  if (!s) { printf("null"); return; }
  /* the vocabulary is C identifiers and SEC patterns -- refuse anything that
   * would need escaping instead of implementing an escaper nothing exercises */
  if (strchr(s, '"') || strchr(s, '\\')) {
    fprintf(stderr, "gen_attach_schema: string needs JSON escaping: %s\n", s);
    exit(1);
  }
  printf("\"%s\"", s);
}

static CcSecMode derived_mode(const char *pattern) {
  if (!pattern) return CC_SEC_NONE;
  const char *lt = strchr(pattern, '<');
  if (!lt) return CC_SEC_FIXED;
  return strchr(lt + 1, '<') ? CC_SEC_SPLIT2 : CC_SEC_TEMPLATE;
}

int main(void) {
  static const char *mode_name[] = { "fixed", "template", "split2", "none" };
  printf("[\n");
  for (int i = 0; i < CC_N_ATTACH_DECLS; i++) {
    const CcAttachDecl *d = &cc_attach_decls[i];
    if (derived_mode(d->sec_pattern) != d->sec_mode) {
      fprintf(stderr, "gen_attach_schema: %s: sec_mode contradicts sec_pattern %s\n",
              d->ruby_kind, d->sec_pattern ? d->sec_pattern : "(null)");
      return 1;
    }
    printf("  { \"kind\": "); js(d->ruby_kind);
    printf(", \"detect\": "); js(d->detect == CC_AD_PREFIX ? "prefix" : "class");
    printf(", \"prefix\": "); js(d->prefix);
    printf(", \"sec_mode\": "); js(mode_name[d->sec_mode]);
    printf(", \"sec\": "); js(d->sec_pattern);
    printf(", \"ctx_type\": "); js(d->ctx_type);
    printf(", \"kname\": "); js(d->kname);
    printf(", \"ctx_prefixed\": %s", d->ctx_prefixed ? "true" : "false");
    printf(", \"verdict\": %s", d->verdict ? "true" : "false");
    printf(", \"iter_guard\": %s", d->iter_guard ? "true" : "false");
    printf(", \"usdt\": %s", d->usdt ? "true" : "false");
    printf(", \"xdp_tail\": %s", d->xdp_tail ? "true" : "false");
    printf(", \"tcp_slice\": %s", d->tcp_slice ? "true" : "false");
    printf(", \"rest_needs_sep\": %s", d->rest_needs_sep ? "true" : "false");
    printf(", \"rest_excludes\": "); js(d->rest_excludes);
    printf(" }%s\n", i + 1 < CC_N_ATTACH_DECLS ? "," : "");
  }
  printf("]\n");
  return 0;
}
