/* spinel_ebpf_cc -- C port of spinel-ebpf's eBPF codegen.
 *
 * Reads the SPINEL-IR v1 text (`--emit-ir`) + AST dump (`--dump-ast`) and emits
 * the .bpf.c, aiming to be BYTE-IDENTICAL to the Ruby `CodegenBpf.emit`. The Ruby
 * co-process stays the regression oracle (tools/cgen_oracle.rb diffs the two).
 *
 * Stage 1 scope grows one feature at a time, each verified byte-identical:
 *   02_integer_arith -- int-param methods, arithmetic-expr bodies, SEC("syscall").
 *
 * Conventions follow upstream spinel src/ (convention audit): 2-space indent,
 * K&R braces, block comments only, `Buf`/`nt_*`/`ty_*` types mirror upstream so the
 * Stage-2 in-process plugin can swap our text parsers for the real NodeTable/Compiler.
 * Anything not yet ported is a hard error (there is no silent fallback). Pure host
 * text processing -- builds with cc on macOS/Linux.
 *
 *   spinel_ebpf_cc <unit.ir> <unit.ast> <base_name>   # -> .bpf.c on stdout
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>   /* access() for the best-effort BTF reader */

/* Fixed hand-written BPF C helpers live as pristine .template.c files under
 * templates/, embedded here at build time (tools/embed_templates.rb). Each is a
 * `static const char tpl_<name>[]` with @KEY@ slots filled by tpl_emit (e.g.
 * @SIG@ = function signature, @UNIT@ = per-unit name prefix); slot-free ones go
 * through bare buf_puts. Keeps fixed snippets whose *shape* doesn't depend on
 * program structure out of the codegen logic without a runtime file dep. */
#include "templates_gen.h"

/* Packed-record ringbuf layouts are *data*, not template text: one declaration
 * per channel feeds the kernel struct (S1), the userspace mirror (S2) and the
 * capabilities surface. */
#include "record_schema.h"

/* ---------- diagnostics (mirror upstream `spinel:` + exit(1)) ---------- */

static void die(const char *msg, const char *detail) {
  fprintf(stderr, "spinel-ebpf: %s%s%s\n", msg,
          detail ? ": " : "", detail ? detail : "");
  exit(1);
}

#ifndef SPNL_INPROCESS  /* file slurp -- text driver (main) only */
static char *slurp(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) die("cannot open", path);
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = malloc((size_t)n + 1);
  if (!buf) die("oom", path);
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) die("short read", path);
  buf[n] = '\0';
  fclose(f);
  return buf;
}
#endif  /* SPNL_INPROCESS (slurp) */

/* ---------- output buffer (Buf: same layout + API as upstream codegen_util.c,
 * so Stage 2 drops these three and links the real ones) ---------- */

typedef struct { char *p; size_t len, cap; } Buf;

static void buf_putn(Buf *b, const char *s, size_t n) {
  if (b->len + n + 1 > b->cap) {
    size_t nc = b->cap ? b->cap : 256;
    while (b->len + n + 1 > nc) nc *= 2;
    b->p = realloc(b->p, nc);
    b->cap = nc;
  }
  memcpy(b->p + b->len, s, n);
  b->len += n;
  b->p[b->len] = '\0';
}
static void buf_puts(Buf *b, const char *s) { buf_putn(b, s, strlen(s)); }

/* non-truncating printf-append: 512B stack fast path, exact-size malloc fallback. */
static void buf_printf(Buf *b, const char *fmt, ...) {
  char tmp[512];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  if (n < 0) die("vsnprintf", NULL);
  if ((size_t)n < sizeof tmp) { buf_putn(b, tmp, (size_t)n); return; }
  char *big = malloc((size_t)n + 1);
  if (!big) die("oom", NULL);
  va_start(ap, fmt);
  vsnprintf(big, (size_t)n + 1, fmt, ap);
  va_end(ap);
  buf_putn(b, big, (size_t)n);
  free(big);
}

/* emit an embedded template (templates_gen.h), substituting its @KEY@ slots.
 * `slots[i].key` includes the surrounding @...@ (e.g. "@SIG@"). Each occurrence
 * of a key is replaced by its value; everything else is copied verbatim. */
typedef struct { const char *key, *val; } TplSlot;
static void tpl_emit(Buf *b, const char *tpl, const TplSlot *slots, int n) {
  for (const char *p = tpl; *p; ) {
    if (*p == '@') {
      const char *rep = NULL; size_t kl = 0;
      for (int i = 0; i < n; i++) {
        size_t l = strlen(slots[i].key);
        if (!strncmp(p, slots[i].key, l)) { rep = slots[i].val; kl = l; break; }
      }
      if (rep) { buf_puts(b, rep); p += kl; continue; }
    }
    buf_putn(b, p, 1); p++;
  }
}

/* split `s` on `sep` into out[] (returns count). Empty fields preserved
 * (split(-1) semantics). The strdup'd backing buffer is leaked: a short-lived
 * tool; Stage-2 in-process must add free discipline (convention audit). */
static int split(const char *s, char sep, char ***out) {
  char *copy = strdup(s);
  int cap = 8, n = 0;
  char **arr = malloc(sizeof(char *) * cap);
  char *start = copy;
  for (char *c = copy; ; c++) {
    if (*c == sep || *c == '\0') {
      if (n + 1 > cap) { cap *= 2; arr = realloc(arr, sizeof(char *) * cap); }
      int last = (*c == '\0');
      *c = '\0';
      arr[n++] = start;
      start = c + 1;
      if (last) break;
    }
  }
  *out = arr;
  return n;
}

/* malloc'd sprintf (non-truncating). */
static char *msprintf(const char *fmt, ...) {
  char tmp[512];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  if (n < 0) die("vsnprintf", NULL);
  char *out = malloc((size_t)n + 1);
  if (!out) die("oom", NULL);
  if ((size_t)n < sizeof tmp) { memcpy(out, tmp, (size_t)n + 1); return out; }
  va_start(ap, fmt); vsnprintf(out, (size_t)n + 1, fmt, ap); va_end(ap);
  return out;
}

/* ordered list of owned strings (function body lines / a name set). */
typedef struct { char **v; int n, cap; } Lines;
static void lines_push(Lines *L, char *s) {
  if (L->n + 1 > L->cap) { L->cap = L->cap ? L->cap * 2 : 8; L->v = realloc(L->v, sizeof(char *) * L->cap); }
  L->v[L->n++] = s;
}
static int lines_has(Lines *L, const char *s) {
  for (int i = 0; i < L->n; i++) if (!strcmp(L->v[i], s)) return 1;
  return 0;
}

/* tpl_emit for statement lowering (templates/bi_*.template.c): substitute the
 * slots, strip the template's trailing newline, and push the result as ONE
 * multi-line Lines entry. Downstream indentation (cc_indent_each / cs depth
 * passes) prefixes every embedded line, so this is byte-identical to pushing
 * each line individually. */
static void tpl_emit_lines(Lines *L, const char *tpl, const TplSlot *slots, int n) {
  Buf b; memset(&b, 0, sizeof b);
  tpl_emit(&b, tpl, slots, n);
  if (b.len && b.p[b.len - 1] == '\n') b.p[--b.len] = '\0';
  lines_push(L, b.p ? b.p : strdup(""));
}

/* ---------- typed record channels ----------
 *
 * The packed-record layouts are declared as data in record_schema.h rather than
 * hand-written as templates/ text, so that the one declaration can feed
 * the kernel struct (here), the userspace mirror (S2) and the capabilities
 * surface (S3). This emitter is the S1 consumer: it prints the record struct and
 * its ringbuf map, byte-identically to the template it replaces. */
static void cc_rec_emit_channel(Buf *b, const CcRecSchema *s, const char *unit) {
  /* A channel that lives inside a larger section (http/redis/offcpu keep their
   * pending/stash maps in a template) declares no banner: the section already
   * printed one, and inventing a second would change the emitted text. */
  if (s->banner) buf_printf(b, "%s\n", s->banner);
  buf_printf(b, "struct %s_%s {\n", unit, s->struct_suffix);
  for (int i = 0; i < s->nfields; i++) {
    const CcRecField *f = &s->fields[i];
    if (f->count > 0) buf_printf(b, "    %s %s[%d];\n", f->ctype, f->name, f->count);
    else              buf_printf(b, "    %s %s;\n", f->ctype, f->name);
  }
  buf_puts(b, "};\n\n");
  buf_puts(b, "struct {\n    __uint(type, BPF_MAP_TYPE_RINGBUF);\n");
  buf_printf(b, "    __uint(max_entries, %s);\n", s->ringbuf_size);
  buf_printf(b, "} %s_%s SEC(\".maps\");\n", unit, s->map_suffix);
}

/* ---------- types (CcTy mirrors upstream types.h; Stage 2 reads it directly
 * from Scope.ret / LocalVar.type instead of the legacy string tag) ---------- */

typedef enum { CC_TY_UNKNOWN, CC_TY_INT, CC_TY_VOID, CC_TY_BOOL } CcTy;

static CcTy ty_from_legacy(const char *s) {
  /* spinel widens a type to nullable (`int?`) when a value can be nil
   * (e.g. `if cond; spnl_emit(x); end` with no else). Nullability is orthogonal
   * to eBPF eligibility -- nil lowers to 0/__s64 -- so strip a trailing `?` and
   * match the base type (Ruby partition `t.end_with?("?") ? t[0..-2] : t`). */
  size_t n = strlen(s);
  size_t base = (n > 0 && s[n - 1] == '?') ? n - 1 : n;
  if (base == 3 && !strncmp(s, "int", 3)) return CC_TY_INT;
  /* `bool` lowers to __s32 (Ruby SPINEL_TYPE_TO_C["bool"]); eBPF-eligible. */
  if (base == 4 && !strncmp(s, "bool", 4)) return CC_TY_BOOL;
  /* `nil`/`void` both map to a void C return (Ruby NIL_TYPE_MAP). */
  if ((base == 4 && !strncmp(s, "void", 4)) || (base == 3 && !strncmp(s, "nil", 3))) return CC_TY_VOID;
  return CC_TY_UNKNOWN;
}
static const char *ty_legacy_name(CcTy t) {
  switch (t) {
    case CC_TY_INT: return "int"; case CC_TY_VOID: return "void";
    case CC_TY_BOOL: return "bool"; default: return "?";
  }
}
/* C declaration type (Ruby SPINEL_TYPE_TO_C + the void inner-return). */
static const char *ty_to_c(CcTy t) {
  switch (t) {
    case CC_TY_INT: return "__s64"; case CC_TY_VOID: return "void";
    case CC_TY_BOOL: return "__s32";   /* Ruby SPINEL_TYPE_TO_C["bool"] */
    default: return NULL;
  }
}

/* ---------- IR (text mirror of upstream Compiler.scopes[]; one Method per def) ---------- */

typedef struct {
  const char *name;            /* Scope.name (bare method name) */
  const char *cls;             /* owning class name, or NULL for top-level (Scope.class_id) */
  char **pnames; CcTy *ptypes; int nparams;   /* Scope.pnames + locals[].type */
  CcTy ret;                  /* Scope.ret */
  int body_id;                 /* Scope.body (StatementsNode id) */
  int so_kind;                 /* struct_ops kind (SO_*), 0 = not a struct_ops member */
  const char *so_member;       /* struct_ops member name (e.g. "enqueue") */
} Method;

/* struct_ops kinds (class X < BPF::TcpCC / BPF::SchedExt / BPF::Qdisc). */
enum { SO_NONE = 0, SO_TCP_CC, SO_SCHED_EXT, SO_QDISC };

/* ---------- one definition, many attach points ----------
 *
 * `on :kprobe, %w[vfs_read vfs_write ...] do ... end` binds ONE body to N
 * symbols. There are two lowerings, and which one runs is the CODEGEN's
 * decision, not something the body can observe:
 *
 *   expand  N programs, each SEC("kprobe/<sym>"), the symbol index a literal.
 *           Costs verifier time x N and one attach fd per symbol. Needs nothing
 *           newer than a plain kprobe already needs.
 *   multi   ONE program, SEC("kprobe.multi"), attached by glue.c with a symbol
 *           array and a per-symbol COOKIE. One program and one link whatever N
 *           is -- but needs kernel 5.18 (kprobe_multi + bpf_get_attach_cookie).
 *
 * The two mechanisms answer "which symbol am I?"
 * differently -- a compile-time constant on one side, a runtime helper call on
 * the other. If that difference reached the author, then code written against a
 * short list would break the moment the list grew past the threshold. So the
 * BODY IS COMPILED ONCE: the inner takes a `__spnl_sym` parameter, the single
 * spelling `attached_index` / `attached_symbol_eq("sym")` lowers to it, and only
 * the WRAPPER differs (a literal per expanded program vs bpf_get_attach_cookie
 * in the multi one). The `_inner` text is byte-identical between the lowerings,
 * which is a thing a test can check rather than a thing a comment can claim.
 *
 * WHY THE SWITCH IS STILL REACHABLE (`via: :expand` / `via: :multi`). Being
 * invisible to the body is not the same as being invisible to deployment: the
 * multi lowering raises the probe's kernel floor from 5.2 to 5.18, which
 * `portability.rb` reports and an operator may not be able to satisfy. A
 * mechanism that changes where a probe can RUN must be nameable. It never
 * changes what the probe MEANS. */
enum { CC_MA_AUTO = 0, CC_MA_EXPAND, CC_MA_MULTI };
/* MEASURED, not chosen (5 reps per N, arm64). Median load+attach microseconds:
 *
 *      N      4     8    12    14    16    24
 *   expand  1550  2889  4026  4645  5363  7971      (grows ~linearly)
 *   multi   4123  4670  4535  4560  4660  4848      (flat)
 *
 * 16 is the smallest N at which the multi lowering won every repetition. The
 * rule that picks it is deliberately conservative: `auto` must never raise the
 * probe's kernel floor from 5.2 to 5.18 for a mechanism that is not yet winning
 * outright. Below 16, expansion is both faster AND more portable, so there is
 * nothing to trade.
 *
 * (Time is not the only axis -- expansion also costs 3N+6 open fds and a .bpf.o
 * that grew 9K->194K over N=1..256, against a flat 8 fds and 9K. Those favour
 * multi earlier, which is why the threshold sits at the low end of the measured
 * crossover band rather than above it.)
 *
 * Mirrored by Capabilities::ATTACH_MULTI_THRESHOLD; tests/spinel_ebpf/
 * attach_multi_test.rb reads this line so the two numbers cannot drift apart. */
#define CC_MULTI_AUTO_THRESHOLD 16
#define CC_MULTI_MAX_SYMS 512
#define CC_MULTI_MAX_SETS 64
typedef struct { char *mname; char **syms; int nsyms; int declared_mode; int mode; } CcMulti;
static CcMulti g_multi[CC_MULTI_MAX_SETS];
static int     g_n_multi = 0;

static CcMulti *cc_multi_for(const char *mname) {
  if (!mname) return NULL;
  for (int i = 0; i < g_n_multi; i++)
    if (!strcmp(g_multi[i].mname, mname)) return &g_multi[i];
  return NULL;
}

typedef struct {
  Method *m; int n;
  /* class ivar tables (for emit_ivar_maps), one entry per class. */
  int ncls; char **cls_names; char **cls_ivar_names; char **cls_ivar_types;
  char **cls_parents;          /* class superclass (BPF_SchedExt etc.), one per class */
  /* NOTE: top-level ivars are no longer carried in the IR -- Stage 2
   * derives them from an AST scan (cc_collect_ivar_names), since the
   * upstream C compiler does not emit @toplevel_ivar_names. */
} IR;

#ifndef SPNL_INPROCESS  /* text IR/AST parsers -- Stage 1 / oracle build only */
/* percent-decode the separator escapes the IR uses inside |-joined fields
 * (%7C='|', %20=' ', %0A='\n'). Returns a malloc'd string. */
static char *pct_decode(const char *s) {
  size_t n = strlen(s);
  char *out = malloc(n + 1), *o = out;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '%' && i + 2 < n + 1 && s[i+1] && s[i+2]) {
      char h[3] = { s[i+1], s[i+2], 0 };
      char *end; long v = strtol(h, &end, 16);
      if (end == h + 2) { *o++ = (char)v; i += 2; continue; }
    }
    *o++ = s[i];
  }
  *o = '\0';
  return out;
}

/* AST S-field decode (mirrors parse_spinel_ast unescape_str): percent-encoding
 * (%XX, requires i+2<n) + backslash escapes (\n \t \r \\ \" \0). e.g. the
 * modulo operator method name arrives as "%25". Returns a malloc'd string. */
static int cc_hexv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static char *cc_unescape(const char *s) {
  size_t n = strlen(s), i = 0, o = 0;
  char *out = malloc(n + 1);
  while (i < n) {
    char c = s[i];
    if (c == '%' && i + 2 < n) {
      int hi = cc_hexv(s[i + 1]), lo = cc_hexv(s[i + 2]);
      if (hi >= 0 && lo >= 0) { out[o++] = (char)((hi << 4) | lo); i += 3; continue; }
    }
    if (c == '\\' && i + 1 < n) {
      char nx = s[i + 1];
      switch (nx) {
        case 'n': out[o++] = '\n'; break; case 't': out[o++] = '\t'; break;
        case 'r': out[o++] = '\r'; break; case '\\': out[o++] = '\\'; break;
        case '"': out[o++] = '"'; break;  case '0': out[o++] = '\0'; break;
        default: out[o++] = '\\'; out[o++] = nx; break;
      }
      i += 2;
    } else { out[o++] = c; i++; }
  }
  out[o] = '\0';
  return out;
}

/* rest-of-line after `SA @key <count> ` / `IA @key <count> `, or NULL. */
static const char *ir_payload(const char *line, const char *key) {
  size_t klen = strlen(key);
  const char *p = line;
  if (strncmp(p, "SA ", 3) != 0 && strncmp(p, "IA ", 3) != 0) return NULL;
  p += 3;
  if (strncmp(p, key, klen) != 0 || p[klen] != ' ') return NULL;
  p += klen + 1;
  while (*p && *p != ' ') p++;   /* skip the count token */
  if (*p == ' ') p++;
  return p;                      /* may be "" (empty array) */
}
#endif  /* SPNL_INPROCESS (text IR field helpers) */

/* fill a Method's params from a comma-list of names + comma-list of type tags. */
static char *cc_safe_dup(const char *name);   /* C-keyword sanitizer (defined below) */

static void method_set_params(Method *me, const char *pn, const char *pt) {
  if (!pn || !pn[0]) return;
  me->nparams = split(pn, ',', &me->pnames);
  /* sanitize param names at the parse leaf so every downstream use
   * (ctx struct field, inner signature, syscall wrapper `ctx->p`) is C-safe.
   * split() returns interior pointers into one buffer, so don't free the old
   * pname (the buffer is leaked wholesale -- this is a one-shot tool). */
  for (int k = 0; k < me->nparams; k++) me->pnames[k] = cc_safe_dup(me->pnames[k]);
  char **tt; int nt = split(pt ? pt : "", ',', &tt);
  me->ptypes = calloc(me->nparams, sizeof(CcTy));
  for (int k = 0; k < me->nparams; k++) me->ptypes[k] = ty_from_legacy(k < nt ? tt[k] : "");
}

#ifndef SPNL_INPROCESS  /* text IR parser -- Stage 1 / oracle build only */
static void ir_parse(const char *text, IR *ir) {
  memset(ir, 0, sizeof *ir);
  char **names = NULL, **pnames = NULL, **ptypes = NULL, **rets = NULL, **bids = NULL;
  int n_names = 0, n_pnames = 0, n_ptypes = 0, n_rets = 0, n_bids = 0;
  /* class tables (one entry per class, |-joined at the top level). */
  char **cmn = NULL, **cmp = NULL, **cmpt = NULL, **cmr = NULL, **cmb = NULL;
  int n_cn = 0, n_cmn = 0, n_cmp = 0, n_cmpt = 0, n_cmr = 0, n_cmb = 0;
  char *copy = strdup(text), *save;
  for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    const char *pv;
    if      ((pv = ir_payload(line, "@meth_names")))        n_names  = split(pv, '|', &names);
    else if ((pv = ir_payload(line, "@meth_param_names")))  n_pnames = split(pv, '|', &pnames);
    else if ((pv = ir_payload(line, "@meth_param_types")))  n_ptypes = split(pv, '|', &ptypes);
    else if ((pv = ir_payload(line, "@meth_return_types"))) n_rets   = split(pv, '|', &rets);
    else if ((pv = ir_payload(line, "@meth_body_ids")))     n_bids   = split(pv, ',', &bids);
    else if ((pv = ir_payload(line, "@cls_names")))         n_cn     = split(pv, '|', &ir->cls_names);
    else if ((pv = ir_payload(line, "@cls_ivar_names")))             split(pv, '|', &ir->cls_ivar_names);
    else if ((pv = ir_payload(line, "@cls_ivar_types")))             split(pv, '|', &ir->cls_ivar_types);
    else if ((pv = ir_payload(line, "@cls_meth_names")))    n_cmn    = split(pv, '|', &cmn);
    else if ((pv = ir_payload(line, "@cls_meth_params")))   n_cmp    = split(pv, '|', &cmp);
    else if ((pv = ir_payload(line, "@cls_meth_ptypes")))   n_cmpt   = split(pv, '|', &cmpt);
    else if ((pv = ir_payload(line, "@cls_meth_returns")))  n_cmr    = split(pv, '|', &cmr);
    else if ((pv = ir_payload(line, "@cls_meth_bodies")))   n_cmb    = split(pv, '|', &cmb);
    else if ((pv = ir_payload(line, "@cls_parents")))                 split(pv, '|', &ir->cls_parents);
    /* @toplevel_ivar_names / @toplevel_ivar_types are intentionally ignored:
     * Stage 2 derives top-level ivars from the AST instead (see IR decl). */
  }
  ir->ncls = n_cn;

  /* total = top-level methods + per-class methods (names are ';'-joined within a class). */
  int total = n_names;
  for (int c = 0; c < n_cmn; c++) { char **t; total += split(cmn[c], ';', &t); }
  ir->m = calloc(total > 0 ? total : 1, sizeof(Method));
  int mi = 0;

  for (int i = 0; i < n_names; i++) {            /* top-level methods (Scope.class_id == none) */
    Method *me = &ir->m[mi++];
    me->name    = names[i];
    me->ret     = (i < n_rets) ? ty_from_legacy(rets[i]) : CC_TY_UNKNOWN;
    me->body_id = (i < n_bids) ? atoi(bids[i]) : -1;
    method_set_params(me, (i < n_pnames) ? pnames[i] : "", (i < n_ptypes) ? ptypes[i] : "");
  }

  for (int c = 0; c < n_cn && c < n_cmn; c++) {  /* class methods (within-class: names ';', param-sets '|') */
    char **mn; int nm = split(cmn[c], ';', &mn);
    char **rr; int nr = (c < n_cmr) ? split(cmr[c], ';', &rr) : 0;
    char **bb; int nb = (c < n_cmb) ? split(cmb[c], ';', &bb) : 0;
    char **pp; int npp = (c < n_cmp)  ? split(pct_decode(cmp[c]),  '|', &pp)  : 0;
    char **qq; int nqq = (c < n_cmpt) ? split(pct_decode(cmpt[c]), '|', &qq) : 0;
    /* a `class X < BPF::SchedExt/Qdisc/TcpCC` maps its methods to struct_ops
     * members (synthesized top-level `<prefix>__<member>` names, cls cleared). */
    const char *parent = (ir->cls_parents && ir->cls_parents[c]) ? ir->cls_parents[c] : "";
    int so_kind = SO_NONE; const char *so_prefix = NULL;
    if      (!strcmp(parent, "BPF_SchedExt")) { so_kind = SO_SCHED_EXT; so_prefix = "sched_ext"; }
    else if (!strcmp(parent, "BPF_Qdisc"))    { so_kind = SO_QDISC;     so_prefix = "qdisc"; }
    else if (!strcmp(parent, "BPF_TcpCC"))    { so_kind = SO_TCP_CC;    so_prefix = "tcp_cc"; }
    for (int j = 0; j < nm; j++) {
      Method *me = &ir->m[mi++];
      me->ret     = (j < nr) ? ty_from_legacy(rr[j]) : CC_TY_UNKNOWN;
      me->body_id = (j < nb) ? atoi(bb[j]) : -1;
      method_set_params(me, (j < npp) ? pp[j] : "", (j < nqq) ? qq[j] : "");
      if (so_kind) {              /* struct_ops member: top-level <prefix>__<member> */
        me->cls = NULL;
        me->name = msprintf("%s__%s", so_prefix, mn[j]);
        me->so_kind = so_kind;
        me->so_member = mn[j];
      } else {
        me->cls = ir->cls_names[c];
        me->name = mn[j];
      }
    }
  }
  ir->n = mi;
}
#endif  /* SPNL_INPROCESS (text IR parser) */

/* ---------- AST node table (mirrors upstream node_table.h SpNode/NodeTable;
 * `nt_*` accessors take (AST*, id, key) so Stage 2 points them at the real one) ---------- */

#ifdef SPNL_INPROCESS
/* Stage 2: read the upstream Compiler's NodeTable directly instead of a
 * text dump. node_table.h gives SpNode/NodeTable + the nt_* accessors (linked
 * from node_table.o); compiler.h adds Compiler/Scope/ClassInfo/LocalVar +
 * scope_local + ty_name, used by fill_ir_from_compiler. My internal int type
 * enum was renamed CcTy/CC_TY_* so it no longer collides with upstream TyKind. */
#include "spinel_upstream_contract.h"  /* sce_* accessors; pulls in compiler.h */
typedef NodeTable AST;
static SpNode *node_at(AST *t, int id) {
  if (id < 0 || id >= t->count) return NULL;
  return t->nodes[id].type ? &t->nodes[id] : NULL;
}
#else
typedef struct { char *key, *val; }       StrF;
typedef struct { char *key; long long val; } IntF;
typedef struct { char *key; int ref; }    RefF;
typedef struct { char *key; int *ids, n; } ArrF;

typedef struct {
  char *type;
  StrF s[8]; int ns;
  IntF i[8]; int ni;
  RefF r[8]; int nr;
  ArrF a[8]; int na;
} SpNode;

typedef struct { SpNode *nodes; int cap; } AST;

static SpNode *node_at(AST *t, int id) {
  if (id < 0 || id >= t->cap) return NULL;
  return t->nodes[id].type ? &t->nodes[id] : NULL;
}
static void ast_ensure(AST *t, int id) {
  if (id < t->cap) return;
  int oc = t->cap;
  t->cap = id + 64;
  t->nodes = realloc(t->nodes, sizeof(SpNode) * t->cap);
  memset(t->nodes + oc, 0, sizeof(SpNode) * (t->cap - oc));
}

/* value = rest of line after the first `tok` fields (handles spaces in S values). */
static const char *after_fields(const char *line, int tok) {
  const char *p = line;
  for (int i = 0; i < tok; i++) { while (*p && *p != ' ') p++; if (*p) p++; }
  return p;
}

static void ast_parse(const char *text, AST *t) {
  memset(t, 0, sizeof *t);
  char *copy = strdup(text), *save;
  for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    int id; char key[64], ty[64]; int ref;
    if (strncmp(line, "N ", 2) == 0) {
      if (sscanf(line, "N %d %63s", &id, ty) == 2) { ast_ensure(t, id); t->nodes[id].type = strdup(ty); }
    } else if (strncmp(line, "S ", 2) == 0) {
      if (sscanf(line, "S %d %63s", &id, key) == 2) {
        SpNode *nd = node_at(t, id);
        if (nd) { if (nd->ns >= 8) die("S-field overflow (raise SpNode cap)", nd->type);
          nd->s[nd->ns].key = strdup(key); nd->s[nd->ns].val = cc_unescape(after_fields(line, 3)); nd->ns++; }
      }
    } else if (strncmp(line, "I ", 2) == 0) {
      long long iv;
      if (sscanf(line, "I %d %63s %lld", &id, key, &iv) == 3) {
        SpNode *nd = node_at(t, id);
        if (nd) { if (nd->ni >= 8) die("I-field overflow", nd->type);
          nd->i[nd->ni].key = strdup(key); nd->i[nd->ni].val = iv; nd->ni++; }
      }
    } else if (strncmp(line, "R ", 2) == 0) {
      if (sscanf(line, "R %d %63s %d", &id, key, &ref) == 3) {
        SpNode *nd = node_at(t, id);
        if (nd) { if (nd->nr >= 8) die("R-field overflow", nd->type);
          nd->r[nd->nr].key = strdup(key); nd->r[nd->nr].ref = ref; nd->nr++; }
      }
    } else if (strncmp(line, "A ", 2) == 0) {
      if (sscanf(line, "A %d %63s", &id, key) == 2) {
        SpNode *nd = node_at(t, id);
        if (nd) { if (nd->na >= 8) die("A-field overflow", nd->type);
          const char *csv = after_fields(line, 3);
          ArrF *af = &nd->a[nd->na++];
          af->key = strdup(key);
          if (csv[0] == '\0') { af->ids = NULL; af->n = 0; }
          else { char **parts; int np = split(csv, ',', &parts);
                 af->ids = calloc(np, sizeof(int)); af->n = np;
                 for (int k = 0; k < np; k++) af->ids[k] = atoi(parts[k]); }
        }
      }
    }
  }
}

static const char *nt_type(AST *t, int id) { SpNode *n = node_at(t, id); return n ? n->type : NULL; }
static const char *nt_str(AST *t, int id, const char *key) {
  SpNode *n = node_at(t, id); if (!n) return NULL;
  for (int i = 0; i < n->ns; i++) if (!strcmp(n->s[i].key, key)) return n->s[i].val;
  return NULL;
}
static int nt_ref(AST *t, int id, const char *key) {
  SpNode *n = node_at(t, id); if (!n) return -1;
  for (int i = 0; i < n->nr; i++) if (!strcmp(n->r[i].key, key)) return n->r[i].ref;
  return -1;
}
static long long nt_int(AST *t, int id, const char *key, long long dflt) {
  SpNode *n = node_at(t, id); if (!n) return dflt;
  for (int i = 0; i < n->ni; i++) if (!strcmp(n->i[i].key, key)) return n->i[i].val;
  return dflt;
}
static const int *nt_arr(AST *t, int id, const char *key, int *out_n) {
  *out_n = 0;
  SpNode *n = node_at(t, id); if (!n) return NULL;
  for (int i = 0; i < n->na; i++) if (!strcmp(n->a[i].key, key)) { *out_n = n->a[i].n; return n->a[i].ids; }
  return NULL;
}
#endif  /* SPNL_INPROCESS (AST node table source) */

/* ---------- eBPF codegen ---------- */

/* current unit's IR, for BPF-to-BPF call resolution (upstream uses g_* globals
 * across its split codegen; same idiom). Set at the top of ebpf_codegen_program. */
static const IR *g_ir = NULL;
static const char *g_unit = "";   /* sanitized unit name, for per-unit map names */
static int g_uses_sock_owner = 0;  /* unit uses sock_owner_set -> emit corr map + correlate emit_connect */
static int g_uses_l7 = 0;          /* unit uses req_start/emit_l7 -> emit send-time correlation map */
static int g_uses_http_l7 = 0;     /* unit uses http_req_start/http_resp_stash/http_emit -> HTTP L7 RED */
static int g_uses_offcpu = 0;      /* unit uses offcpu_* -> off-CPU-during-request correlation */
static int g_uses_dns_lat = 0;     /* unit uses dns_req_start/dns_resp_stash/dns_emit -> DNS RTT (txid-keyed) */
static int g_uses_redis_l7 = 0;    /* unit uses redis_req_start/redis_resp_stash/redis_emit -> Redis L7 RED */
static int g_if_counter = 0;   /* fresh temp counter (`fresh`), reset per method */
static const Method *g_method = NULL;  /* method being lowered (for ivar map scope) */
static Lines *g_body = NULL;   /* current method's line accumulator (Ruby @lines) */

/* Runtime parameters. A top-level `param :name, default: N`
 * becomes `volatile const __s64 spnl_param_<name> = N;` in .rodata, which the
 * loader patches between skeleton __open() and __load(). Declared here (not in
 * IR) because the declaration is a top-level statement, which the upstream
 * analyzer never turns into a Scope -- the same reason top-level ivars are an AST
 * scan. Filled by cc_scan_params() at the top of ebpf_codegen_program. */
#define CC_MAX_PARAMS 32
static char *g_param_names[CC_MAX_PARAMS];   /* Ruby name, e.g. "target_pid" */
static long long g_param_defaults[CC_MAX_PARAMS];
static int g_n_params = 0;
static int g_param_used[CC_MAX_PARAMS];      /* referenced by an eBPF method? */

/* -1 when `name` is not a declared parameter. */
static int cc_param_index(const char *name) {
  if (!name) return -1;
  for (int i = 0; i < g_n_params; i++) if (!strcmp(g_param_names[i], name)) return i;
  return -1;
}

/* The in-kernel common filter.
 *
 * `filter_by :pid, :comm` at the top level declares, once, what this probe may
 * be narrowed by; the codegen then injects `if (spnl_filter_discard()) return 0;`
 * at the head of EVERY attach handler in the unit. The declaration is the whole
 * surface -- there is no per-handler call to forget, which is the point: a probe
 * narrowed in four of its five handlers is still a probe that reports everything,
 * and that failure survives every gate we have (the channel balance report can
 * say "nothing came out", never "the wrong things came out").
 *
 * The keys are a fixed vocabulary, not user-named parameters, so they carry their
 * own `spnl_filter_*` symbols and their own SPNL_FILTER_<KEY> environment
 * variables rather than going through `param`. Two reasons: `param :pid`
 * is already refused (the `pid` builtin owns that name), and a fixed vocabulary
 * is something `describe` / `capabilities --json` can enumerate ahead of time.
 *
 * `unset` is per key, because 0 is not a free value everywhere: uid 0 is root and
 * has to be selectable, so uid/gid use -1. pid/tid 0 is the idle task and cgroup
 * id 0 does not exist, so those use 0 (the same convention Inspektor Gadget
 * uses). */
typedef struct {
  const char *key;      /* Ruby symbol in `filter_by` */
  const char *sym;      /* C identifier in .rodata */
  const char *env;      /* SPNL_FILTER_<KEY> */
  const char *init;     /* initialiser = the "unset" value */
  const char *unset_c;  /* C predicate: the key IS set */
  const char *desc;
} CcFilterKey;

/* Order here is the emission order and the order `describe` prints. */
static const CcFilterKey CC_FILTER_KEYS[] = {
  { "pid",       "spnl_filter_pid",       "SPNL_FILTER_PID",       "0",  "spnl_filter_pid != 0",       "thread-group id (what userspace calls the pid)" },
  { "tid",       "spnl_filter_tid",       "SPNL_FILTER_TID",       "0",  "spnl_filter_tid != 0",       "kernel thread id" },
  { "uid",       "spnl_filter_uid",       "SPNL_FILTER_UID",       "-1", "spnl_filter_uid >= 0",       "effective uid (unset is -1: uid 0 is root)" },
  { "gid",       "spnl_filter_gid",       "SPNL_FILTER_GID",       "-1", "spnl_filter_gid >= 0",       "effective gid (unset is -1: gid 0 is root)" },
  { "cgroup_id", "spnl_filter_cgroup_id", "SPNL_FILTER_CGROUP_ID", "0",  "spnl_filter_cgroup_id != 0", "cgroup id (= cgroup-dir inode; one container/pod)" },
  { "comm",      "spnl_filter_comm",      "SPNL_FILTER_COMM",      "{}", "spnl_filter_comm[0] != '\\0'", "task comm, exact match, max 15 chars" },
};
#define CC_N_FILTER_KEYS ((int)(sizeof CC_FILTER_KEYS / sizeof CC_FILTER_KEYS[0]))

static unsigned g_filter_mask = 0;   /* bit i = CC_FILTER_KEYS[i] declared */
static int g_filter_declared = 0;    /* saw a `filter_by` statement at all */

static int cc_filter_key_index(const char *name) {
  if (!name) return -1;
  for (int i = 0; i < CC_N_FILTER_KEYS; i++) if (!strcmp(CC_FILTER_KEYS[i].key, name)) return i;
  return -1;
}
#define CC_FILTER_HAS(i) ((g_filter_mask >> (i)) & 1u)

/* --target amp-m7. When set, ivar -> static-memory RMW at a
 * baked carveout address and spnl_emit -> amp_emit() helper call, so the same
 * body lowering emits an h2.c-shaped .bpf.c (no vmlinux/maps/SEC) that
 * clang -target bpf compiles to bytecode for the micro-bpf ARMv7E-M AOT. */
static int g_amp = 0;
static char *g_amp_ivars[64];
static int g_amp_nivars = 0;

/* Dry-run / monitor mode (env SPNL_ENFORCEMENT=monitor). Set at the top of
 * ebpf_codegen_program. In a monitor build the deny path is not emitted at all --
 * this is the AOT differentiator over a runtime policy-mode byte (a monitor
 * binary literally cannot deny). The inner handler still runs so every observable
 * side effect (map updates / emit / counters) is preserved; only the verdict of
 * enforcement-carrying attach kinds is neutralized to their "allow" constant.
 * See cc_monitor_allow for which kinds and which constant. */
static int g_monitor = 0;
/* mirror of the fixed AMP ABI (spnl/amp_abi.h -> the default board profile,
 * imx95m7). Baking these constants into amp-m7 output makes blobs single-pass /
 * firmware-independent (no per-build `nm` for the ivar carveout, no
 * -DSPNL_AMP_IVARS_BASE override).
 * KEEP IN SYNC with that header -- changing either value is an ABI-version bump.
 * (Not #included to avoid adding -Iinclude to every codegen build site; the
 * amp regression greps these values against the header, catching drift.) */
/* These are the **defaults**, not the only possible values. A second board
 * profile needs different addresses, because its real-time core executes from
 * DDR and the ahead-of-time compiler cannot bake an immediate with bit 31 set.
 * So both emitted values sit behind `#ifndef` and the build step supplies the
 * board's own -- which is how the generator itself stays board-agnostic. */
#define AMP_ABI_VERSION_MIRROR 1u          /* = AMP_ABI_VERSION */
#define AMP_IVARS_BASE_MIRROR  0x2003FF00u /* = AMP_IVARS_BASE (DTCM top - 256B) */
static int amp_ivar_slot(const char *iv) {   /* iv keeps its '@' */
  const char *bare = (iv[0] == '@') ? iv + 1 : iv;
  for (int i = 0; i < g_amp_nivars; i++)
    if (!strcmp(g_amp_ivars[i], bare)) return i;
  if (g_amp_nivars >= 64) die("amp-m7: too many ivars (max 64)", bare);
  g_amp_ivars[g_amp_nivars] = strdup(bare);
  return g_amp_nivars++;
}

/* bpf_d_path is kernel-gated, and the gate is NOT a plain name list --
 * Measurement shows lsm/file_open loads but lsm/file_permission is rejected
 * ("helper call is not allowed in probe"), while fmod_ret/security_file_permission
 * is OK. So only the hooks actually measured to load are permitted; nothing is
 * guessed and nothing falls back silently. Shared by emit_path (statement) and
 * path_eq/path_starts_with/path_contains (expressions).
 *
 * Measuring the whole matrix made the shape of the kernel gate fall out of it:
 *   - LSM progs   : allowed iff the hook is a SLEEPABLE lsm hook (that is why
 *                   lsm/file_open loads and lsm/file_permission / lsm/path_chroot
 *                   do not -- same helper, different hook).
 *   - fmod_ret /  : allowed iff the attach target is in the kernel's fixed
 *     fentry/fexit  btf_allowlist_d_path (security_file_open / _file_permission /
 *                   _inode_getattr / security_path_truncate + vfs_truncate /
 *                   vfs_fallocate / dentry_open / vfs_getattr / filp_close). So
 *                   fmod_ret/security_mmap_file and fmod_ret/security_path_unlink
 *                   are REJECTED even though the LSM form of the same hook loads.
 *   - kprobe      : structurally impossible ("program of this type cannot use
 *                   helper bpf_d_path").
 *
 * The second half of the gate is WHICH ARGUMENT carries the path: the hooks differ,
 * so each entry says how to build a `struct path *` out of the gated argument
 * (cc_dpath_expr). `guard` = NULL-check the pointer first; for lsm/mmap_file that is
 * not merely defensive but LOAD-REQUIRED (its arg is `file__nullable`, and the
 * unguarded form is rejected with "R1 pointer arithmetic on trusted_ptr_or_null_
 * prohibited, null-check it first"). Fail-safe either way: an unknown path yields
 * -1 from bpf_d_path, so it matches nothing -- a path we cannot read is a
 * NON-match. */
typedef enum { CC_DP_FILE = 0, CC_DP_PATH, CC_DP_BINPRM } CcDpathForm;
typedef struct {
  const char *sec;       /* SEC exactly as cc_detect_attach builds it */
  CcDpathForm form;      /* how the gated arg becomes a `struct path *` */
  int guard;             /* NULL-guard the pointer before bpf_d_path */
  const char *measured;  /* which measurement says LOAD_OK */
} CcDpathHook;
static const CcDpathHook CC_DPATH_OK[] = {
  /* --- the original three (output unchanged) --- */
  { "lsm/file_open",                       CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "fmod_ret/security_file_open",         CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "fmod_ret/security_file_permission",   CC_DP_FILE,   0, "measured: LOAD_OK" },
  /* --- `struct file *` arg (lsm/mmap_file's is file__nullable) --- */
  { "lsm/mmap_file",                       CC_DP_FILE,   1, "measured: LOAD_OK" },
  { "lsm/file_ioctl",                      CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "lsm/file_lock",                       CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "lsm/file_receive",                    CC_DP_FILE,   0, "measured: LOAD_OK" },
  /* --- `struct linux_binprm *` arg (exec) --- */
  { "lsm/bprm_check_security",             CC_DP_BINPRM, 1, "measured: LOAD_OK" },
  { "lsm/bprm_creds_for_exec",             CC_DP_BINPRM, 1, "measured: LOAD_OK" },
  { "lsm/bprm_committed_creds",            CC_DP_BINPRM, 1, "measured: LOAD_OK" },
  /* --- the arg IS a `struct path *` (security_path_* family + getattr) --- */
  { "lsm/path_unlink",                     CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_rename",                     CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_mkdir",                      CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_rmdir",                      CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_symlink",                    CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_link",                       CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_truncate",                   CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_chmod",                      CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/path_chown",                      CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "lsm/inode_getattr",                   CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "fmod_ret/security_path_truncate",     CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "fmod_ret/security_inode_getattr",     CC_DP_PATH,   0, "measured: LOAD_OK" },
  /* --- the kernel's own btf_allowlist_d_path (observe only: fentry/fexit
   * carry no verdict, so a deny written here is silently ignored) --- */
  { "fentry/filp_close",                   CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "fexit/filp_close",                    CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "fentry/vfs_fallocate",                CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "fexit/vfs_fallocate",                 CC_DP_FILE,   0, "measured: LOAD_OK" },
  { "fentry/vfs_truncate",                 CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "fexit/vfs_truncate",                  CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "fentry/dentry_open",                  CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "fexit/dentry_open",                   CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "fentry/vfs_getattr",                  CC_DP_PATH,   0, "measured: LOAD_OK" },
  { "fexit/vfs_getattr",                   CC_DP_PATH,   0, "measured: LOAD_OK" },
  { NULL, CC_DP_FILE, 0, NULL }
};
static const CcDpathHook *cc_dpath_hook(const char *sec) {
  for (int i = 0; sec && CC_DPATH_OK[i].sec; i++)
    if (!strcmp(sec, CC_DPATH_OK[i].sec)) return &CC_DPATH_OK[i];
  return NULL;
}
/* path_eq stack budget. The BPF stack is 512B total and the path buffer is only
 * one of the frame's locals. The real limit was found by raising this
 * (override at build time to re-measure): buf<=256 loads, and the frame blows up
 * past that. 256 is kept as the cap with headroom for the rest of the frame. */
#ifndef CC_PATH_EQ_MAX
#define CC_PATH_EQ_MAX 256
#endif
static int g_loop_counter = 0;     /* per-unit loop-callback id (cb names), not reset per method */
static int g_pc_counter = 0;       /* per-unit path_contains callback/struct id (unit scope, not reset per method) */
static Lines *g_deferred = NULL;   /* complete callback/struct blocks, emitted before the inners */
static Lines *g_captures = NULL;   /* capture names active while lowering a loop-callback body */
/* is `name` (already C-safe) an outer local captured by the current loop callback? */
static int cc_is_capture(const char *name) { return g_captures && lines_has(g_captures, name); }

/* locals bound via `t = kptr(ptr, "struct")` -- `t.field` then reads via
 * BPF_CORE_READ on (struct <name> *)t. Reset per method. */
#define MAX_KPTR 16
static const char *g_kptr_names[MAX_KPTR];
static const char *g_kptr_structs[MAX_KPTR];
static int g_n_kptr = 0;
static const char *cc_kptr_struct(const char *name) {
  for (int i = 0; i < g_n_kptr; i++) if (!strcmp(g_kptr_names[i], name)) return g_kptr_structs[i];
  return NULL;
}

/* lowercase a class name into its map prefix (Counter -> counter). */
static char *cc_lower(const char *s) {
  size_t n = strlen(s); char *o = malloc(n + 1);
  for (size_t i = 0; i < n; i++) o[i] = (s[i] >= 'A' && s[i] <= 'Z') ? (char)(s[i] + 32) : s[i];
  o[n] = '\0';
  return o;
}

/* C11 reserved words. A Ruby identifier (param / local / method name)
 * matching one gets a `_` suffix so the emitted .bpf.c compiles (`double` ->
 * `double_`). Idempotent (`double_` isn't a keyword). Applied at every name
 * leaf so the in-memory representation is uniformly C-safe. */
static int cc_is_c_keyword(const char *s) {
  static const char *K[] = {
    "auto","break","case","char","const","continue","default","do","double","else","enum","extern",
    "float","for","goto","if","inline","int","long","register","restrict","return","short","signed",
    "sizeof","static","struct","switch","typedef","union","unsigned","void","volatile","while",
    "_Bool","_Complex","_Imaginary","_Atomic","_Static_assert","_Thread_local",
    "_Alignas","_Alignof","_Generic","_Noreturn", NULL };
  for (int i = 0; K[i]; i++) if (!strcmp(K[i], s)) return 1;
  return 0;
}
static char *cc_safe_dup(const char *name) {
  if (name && name[0] && cc_is_c_keyword(name)) return msprintf("%s_", name);
  return strdup(name ? name : "");
}

/* func name: class method -> "<lowercls>_<name>"; top-level -> bare name (C-safe). */
static char *cc_func_name(const Method *me) {
  if (me->cls) { char *lc = cc_lower(me->cls); char *r = msprintf("%s_%s", lc, me->name); free(lc); return r; }
  return cc_safe_dup(me->name);
}
/* qualified name for comments: "Cls#name" or bare name. */
static char *cc_qual_name(const Method *me) {
  return me->cls ? msprintf("%s#%s", me->cls, me->name) : strdup(me->name);
}
/* ivar map name (Ruby ivar_map_name / top_ivar_map_name); `ivar` keeps its '@'. */
static char *cc_ivar_map(const char *ivar) {
  const char *bare = (ivar[0] == '@') ? ivar + 1 : ivar;
  if (g_amp) {
    /* amp-m7: @x is a 32-bit word in the carveout at IVARS_BASE + 4*slot. The
     * returned lvalue expression is used directly by cc_emit_ivar_read/write/rmw. */
    return msprintf("(*(volatile __u32 *)(SPNL_AMP_IVARS_BASE + %du))", 4 * amp_ivar_slot(bare));
  }
  if (g_method && g_method->cls) { char *lc = cc_lower(g_method->cls); char *r = msprintf("%s_at_%s", lc, bare); free(lc); return r; }
  return msprintf("%s_top_%s", g_unit, bare);
}

/* sanitize a base name into a C identifier (Ruby sanitize_identifier): non-[A-Za-z0-9_]
 * -> '_', and prefix 'u_' if it would start with a digit. */
static char *cc_sanitize(const char *s) {
  size_t n = strlen(s);
  char *out = malloc(n + 3);
  char *o = out;
  if (n && s[0] >= '0' && s[0] <= '9') { *o++ = 'u'; *o++ = '_'; }
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    *o++ = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') ? c : '_';
  }
  *o = '\0';
  return out;
}

/* KNOWN_CONSTANTS subset: ConstantReadNode names the codegen
 * resolves to a literal int. */
static int cc_known_const(const char *name, long long *out) {
  static const struct { const char *n; long long v; } K[] = {
    {"XDP_ABORTED",0},{"XDP_DROP",1},{"XDP_PASS",2},{"XDP_TX",3},{"XDP_REDIRECT",4},
    {"IPPROTO_IP",0},{"IPPROTO_ICMP",1},{"IPPROTO_TCP",6},{"IPPROTO_UDP",17},{"IPPROTO_ICMPV6",58},
    {"ETH_P_IP",0x0800},{"ETH_P_IPV6",0x86DD},{"ETH_P_ARP",0x0806},
    {"TC_ACT_OK",0},{"TC_ACT_RECLASSIFY",1},{"TC_ACT_SHOT",2},{"TC_ACT_PIPE",3},{"TC_ACT_STOLEN",4},
    {"TC_ACT_QUEUED",5},{"TC_ACT_REPEAT",6},{"TC_ACT_REDIRECT",7},{"TC_ACT_TRAP",8},
    {"SK_DROP",0},{"SK_PASS",1},
    {"TCP_FLAG_FIN",0x01},{"TCP_FLAG_SYN",0x02},{"TCP_FLAG_RST",0x04},{"TCP_FLAG_PSH",0x08},
    {"TCP_FLAG_ACK",0x10},{"TCP_FLAG_URG",0x20},{"TCP_FLAG_ECE",0x40},{"TCP_FLAG_CWR",0x80},
    /* the values sock_state()/sock_family() return. Without these the two
     * enumerated accessors could only be compared against magic numbers, which
     * is the same unreviewable-integer problem the byte order work is about.
     * TCP_STATE_* mirrors the Ruby oracle's KNOWN_CONSTANTS one-for-one. */
    {"TCP_STATE_ESTABLISHED",1},{"TCP_STATE_SYN_SENT",2},{"TCP_STATE_SYN_RECV",3},
    {"TCP_STATE_FIN_WAIT1",4},{"TCP_STATE_FIN_WAIT2",5},{"TCP_STATE_TIME_WAIT",6},
    {"TCP_STATE_CLOSE",7},{"TCP_STATE_CLOSE_WAIT",8},{"TCP_STATE_LAST_ACK",9},
    {"TCP_STATE_LISTEN",10},{"TCP_STATE_CLOSING",11},
    /* the BPF_SOCK_OPS_* event codes `sock_ops_op` returns. The
     * BPF::SockOps:: -> BPF_SOCK_OPS_ path prefix was already wired below with
     * nothing behind it, so `if sock_ops_op == BPF::SockOps::STATE_CB` -- the
     * documented form -- died on the constant even once the builtin existed.
     * Mirrors the Ruby oracle's KNOWN_CONSTANTS one-for-one. */
    {"BPF_SOCK_OPS_TIMEOUT_INIT",1},{"BPF_SOCK_OPS_RWND_INIT",2},
    {"BPF_SOCK_OPS_TCP_CONNECT_CB",3},{"BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB",4},
    {"BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB",5},{"BPF_SOCK_OPS_NEEDS_ECN",6},
    {"BPF_SOCK_OPS_BASE_RTT",7},{"BPF_SOCK_OPS_RTO_CB",8},
    {"BPF_SOCK_OPS_RETRANS_CB",9},{"BPF_SOCK_OPS_STATE_CB",10},
    {"BPF_SOCK_OPS_TCP_LISTEN_CB",11},{"BPF_SOCK_OPS_RTT_CB",12},
    {"AF_INET",2},{"AF_INET6",10},
    /* capability BIT INDICES, spelled exactly as the kernel's CAP_* macros
     * so that `CAP_SYS_ADMIN` here and in capsh/`man 7 capabilities`/BTF are the
     * same 21. The temptation is to define them as masks (1<<21) so that
     * `caps & CAP_SYS_ADMIN` accidentally works; that would make the CONSTANT
     * lie about what it is, to rescue one expression nobody should write.
     * has_cap() does the shift instead (see templates/task_attrs.template.c). */
    {"CAP_CHOWN",0},{"CAP_DAC_OVERRIDE",1},{"CAP_DAC_READ_SEARCH",2},{"CAP_FOWNER",3},
    {"CAP_FSETID",4},{"CAP_KILL",5},{"CAP_SETGID",6},{"CAP_SETUID",7},
    {"CAP_SETPCAP",8},{"CAP_LINUX_IMMUTABLE",9},{"CAP_NET_BIND_SERVICE",10},
    {"CAP_NET_BROADCAST",11},{"CAP_NET_ADMIN",12},{"CAP_NET_RAW",13},
    {"CAP_IPC_LOCK",14},{"CAP_IPC_OWNER",15},{"CAP_SYS_MODULE",16},{"CAP_SYS_RAWIO",17},
    {"CAP_SYS_CHROOT",18},{"CAP_SYS_PTRACE",19},{"CAP_SYS_PACCT",20},{"CAP_SYS_ADMIN",21},
    {"CAP_SYS_BOOT",22},{"CAP_SYS_NICE",23},{"CAP_SYS_RESOURCE",24},{"CAP_SYS_TIME",25},
    {"CAP_SYS_TTY_CONFIG",26},{"CAP_MKNOD",27},{"CAP_LEASE",28},{"CAP_AUDIT_WRITE",29},
    {"CAP_AUDIT_CONTROL",30},{"CAP_SETFCAP",31},{"CAP_MAC_OVERRIDE",32},{"CAP_MAC_ADMIN",33},
    {"CAP_SYSLOG",34},{"CAP_WAKE_ALARM",35},{"CAP_BLOCK_SUSPEND",36},{"CAP_AUDIT_READ",37},
    {"CAP_PERFMON",38},{"CAP_BPF",39},{"CAP_CHECKPOINT_RESTORE",40},
    /* file types, the S_IFMT-masked values file_type() returns. Same
     * spelling as <sys/stat.h> and as the mode bits every tool prints. */
    {"S_IFREG",0100000},{"S_IFDIR",0040000},{"S_IFLNK",0120000},{"S_IFSOCK",0140000},
    {"S_IFBLK",0060000},{"S_IFCHR",0020000},{"S_IFIFO",0010000},
    {NULL,0}
  };
  for (int i = 0; K[i].n; i++) if (!strcmp(K[i].n, name)) { *out = K[i].v; return 1; }
  return 0;
}

/* ConstantPathNode paths that emit a C macro name verbatim (u64 constants
 * beyond __s64 range, e.g. SCX_DSQ_GLOBAL = (1ULL<<63)|1). Mirrors MACRO_PATHS. */
static const char *cc_macro_path(const char *path) {
  static const struct { const char *p, *m; } M[] = {
    {"SCX::DSQ::GLOBAL", "SCX_DSQ_GLOBAL"}, {"SCX::DSQ::LOCAL", "SCX_DSQ_LOCAL"},
    {"SCX::SLICE_DFL", "SCX_SLICE_DFL"}, {"SCX::SLICE_INF", "SCX_SLICE_INF"},
    {"SCX::KICK_PREEMPT", "SCX_KICK_PREEMPT"}, {"SCX::ENQ_PREEMPT", "SCX_ENQ_PREEMPT"},
    {NULL, NULL}
  };
  for (int i = 0; M[i].p; i++) if (!strcmp(M[i].p, path)) return M[i].m;
  return NULL;
}

static int cc_known_const(const char *name, long long *out);   /* defined below */
/* module-style constant path (XDP::PASS / IP::Proto::TCP) -> integer.
 * Map the module path prefix to the flat constant prefix (Ruby CONSTANT_PATH_PREFIXES),
 * then resolve the flat name in KNOWN_CONSTANTS. */
static int cc_const_path_value(const char *path, long long *out) {
  static const struct { const char *pp, *fp; } T[] = {
    {"BPF::SockOps::", "BPF_SOCK_OPS_"}, {"TCP::Flag::", "TCP_FLAG_"}, {"TCP::State::", "TCP_STATE_"},
    {"IP::Proto::", "IPPROTO_"}, {"TC::Act::", "TC_ACT_"}, {"Eth::P::", "ETH_P_"},
    /* CAP::SYS_ADMIN -> CAP_SYS_ADMIN, FileType::REG -> S_IFREG. */
    {"CAP::", "CAP_"}, {"FileType::", "S_IF"},
    {"XDP::", "XDP_"}, {"SK::", "SK_"}, {NULL, NULL}
  };
  for (int i = 0; T[i].pp; i++) {
    size_t n = strlen(T[i].pp);
    if (!strncmp(path, T[i].pp, n)) {
      char flat[128]; snprintf(flat, sizeof flat, "%s%s", T[i].fp, path + n);
      return cc_known_const(flat, out);
    }
  }
  return 0;
}

static int cc_is_binary_op(const char *name) {
  static const char *ops[] = {"+","-","*","/","%","==","!=","<",">","<=",">=","&","|","^","<<",">>",NULL};
  for (int i = 0; ops[i]; i++) if (!strcmp(name, ops[i])) return 1;
  return 0;
}

/* eBPF-eligible (Stage 1 minimal partition): a real top-level method (body_id>=0,
 * which drops builtin stubs like `def spnl_emit(x); end`) whose params are all
 * `int` and whose return is `int` or void/nil. */
static int cc_method_eligible(const Method *me) {
  if (me->body_id < 0) return 0;
  /* Ruby SUPPORTED_EBPF_SIGNATURE_TYPES = int/bool/void/nil (nil -> VOID). int
   * -> __s64, bool -> __s32; everything else (string/array/hash/poly/...) is
   * UNKNOWN -> native. */
  if (me->ret != CC_TY_INT && me->ret != CC_TY_VOID && me->ret != CC_TY_BOOL) return 0;
  for (int k = 0; k < me->nparams; k++)
    if (me->ptypes[k] != CC_TY_INT && me->ptypes[k] != CC_TY_BOOL) return 0;
  return 1;
}

/* a same-unit :ebpf method by this name? (a BPF-to-BPF call target). */
static int cc_is_ebpf_method(const char *name) {
  if (!g_ir || !name) return 0;
  for (int i = 0; i < g_ir->n; i++)
    if (cc_method_eligible(&g_ir->m[i]) && !strcmp(g_ir->m[i].name, name)) return 1;
  return 0;
}

/* pkt_* header-access builtins. Each lowers to a no-arg call
 * `spnl_<name>(ctx)` (XDP) or `spnl_tc_<name>(ctx)` (TC) backed by a __noinline
 * helper with bounds checks that satisfy the verifier. Mirrors Ruby PKT_BUILTINS. */
static const char *PKT_BUILTINS[] = {
  "pkt_len", "pkt_eth_proto", "pkt_l4_proto", "pkt_ip4_src", "pkt_ip4_dst",
  "pkt_l4_sport", "pkt_l4_dport", "pkt_tcp_flags", "pkt_l4_payload_len",
  "pkt_ip6_src_hi", "pkt_ip6_src_lo", "pkt_ip6_dst_hi", "pkt_ip6_dst_lo",
  "pkt_tcp_seq", "pkt_tcp_ack",
};
static const char *cc_pkt_canon(const char *name) {
  for (size_t i = 0; i < sizeof PKT_BUILTINS / sizeof *PKT_BUILTINS; i++)
    if (!strcmp(PKT_BUILTINS[i], name)) return PKT_BUILTINS[i];
  return NULL;
}

/* pkt_* builtins seen during the pre-scan, recorded so the helper-emit pass
 * appends one __noinline definition per (name, ctx-kind). Mirrors Ruby
 * ctx.pkt_builtins_used: ordered by first reference, per-name a set of kinds
 * (bit0=xdp, bit1=tc). */
#define MAX_PKT_USES 32
static const char *g_pkt_names[MAX_PKT_USES];
static int g_pkt_kinds[MAX_PKT_USES];
static int g_n_pkt = 0;
static void cc_record_pkt(const char *name, int tc) {
  const char *canon = cc_pkt_canon(name);
  if (!canon) return;
  int bit = tc ? 2 : 1;
  for (int i = 0; i < g_n_pkt; i++)
    if (g_pkt_names[i] == canon) { g_pkt_kinds[i] |= bit; return; }
  if (g_n_pkt >= MAX_PKT_USES) die("too many distinct pkt_* builtins (Stage 1)", name);
  g_pkt_names[g_n_pkt] = canon; g_pkt_kinds[g_n_pkt] = bit; g_n_pkt++;
}

/* Roadmap #2: per-flow conntrack maps, inferred from flow_get/set/del
 * (:name, :field) usage. name -> sorted unique fields + ctx kinds used (bit0 xdp,
 * bit1 tc). Populated by a pre-scan, emitted as LRU_HASH + key-extract helpers. */
#define MAX_FLOW_MAPS 8
#define MAX_FLOW_FIELDS 16
static const char *g_flow_names[MAX_FLOW_MAPS];
static char *g_flow_fields[MAX_FLOW_MAPS][MAX_FLOW_FIELDS];
static int g_flow_nf[MAX_FLOW_MAPS];
static int g_flow_kinds[MAX_FLOW_MAPS];
static int g_n_flow = 0;
static int cc_flow_idx(const char *name) {
  for (int i = 0; i < g_n_flow; i++) if (!strcmp(g_flow_names[i], name)) return i;
  if (g_n_flow >= MAX_FLOW_MAPS) die("too many flow maps (Stage 1)", name);
  g_flow_names[g_n_flow] = strdup(name); g_flow_nf[g_n_flow] = 0; g_flow_kinds[g_n_flow] = 0;
  return g_n_flow++;
}
static void cc_flow_add_field(int mi, const char *f) {
  for (int i = 0; i < g_flow_nf[mi]; i++) if (!strcmp(g_flow_fields[mi][i], f)) return;
  if (g_flow_nf[mi] < MAX_FLOW_FIELDS) g_flow_fields[mi][g_flow_nf[mi]++] = strdup(f);
}

/* attach types (full defs below) -- declared here so cc_lower_expr can resolve a
 * pkt_* builtin's ctx kind (xdp vs tc) from the method being lowered. */
typedef enum { AK_NONE, AK_KPROBE, AK_KRETPROBE, AK_TRACEPOINT, AK_FENTRY, AK_FEXIT, AK_XDP, AK_TC,
               AK_SK_VERDICT, AK_UPROBE, AK_URETPROBE, AK_USDT, AK_LSM, AK_FMOD_RET,
               AK_ITER_TASK, AK_RAW_TP, AK_PERF_EVENT, AK_SOCK_OPS,
               AK_KPROBE_MULTI } AttachKind;
/* ctx_prefixed: the inner takes the kernel ctx as its first arg (xdp/tc, for pkt_*).
 * verdict: the wrapper propagates the inner's int return (XDP_ / TC_ACT_ values).
 * iter_guard: emit `if (!ctx->task) return 0;` (bpf_iter NULL terminator).
 * usdt: emit bpf_usdt_arg prologue + pull in usdt.bpf.h. */
typedef struct { AttachKind kind; char *sec; const char *ctx_type; const char *kname;
                 int ctx_prefixed; int verdict; const char *tp_struct;
                 int iter_guard; int usdt;
                 char *tp_cat; char *tp_event; } Attach;   /* named tracepoint field extraction */
static AttachKind cc_detect_attach(const char *name, Attach *a);

/* one place emits a packet reader, whichever surface named it. Both
 * the flat call (`pkt_l4_proto`) and the chain (`pkt.l4.proto`) come through
 * here, so the claim that the two spellings produce identical C is true by
 * construction rather than by two code paths agreeing. */
static void cc_emit_pkt_call(Buf *b, const char *canon) {
  Attach a = {0}; AttachKind k = g_method ? cc_detect_attach(g_method->name, &a) : AK_NONE;
  if (a.sec) free(a.sec);
  int is_tc = (k == AK_TC);
  if (k != AK_XDP && !is_tc)
    die("pkt_* builtins are only available inside xdp__ or tc__* methods", canon);
  cc_record_pkt(canon, is_tc);
  buf_printf(b, "%s_%s(ctx)", is_tc ? "spnl_tc" : "spnl", canon);
}

/* is this CallNode the leaf of a `pkt`-rooted receiver chain? Walks
 * leaf-first, requiring every LINK BELOW THE LEAF to be an argument-less,
 * block-less CallNode and the root to be a bare `pkt`; writes the joined flat
 * name (`pkt.l4.proto` -> "pkt_l4_proto") to `out`.
 *
 * Deliberately does NOT check that the result is a real reader: an unknown
 * `pkt.<x>` must produce a diagnostic about the packet surface, not the generic
 * "CallNode not yet ported", which is what it used to say for EVERY chain --
 * including the fifteen real ones (measured). Resolution against the
 * flat table happens at the call site so the two answers get different errors. */
static int cc_pkt_chain_name(AST *ast, int nid, char *out, size_t outsz) {
  const char *parts[4]; int np = 0; int cur = nid;
  for (int guard = 0; guard < 4 && cur >= 0; guard++) {
    const char *ty = nt_type(ast, cur);
    if (!ty || strcmp(ty, "CallNode")) return 0;
    if (nt_ref(ast, cur, "block") >= 0) return 0;
    if (cur != nid && nt_ref(ast, cur, "arguments") >= 0) return 0;
    const char *nm = nt_str(ast, cur, "name");
    if (!nm || !*nm) return 0;
    parts[np++] = nm;
    int recv = nt_ref(ast, cur, "receiver");
    if (recv >= 0) { cur = recv; continue; }
    if (strcmp(nm, "pkt") || np < 2) return 0;   /* root must be `pkt`, and `pkt` alone is not a read */
    out[0] = '\0';
    for (int i = np - 1; i >= 0; i--) {
      if (strlen(out) + strlen(parts[i]) + 2 >= outsz) return 0;
      strcat(out, parts[i]); if (i) strcat(out, "_");
    }
    return 1;
  }
  return 0;
}

static void cc_die_bad_pkt_chain(const char *joined, int had_args) {
  if (had_args && !strncmp(joined, "pkt_byte_at", 11))
    die("`pkt.byte_at(off)` is not available: it lowered to the `pkt_dynptr_byte_at` builtin, "
        "which was withdrawn (bpf_dynptr_from_xdp/bpf_dynptr_slice did not survive the port "
        "to the C codegen; it is recorded in Capabilities::WITHDRAWN).\n"
        "  Read the header fields with the other pkt.* readers (pkt.l4.proto, pkt.ip4.src, ...), "
        "or skb_load_byte(off) in a tc__ handler", joined);
  char *msg = msprintf(
    "`%s` is not a packet reader. The pkt.* chain accessor is exactly the flat pkt_* "
    "readers with dots: pkt.len / pkt.eth.proto / pkt.l4.{proto,sport,dport,payload_len} / "
    "pkt.ip4.{src,dst} / pkt.ip6.{src_hi,src_lo,dst_hi,dst_lo} / pkt.tcp.{flags,seq,ack}.\n"
    "  `spinel-ebpf capabilities --json` lists both spellings (surface_sugar).\n"
    "  You wrote (flattened)",
    joined);
  die(msg, joined);
}

/* in a monitor build, return the "allow" verdict literal for an
 * enforcement-carrying attach kind, or NULL for a kind whose return has no policy
 * meaning (xdp/tc datapath, sk_reuseport/sk_msg/sk_skb verdicts, sk_lookup, ...) --
 * those must NOT be rewritten, only the deny decision is neutralized. Only three
 * kinds carry an enforcement verdict today:
 *   lsm/<hook>       0 = allow (a negative errno would deny)
 *   fmod_ret/<func>  0 = don't override -> the original function runs (deny = nonzero)
 *   cgroup/connect4  1 = allow (a denied connect() returns -EPERM)
 *   cgroup/bind4     1 = allow
 * Returns NULL when g_monitor is off, so an enforce build is byte-identical. */
static const char *cc_monitor_allow(const Attach *a) {
  if (!g_monitor) return NULL;
  if (a->kind == AK_LSM)      return "0";
  if (a->kind == AK_FMOD_RET) return "0";
  if (a->kname && (!strcmp(a->kname, "cgroup_connect4") ||
                   !strcmp(a->kname, "cgroup_bind4")))   return "1";
  return NULL;
}

static char *cc_expr_str(AST *ast, int nid);   /* expr node -> malloc'd C string (defined below) */
static char *cc_lower_stmt(AST *ast, int nid, Lines *body);   /* defined below (StatementsNode in expr pos) */

/* The packet-context gate for the datapath builtins.
 *
 * fib_lookup, sk_lookup_tcp, redirect and the skb read/write/checksum family all
 * lower to a helper whose first argument is the attach point's `ctx`. Outside a
 * packet program there is no such ctx, so the call is not "unsupported yet" -- it
 * is meaningless, and it must be refused HERE, where the method name still says
 * which hook the author wrote.
 *
 * Measured before this gate existed: 78_fib_lookup_kprobe reached clang as
 * `bpf_fib_lookup(ctx, ...)` inside a kprobe `_inner` that has no ctx parameter
 * -> "error: use of undeclared identifier 'ctx'"; 80_skb_rewrite_xdp and
 * 82_nat_xdp compiled and were refused by the verifier ("program of this type
 * cannot use helper bpf_skb_store_bytes"); 96_sk_assign_egress compiled AND
 * loaded, so nothing anywhere said the steer could not work at egress. Four
 * fixtures whose own comments say codegen must reject them. The Ruby codegen
 * (src/spinel_ebpf/codegen_bpf.rb, the earlier reference implementation) raises on
 * all four; the C port dropped the checks, and the text-only golden gate never
 * noticed because the broken output was stable.
 *
 * `allow` is a bitmask of CC_CTX_*; `who` is the builtin name for the message. */
enum { CC_CTX_XDP = 1, CC_CTX_TC_INGRESS = 2, CC_CTX_TC_EGRESS = 4 };
#define CC_CTX_TC (CC_CTX_TC_INGRESS | CC_CTX_TC_EGRESS)
#define CC_CTX_PKT (CC_CTX_XDP | CC_CTX_TC)
/* The skb read/write/checksum family all goes through
 * bpf_skb_{load,store}_bytes / bpf_l{3,4}_csum_replace, which the kernel offers
 * to `struct __sk_buff` programs only -- XDP has an xdp_md, not an skb. */
#define CC_SKB_WHY "it reads or rewrites `struct __sk_buff`, and XDP runs before " \
                   "an skb exists (its ctx is a struct xdp_md)"

static void cc_require_pkt_ctx(const char *who, int allow, const char *why) {
  Attach a = {0};
  AttachKind k = g_method ? cc_detect_attach(g_method->name, &a) : AK_NONE;
  int have = 0;
  if (k == AK_XDP) have = CC_CTX_XDP;
  else if (k == AK_TC && a.kname && !strcmp(a.kname, "tc_ingress")) have = CC_CTX_TC_INGRESS;
  else if (k == AK_TC && a.kname && !strcmp(a.kname, "tc_egress"))  have = CC_CTX_TC_EGRESS;
  if (a.sec) free(a.sec);
  if (have & allow) return;

  /* Name the hooks that DO work, in the `def` form the author types. The reactor
   * (`on :xdp`) and class/module forms synthesise exactly these names, so one
   * list covers every surface. */
  char forms[320]; forms[0] = 0;
  if (allow & CC_CTX_XDP)        strcat(forms, "\n    def xdp__<name>          (or `on :xdp`, `class X < BPF::XDP`)");
  if (allow & CC_CTX_TC_INGRESS) strcat(forms, "\n    def tc__ingress__<name>  (or `on :tc_ingress`)");
  if (allow & CC_CTX_TC_EGRESS)  strcat(forms, "\n    def tc__egress__<name>   (or `on :tc_egress`)");
  const char *where = (allow == CC_CTX_TC_INGRESS) ? "a TC ingress classifier"
                    : (allow == CC_CTX_TC)         ? "a TC classifier"
                                                   : "an XDP or TC program";
  char *msg = msprintf("%s is only available inside %s, because %s.\n  Contexts that can supply it:%s"
                       /* ASCII only, deliberately: `check --json` reads this message back, and a
                        * single non-ASCII byte made it die with Encoding::CompatibilityError under
                        * the build container's default US-ASCII locale (measured). Every
                        * other diagnostic in this file is ASCII for the same reason. */
                       "\n  (context gate, measured; downstream this is a clang or verifier error "
                       "that names a C identifier or a helper number instead of the hook you chose.)"
                       "\n  You wrote it in", who, where, why, forms);
  die(msg, g_method ? g_method->name : "<none>");
}

/* the ctx kind ("xdp"/"tc") of the method being lowered, for flow key-extract. */
static const char *cc_flow_kind_str(void) {
  Attach a = {0}; AttachKind k = g_method ? cc_detect_attach(g_method->name, &a) : AK_NONE;
  if (a.sec) free(a.sec);
  if (k == AK_XDP) return "xdp";
  if (k == AK_TC) return "tc";
  die("flow_* is only available inside xdp__ or tc__* methods", g_method ? g_method->name : "?");
  return "tc";
}

/* build "<kfunc>(<arg0>, <arg1>, ...)" for an scx/qdisc kfunc call,
 * applying `cast0` to the first arg as `cast0(<a0>)` (Ruby scx_kfunc_call). */
static char *cc_kfunc_call_str(AST *ast, int nid, const char *kfunc, int arity, const char *cast0) {
  int args_id = nt_ref(ast, nid, "arguments");
  int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
  if (na != arity) die("kfunc arity mismatch (Stage 1)", kfunc);
  Buf c; memset(&c, 0, sizeof c);
  buf_printf(&c, "%s(", kfunc);
  for (int i = 0; i < na; i++) {
    char *e = cc_expr_str(ast, ids[i]);
    if (i) buf_puts(&c, ", ");
    if (i == 0 && cast0) buf_printf(&c, "%s(%s)", cast0, e);
    else buf_puts(&c, e);
    free(e);
  }
  buf_puts(&c, ")");
  return c.p;
}

/* BPF qdisc kfuncs -- per-arg cast list (Ruby QDISC_KFUNC_TABLE). All are
 * side-effecting statements. casts[i] applied as `cast(<arg_i>)`, NULL = no cast. */
typedef struct { const char *name, *kfunc; int arity; const char *casts[3]; } QdiscKf;
static const QdiscKf QDISC_KFUNCS[] = {
  {"qdisc_skb_drop", "bpf_qdisc_skb_drop", 2, {"(struct sk_buff *)(unsigned long)", "(struct bpf_sk_buff_ptr *)(unsigned long)", NULL}},
  {"qdisc_init_prologue", "bpf_qdisc_init_prologue", 2, {"(struct Qdisc *)(unsigned long)", "(struct netlink_ext_ack *)(unsigned long)", NULL}},
  {"qdisc_reset_destroy_epilogue", "bpf_qdisc_reset_destroy_epilogue", 1, {"(struct Qdisc *)(unsigned long)", NULL, NULL}},
  {"qdisc_watchdog_schedule", "bpf_qdisc_watchdog_schedule", 3, {"(struct Qdisc *)(unsigned long)", NULL, NULL}},
  {"qdisc_bstats_update", "bpf_qdisc_bstats_update", 2, {"(struct Qdisc *)(unsigned long)", "(const struct sk_buff *)(unsigned long)", NULL}},
  {NULL, NULL, 0, {NULL, NULL, NULL}}
};
static const QdiscKf *cc_qdisc_kf(const char *name) {
  for (int i = 0; QDISC_KFUNCS[i].name; i++) if (!strcmp(QDISC_KFUNCS[i].name, name)) return &QDISC_KFUNCS[i];
  return NULL;
}
static char *cc_qdisc_call_str(AST *ast, int nid, const QdiscKf *kf) {
  int args_id = nt_ref(ast, nid, "arguments");
  int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
  if (na != kf->arity) die("qdisc kfunc arity mismatch (Stage 1)", kf->name);
  Buf c; memset(&c, 0, sizeof c);
  buf_printf(&c, "%s(", kf->kfunc);
  for (int i = 0; i < na; i++) {
    char *e = cc_expr_str(ast, ids[i]);
    if (i) buf_puts(&c, ", ");
    const char *cast = (i < 3) ? kf->casts[i] : NULL;
    if (cast) buf_printf(&c, "%s(%s)", cast, e); else buf_puts(&c, e);
    free(e);
  }
  buf_puts(&c, ")");
  return c.p;
}

/* ---------- CAst: structured C-expression nodes + a precedence-driven
 * printer. Replaces hand-balanced string concatenation for the precedence-bearing
 * expression forms (binops, ||/&&, parens) so changes are node transforms, not
 * paren surgery. Mirrors src/spinel_ebpf/c_ast.rb (CExpr/CPrinter). Un-structured
 * leaves are captured as a primary CE_RAW (the existing string lowering), so the
 * minimal-paren printer reproduces the current output byte-identically: a
 * precedence-parsed Ruby tree never has a looser-binding child except via an
 * explicit ParenthesesNode (modeled as CE_PAREN, primary precedence). ---------- */
typedef enum { CE_RAW, CE_PAREN, CE_CAST, CE_UNARY, CE_BINOP, CE_CALL, CE_SUBSCRIPT } CEKind;
typedef struct CExpr {
  CEKind kind;
  char *text;              /* CE_RAW: token; CE_BINOP/CE_UNARY: op; CE_CAST: type; CE_CALL: callee */
  struct CExpr *a, *b;     /* binop: lhs/rhs; paren/cast/unary: a */
  struct CExpr **args; int nargs;   /* CE_CALL */
} CExpr;

enum { CE_PREC_CAST = 80, CE_PREC_UNARY = 80, CE_PREC_POSTFIX = 90, CE_PREC_PRIMARY = 100 };

/* operator precedence (mirrors BINOP_PREC in c_ast.rb; larger binds tighter). */
static int ce_binop_prec(const char *op) {
  if (!strcmp(op, "||")) return 20;
  if (!strcmp(op, "&&")) return 25;
  if (!strcmp(op, "|"))  return 30;
  if (!strcmp(op, "^"))  return 35;
  if (!strcmp(op, "&"))  return 40;
  if (!strcmp(op, "==") || !strcmp(op, "!=")) return 45;
  if (!strcmp(op, "<") || !strcmp(op, "<=") || !strcmp(op, ">") || !strcmp(op, ">=")) return 50;
  if (!strcmp(op, "<<") || !strcmp(op, ">>")) return 55;
  if (!strcmp(op, "+") || !strcmp(op, "-")) return 60;
  if (!strcmp(op, "*") || !strcmp(op, "/") || !strcmp(op, "%")) return 70;
  die("unknown C binop", op);
  return 0;
}
static int ce_prec(const CExpr *e) {
  switch (e->kind) {
    case CE_BINOP: return ce_binop_prec(e->text);
    case CE_CAST: case CE_UNARY: return CE_PREC_CAST;
    case CE_CALL: case CE_SUBSCRIPT: return CE_PREC_POSTFIX;
    default: return CE_PREC_PRIMARY;   /* CE_RAW, CE_PAREN */
  }
}
/* builders -- malloc'd; this one-shot tool leaks like the rest. */
static CExpr *ce_new(CEKind k) { CExpr *e = calloc(1, sizeof *e); if (!e) die("oom", "CExpr"); e->kind = k; return e; }
static CExpr *ce_raw(char *t)                          { CExpr *e = ce_new(CE_RAW);   e->text = t; return e; }
static CExpr *ce_paren(CExpr *in)                      { CExpr *e = ce_new(CE_PAREN); e->a = in; return e; }
static CExpr *ce_binop(const char *op, CExpr *l, CExpr *r) { CExpr *e = ce_new(CE_BINOP); e->text = strdup(op); e->a = l; e->b = r; return e; }
static CExpr *ce_cast(const char *ty, CExpr *op)       { CExpr *e = ce_new(CE_CAST);  e->text = strdup(ty); e->a = op; return e; }
static CExpr *ce_call(const char *callee, CExpr **args, int n) {
  CExpr *e = ce_new(CE_CALL); e->text = strdup(callee);
  e->args = malloc(sizeof(CExpr *) * (n > 0 ? n : 1));
  for (int i = 0; i < n; i++) e->args[i] = args[i];
  e->nargs = n; return e;
}
static CExpr *ce_subscript(CExpr *recv, CExpr *idx) { CExpr *e = ce_new(CE_SUBSCRIPT); e->a = recv; e->b = idx; return e; }
/* (ce_unary builder lands when prefix-op forms are converted; ce_print handles it.) */

static void ce_print(const CExpr *e, Buf *b);
static void ce_child(const CExpr *c, int needs_paren, Buf *b) {
  if (needs_paren) buf_puts(b, "(");
  ce_print(c, b);
  if (needs_paren) buf_puts(b, ")");
}
static void ce_print(const CExpr *e, Buf *b) {
  switch (e->kind) {
    case CE_RAW:   buf_puts(b, e->text); return;
    case CE_PAREN: buf_puts(b, "("); ce_print(e->a, b); buf_puts(b, ")"); return;
    case CE_CAST:  buf_printf(b, "(%s)", e->text); ce_child(e->a, ce_prec(e->a) < CE_PREC_CAST, b); return;
    case CE_UNARY: buf_puts(b, e->text);           ce_child(e->a, ce_prec(e->a) < CE_PREC_UNARY, b); return;
    case CE_BINOP: {
      int p = ce_binop_prec(e->text);
      ce_child(e->a, ce_prec(e->a) <  p, b);   /* lhs: strict < (C binops are left-assoc) */
      buf_printf(b, " %s ", e->text);
      ce_child(e->b, ce_prec(e->b) <= p, b);   /* rhs: <= */
      return;
    }
    case CE_CALL:
      buf_printf(b, "%s(", e->text);
      for (int i = 0; i < e->nargs; i++) { if (i) buf_puts(b, ", "); ce_print(e->args[i], b); }
      buf_puts(b, ")");
      return;
    case CE_SUBSCRIPT:
      ce_child(e->a, ce_prec(e->a) < CE_PREC_POSTFIX, b);
      buf_puts(b, "["); ce_print(e->b, b); buf_puts(b, "]");
      return;
  }
}

/* build a CExpr for the precedence-bearing forms (binop / ||,&& / parens),
 * recursing so nested precedence is structural; any other node is captured as a
 * primary CE_RAW via the existing string lowering (cc_expr_str). */
static CExpr *cc_build_expr(AST *ast, int nid) {
  const char *ty = nt_type(ast, nid);
  if (ty && !strcmp(ty, "ParenthesesNode")) {
    int body = nt_ref(ast, nid, "body");
    if (body < 0) return ce_raw(strdup("0"));
    return ce_paren(cc_build_expr(ast, body));
  }
  if (ty && (!strcmp(ty, "OrNode") || !strcmp(ty, "AndNode"))) {
    int l = nt_ref(ast, nid, "left"), r = nt_ref(ast, nid, "right");
    if (l < 0 || r < 0) die("OrNode/AndNode missing operand", ty);
    /* Build operands left-to-right via locals: cc_build_expr has side effects
       (it allocates the _pN ivar-lookup temporaries and emits their prelude
       lines), and C leaves the evaluation order of function arguments
       unspecified -- sequencing keeps the emitted output identical across
       compilers/architectures (gcc evaluates args L->R on arm64 but R->L on x86). */
    CExpr *lhs = cc_build_expr(ast, l);
    CExpr *rhs = cc_build_expr(ast, r);
    return ce_binop(ty[0] == 'O' ? "||" : "&&", lhs, rhs);
  }
  if (ty && !strcmp(ty, "CallNode")) {
    const char *name = nt_str(ast, nid, "name");
    if (name && cc_is_binary_op(name)) {
      int recv = nt_ref(ast, nid, "receiver");
      int args_id = nt_ref(ast, nid, "arguments");
      if (recv < 0 || args_id < 0) die("binop CallNode missing operand", name);
      const char *at = nt_type(ast, args_id);
      if (!at || strcmp(at, "ArgumentsNode")) die("binop args not ArgumentsNode", NULL);
      int na; const int *ids = nt_arr(ast, args_id, "arguments", &na);
      if (na != 1) die("binop expects 1 arg", name);
      /* left-to-right via locals (unspecified arg-eval order; see OrNode above) */
      CExpr *lhs = cc_build_expr(ast, recv);
      CExpr *rhs = cc_build_expr(ast, ids[0]);
      return ce_binop(name, lhs, rhs);
    }
  }
  return ce_raw(cc_expr_str(ast, nid));   /* leaf / not-yet-structured: primary */
}

/* `((__s64)BPF_CORE_READ((struct <strct> *)(unsigned long)(<ptr>), <field>...))`
 * as a CAst tree (was hand-balanced string concat). `ptr_text` is consumed by the
 * tree (CE_RAW); `fields` are bare macro field tokens (e.g. "sk_sndbuf" or a dotted
 * "__sk_common.skc_dport"). The explicit (<ptr>) paren is modeled with CE_PAREN so
 * the minimal-paren printer reproduces the original output byte-for-byte. */
static CExpr *cc_core_read(const char *strct, char *ptr_text, char **fields, int nf) {
  char *ptrty = msprintf("struct %s *", strct);
  CExpr *pcast = ce_cast(ptrty, ce_cast("unsigned long", ce_paren(ce_raw(ptr_text))));
  free(ptrty);
  CExpr **args = malloc(sizeof(CExpr *) * (nf + 1));
  args[0] = pcast;
  for (int i = 0; i < nf; i++) args[i + 1] = ce_raw(strdup(fields[i]));
  CExpr *e = ce_paren(ce_cast("__s64", ce_call("BPF_CORE_READ", args, nf + 1)));
  free(args);
  return e;
}

/* ---------- kfield_str -- the STRING sibling of kfield ----------
 *
 * kfield yields `((__s64)BPF_CORE_READ(...))`, which is a scalar by construction.
 * A string field needs a bounded destination and, depending on the shape of the
 * LAST hop, either one probe read or two. The shape question is answered by the C
 * type system at compile time (see templates/kfield_str.template.c); everything
 * here is text assembly around that.
 *
 * The accessor convention is kfield's, unchanged: a comma is a POINTER hop,
 * a dot is an embedded member. `kfield_str(file, "file", "f_path.dentry", "d_name.name")`
 * therefore means file->f_path.dentry (a hop) then ->d_name.name (embedded, and the
 * string). That is exactly the argument split BPF_CORE_READ* already wants. */

/* `((struct T *)0)->a->b->c` -- the field path against a null base. Only its TYPE is
 * ever used (SPNL_KSTR_IS_PTR and _Static_assert are unevaluated contexts), so the
 * null base is never dereferenced. Caller frees. */
static char *cc_kstr_chain(const char *strct, char **fields, int nf) {
  Buf b; memset(&b, 0, sizeof b);
  buf_printf(&b, "((struct %s *)0)", strct);
  for (int i = 0; i < nf; i++) buf_printf(&b, "->%s", fields[i]);
  return b.p;
}

/* `a, b, c` -- the accessor list in the form BPF_CORE_READ* takes it. Caller frees. */
static char *cc_kstr_accessors(char **fields, int nf) {
  Buf b; memset(&b, 0, sizeof b);
  for (int i = 0; i < nf; i++) buf_printf(&b, "%s%s", i ? ", " : "", fields[i]);
  return b.p;
}

/* The call as the author wrote it, escaped for a C string literal, so the
 * _Static_assert that fires names the Ruby line rather than the expansion
 * (reason + what you wrote + how to fix). Caller frees.
 *
 * ASCII only, unlike the comments this file emits. This particular text is quoted
 * back by ANOTHER tool (clang prints it in the diagnostic) and then re-read by
 * `spinel-ebpf check`, which scans clang's stderr -- and a non-UTF-8 default locale
 * turns a stray multi-byte character there into an ArgumentError stack trace
 * instead of the message (measured). */
static char *cc_kstr_call_text(const char *who, const char *ptrexpr, const char *strct,
                               char **fields, int nf, const char *lit) {
  Buf b; memset(&b, 0, sizeof b);
  buf_printf(&b, "%s(%s, \\\"%s\\\"", who, ptrexpr, strct);
  for (int i = 0; i < nf; i++) buf_printf(&b, ", \\\"%s\\\"", fields[i]);
  if (lit) buf_printf(&b, ", \\\"%s\\\"", lit);
  buf_puts(&b, ")");
  return b.p;
}

/* Emit the read of a kernel string field into `dst` (a char array lvalue) and hand
 * back the name of the __s64 temp holding the helper's return value (caller frees).
 *
 * Three lines, in this order and for these reasons:
 *   1. the base pointer goes into a typed temp -- the author's expression may itself
 *      contain a comma, and it is about to be a macro argument;
 *   2. a _Static_assert that the chain lands on 1-byte elements. Without it a chain
 *      that stops one hop short (say on `struct dentry *`) still looks like "a
 *      pointer" to SPNL_KSTR_IS_PTR and would be read as a string;
 *   3. the read itself, shape chosen by the C type of the last field. */
static char *cc_emit_kfield_str_read(Lines *body, const char *ind, const char *dst,
                                     const char *who, const char *ptrexpr,
                                     const char *strct, char **fields, int nf,
                                     const char *lit, const char *extra_hint) {
  int n = ++g_if_counter;
  char *chain = cc_kstr_chain(strct, fields, nf);
  char *acc   = cc_kstr_accessors(fields, nf);
  char *call  = cc_kstr_call_text(who, ptrexpr, strct, fields, nf, lit);
  lines_push(body, msprintf("%sstruct %s *_ksp%d = (struct %s *)(unsigned long)(%s);",
                            ind, strct, n, strct, ptrexpr));
  lines_push(body, msprintf("%sSPNL_KSTR_CHECK(%s,", ind, chain));
  lines_push(body, msprintf("%s    \"%s: the last field must be characters "
                            "(char[N] or char *); this chain ends on something else.%s\");",
                            ind, call, extra_hint ? extra_hint : ""));
  lines_push(body, msprintf("%s__s64 _ksr%d = SPNL_KFIELD_STR(%s, %s, _ksp%d, %s);",
                            ind, n, dst, chain, n, acc));
  free(chain); free(acc); free(call);
  return msprintf("_ksr%d", n);
}

/* Parse `(ptr, "struct", "field"..., ["literal"])`, shared by both kfield_str forms.
 * With `want_lit` the LAST string argument is the value to compare, not a field.
 * That is the one ambiguous thing about the eq form's shape (every argument is a
 * string), so it is stated in the arity message AND caught downstream: omitting the
 * literal silently promotes the last FIELD to it, leaving a chain that stops on a
 * struct pointer -- which the _Static_assert refuses. Field pointers are borrowed
 * from the AST; the caller frees *ptr_out and the *fields_out array itself. */
static void cc_kstr_args(AST *ast, int nid, int want_lit,
                         char **ptr_out, const char **strct_out,
                         char ***fields_out, int *nf_out, const char **lit_out) {
  int args_id = nt_ref(ast, nid, "arguments");
  int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
  int need = want_lit ? 4 : 3;
  if (na < need)
    die(want_lit
        ? "kfield_str_eq expects (ptr, \"struct\", \"field\"..., \"literal\") -- the LAST "
          "string is the value to compare; everything between the struct name and it is "
          "the field path (comma = pointer hop, dot = embedded member)"
        : "emit_kfield_str expects (ptr, \"struct\", \"field\"...) "
          "(comma = pointer hop, dot = embedded member)", NULL);
  *ptr_out = cc_expr_str(ast, ids[0]);
  *strct_out = nt_str(ast, ids[1], "content");
  if (!*strct_out) die("kfield_str: the struct name must be a string literal", NULL);
  if (want_lit) {
    *lit_out = nt_str(ast, ids[na - 1], "content");
    if (!*lit_out)
      die("kfield_str_eq: the value to compare must be a string literal "
          "(it is compiled into the program as an unrolled byte compare)", NULL);
    na--;
  } else {
    *lit_out = NULL;
  }
  int nf = na - 2;
  char **fields = malloc(sizeof(char *) * (size_t)nf);
  if (!fields) die("oom", "kfield_str fields");
  for (int k = 2; k < na; k++) {
    const char *fld = nt_str(ast, ids[k], "content");
    if (!fld) die("kfield_str: field names must be string literals", NULL);
    fields[k - 2] = (char *)fld;
  }
  *fields_out = fields;
  *nf_out = nf;
}

/* Emit the compare for kfield_str_eq into g_body; hand back the match
 * expression in `b`. Sibling of cc_emit_path_eq_g, and the buffer rule is where
 * they part company -- measured, not assumed:
 *
 *   path_eq sizes the buffer to the literal exactly, which is CORRECT there because
 *   bpf_d_path refuses to truncate (-ENAMETOOLONG => non-match).
 *   bpf_probe_read_kernel_str truncates SILENTLY instead: reading a 15-char value
 *   into char[4] returns 4 with "abc\0" -- byte-for-byte what a real 3-char "abc"
 *   returns (measured). The exact-size trick would therefore make
 *   `kfield_str_eq(..., "abc")` fire on "abc4_target.txt": an OVER-match, i.e. a
 *   selector that hits files it was never pointed at.
 *
 * So the buffer gets one spare byte (literal + NUL + 1). Then `ret == len + 1` says
 * the value ENDED inside the buffer, and only then are the bytes compared:
 *   value == literal  -> ret = len+1                    match
 *   value longer      -> ret = len+2 (truncated)        no match
 *   value shorter     -> ret = strlen+1 < len+1         no match
 * A fault returns negative and matches nothing, the same fail-safe path_eq uses. */
static void cc_emit_kfield_str_eq(Buf *b, const char *rc, int n, const char *buf,
                                  const char *lit, size_t len) {
  lines_push(g_body, msprintf("__s64 _ksm%d = (%s == %zu);", n, rc, len + 1));
  for (size_t i = 0; i < len; i++)
    lines_push(g_body, msprintf("_ksm%d = _ksm%d && (%s[%zu] == %d);",
                                n, n, buf, i, (int)(unsigned char)lit[i]));
  buf_printf(b, "(_ksm%d)", n);
}

/* ivar map idioms (key=__u32 singleton). These factor the multi-line
 * lines_push idioms -- the only value is keeping the fresh-counter (g_if_counter)
 * bookkeeping in one place so the `_kN`/`_pN`/`_vN` indices can't drift between
 * the declaration and its uses. Counter allocation order is preserved exactly,
 * so the emitted text is byte-identical to the former inline sequences. */

/* @x read: emit `_kN`+lookup prelude into `pre`, return the read expression
 * "(_pN ? *_pN : 0)" (caller frees). Counter order: k, p. */
static char *cc_emit_ivar_read(Lines *pre, const char *map) {
  if (g_amp) { (void)pre; return strdup(map); }   /* map is the carveout lvalue expr */
  int kk = ++g_if_counter, pp = ++g_if_counter;
  lines_push(pre, msprintf("__u32 _k%d = 0;", kk));
  lines_push(pre, msprintf("__s64 *_p%d = bpf_map_lookup_elem(&%s, &_k%d);", pp, map, kk));
  return msprintf("(_p%d ? *_p%d : 0)", pp, pp);
}

/* @x = rhs: emit key + value-temp + update into `body`, return "_vN" (caller
 * frees). Counter order: k, v. */
static char *cc_emit_ivar_write(Lines *body, const char *map, const char *rhs) {
  if (g_amp) { lines_push(body, msprintf("%s = (%s);", map, rhs)); return strdup(map); }
  int kk = ++g_if_counter, vv = ++g_if_counter;
  lines_push(body, msprintf("__u32 _k%d = 0;", kk));
  lines_push(body, msprintf("__s64 _v%d = %s;", vv, rhs));
  lines_push(body, msprintf("bpf_map_update_elem(&%s, &_k%d, &_v%d, BPF_ANY);", map, kk, vv));
  return msprintf("_v%d", vv);
}

/* @x op= rhs: lookup-compute-update into `body`, return "_vN" (caller frees).
 * Counter order: k, p, v. */
static char *cc_emit_ivar_rmw(Lines *body, const char *map, const char *op, const char *rhs) {
  if (g_amp) { lines_push(body, msprintf("%s = %s %s (%s);", map, map, op, rhs)); return strdup(map); }
  int kk = ++g_if_counter, pp = ++g_if_counter, vv = ++g_if_counter;
  lines_push(body, msprintf("__u32 _k%d = 0;", kk));
  lines_push(body, msprintf("__s64 *_p%d = bpf_map_lookup_elem(&%s, &_k%d);", pp, map, kk));
  lines_push(body, msprintf("__s64 _v%d = (_p%d ? *_p%d : 0) %s (%s);", vv, pp, pp, op, rhs));
  lines_push(body, msprintf("bpf_map_update_elem(&%s, &_k%d, &_v%d, BPF_ANY);", map, kk, vv));
  return msprintf("_v%d", vv);
}

/* FIFO qdisc enqueue: emit the do/while(0) push block into g_body, return
 * the NET_XMIT_* result temp "_qp_retN" (caller frees). skb_c/tf_c are the
 * pre-casted skb / to_free expressions. Factored out of cc_lower_expr so the
 * CallNode dispatch reads as one line; verifier-shaped text is unchanged. */
static char *cc_emit_queue_push(const char *skb_c, const char *tf_c) {
  int rv = ++g_if_counter;
  lines_push(g_body, msprintf("__s64 _qp_ret%d = 1;  /* NET_XMIT_DROP unless we make it through */", rv));
  lines_push(g_body, strdup("do {"));
  lines_push(g_body, strdup("    struct spnl_qdisc_skb_node *_qpn = bpf_obj_new(typeof(*_qpn));"));
  lines_push(g_body, strdup("    if (!_qpn) {"));
  lines_push(g_body, msprintf("        bpf_qdisc_skb_drop(%s, %s);", skb_c, tf_c));
  lines_push(g_body, strdup("        break;"));
  lines_push(g_body, strdup("    }"));
  lines_push(g_body, msprintf("    struct sk_buff *_swap = bpf_kptr_xchg(&_qpn->skb, %s);", skb_c));
  lines_push(g_body, strdup("    if (_swap) {"));
  lines_push(g_body, msprintf("        bpf_qdisc_skb_drop(_swap, %s);", tf_c));
  lines_push(g_body, strdup("        bpf_obj_drop(_qpn);"));
  lines_push(g_body, strdup("        break;"));
  lines_push(g_body, strdup("    }"));
  lines_push(g_body, strdup("    bpf_spin_lock(&spnl_qdisc_q_lock);"));
  lines_push(g_body, strdup("    bpf_list_push_back(&spnl_qdisc_q_head, &_qpn->node);"));
  lines_push(g_body, strdup("    bpf_spin_unlock(&spnl_qdisc_q_lock);"));
  lines_push(g_body, msprintf("    _qp_ret%d = 0;  /* NET_XMIT_SUCCESS */", rv));
  lines_push(g_body, strdup("} while (0);"));
  return msprintf("_qp_ret%d", rv);
}

/* FIFO qdisc dequeue: emit the do/while(0) pop block into g_body, return
 * the skb-pointer-as-__s64 result temp "_qpop_retN" (caller frees). */
static char *cc_emit_queue_pop(void) {
  int rv = ++g_if_counter;
  lines_push(g_body, msprintf("__s64 _qpop_ret%d = 0;", rv));
  lines_push(g_body, strdup("do {"));
  lines_push(g_body, strdup("    struct bpf_list_node *_qpn = NULL;"));
  lines_push(g_body, strdup("    struct sk_buff *_qpr = NULL;"));
  lines_push(g_body, strdup("    bpf_spin_lock(&spnl_qdisc_q_lock);"));
  lines_push(g_body, strdup("    _qpn = bpf_list_pop_front(&spnl_qdisc_q_head);"));
  lines_push(g_body, strdup("    bpf_spin_unlock(&spnl_qdisc_q_lock);"));
  lines_push(g_body, strdup("    if (!_qpn) break;"));
  lines_push(g_body, strdup("    struct spnl_qdisc_skb_node *_qps = container_of(_qpn, struct spnl_qdisc_skb_node, node);"));
  lines_push(g_body, strdup("    _qpr = bpf_kptr_xchg(&_qps->skb, NULL);"));
  lines_push(g_body, strdup("    bpf_obj_drop(_qps);"));
  lines_push(g_body, msprintf("    _qpop_ret%d = (__s64)(unsigned long)_qpr;", rv));
  lines_push(g_body, strdup("} while (0);"));
  return msprintf("_qpop_ret%d", rv);
}

/* The 16-byte event header: the four hdr.* assignments shared verbatim by every
 * ringbuf emit idiom (spnl_emit / emit_str|pair|3|4 / emit_argv / emit_comm).
 * `var` is the reserved-event pointer expr (e.g. "_e3"), `ind` the leading
 * indentation. Dedups what was 4 copies of the same 4 lines. */
static void cc_push_evt_hdr(Lines *body, const char *ind, const char *var) {
  lines_push(body, msprintf("%s%s->hdr.type = SPNL_EVT_USER_BASE;", ind, var));
  lines_push(body, msprintf("%s%s->hdr.version = SPNL_EVENT_HDR_VERSION;", ind, var));
  lines_push(body, msprintf("%s%s->hdr.reserved = 0;", ind, var));
  lines_push(body, msprintf("%s%s->hdr.timestamp = bpf_ktime_get_ns();", ind, var));
}

/* conntrack idioms (per-flow LRU_HASH keyed by the 4-tuple). All three
 * key off `mn` (map name) + the xdp/tc key-extract helper; factored so the
 * `_fkN`/`_fpN`/`_fokN` fresh-counter bookkeeping stays in one place. */

/* flow_get read: emit key+lookup prelude into `pre`, return the read expression
 * "(_fpN ? (__s64)_fpN->fld : 0)" (caller frees). Counter order: k, p. */
static char *cc_emit_flow_get(Lines *pre, const char *mn, const char *fld) {
  const char *kind = cc_flow_kind_str();
  int kv = ++g_if_counter, pv = ++g_if_counter;
  lines_push(pre, msprintf("struct spnl_flow_%s_%s_k _fk%d = {};", g_unit, mn, kv));
  lines_push(pre, msprintf("struct spnl_flow_%s_%s_v *_fp%d = (spnl_flow_%s_%s_key_%s(ctx, &_fk%d) == 0) ? bpf_map_lookup_elem(&spnl_flow_%s_%s, &_fk%d) : NULL;",
                           g_unit, mn, pv, g_unit, mn, kind, kv, g_unit, mn, kv));
  return msprintf("(_fp%d ? (__s64)_fp%d->%s : 0)", pv, pv, fld);
}

/* flow_set write (lookup-or-insert, then set field) into `body`. Counter order:
 * k, z, ok, p. */
static void cc_emit_flow_set(Lines *body, const char *mn, const char *fld, const char *val) {
  const char *kind = cc_flow_kind_str();
  int fk = ++g_if_counter, fz = ++g_if_counter, fok = ++g_if_counter, fp = ++g_if_counter;
  lines_push(body, msprintf("struct spnl_flow_%s_%s_k _fk%d = {};", g_unit, mn, fk));
  lines_push(body, msprintf("struct spnl_flow_%s_%s_v _fz%d = {};", g_unit, mn, fz));
  lines_push(body, msprintf("int _fok%d = spnl_flow_%s_%s_key_%s(ctx, &_fk%d);", fok, g_unit, mn, kind, fk));
  lines_push(body, msprintf("struct spnl_flow_%s_%s_v *_fp%d = _fok%d == 0 ? bpf_map_lookup_elem(&spnl_flow_%s_%s, &_fk%d) : NULL;", g_unit, mn, fp, fok, g_unit, mn, fk));
  lines_push(body, msprintf("if (_fok%d == 0 && !_fp%d) bpf_map_update_elem(&spnl_flow_%s_%s, &_fk%d, &_fz%d, BPF_ANY);", fok, fp, g_unit, mn, fk, fz));
  lines_push(body, msprintf("if (_fok%d == 0 && !_fp%d) _fp%d = bpf_map_lookup_elem(&spnl_flow_%s_%s, &_fk%d);", fok, fp, fp, g_unit, mn, fk));
  lines_push(body, msprintf("if (_fp%d) _fp%d->%s = (__u64)(%s);", fp, fp, fld, val));
}

/* flow_del: delete the entry if the key extracts. Counter order: k. */
static void cc_emit_flow_del(Lines *body, const char *mn) {
  const char *kind = cc_flow_kind_str();
  int fk = ++g_if_counter;
  lines_push(body, msprintf("struct spnl_flow_%s_%s_k _fk%d = {};", g_unit, mn, fk));
  lines_push(body, msprintf("if (spnl_flow_%s_%s_key_%s(ctx, &_fk%d) == 0) bpf_map_delete_elem(&spnl_flow_%s_%s, &_fk%d);", g_unit, mn, kind, fk, g_unit, mn, fk));
}

/* The gate error names EVERY hook you could have written this in
 * (grouped by which argument carries the path, because that is what the reader
 * has to pick). Generated from CC_DPATH_OK so the list cannot drift from the
 * measurement -- reason + evidence + how to fix (see error_quality_test). */
static char *cc_dpath_hooks_str(void) {
  static const char *const label[] = { "file arg", "path arg", "binprm arg" };
  Buf b; memset(&b, 0, sizeof b);
  for (int f = 0; f < 3; f++) {
    buf_printf(&b, "\n    %-10s: ", label[f]);
    int n = 0;
    for (int i = 0; CC_DPATH_OK[i].sec; i++) {
      if ((int)CC_DPATH_OK[i].form != f) continue;
      const char *sec = CC_DPATH_OK[i].sec, *slash = strchr(sec, '/');
      /* SEC -> the `def` name the user writes: lsm/file_open -> lsm__file_open */
      buf_printf(&b, "%sdef %.*s__%s", n++ ? " / " : "",
                 (int)(slash ? slash - sec : (long)strlen(sec)), sec, slash ? slash + 1 : "");
    }
  }
  return b.p;
}

/* Enforce the bpf_d_path kernel gate (CC_DPATH_OK) and hand back the matched hook
 * (its `form` decides how the gated arg becomes a `struct path *`). Shared by
 * path_eq / path_starts_with / path_contains / parent_path_eq / emit_path /
 * emit_parent_path. die() with the offending SEC. */
static const CcDpathHook *cc_require_dpath_ok(const char *who) {
  Attach a = {0};
  (void)(g_method ? cc_detect_attach(g_method->name, &a) : AK_NONE);
  const CcDpathHook *h = cc_dpath_hook(a.sec);
  if (!h) {
    char *hooks = cc_dpath_hooks_str();
    char *msg = msprintf("%s: bpf_d_path is kernel-gated (measured: LSM allows it "
                         "only on sleepable hooks, fmod_ret/fentry only on the kernel's "
                         "btf_allowlist_d_path; kprobe never). Write it in one of the "
                         "measured-OK hooks:%s\n  (got SEC)", who, hooks);
    die(msg, a.sec ? a.sec : "<none>");
  }
  if (a.sec) free(a.sec);
  return h;
}

/* build the `struct path *` expression for the gated argument of THIS hook.
 * The hooks disagree about what they hand you, so the form is per-SEC (a plain
 * `&file->f_path` on lsm/path_unlink's `struct path *` arg would be rejected at
 * load, not at compile time). Any prep temporaries go into `body` with `ind`
 * indentation; *guard_out (or NULL) is the pointer to NULL-check first.
 *
 * Trusted-ness is the constraint: bpf_d_path needs a trusted/rcu pointer,
 * so every hop here is a DIRECT DEREF -- BPF_CORE_READ would return a scalar and
 * the verifier would reject the call. */
static char *cc_dpath_expr(const CcDpathHook *h, const char *argexpr, Lines *body,
                           const char *ind, char **guard_out) {
  *guard_out = NULL;
  if (h->form == CC_DP_PATH)                    /* the arg already IS a struct path * */
    return msprintf("((struct path *)(unsigned long)(%s))", argexpr);
  if (h->form == CC_DP_BINPRM) {                /* exec: bprm->file->f_path (2 hops) */
    int q = ++g_if_counter;
    lines_push(body, msprintf("%sstruct linux_binprm *_pq%d = (struct linux_binprm *)(unsigned long)(%s);", ind, q, argexpr));
    lines_push(body, msprintf("%sstruct file *_pg%d = _pq%d ? _pq%d->file : 0;", ind, q, q, q));
    *guard_out = msprintf("_pg%d", q);
    return msprintf("&_pg%d->f_path", q);
  }
  if (!h->guard)                                /* the original shape -- byte-identical */
    return msprintf("&((struct file *)(unsigned long)(%s))->f_path", argexpr);
  int g = ++g_if_counter;                       /* file__nullable (lsm/mmap_file) */
  lines_push(body, msprintf("%sstruct file *_pg%d = (struct file *)(unsigned long)(%s);", ind, g, argexpr));
  *guard_out = msprintf("_pg%d", g);
  return msprintf("&_pg%d->f_path", g);
}

/* emit the path-compare into g_body and hand back the match expr in `b`.
 * `pathexpr` is a `struct path *` expression (file's f_path, or parent's exe f_path).
 * AOT: literal length + bytes known at compile time -> exact-sized stack buffer +
 * unrolled byte compare, length-first for short-circuit. Buffer sized to the literal
 * is the correct semantics (a longer real path yields -ENAMETOOLONG, and so no match).
 * `guard` (or NULL) is a pointer that must be non-NULL before the call -- a NULL
 * one yields -1, i.e. a non-match, the same fail-safe as -ENAMETOOLONG. */
static void cc_emit_path_eq_g(Buf *b, const char *pathexpr, const char *guard, const char *lit) {
  size_t len = strlen(lit);
  if (len == 0) die("path compare: empty path literal", NULL);
  /* exact literal + NUL, rounded to 8 for stack alignment. Refuse long literals at
   * compile time rather than emit a program clang/verifier rejects. */
  size_t sz = ((len + 1 + 7) / 8) * 8;
  if (sz > CC_PATH_EQ_MAX)
    die("path compare: path literal too long for the BPF stack", lit);
  int n = ++g_if_counter;
  lines_push(g_body, msprintf("char _pb%d[%zu] = {0};", n, sz));
  if (guard)
    lines_push(g_body, msprintf("__s64 _pr%d = %s ? bpf_d_path(%s, _pb%d, sizeof(_pb%d)) : -1;", n, guard, pathexpr, n, n));
  else
    lines_push(g_body, msprintf("__s64 _pr%d = bpf_d_path(%s, _pb%d, sizeof(_pb%d));", n, pathexpr, n, n));
  lines_push(g_body, msprintf("__s64 _pm%d = (_pr%d == %zu);", n, n, len + 1));
  for (size_t i = 0; i < len; i++)
    lines_push(g_body, msprintf("_pm%d = _pm%d && (_pb%d[%zu] == %d);", n, n, n, i, (int)(unsigned char)lit[i]));
  buf_printf(b, "(_pm%d)", n);
}
static void cc_emit_path_eq(Buf *b, const char *pathexpr, const char *lit) {
  cc_emit_path_eq_g(b, pathexpr, NULL, lit);   /* unguarded (task chain / non-nullable file) */
}

/* emit a PREFIX path-compare into g_body; hand back the match expr in `b`.
 * Sibling of cc_emit_path_eq, but the correctness constraint differs and drives
 * the design:
 *   - path_eq (exact): the matched path IS the literal (< 256B), so a small stack
 *     buffer always fits.
 *   - path_starts_with (prefix): the matched path is `prefix + arbitrary suffix`,
 *     up to PATH_MAX (4096). bpf_d_path writes the WHOLE path and returns
 *     -ENAMETOOLONG when the buffer is too small -- so a small buffer would make a
 *     LONG path under the prefix FAIL to match = a deny/audit BYPASS (an attacker
 *     evades with a long filename). So the buffer must hold a full PATH_MAX path.
 * 4096 does NOT fit the 512B BPF stack, so we read into a per-unit PERCPU_ARRAY
 * scratch (<unit>_path_scratch, one char[4096] slot; declared once per unit,
 * gated on uses_path_scratch). bpf_map_lookup_elem yields a PTR_TO_MAP_VALUE of
 * 4096 bytes; the unrolled `_buf[i]` reads (i < prefix_len <= 256 < 4096) are
 * provably in-bounds so the verifier accepts them, and they are guarded by the
 * NULL check on the lookup. Fails safe: a negative bpf_d_path return (or a path
 * shorter than the prefix) makes the length test 0, and && short-circuits. */
static void cc_emit_path_starts_with(Buf *b, const char *pathexpr, const char *guard, const char *lit) {
  size_t len = strlen(lit);
  if (len == 0) die("path prefix compare: empty path literal", NULL);
  /* Cap the unrolled prefix length (consistent with path_eq's CC_PATH_EQ_MAX).
   * The buffer is a 4096B map value, not the stack, so the wall here is the
   * number of unrolled byte comparisons, not the frame size. */
  if (len > CC_PATH_EQ_MAX)
    die("path prefix compare: path literal too long (the cap is CC_PATH_EQ_MAX)", lit);
  int n = ++g_if_counter;
  lines_push(g_body, msprintf("__s64 _pm%d = 0;", n));
  lines_push(g_body, msprintf("__u32 _pz%d = 0;", n));
  lines_push(g_body, msprintf("char *_pbuf%d = bpf_map_lookup_elem(&%s_path_scratch, &_pz%d);", n, g_unit, n));
  lines_push(g_body, msprintf("if (_pbuf%d) {", n));
  if (guard)   /* unknown path (NULL arg) -> -1 -> length test fails -> no match */
    lines_push(g_body, msprintf("    __s64 _pr%d = %s ? bpf_d_path(%s, _pbuf%d, 4096) : -1;", n, guard, pathexpr, n));
  else
    lines_push(g_body, msprintf("    __s64 _pr%d = bpf_d_path(%s, _pbuf%d, 4096);", n, pathexpr, n));
  /* path at least as long as the prefix (strlen+1 >= prefix_len+1); fails safe on
   * -ENAMETOOLONG (< 0) and on paths shorter than the prefix. */
  lines_push(g_body, msprintf("    _pm%d = (_pr%d >= %zu);", n, n, len + 1));
  for (size_t i = 0; i < len; i++)
    lines_push(g_body, msprintf("    _pm%d = _pm%d && (_pbuf%d[%zu] == %d);", n, n, n, i, (int)(unsigned char)lit[i]));
  lines_push(g_body, msprintf("}"));
  buf_printf(b, "(_pm%d)", n);
}

/* emit a SUBSTRING path-compare into g_body; hand back the match expr in `b`.
 * The third of the path matchers: path_eq is exact, path_starts_with takes a
 * prefix, and path_contains looks for the literal at ANY offset. A substring can sit
 * anywhere up to PATH_MAX, so this is a sliding-window search over the whole path;
 * a crafted long path with the substring near the end must NOT bypass the deny
 * (no-bypass, same principle as path_starts_with's 4096B per-cpu buffer). A full
 * unroll (4096 windows x N bytes) is verifier/code-size infeasible, so we bpf_loop
 * over the window positions with the N-byte compare unrolled inside the callback.
 *
 * Verifier notes preserved from measurement:
 *   - CONSTANT 4096 bpf_loop bound (bpf_loop needs a bounded scalar; the callback's
 *     `if (i+N > plen) return 1` stops at the real end. _pr from bpf_d_path is NOT
 *     range-tracked, so it can't be the loop bound).
 *   - `& 4095` on every index makes buf[(i+j)&4095] provably in-bounds on the 4096B
 *     map value (i<4096 logically, but the verifier needs the mask to prove it).
 *   - RE-LOOKUP the scratch map inside the callback (don't stash the pointer in the
 *     ctx) -- passing PTR_TO_MAP_VALUE through a struct field loses the bound. */
static void cc_emit_path_contains(Buf *b, const char *pathexpr, const char *guard, const char *lit) {
  size_t len = strlen(lit);
  if (len == 0) die("path substring compare: empty path literal", NULL);
  /* Same unrolled-compare cap as path_eq/path_starts_with: the buffer is a 4096B
   * map value, so the wall is the number of unrolled byte comparisons, not frame. */
  if (len > CC_PATH_EQ_MAX)
    die("path substring compare: path literal too long (substr cap is CC_PATH_EQ_MAX)", lit);
  int n = ++g_pc_counter;   /* unit-global unique: callback + struct live at unit scope */

  /* deferred (unit scope, before the inners): the search-state ctx struct, then the
   * bpf_loop callback that compares the N-byte window at offset i. */
  {
    Buf st; memset(&st, 0, sizeof st);
    buf_printf(&st, "/* path_contains ctx: whole-path substring search state */\n");
    buf_printf(&st, "struct %s_pc_ctx%d { __s64 plen; __s64 found; };\n", g_unit, n);
    lines_push(g_deferred, st.p);
  }
  {
    Buf cb; memset(&cb, 0, sizeof cb);
    buf_printf(&cb, "/* path_contains callback: does the %zu-byte literal start at offset i? */\n", len);
    buf_printf(&cb, "static long %s_pc_cb%d(__u32 i, void *ctx)\n{\n", g_unit, n);
    buf_printf(&cb, "    struct %s_pc_ctx%d *c = ctx;\n", g_unit, n);
    buf_printf(&cb, "    if ((__s64)i + %zu > c->plen) return 1;   /* window past end -> stop the loop */\n", len);
    buf_printf(&cb, "    __u32 z = 0;\n");
    buf_printf(&cb, "    char *buf = bpf_map_lookup_elem(&%s_path_scratch, &z);   /* re-lookup: fresh map-value bound */\n", g_unit);
    buf_printf(&cb, "    if (!buf) return 1;\n");
    buf_printf(&cb, "    __s64 m = 1;\n");
    for (size_t j = 0; j < len; j++)
      buf_printf(&cb, "    m = m && (buf[(i + %zu) & 4095] == %d);\n", j, (int)(unsigned char)lit[j]);
    buf_printf(&cb, "    if (m) { c->found = 1; return 1; }   /* found -> stop early */\n");
    buf_printf(&cb, "    return 0;\n}\n");
    lines_push(g_deferred, cb.p);
  }

  /* call site: d_path the whole path into the scratch map, then bpf_loop the search
   * with a CONSTANT 4096 bound (the callback breaks early at the real path end). */
  lines_push(g_body, msprintf("__s64 _found%d = 0;", n));
  lines_push(g_body, strdup("{"));
  lines_push(g_body, msprintf("    __u32 _z%d = 0;", n));
  lines_push(g_body, msprintf("    char *_buf%d = bpf_map_lookup_elem(&%s_path_scratch, &_z%d);", n, g_unit, n));
  lines_push(g_body, msprintf("    if (_buf%d) {", n));
  if (guard)   /* unknown path (NULL arg) -> -1 -> the length test fails -> no match */
    lines_push(g_body, msprintf("        __s64 _pr%d = %s ? bpf_d_path(%s, _buf%d, 4096) : -1;", n, guard, pathexpr, n));
  else
    lines_push(g_body, msprintf("        __s64 _pr%d = bpf_d_path(%s, _buf%d, 4096);", n, pathexpr, n));
  lines_push(g_body, msprintf("        if (_pr%d > %zu) {", n, len));   /* path at least as long as the literal */
  lines_push(g_body, msprintf("            struct %s_pc_ctx%d _c%d = {};", g_unit, n, n));
  lines_push(g_body, msprintf("            _c%d.plen = _pr%d - 1;", n, n));
  lines_push(g_body, msprintf("            _c%d.found = 0;", n));
  lines_push(g_body, msprintf("            bpf_loop(4096, &%s_pc_cb%d, &_c%d, 0);", g_unit, n, n));
  lines_push(g_body, msprintf("            _found%d = _c%d.found;", n, n));
  lines_push(g_body, strdup("        }"));
  lines_push(g_body, strdup("    }"));
  lines_push(g_body, strdup("}"));
  buf_printf(b, "(_found%d)", n);
}

/* --------: tcp_sock field accessors ----------
 * Production port of the Ruby oracle (codegen_bpf.rb TCP_SOCK_READERS/WRITERS/
 * ADDERS + the `sk.<field>` dot sugar). Valid only inside a
 * struct_ops/tcp_congestion_ops member (SO_TCP_CC), where the kernel hands us a
 * TRUSTED `struct sock *` -- so we DIRECT-DEREF the field (NOT BPF_CORE_READ),
 * mirroring how the kernel TCP stack itself touches these fields. The emitted C
 * matches emit_tcp_sock_read/assign/compound byte-for-byte:
 *   read     : ((__s64)((struct tcp_sock *)(unsigned long)(<sk>))->F)
 *   assign   : ((struct tcp_sock *)(unsigned long)(<sk>))->F = (__u32)(<v>);
 *   compound : ((struct tcp_sock *)(unsigned long)(<sk>))->F += (__u32)(<v>); */
/* tcp_cc context = the method is a tcp_congestion_ops member. Mirror the Ruby
 * oracle's detect_attach(method_name): a NAME-prefix check ("tcp_cc__"), not the
 * class-derived so_kind. This covers BOTH surfaces -- `class X < BPF::TcpCC`
 * (so_kind set, name synthesized to tcp_cc__<member>) and the top-level
 * `def tcp_cc__<member>` form (so_kind unset but the name already carries the
 * prefix, e.g. examples/observability/tcp_cc_reno.rb). */
static int cc_in_tcp_cc(void) {
  return g_method && g_method->name && !strncmp(g_method->name, "tcp_cc__", 8);
}

static const char *cc_tcp_sock_reader_field(const char *name) {   /* tcp_sock_<field>(sk) */
  if (!name) return NULL;
  if (!strcmp(name, "tcp_sock_snd_cwnd"))       return "snd_cwnd";
  if (!strcmp(name, "tcp_sock_snd_ssthresh"))   return "snd_ssthresh";
  if (!strcmp(name, "tcp_sock_snd_nxt"))        return "snd_nxt";
  if (!strcmp(name, "tcp_sock_snd_una"))        return "snd_una";
  if (!strcmp(name, "tcp_sock_packets_out"))    return "packets_out";
  if (!strcmp(name, "tcp_sock_delivered"))      return "delivered";
  if (!strcmp(name, "tcp_sock_snd_cwnd_cnt"))   return "snd_cwnd_cnt";
  if (!strcmp(name, "tcp_sock_snd_cwnd_clamp")) return "snd_cwnd_clamp";
  if (!strcmp(name, "tcp_sock_prior_cwnd"))     return "prior_cwnd";
  return NULL;
}
static const char *cc_tcp_sock_writer_field(const char *name) {   /* tcp_sock_<field>_set(sk, v) */
  if (!name) return NULL;
  if (!strcmp(name, "tcp_sock_snd_cwnd_set"))     return "snd_cwnd";
  if (!strcmp(name, "tcp_sock_snd_ssthresh_set")) return "snd_ssthresh";
  if (!strcmp(name, "tcp_sock_snd_cwnd_cnt_set")) return "snd_cwnd_cnt";
  return NULL;
}
static const char *cc_tcp_sock_adder_field(const char *name) {   /* tcp_sock_<field>_add(sk, d) */
  if (!name) return NULL;
  if (!strcmp(name, "tcp_sock_snd_cwnd_add"))     return "snd_cwnd";
  if (!strcmp(name, "tcp_sock_snd_cwnd_cnt_add")) return "snd_cwnd_cnt";
  return NULL;
}
/* is `name` a bare tcp_sock field (dot form sk.<field>)? == the 9 reader fields. */
static int cc_tcp_sock_is_field(const char *name) {
  if (!name) return 0;
  static const char *const F[] = {
    "snd_cwnd", "snd_ssthresh", "snd_nxt", "snd_una", "packets_out",
    "delivered", "snd_cwnd_cnt", "snd_cwnd_clamp", "prior_cwnd", NULL };
  for (int i = 0; F[i]; i++) if (!strcmp(name, F[i])) return 1;
  return 0;
}
static void cc_emit_tcp_sock_read(Buf *b, const char *field, const char *recv_expr) {
  buf_printf(b, "((__s64)((struct tcp_sock *)(unsigned long)(%s))->%s)", recv_expr, field);
}
/* push the field write/compound side-effect line; c_op is "=", "+=" or "-=". */
static void cc_emit_tcp_sock_write(Lines *body, const char *field, const char *c_op,
                                   const char *recv_expr, const char *val_expr) {
  lines_push(body, msprintf("((struct tcp_sock *)(unsigned long)(%s))->%s %s (__u32)(%s);",
                            recv_expr, field, c_op, val_expr));
}

/* ---------- sock_* accessors -- read a `struct sock *` by name ----------
 *
 * The sibling of tcp_sock_* directly above, and its opposite on BOTH axes:
 *
 *   pointer   tcp_sock_*  gets the TRUSTED sk the struct_ops/tcp_cc hook hands
 *             it, so it direct-derefs.  sock_* takes an UNTRUSTED pointer (a
 *             kprobe argument), so it MUST go through BPF_CORE_READ (D2).
 *             Measured: the direct-deref form does not load at all --
 *             "R1 invalid mem access 'scalar'" (measure/m02_untrusted.txt).
 *
 *   value     tcp_sock_* returns the field as-is; every field it exposes is a
 *             host-order counter.  sock_* spans a struct whose byte order is
 *             MIXED, so each accessor carries its own conversion (D1).
 *
 * On D1, the reason the conversion lives here and not in the caller's Ruby:
 * skc_dport is __be16 but skc_num (the source port) is __u16, so on one
 * connection the raw reads are dport=47903 / sport=60404 and the uniformly
 * byte-swapped reads are 8123 / 62699.  All four are plausible port numbers, so
 * whichever single rule an author picks, one of the two ports is silently wrong
 * (measure/m01_byteorder.txt).  No rule the caller can write is correct for both;
 * only the accessor knows which field it is reading.  Everything below is
 * therefore in HOST order, which is also what every other named accessor in the
 * codebase returns (pkt_l4_sport, pkt_ip4_src, sock_addr_port, ...).
 *
 * IPv6 uses the hi/lo split the packet readers use (128 bits do not fit in __s64), byte-swapped
 * per 32-bit word exactly as pkt_ip6_* does, so ::1 reads back as hi=0 lo=1. */
typedef enum { SK_RAW, SK_NTOHS, SK_NTOHL, SK_V6HI, SK_V6LO } CcSockConv;
typedef struct { const char *name, *field; CcSockConv conv; } CcSockAcc;
static const CcSockAcc CC_SOCK_ACC[] = {
  /* name             field in struct sock              conversion (see D1) */
  {"sock_sport",      "__sk_common.skc_num",           SK_RAW},    /* __u16  ALREADY host order */
  {"sock_dport",      "__sk_common.skc_dport",         SK_NTOHS},  /* __be16 network order */
  {"sock_saddr",      "__sk_common.skc_rcv_saddr",     SK_NTOHL},  /* __be32 network order */
  {"sock_daddr",      "__sk_common.skc_daddr",         SK_NTOHL},  /* __be32 network order */
  {"sock_family",     "__sk_common.skc_family",        SK_RAW},    /* AF_INET / AF_INET6 */
  {"sock_state",      "__sk_common.skc_state",         SK_RAW},    /* TCP_STATE_* */
  {"sock_protocol",   "sk_protocol",                   SK_RAW},    /* IPPROTO_* */
  {"sock_saddr6_hi",  "__sk_common.skc_v6_rcv_saddr",  SK_V6HI},
  {"sock_saddr6_lo",  "__sk_common.skc_v6_rcv_saddr",  SK_V6LO},
  {"sock_daddr6_hi",  "__sk_common.skc_v6_daddr",      SK_V6HI},
  {"sock_daddr6_lo",  "__sk_common.skc_v6_daddr",      SK_V6LO},
  {NULL, NULL, SK_RAW}
};
static const CcSockAcc *cc_sock_acc(const char *name) {
  if (!name) return NULL;
  for (int i = 0; CC_SOCK_ACC[i].name; i++)
    if (!strcmp(CC_SOCK_ACC[i].name, name)) return &CC_SOCK_ACC[i];
  return NULL;
}
/* Append the read for `sock_<field>(<ptr>)`. The IPv6 halves need the pointer
 * twice (one CO-RE read per 32-bit word), so they hoist it into a temp rather
 * than lowering the caller's expression twice. */
static void cc_emit_sock_read(Buf *b, const CcSockAcc *a, const char *ptr_text) {
  if (a->conv == SK_V6HI || a->conv == SK_V6LO) {
    int n = ++g_if_counter;
    int i0 = (a->conv == SK_V6HI) ? 0 : 2;
    lines_push(g_body, msprintf("struct sock *_skp%d = (struct sock *)(unsigned long)(%s);", n, ptr_text));
    buf_printf(b, "((__s64)((((__u64)bpf_ntohl(BPF_CORE_READ(_skp%d, %s.in6_u.u6_addr32[%d]))) << 32)"
                  " | (__u64)bpf_ntohl(BPF_CORE_READ(_skp%d, %s.in6_u.u6_addr32[%d]))))",
               n, a->field, i0, n, a->field, i0 + 1);
    return;
  }
  if (a->conv == SK_NTOHS)
    buf_printf(b, "((__s64)(__u16)bpf_ntohs(BPF_CORE_READ((struct sock *)(unsigned long)(%s), %s)))",
               ptr_text, a->field);
  else if (a->conv == SK_NTOHL)
    buf_printf(b, "((__s64)(__u32)bpf_ntohl(BPF_CORE_READ((struct sock *)(unsigned long)(%s), %s)))",
               ptr_text, a->field);
  else
    buf_printf(b, "((__s64)BPF_CORE_READ((struct sock *)(unsigned long)(%s), %s))",
               ptr_text, a->field);
}

/* ---------- capabilities / namespaces / file type ----------
 *
 * Three Tetragon selectors (matchCapabilities / matchNamespaces / FileType) that
 * `kfield` could already REACH -- cred, nsproxy and i_mode are all ordinary CO-RE
 * chains. What kfield cannot supply is what the value MEANS once you have it,
 * and all three are cases where the raw value cannot be compared correctly:
 *
 *   cap_effective  a 64-bit BIT SET. `caps & CAP_SYS_ADMIN` tests bits 0/2/4 and
 *                  returns the same 21 whether or not the bit is set (m01).
 *   ns inode       a number that means nothing on its own; "is this the host"
 *                  needs a second number from outside the task (m03).
 *   i_mode         type bits packed with permission bits. `== S_IFREG` is false
 *                  for every regular file; `& S_IFDIR` is TRUE for a socket (m04).
 *
 * So the surface is predicates where the comparison is the trap, plus values
 * where correlation is the point -- each carrying its meaning in VALUE_SEMANTICS
 * (the same rule the sock_* accessors follow).
 *
 * The gate splits the seven 2:1 and not along the "is it new" line: the six that
 * read bpf_get_current_task() are refused outside process context, and
 * file_type, which reads a pointer the hook hands it, is ungated exactly like
 * kfield. See cc_require_task_ctx. */

/* ns_id(:key) / in_host_ns(:key). `host` is the member of `struct nsproxy` that
 * holds the initial namespace; NULL where the answer is not in nsproxy. */
typedef struct { const char *key, *chain, *host; } CcNsKey;
static const CcNsKey CC_NS_KEYS[] = {
  {"mnt",    "nsproxy, mnt_ns, ns.inum",     "mnt_ns"},
  {"net",    "nsproxy, net_ns, ns.inum",     "net_ns"},
  {"uts",    "nsproxy, uts_ns, ns.inum",     "uts_ns"},
  {"ipc",    "nsproxy, ipc_ns, ns.inum",     "ipc_ns"},
  {"cgroup", "nsproxy, cgroup_ns, ns.inum",  "cgroup_ns"},
  {"time",   "nsproxy, time_ns, ns.inum",    "time_ns"},
  /* user namespaces hang off cred, not nsproxy, so both halves are special */
  {"user",   "cred, user_ns, ns.inum",       NULL},
  /* pid is special the other way: nsproxy has only pid_ns_for_children, which is
   * a DIFFERENT namespace for a task that unshared without forking (m02 run D).
   * NULL chain -> spnl_pid_ns_inum(). For the INITIAL task the two coincide, so
   * the host side can use init_nsproxy's member. */
  {"pid",    NULL,                           "pid_ns_for_children"},
  {NULL, NULL, NULL}
};
static const CcNsKey *cc_ns_key(const char *k) {
  if (!k) return NULL;
  for (int i = 0; CC_NS_KEYS[i].key; i++) if (!strcmp(CC_NS_KEYS[i].key, k)) return &CC_NS_KEYS[i];
  return NULL;
}
static char *cc_ns_keys_str(void) {
  Buf b = {0};
  for (int i = 0; CC_NS_KEYS[i].key; i++) buf_printf(&b, "%s%s", i ? " " : "", CC_NS_KEYS[i].key);
  return b.p;
}

/* has_cap family -> the `struct cred` member each one reads. */
static const char *cc_cap_set(const char *name) {
  if (!strcmp(name, "has_cap"))             return "cap_effective";
  if (!strcmp(name, "has_cap_permitted"))   return "cap_permitted";
  if (!strcmp(name, "has_cap_inheritable")) return "cap_inheritable";
  return NULL;
}

/* Is the enclosing handler one where "the current task" is the task that caused
 * the event? Measured for the two ends of the range (m05): a kprobe reports the
 * caller, an XDP program reports whatever was on the CPU. In between, the
 * classification is by where the kernel invokes the program type, and the
 * refusal is the conservative direction -- the bpf_d_path gate set the precedent that a gate is
 * widened by measurement, not by argument.
 *
 * cgroup/connect4 and cgroup/bind4 are the one exception inside AK_SK_VERDICT,
 * which lumps eight SECs under one kind. They run on the connect(2)/bind(2)
 * syscall path, and m05 measured connect4 reporting the connecting process, so
 * they are allowed BY SEC rather than by kind. */
static int cc_task_ctx_kind_ok(AttachKind k, const char *kname) {
  switch (k) {
    case AK_KPROBE: case AK_KRETPROBE: case AK_TRACEPOINT: case AK_RAW_TP:
    case AK_FENTRY: case AK_FEXIT: case AK_UPROBE: case AK_URETPROBE:
    case AK_USDT:   case AK_PERF_EVENT: case AK_LSM: case AK_FMOD_RET:
    case AK_KPROBE_MULTI:   /* same kernel-function entry context as AK_KPROBE */
      return 1;
    case AK_SK_VERDICT:
      return kname && (!strcmp(kname, "cgroup_connect4") || !strcmp(kname, "cgroup_bind4"));
    default:
      return 0;
  }
}

/* Refuse `who` outside a hook where the current task is the actor.
 *
 * The failure this prevents is silent in the strongest sense: m05 measured an
 * XDP program answering has_cap(CAP::SYS_ADMIN) with TRUE about a CPU burner
 * while the actual actor's answer was FALSE. Not an error, not a zero -- a real
 * capability set belonging to the wrong task, indistinguishable downstream from
 * a correct one. That is the difference from kfield/kfield_str, which are
 * ungated because they read a pointer the caller supplies. */
static void cc_require_task_ctx(const char *who) {
  Attach a = {0};
  AttachKind k = g_method ? cc_detect_attach(g_method->name, &a) : AK_NONE;
  int ok = cc_task_ctx_kind_ok(k, a.kname);
  if (!ok) {
    char *msg = msprintf(
      "%s reads the CURRENT TASK, and `%s` is not a hook where the current task is "
      "the one that caused the event. In a packet or socket program it is whichever "
      "task the interrupt landed on, so the answer is about the wrong process and "
      "nothing says so (measured: the same call in XDP reported a CPU burner's "
      "capabilities as the packet's). Write it in a process-context handler: "
      "kprobe kretprobe tracepoint raw_tp fentry fexit uprobe uretprobe usdt kprobe_multi "
      "perf_event lsm fmod_ret cgroup__connect4 cgroup__bind4. To read a task "
      "OTHER than the current one, use kfield(<task ptr>, \"task_struct\", ...)",
      who, g_method && g_method->name ? g_method->name : "<no attach handler>");
    die(msg, a.sec ? a.sec : (g_method && g_method->name ? g_method->name : "?"));
  }
  if (a.sec) free(a.sec);
}

/* The one argument of ns_id/in_host_ns: a symbol literal, resolved at compile
 * time (the key picks a C field name, so it cannot be computed). */
static const CcNsKey *cc_ns_arg(AST *ast, int nid, const char *who) {
  int aid = nt_ref(ast, nid, "arguments");
  int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
  char *keys = cc_ns_keys_str();
  if (na != 1 || !ids) {
    char *m = msprintf("%s expects exactly one namespace key, e.g. %s(:mnt). Accepted keys: %s", who, who, keys);
    die(m, NULL);
  }
  const char *at = nt_type(ast, ids[0]);
  if (!at || strcmp(at, "SymbolNode")) {
    char *m = msprintf("%s: the namespace key must be a symbol literal, e.g. %s(:mnt) -- it "
                       "selects a kernel field at compile time, so it cannot be a variable. "
                       "Accepted keys: %s", who, who, keys);
    die(m, NULL);
  }
  const char *k = nt_str(ast, ids[0], "value");
  const CcNsKey *nk = cc_ns_key(k);
  if (!nk) {
    char *m = msprintf("%s: accepted keys are %s. Unknown key", who, keys);
    die(m, k ? k : "?");
  }
  free(keys);
  return nk;
}

/* lower an expression node -> append its C text to `b`. Stage-1 subset. */
static void cc_lower_expr(AST *ast, int nid, Buf *b) {
  const char *ty = nt_type(ast, nid);
  if (!ty) die("missing node", NULL);
  if (!strcmp(ty, "LocalVariableReadNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (!nm) die("LocalVariableReadNode missing name", NULL);
    char *s = cc_safe_dup(nm);   /* C-keyword sanitize */
    if (cc_is_capture(s)) buf_printf(b, "(*_lc->%s)", s);   /* captured outer local */
    else buf_puts(b, s);
    free(s);
    return;
  }
  if (!strcmp(ty, "IntegerNode")) {
    buf_printf(b, "%lld", nt_int(ast, nid, "value", 0));
    return;
  }
  if (!strcmp(ty, "OrNode") || !strcmp(ty, "AndNode")) {   /* a || b / a && b (CAst) */
    ce_print(cc_build_expr(ast, nid), b);
    return;
  }
  if (!strcmp(ty, "ParenthesesNode")) {   /* (expr) */
    int body = nt_ref(ast, nid, "body");
    if (body < 0) { buf_puts(b, "0"); return; }
    buf_puts(b, "(");
    cc_lower_expr(ast, body, b);
    buf_puts(b, ")");
    return;
  }
  if (!strcmp(ty, "StatementsNode")) {   /* expr-position (e.g. ParenthesesNode body) -> last value */
    char *v = cc_lower_stmt(ast, nid, g_body);
    buf_puts(b, v ? v : "0");
    free(v);
    return;
  }
  if (!strcmp(ty, "ConstantReadNode")) {   /* XDP_PASS etc. -> literal int */
    const char *nm = nt_str(ast, nid, "name");
    long long v = 0;
    if (!nm || !cc_known_const(nm, &v)) die("constant not lowerable (Stage 1 KNOWN_CONSTANTS)", nm ? nm : "?");
    buf_printf(b, "%lld", v);
    return;
  }
  if (!strcmp(ty, "ConstantPathNode")) {   /* SCX::DSQ::GLOBAL -> C macro verbatim */
    char path[128]; path[0] = '\0';        /* walk parent chain, build "A::B::C" */
    int cur = nid;
    const char *parts[8]; int np = 0;
    for (int guard = 0; guard < 8 && cur >= 0; guard++) {
      const char *ct = nt_type(ast, cur);
      const char *nm = nt_str(ast, cur, "name");
      if (!ct || !nm) break;
      if (!strcmp(ct, "ConstantPathNode")) { parts[np++] = nm; cur = nt_ref(ast, cur, "parent"); }
      else if (!strcmp(ct, "ConstantReadNode")) { parts[np++] = nm; cur = -1; }
      else break;
    }
    for (int i = np - 1; i >= 0; i--) { strcat(path, parts[i]); if (i) strcat(path, "::"); }   /* root-first */
    const char *macro = cc_macro_path(path);
    if (macro) { buf_puts(b, macro); return; }   /* u64 macro verbatim */
    long long pv = 0;
    if (cc_const_path_value(path, &pv)) { buf_printf(b, "%lld", pv); return; }   /* -> integer */
    die("ConstantPathNode not lowerable (Stage 1)", path);
  }
  if (!strcmp(ty, "InstanceVariableReadNode")) {   /* @x -> map lookup, default 0 */
    const char *iv = nt_str(ast, nid, "name");
    if (!iv) die("InstanceVariableReadNode missing name", NULL);
    char *map = cc_ivar_map(iv);
    char *rd = cc_emit_ivar_read(g_body, map);   /* k+lookup prelude -> "(_pN ? *_pN : 0)" */
    buf_puts(b, rd);
    free(rd); free(map);
    return;
  }
  if (!strcmp(ty, "CallNode")) {
    const char *name = nt_str(ast, nid, "name");
    if (name && cc_is_binary_op(name)) {   /* `lhs op rhs` via CAst (precedence-driven parens) */
      ce_print(cc_build_expr(ast, nid), b);
      return;
    }
    /* `t.field` where t was bound via kptr(ptr, "struct") -> BPF_CORE_READ. */
    {
      int recv = nt_ref(ast, nid, "receiver");
      if (name && recv >= 0) {
        const char *rt = nt_type(ast, recv);
        if (rt && !strcmp(rt, "LocalVariableReadNode")) {
          const char *rnm = nt_str(ast, recv, "name");
          char *rs = rnm ? cc_safe_dup(rnm) : NULL;
          const char *strct = rs ? cc_kptr_struct(rs) : NULL;
          if (strct) {
            int args_id = nt_ref(ast, nid, "arguments");
            int na = 0; if (args_id >= 0) nt_arr(ast, args_id, "arguments", &na);
            if (na != 0) die("kptr field read takes no args (Stage 1)", name);
            char *fields[1] = { (char *)name };
            ce_print(cc_core_read(strct, cc_expr_str(ast, recv), fields, 1), b);
            free(rs);
            return;
          }
          free(rs);
        }
        /* sk.<field> dot-read sugar (tcp_cc context) -> direct deref of the
         * trusted struct_ops `sk`. Arrives as a CallNode: receiver=sk, name=<field>,
         * no args. Mirrors codegen_bpf.rb try_tcp_sock_dot_call (reader branch). */
        if (cc_in_tcp_cc() && cc_tcp_sock_is_field(name)) {
          int args_id = nt_ref(ast, nid, "arguments");
          int na = 0; if (args_id >= 0) nt_arr(ast, args_id, "arguments", &na);
          if (na != 0) die("sk.<field> reader takes no args (Stage 1)", name);
          char *rexpr = cc_expr_str(ast, recv);
          cc_emit_tcp_sock_read(b, name, rexpr);
          free(rexpr);
          return;
        }
      }
    }
    if (name && !strcmp(name, "kfield")) {   /* kfield(ptr, "struct", "field"...) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na < 3) die("kfield expects (ptr, \"struct\", \"field\"...)", NULL);
      char *ptr = cc_expr_str(ast, ids[0]);
      const char *strct = nt_str(ast, ids[1], "content");
      if (!strct) die("kfield struct name must be a string literal", NULL);
      int nf = na - 2;
      char **fields = malloc(sizeof(char *) * (nf > 0 ? nf : 1));
      for (int k = 2; k < na; k++) {
        const char *fld = nt_str(ast, ids[k], "content");
        if (!fld) die("kfield field name must be a string literal", NULL);
        fields[k - 2] = (char *)fld;
      }
      ce_print(cc_core_read(strct, ptr, fields, nf), b);
      free(fields);
      return;
    }
    /* sock_<field>(sk) -- the named vocabulary over `struct sock *`, on top
     * of the same CO-RE read kfield does. kfield can already reach these fields
     * (it is what reads skc_dport today); what it cannot do is know that skc_dport
     * needs a byte swap and skc_num does not. That knowledge is what the name
     * buys, so these are flat calls taking the pointer, NOT a `sk.dport` dot
     * form: `sk.<field>` is already spoken for by the receiver-dot accessor, whose
     * gate is a method name prefix plus a fixed field table and never looks at the
     * receiver at all. See the table above for the per-field conversions. */
    if (name) {
      const CcSockAcc *acc = cc_sock_acc(name);
      if (acc) {
        int args_id = nt_ref(ast, nid, "arguments");
        int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
        if (na != 1)
          die("sock_* accessors expect exactly one argument: the struct sock * to read "
              "(e.g. sock_dport(sk) inside def kprobe__tcp_sendmsg(sk))", name);
        char *ptr = cc_expr_str(ast, ids[0]);
        cc_emit_sock_read(b, acc, ptr);
        free(ptr);
        return;
      }
    }
    /* kfield_str_eq(ptr, "struct", "field"..., "literal") -- does a kernel
     * struct's STRING field equal a compile-time literal? The expression form (it
     * drives `if`), sibling of kfield (scalar) and of path_eq (full path via
     * bpf_d_path). Different axis from path_eq: this compares a structural
     * field, so it reaches strings bpf_d_path cannot produce at all -- a kprobe can
     * never call bpf_d_path but can read file->f_path.dentry->d_name.name.
     *
     * No hook gate: bpf_probe_read_kernel_str was measured LOAD_OK in all 24
     * program types the codegen emits, exactly matching the bpf_probe_read_kernel
     * that ungated kfield already uses. */
    if (name && !strcmp(name, "kfield_str_eq")) {
      char *ptr = NULL; const char *strct = NULL, *lit = NULL;
      char **fields = NULL; int nf = 0;
      cc_kstr_args(ast, nid, 1, &ptr, &strct, &fields, &nf, &lit);
      size_t len = strlen(lit);
      if (len == 0) die("kfield_str_eq: empty literal", NULL);
      /* literal + NUL + one spare byte so truncation is observable (see
       * cc_emit_kfield_str_eq), rounded to 8 for stack alignment. */
      size_t sz = ((len + 2 + 7) / 8) * 8;
      if (sz > CC_PATH_EQ_MAX)
        die("kfield_str_eq: literal too long for the BPF stack (the wall was measured)", lit);
      int n = ++g_if_counter;
      char *bufname = msprintf("_ksb%d", n);
      lines_push(g_body, msprintf("char %s[%zu] = {0};", bufname, sz));
      char *rc = cc_emit_kfield_str_read(g_body, "", bufname, "kfield_str_eq", ptr, strct,
                                         fields, nf, lit,
                                         " Note: the LAST string argument is the literal to "
                                         "compare, not a field; a missing literal leaves the "
                                         "chain one hop short.");
      cc_emit_kfield_str_eq(b, rc, n, bufname, lit, len);
      free(rc); free(bufname); free(fields); free(ptr);
      return;
    }
    if (name && !strcmp(name, "flow_get")) {   /* conntrack field read */
      int aid = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
      if (na != 2) die("flow_get(:name, :field) expects 2 args", NULL);
      const char *mn = nt_str(ast, ids[0], "value"), *fld = nt_str(ast, ids[1], "value");
      if (!mn || !fld) die("flow_get needs symbol args", NULL);
      char *r = cc_emit_flow_get(g_body, mn, fld);
      buf_puts(b, r);
      free(r);
      return;
    }
    if (name && !strcmp(name, "arena_set")) {   /* flat arena slot write */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("arena_set expects 2 args (index, value)", NULL);
      char *idx = cc_expr_str(ast, ids[0]), *val = cc_expr_str(ast, ids[1]);
      buf_printf(b, "({ %s_arena_data[(__u64)(%s) & 511] = (__u64)(%s); (__s64)0; })", g_unit, idx, val);
      free(idx); free(val);
      return;
    }
    if (name && !strcmp(name, "arena_get")) {   /* flat arena slot read */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("arena_get expects 1 arg (index)", NULL);
      char *arr = msprintf("%s_arena_data", g_unit);
      CExpr *index = ce_binop("&", ce_cast("__u64", ce_paren(ce_raw(cc_expr_str(ast, ids[0])))), ce_raw(strdup("511")));
      ce_print(ce_paren(ce_cast("__s64", ce_subscript(ce_raw(arr), index))), b);
      return;
    }
    if (name && (!strcmp(name, "arena_hash_set") || !strcmp(name, "arena_hash_get") || !strcmp(name, "arena_hash_del"))) {
      int args_id = nt_ref(ast, nid, "arguments");   /* open-addressing hash in the arena */
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      int want = !strcmp(name, "arena_hash_set") ? 2 : 1;
      if (na != want) die("arena_hash_* arity", name);
      char *key = cc_expr_str(ast, ids[0]);
      const char *d = g_unit; int n = ++g_if_counter;
      if (!strcmp(name, "arena_hash_set")) {
        char *val = cc_expr_str(ast, ids[1]);
        buf_printf(b, "({\n    __u64 _hk%d = (__u64)(%s); __u64 _hv%d = (__u64)(%s); __s64 _hok%d = 0;\n", n, key, n, val, n);
        buf_printf(b, "    __u32 _hh%d = ((__u32)_hk%d * 2654435761U) & 255U;\n    #pragma unroll\n", n, n);
        buf_printf(b, "    for (int _hi%d = 0; _hi%d < 8; _hi%d++) {\n", n, n, n);
        buf_printf(b, "        __u32 _hs%d = (_hh%d + (__u32)_hi%d) & 255U;\n", n, n, n);
        buf_printf(b, "        __u64 _hek%d = %s_arena_data[2U * _hs%d];\n", n, d, n);
        buf_printf(b, "        if (!_hok%d && (_hek%d == 0 || _hek%d == _hk%d)) {\n", n, n, n, n);
        buf_printf(b, "            %s_arena_data[2U * _hs%d] = _hk%d; %s_arena_data[2U * _hs%d + 1] = _hv%d; _hok%d = 1;\n", d, n, n, d, n, n, n);
        buf_printf(b, "        }\n    }\n    _hok%d;\n})", n);
        free(val);
      } else if (!strcmp(name, "arena_hash_get")) {
        buf_printf(b, "({\n    __u64 _hk%d = (__u64)(%s); __s64 _hr%d = 0; __s64 _hf%d = 0;\n", n, key, n, n);
        buf_printf(b, "    __u32 _hh%d = ((__u32)_hk%d * 2654435761U) & 255U;\n    #pragma unroll\n", n, n);
        buf_printf(b, "    for (int _hi%d = 0; _hi%d < 8; _hi%d++) {\n", n, n, n);
        buf_printf(b, "        __u32 _hs%d = (_hh%d + (__u32)_hi%d) & 255U;\n", n, n, n);
        buf_printf(b, "        __u64 _hek%d = %s_arena_data[2U * _hs%d];\n", n, d, n);
        buf_printf(b, "        if (!_hf%d && _hek%d == _hk%d) { _hr%d = (__s64)%s_arena_data[2U * _hs%d + 1]; _hf%d = 1; }\n", n, n, n, n, d, n, n);
        buf_printf(b, "    }\n    _hr%d;\n})", n);
      } else {   /* arena_hash_del */
        buf_printf(b, "({\n    __u64 _hk%d = (__u64)(%s); __s64 _hd%d = 0;\n", n, key, n);
        buf_printf(b, "    __u32 _hh%d = ((__u32)_hk%d * 2654435761U) & 255U;\n    #pragma unroll\n", n, n);
        buf_printf(b, "    for (int _hi%d = 0; _hi%d < 8; _hi%d++) {\n", n, n, n);
        buf_printf(b, "        __u32 _hs%d = (_hh%d + (__u32)_hi%d) & 255U;\n", n, n, n);
        buf_printf(b, "        __u64 _hek%d = %s_arena_data[2U * _hs%d];\n", n, d, n);
        buf_printf(b, "        if (!_hd%d && _hek%d == _hk%d) { %s_arena_data[2U * _hs%d] = ~0ULL; %s_arena_data[2U * _hs%d + 1] = 0; _hd%d = 1; }\n", n, n, n, d, n, d, n, n);
        buf_printf(b, "    }\n    _hd%d;\n})", n);
      }
      free(key);
      return;
    }
    if (name && !strcmp(name, "arena_list_push")) {   /* singly-linked list in the arena */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("arena_list_push expects 1 arg (value)", NULL);
      char *val = cc_expr_str(ast, ids[0]);
      const char *d = g_unit; int n = ++g_if_counter;
      buf_printf(b, "({\n    __u64 _lv%d = (__u64)(%s);\n", n, val);
      buf_printf(b, "    __u64 _li%d = %s_arena_data[1];          /* bump pointer */\n", n, d);
      buf_printf(b, "    if (_li%d == 0) _li%d = 1;       /* node indices start at 1 */\n", n, n);
      buf_printf(b, "    __s64 _lok%d = 0;\n    if (_li%d < 256) {\n", n, n);
      buf_printf(b, "        %s_arena_data[(2U * _li%d) & 511] = _lv%d;\n", d, n, n);
      buf_printf(b, "        %s_arena_data[(2U * _li%d + 1) & 511] = %s_arena_data[0]; /* next = head */\n", d, n, d);
      buf_printf(b, "        %s_arena_data[0] = _li%d;            /* head = new node */\n", d, n);
      buf_printf(b, "        %s_arena_data[1] = _li%d + 1;        /* bump++ */\n", d, n);
      buf_printf(b, "        _lok%d = 1;\n    }\n    _lok%d;\n})", n, n);
      free(val);
      return;
    }
    if (name && !strcmp(name, "arena_list_sum")) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; if (args_id >= 0) nt_arr(ast, args_id, "arguments", &na);
      if (na != 0) die("arena_list_sum expects 0 args", NULL);
      const char *d = g_unit; int n = ++g_if_counter;
      buf_printf(b, "({\n    __u64 _ls%d = 0, _lc%d = %s_arena_data[0];   /* head */\n    #pragma unroll\n", n, n, d);
      buf_printf(b, "    for (int _lj%d = 0; _lj%d < 16; _lj%d++) {\n", n, n, n);
      buf_printf(b, "        if (_lc%d != 0 && _lc%d < 256) {\n", n, n);
      buf_printf(b, "            _ls%d += %s_arena_data[(2U * _lc%d) & 511];\n", n, d, n);
      buf_printf(b, "            _lc%d = %s_arena_data[(2U * _lc%d + 1) & 511];\n", n, d, n);
      buf_printf(b, "        }\n    }\n    (__s64)_ls%d;\n})", n);
      return;
    }
    if (name && !strcmp(name, "redirect")) {   /* bpf_redirect(ifindex) */
      cc_require_pkt_ctx("redirect", CC_CTX_PKT,
                         "bpf_redirect forwards the packet the program was called on, and it "
                         "returns the verdict (XDP_REDIRECT / TC_ACT_REDIRECT) the handler must return");
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("redirect expects 1 arg (ifindex)", NULL);
      char *oif = cc_expr_str(ast, ids[0]);
      buf_printf(b, "(__s64)bpf_redirect((__u32)(%s), 0)", oif);
      free(oif);
      return;
    }
    if (name && (!strcmp(name, "sk_lookup_tcp") || !strcmp(name, "sk_assign_tcp"))) {
      /* sk_lookup_tcp reads the netns off `ctx` (xdp/tc); sk_assign_tcp
       * steers the skb being received, which only exists on ingress. */
      if (!strcmp(name, "sk_assign_tcp"))
        cc_require_pkt_ctx("sk_assign_tcp", CC_CTX_TC_INGRESS,
                           "bpf_sk_assign steers the skb currently being RECEIVED to a socket, "
                           "so there is nothing to steer on egress or in XDP");
      else
        cc_require_pkt_ctx("sk_lookup_tcp", CC_CTX_PKT,
                           "bpf_sk_lookup_tcp takes the packet ctx to pick the network namespace");
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 4) die("sk_lookup_tcp/sk_assign_tcp expects 4 args (saddr, daddr, sport, dport)", name);
      char *sa = cc_expr_str(ast, ids[0]), *da = cc_expr_str(ast, ids[1]);
      char *sp = cc_expr_str(ast, ids[2]), *dp = cc_expr_str(ast, ids[3]);
      int assign = !strcmp(name, "sk_assign_tcp");
      const char *tup = assign ? "_spnl_aktup" : "_spnl_sktup";
      const char *skv = assign ? "_spnl_ask" : "_spnl_sk";
      const char *rv  = assign ? "_spnl_akr" : "_spnl_skr";
      int n = ++g_if_counter;
      buf_printf(b, "({\n    struct bpf_sock_tuple %s_%d = {};\n", tup, n);
      buf_printf(b, "    %s_%d.ipv4.saddr = bpf_htonl((__u32)(%s));\n", tup, n, sa);
      buf_printf(b, "    %s_%d.ipv4.daddr = bpf_htonl((__u32)(%s));\n", tup, n, da);
      buf_printf(b, "    %s_%d.ipv4.sport = bpf_htons((__u16)(%s));\n", tup, n, sp);
      buf_printf(b, "    %s_%d.ipv4.dport = bpf_htons((__u16)(%s));\n", tup, n, dp);
      buf_printf(b, "    struct bpf_sock *%s_%d = bpf_sk_lookup_tcp(ctx, &%s_%d, sizeof(%s_%d.ipv4), -1, 0);\n", skv, n, tup, n, tup, n);
      buf_printf(b, "    __s64 %s_%d = -1;\n", rv, n);
      if (assign)
        buf_printf(b, "    if (%s_%d) { %s_%d = (__s64)bpf_sk_assign(ctx, %s_%d, 0); bpf_sk_release(%s_%d); }\n", skv, n, rv, n, skv, n, skv, n);
      else
        buf_printf(b, "    if (%s_%d) { %s_%d = (__s64)%s_%d->state; bpf_sk_release(%s_%d); }\n", skv, n, rv, n, skv, n, skv, n);
      buf_printf(b, "    %s_%d;\n})", rv, n);
      free(sa); free(da); free(sp); free(dp);
      return;
    }
    if (name && !strcmp(name, "fib_lookup")) {   /* IPv4 route lookup -> ({...}) stmt-expr */
      cc_require_pkt_ctx("fib_lookup", CC_CTX_PKT,
                         "bpf_fib_lookup takes the packet ctx to pick the routing table");
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("fib_lookup expects 1 arg (ipv4 dst)", NULL);
      char *dst = cc_expr_str(ast, ids[0]);
      int n = ++g_if_counter;
      buf_printf(b, "({\n");
      buf_printf(b, "    struct bpf_fib_lookup _spnl_fib_%d = {};\n", n);
      buf_printf(b, "    _spnl_fib_%d.family = 2; /* AF_INET */\n", n);
      buf_printf(b, "    _spnl_fib_%d.ipv4_dst = bpf_htonl((__u32)(%s));\n", n, dst);
      buf_printf(b, "    __s64 _spnl_fibret_%d = bpf_fib_lookup(ctx, &_spnl_fib_%d, sizeof(_spnl_fib_%d), 0);\n", n, n, n);
      buf_printf(b, "    (__s64)(_spnl_fibret_%d == 0 ? _spnl_fib_%d.ifindex : (__s64)-1);\n", n, n);
      buf_puts(b, "})");
      free(dst);
      return;
    }
    if (name && !strcmp(name, "fib_lookup6")) {   /* IPv6 route lookup */
      cc_require_pkt_ctx("fib_lookup6", CC_CTX_PKT,
                         "bpf_fib_lookup takes the packet ctx to pick the routing table");
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("fib_lookup6 expects 2 args (dst_hi, dst_lo)", NULL);
      char *hi = cc_expr_str(ast, ids[0]), *lo = cc_expr_str(ast, ids[1]);
      int n = ++g_if_counter;
      buf_printf(b, "({\n");
      buf_printf(b, "    struct bpf_fib_lookup _spnl_fib6_%d = {};\n", n);
      buf_printf(b, "    _spnl_fib6_%d.family = 10; /* AF_INET6 */\n", n);
      buf_printf(b, "    _spnl_fib6_%d.ipv6_dst[0] = bpf_htonl((__u32)((__u64)(%s) >> 32));\n", n, hi);
      buf_printf(b, "    _spnl_fib6_%d.ipv6_dst[1] = bpf_htonl((__u32)(%s));\n", n, hi);
      buf_printf(b, "    _spnl_fib6_%d.ipv6_dst[2] = bpf_htonl((__u32)((__u64)(%s) >> 32));\n", n, lo);
      buf_printf(b, "    _spnl_fib6_%d.ipv6_dst[3] = bpf_htonl((__u32)(%s));\n", n, lo);
      buf_printf(b, "    __s64 _spnl_fib6ret_%d = bpf_fib_lookup(ctx, &_spnl_fib6_%d, sizeof(_spnl_fib6_%d), 0);\n", n, n, n);
      buf_printf(b, "    (__s64)(_spnl_fib6ret_%d == 0 ? _spnl_fib6_%d.ifindex : (__s64)-1);\n", n, n);
      buf_puts(b, "})");
      free(hi); free(lo);
      return;
    }
    /* skb packet read/write + checksum fixups (TC). All single-line ({...}). */
    if (name && (!strcmp(name, "skb_load_byte") || !strcmp(name, "skb_load_u16") || !strcmp(name, "skb_load_u32"))) {
      cc_require_pkt_ctx(name, CC_CTX_TC, CC_SKB_WHY);
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("skb_load_* expects 1 arg (offset)", name);
      char *off = cc_expr_str(ast, ids[0]);
      int n = ++g_if_counter;
      if (!strcmp(name, "skb_load_byte"))
        buf_printf(b, "({ __u8 _spnl_lb_%d = 0; __s64 _r%d = bpf_skb_load_bytes(ctx, (%s), &_spnl_lb_%d, 1); (__s64)(_r%d < 0 ? (__s64)-1 : (__s64)_spnl_lb_%d); })", n, n, off, n, n, n);
      else if (!strcmp(name, "skb_load_u16"))
        buf_printf(b, "({ __u16 _spnl_l2r_%d = 0; __s64 _r%d = bpf_skb_load_bytes(ctx, (%s), &_spnl_l2r_%d, 2); (__s64)(_r%d < 0 ? (__s64)-1 : (__s64)(__u16)bpf_ntohs(_spnl_l2r_%d)); })", n, n, off, n, n, n);
      else
        buf_printf(b, "({ __u32 _spnl_l4r_%d = 0; __s64 _r%d = bpf_skb_load_bytes(ctx, (%s), &_spnl_l4r_%d, 4); (__s64)(_r%d < 0 ? (__s64)-1 : (__s64)(__u32)bpf_ntohl(_spnl_l4r_%d)); })", n, n, off, n, n, n);
      free(off);
      return;
    }
    if (name && (!strcmp(name, "skb_store_byte") || !strcmp(name, "skb_store_u16") || !strcmp(name, "skb_store_u32"))) {
      cc_require_pkt_ctx(name, CC_CTX_TC, CC_SKB_WHY);
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("skb_store_* expects 2 args (offset, value)", name);
      char *off = cc_expr_str(ast, ids[0]), *val = cc_expr_str(ast, ids[1]);
      int n = ++g_if_counter;
      if (!strcmp(name, "skb_store_byte"))
        buf_printf(b, "({ __u8 _spnl_sb_%d = (__u8)(%s); (__s64)bpf_skb_store_bytes(ctx, (%s), &_spnl_sb_%d, 1, 0); })", n, val, off, n);
      else if (!strcmp(name, "skb_store_u16"))
        buf_printf(b, "({ __u16 _spnl_s2_%d = bpf_htons((__u16)(%s)); (__s64)bpf_skb_store_bytes(ctx, (%s), &_spnl_s2_%d, 2, 0); })", n, val, off, n);
      else
        buf_printf(b, "({ __u32 _spnl_su_%d = bpf_htonl((__u32)(%s)); (__s64)bpf_skb_store_bytes(ctx, (%s), &_spnl_su_%d, 4, 0); })", n, val, off, n);
      free(off); free(val);
      return;
    }
    if (name && (!strcmp(name, "l3_csum_replace") || !strcmp(name, "l4_csum_replace") ||
                 !strcmp(name, "l3_csum_replace_ip") || !strcmp(name, "l4_csum_replace_ip"))) {
      cc_require_pkt_ctx(name, CC_CTX_TC, CC_SKB_WHY);
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 3) die("*_csum_replace expects 3 args (offset, from, to)", name);
      char *off = cc_expr_str(ast, ids[0]), *from = cc_expr_str(ast, ids[1]), *to = cc_expr_str(ast, ids[2]);
      int l3 = (name[1] == '3');
      int ip = (strstr(name, "_ip") != NULL);
      const char *fn = l3 ? "bpf_l3_csum_replace" : "bpf_l4_csum_replace";
      if (ip) {
        const char *flags = l3 ? "4" : "((1 << 4) | 4)";
        buf_printf(b, "(__s64)%s(ctx, (%s), bpf_htonl((__u32)(%s)), bpf_htonl((__u32)(%s)), %s)", fn, off, from, to, flags);
      } else {
        buf_printf(b, "(__s64)%s(ctx, (%s), bpf_htons((__u16)(%s)), bpf_htons((__u16)(%s)), 2)", fn, off, from, to);
      }
      free(off); free(from); free(to);
      return;
    }
    if (name && !strcmp(name, "l4_offset")) {   /* 14 + IHL*4 */
      cc_require_pkt_ctx("l4_offset", CC_CTX_TC, CC_SKB_WHY);   /* reads IHL via bpf_skb_load_bytes */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; if (args_id >= 0) nt_arr(ast, args_id, "arguments", &na);
      if (na != 0) die("l4_offset expects 0 args", NULL);
      int n = ++g_if_counter;
      buf_printf(b, "({ __u8 _spnl_lo%d = 0; bpf_skb_load_bytes(ctx, 14, &_spnl_lo%d, 1); (__s64)(14 + (_spnl_lo%d & 0x0f) * 4); })", n, n, n);
      return;
    }
    if (name && !strcmp(name, "field_exists")) {   /* CO-RE field existence -> 0/1 */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 3) die("field_exists expects (ptr, \"struct\", \"field\")", NULL);
      char *ptr = cc_expr_str(ast, ids[0]);
      const char *strct = nt_str(ast, ids[1], "content");
      const char *fld = nt_str(ast, ids[2], "content");
      if (!strct || !fld) die("field_exists struct/field must be string literals", NULL);
      buf_printf(b, "((__s64)bpf_core_field_exists(((struct %s *)(unsigned long)(%s))->%s))", strct, ptr, fld);
      free(ptr);
      return;
    }
    if (name && !strcmp(name, "kptr")) {   /* kptr(ptr, "struct") -> ((__s64)(ptr)) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("kptr expects (ptr, \"struct\")", NULL);
      char *ptr = cc_expr_str(ast, ids[0]);
      buf_printf(b, "((__s64)(%s))", ptr);
      free(ptr);
      return;
    }
    if (cc_is_ebpf_method(name)) {   /* BPF-to-BPF call -> <name>_inner(args) */
      int args_id = nt_ref(ast, nid, "arguments");
      buf_printf(b, "%s_inner(", name);
      if (args_id >= 0) {
        int na; const int *ids = nt_arr(ast, args_id, "arguments", &na);
        for (int k = 0; k < na; k++) { if (k) buf_puts(b, ", "); cc_lower_expr(ast, ids[k], b); }
      }
      buf_puts(b, ")");
      return;
    }
    if (name && (!strcmp(name, "blocklist_match") || !strcmp(name, "cidr_blocklist_match"))) {
      /* exact-HASH / LPM-TRIE blocklist lookup. -> spnl_<name>(<ip>). */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("blocklist_match expects 1 arg (ip)", name);
      buf_printf(b, "spnl_%s(", name);
      cc_lower_expr(ast, ids[0], b);
      buf_puts(b, ")");
      return;
    }
    /* zero-arg kernel-context builtins (s64(...) wraps the cast in a paren). */
    if (name && !strcmp(name, "ktime_ns"))     { buf_puts(b, g_amp ? "((__s64)amp_ktime())" : "((__s64)bpf_ktime_get_ns())"); return; }   /* amp -> PHC helper (id 2) */
    if (name && (!strcmp(name, "pid") || !strcmp(name, "tgid")))
      { buf_puts(b, "((__s64)(bpf_get_current_pid_tgid() >> 32))"); return; }
    if (name && !strcmp(name, "tid"))          { buf_puts(b, "((__s64)(__u32)bpf_get_current_pid_tgid())"); return; }
    if (name && !strcmp(name, "cpu_id"))        { buf_puts(b, "((__s64)bpf_get_smp_processor_id())"); return; }
    /* uid / gid -- the two halves of bpf_get_current_uid_gid(). Added with
     * the common filter so `filter_by :uid` is not a key the language can filter
     * on but not read: the hand-written equivalent of the injected guard
     * (`if uid == target_uid`) has to be writable, or the declaration would be a
     * black box rather than a shorthand. */
    if (name && !strcmp(name, "uid"))           { buf_puts(b, "((__s64)(__u32)bpf_get_current_uid_gid())"); return; }
    if (name && !strcmp(name, "gid"))           { buf_puts(b, "((__s64)(__u32)(bpf_get_current_uid_gid() >> 32))"); return; }
    /* cgroup_id -- the current cgroup id (= kernfs id / cgroup-dir inode) for
     * k8s pod correlation. In process-context hooks (kprobe/tracepoint/LSM/fmod_ret)
     * it returns the id of the task's memory-cgroup dir under the v2 hierarchy, i.e.
     * .../kubepods/.../pod<UID>/<container-id>, which userspace maps to the pod. */
    if (name && !strcmp(name, "cgroup_id"))     { buf_puts(b, "((__s64)bpf_get_current_cgroup_id())"); return; }
    /* WHICH of the declared symbols am I? ONE spelling, two lowerings.
     *
     * Both forms lower to the inner's __spnl_sym parameter and nothing else, so
     * the body cannot tell whether that value arrived as a compile-time literal
     * (expansion) or out of bpf_get_attach_cookie (kprobe_multi). That is the
     * whole point: the mechanism changes with the list SIZE, and code whose
     * meaning changed with the list size would be a trap.
     *
     * attached_symbol_eq is the form to prefer -- it survives reordering the
     * list, and a typo is a compile error here rather than a comparison that is
     * quietly always false. attached_index exists because emitting the index is
     * how userspace gets told which symbol fired (the table is published by
     * `describe` / `capabilities --json`). */
    if (name && (!strcmp(name, "attached_index") || !strcmp(name, "attached_symbol_eq"))) {
      CcMulti *mu = cc_multi_for(g_method ? g_method->name : NULL);
      if (!mu)
        die(msprintf("%s is only available inside a multi-symbol handler "
                     "(`on :kprobe, %%w[a b c] do ... end`). In a 1-to-1 handler the "
                     "attach point is the method name, so there is nothing to ask", name), NULL);
      int aid = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
      if (!strcmp(name, "attached_index")) {
        if (na != 0) die("attached_index takes no arguments", NULL);
        buf_puts(b, "(__spnl_sym)");
        return;
      }
      const char *lit = (na == 1 && nt_type(ast, ids[0]) &&
                         !strcmp(nt_type(ast, ids[0]), "StringNode"))
                        ? nt_str(ast, ids[0], "content") : NULL;
      if (!lit)
        die("attached_symbol_eq expects one string literal, e.g. "
            "attached_symbol_eq(\"vfs_read\") (it is resolved to an index at compile time)", NULL);
      int idx = -1;
      for (int s = 0; s < mu->nsyms; s++) if (!strcmp(mu->syms[s], lit)) { idx = s; break; }
      if (idx < 0) {
        Buf l; memset(&l, 0, sizeof l);
        for (int s = 0; s < mu->nsyms; s++) buf_printf(&l, "%s%s", s ? " " : "", mu->syms[s]);
        char *msg = msprintf("attached_symbol_eq: \"%s\" is not in this handler's list "
                             "(declared: %s). A name that is not attached can never match, "
                             "so this is refused rather than compiled to a constant false",
                             lit, l.p ? l.p : "");
        free(l.p);
        die(msg, NULL);
      }
      buf_printf(b, "(__spnl_sym == %d)", idx);
      return;
    }
    /* ppid -- the calling process's PARENT tgid. Scalar read, so BPF_CORE_READ
     * (probe_read; untrusted-safe), not a direct dereference. That distinction matters. Returns the
     * INIT-namespace pid (like all BPF pids); container /proc pids differ. */
    if (name && !strcmp(name, "ppid"))
      { buf_puts(b, "((__s64)BPF_CORE_READ(bpf_get_current_task_btf(), real_parent, tgid))"); return; }
    /* has_cap(CAP::SYS_ADMIN) -- a BIT TEST, not a comparison.
     *
     * AOT is what makes this one instruction: the capability number is known at
     * compile time, so `(caps >> 21) & 1` folds to a single shift+and against a
     * loaded field. Tetragon cannot do that -- its selectors arrive as YAML after
     * the program is built, so a capability match is a value-set map plus an
     * interpreter walk over it.
     *
     * The predicate exists because the value cannot be compared correctly by
     * hand: `cap_effective & CAP_SYS_ADMIN` returns 21 in both directions (measured). */
    if (name && cc_cap_set(name)) {
      int aid = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
      if (na != 1)
        die("has_cap family expects one capability, e.g. has_cap(CAP::SYS_ADMIN) "
            "(the flat spelling CAP_SYS_ADMIN works too)", name);
      cc_require_task_ctx(name);
      char *n = cc_expr_str(ast, ids[0]);
      buf_printf(b, "SPNL_HAS_CAP(%s, %s)", cc_cap_set(name), n);
      free(n);
      return;
    }
    if (name && !strcmp(name, "cap_effective")) {   /* the whole set, for reporting */
      cc_require_task_ctx(name);
      buf_puts(b, "((__s64)SPNL_CAPS(cap_effective))");
      return;
    }
    if (name && !strcmp(name, "ns_id")) {           /* namespace inode number */
      const CcNsKey *nk = cc_ns_arg(ast, nid, "ns_id");
      cc_require_task_ctx("ns_id");
      if (!nk->chain) buf_puts(b, "spnl_pid_ns_inum()");   /* :pid -- see the table */
      else buf_printf(b, "((__s64)BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), %s))",
                      nk->chain);
      return;
    }
    if (name && !strcmp(name, "in_host_ns")) {      /* ... == the initial one */
      const CcNsKey *nk = cc_ns_arg(ast, nid, "in_host_ns");
      cc_require_task_ctx("in_host_ns");
      Buf cur = {0};
      if (!nk->chain) buf_puts(&cur, "spnl_pid_ns_inum()");
      else buf_printf(&cur, "((__s64)BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), %s))",
                      nk->chain);
      if (nk->host) buf_printf(b, "((__s64)(%s == SPNL_HOST_NS(%s)))", cur.p, nk->host);
      else          buf_printf(b, "((__s64)(%s == SPNL_HOST_USER_NS()))", cur.p);
      free(cur.p);
      return;
    }
    /* file_type(file) -- the S_IFMT-masked type of the inode behind a
     * `struct file *`. Masked HERE, so the caller writes equality and equality is
     * the only thing left to get right: on the raw i_mode, `== S_IFREG` is false
     * for every regular file and `& S_IFDIR` is true for a socket (m04).
     *
     * Ungated, unlike everything above it in this section: the pointer comes from
     * the hook's own argument, so there is no "current task" to be wrong about.
     * Same rule, and the same CO-RE read, as kfield. */
    if (name && !strcmp(name, "file_type")) {
      int aid = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
      if (na != 1)
        die("file_type expects one argument: the `struct file *` the hook hands you "
            "(e.g. file_type(file) inside def lsm__file_open(file, ret))", name);
      char *p = cc_expr_str(ast, ids[0]);
      buf_printf(b, "((__s64)(BPF_CORE_READ((struct file *)(unsigned long)(%s), f_inode, i_mode) & 0170000))", p);
      free(p);
      return;
    }
    if (name && (!strcmp(name, "lat_start") || !strcmp(name, "lat_end"))) {   /* keyed latency */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("lat_start/lat_end expects 1 arg (key)", name);
      char *k = cc_expr_str(ast, ids[0]);
      buf_printf(b, "spnl_lat_%s_key(%s)", !strcmp(name, "lat_start") ? "start" : "end", k);
      free(k);
      return;
    }
    if (name && (!strcmp(name, "depth_inc") || !strcmp(name, "depth_dec"))) {   /* depth-collapse */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("depth_inc/depth_dec expects 1 arg (key)", name);
      char *k = cc_expr_str(ast, ids[0]);
      buf_printf(b, "spnl_depth_%s(%s)", !strcmp(name, "depth_inc") ? "inc" : "dec", k);
      free(k);
      return;
    }
    if (name && !strcmp(name, "latency_end"))  { buf_puts(b, "spnl_latency_end()"); return; }
    if (name && (!strcmp(name, "scx_consume") || !strcmp(name, "scx_pick_idle_cpu"))) {   /* scx kfunc (value) */
      const char *kf = !strcmp(name, "scx_consume") ? "scx_bpf_dsq_move_to_local" : "scx_bpf_pick_idle_cpu";
      int arity = !strcmp(name, "scx_consume") ? 1 : 2;
      const char *c0 = !strcmp(name, "scx_consume") ? NULL : "(const struct cpumask *)(unsigned long)";
      char *cs = cc_kfunc_call_str(ast, nid, kf, arity, c0);
      buf_printf(b, "((__s64)%s)", cs);
      free(cs);
      return;
    }
    if (name && !strcmp(name, "stack_id"))      { buf_puts(b, "((__s64)bpf_get_stackid(ctx, &bpf_stacks, 0))"); return; }   /* kernel */
    if (name && !strcmp(name, "user_stack_id")) { buf_puts(b, "((__s64)bpf_get_stackid(ctx, &bpf_stacks, (1ULL << 8)))"); return; }  /* user */
    if (name && !strcmp(name, "divu")) {   /* (__s64)((__u64)(a) / (__u64)(b)) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("divu expects 2 args (a, b)", NULL);
      CExpr *q = ce_binop("/", ce_cast("__u64", ce_paren(ce_raw(cc_expr_str(ast, ids[0])))),
                               ce_cast("__u64", ce_paren(ce_raw(cc_expr_str(ast, ids[1])))));
      ce_print(ce_paren(ce_cast("__s64", ce_paren(q))), b);
      return;
    }
    if (name && !strcmp(name, "i32")) {   /* read a 32-bit kernel arg correctly.
        kprobe args arrive as __s64 (full register); a 32-bit `int` arg (e.g. tcp_cleanup_rbuf's
        `copied`) has UNDEFINED upper 32 bits on arm64, so `arg > 0` is unreliable. i32(x) truncates
        to 32 bits and sign-extends: ((__s64)(__s32)(x)). Do NOT use on pointer/64-bit args. */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("i32 expects 1 arg (a 32-bit kernel value)", NULL);
      ce_print(ce_paren(ce_cast("__s64", ce_cast("__s32", ce_paren(ce_raw(cc_expr_str(ast, ids[0])))))), b);
      return;
    }
    if (name && !strcmp(name, "comm_hash")) {   /* 16B comm on stack, return first 8 bytes */
      int ch = ++g_if_counter;
      lines_push(g_body, msprintf("char _ch%d[16] = {0};", ch));
      lines_push(g_body, msprintf("bpf_get_current_comm(_ch%d, sizeof(_ch%d));", ch, ch));
      buf_printf(b, "((__s64)(*((__u64 *)_ch%d)))", ch);
      return;
    }
    /* The bpf_redirect_map family: xsk, dev and cpumap. All three are the same
     * shape (one map, one index); cpumap_redirect was measured missing from the C
     * port while its two siblings were there, so the capability advertised a
     * three-way family with a hole in the middle. */
    if (name && (!strcmp(name, "xsk_redirect") || !strcmp(name, "dev_redirect") ||
                 !strcmp(name, "cpumap_redirect"))) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("xsk_redirect/dev_redirect/cpumap_redirect expects 1 arg", name);
      char *q = cc_expr_str(ast, ids[0]);
      if (!strcmp(name, "xsk_redirect"))        buf_printf(b, "(__s64)bpf_redirect_map(&bpf_xskmap, (__u32)(%s), XDP_PASS)", q);
      else if (!strcmp(name, "dev_redirect"))   buf_printf(b, "(__s64)bpf_redirect_map(&bpf_devmap, (__u32)(%s), 0)", q);
      else                                      buf_printf(b, "(__s64)bpf_redirect_map(&spnl_cpumap, (__u32)(%s), 0)", q);
      free(q);
      return;
    }
    if (name && !strcmp(name, "fifo_pop"))  { buf_puts(b, "spnl_fifo_pop()"); return; }
    if (name && !strcmp(name, "lifo_pop"))  { buf_puts(b, "spnl_lifo_pop()"); return; }
    if (name && (!strcmp(name, "fifo_push") || !strcmp(name, "lifo_push"))) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("fifo_push/lifo_push expects 1 arg (value)", name);
      char *v = cc_expr_str(ast, ids[0]);
      buf_printf(b, "spnl_%s(%s)", name, v);   /* spnl_fifo_push / spnl_lifo_push */
      free(v);
      return;
    }
    /* iter_task() -> the task_struct* the iter/task program was invoked for, as
     * __s64 (feed it to kfield()/kptr() to read fields).
     *
     * This was measured missing from the C port while `def iter__task__<n>`
     * itself was ported, so tests/fixtures/62_iter_task.rb -- the only thing
     * anyone ran -- exercised the attach and never the builtin, and the
     * capability read "iter/task programs can enumerate tasks" when all they
     * could do was count them. The inner is ctx-prefixed (AK_ITER_TASK sets
     * ctx_prefixed), so `ctx` is in scope here. */
    if (name && !strcmp(name, "iter_task")) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; (void)(args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL);
      if (na != 0) die("iter_task expects no args", name);
      Attach a = {0}; AttachKind k = g_method ? cc_detect_attach(g_method->name, &a) : AK_NONE;
      if (a.sec) free(a.sec);
      if (k != AK_ITER_TASK)
        die("iter_task() is only valid inside iter__task__<name> methods\n"
            "  (it reads the iterator's ctx->task; no other attach point has one)\n"
            "  You wrote it in", g_method ? g_method->name : "<none>");
      /* The NULL check is not defensive style, it is required to LOAD, and the
       * barrier_var is required for the check to survive clang.
       *
       * Measured with clang 19, three shapes:
       *   bare `(__s64)(unsigned long)ctx->task`
       *       -> "R6 pointer arithmetic on trusted_ptr_or_null_ prohibited,
       *           null-check it first". The wrapper's own `if (!ctx->task)
       *           return 0` does not help: the inner is __noinline, so the
       *           verifier walks it as a separate function.
       *   `__s64 v = 0; if (p) v = (__s64)(unsigned long)p;`
       *       -> still rejected. In C that IS `v = (long)p` (NULL is 0), so
       *          clang folds the branch away and round-trips the pointer.
       *   with barrier_var(p) inside the branch  -> LOAD OK.
       *
       * The Ruby oracle emitted the bare cast, and 62_iter_task.rb only ever
       * exercised the attach, so `iter_task()` + kfield very likely never loaded
       * on any kernel -- the port lost something that was itself unverified. */
      int it = ++g_if_counter;
      lines_push(g_body, msprintf("struct task_struct *_it%d = ctx->task;", it));
      lines_push(g_body, msprintf("__s64 _itv%d = 0;", it));
      lines_push(g_body, msprintf("if (_it%d) { barrier_var(_it%d); _itv%d = (__s64)(unsigned long)_it%d; }",
                                  it, it, it, it));
      buf_printf(b, "_itv%d", it);
      return;
    }
    /* The two sock_ops ctx readers. Gated on the attach kind for
     * the same reason iter_task() is: they name fields of `struct bpf_sock_ops`,
     * and outside a sockops program there is no such ctx -- deferring that to
     * clang would report an undeclared identifier instead of the hook the author
     * chose (the context-gate rule). */
    if (name && (!strcmp(name, "sock_ops_op") || !strcmp(name, "sock_ops_state"))) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; (void)(args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL);
      if (na != 0) die("sock_ops_op / sock_ops_state expect no args", name);
      Attach so = {0}; AttachKind sk = g_method ? cc_detect_attach(g_method->name, &so) : AK_NONE;
      if (so.sec) free(so.sec);
      if (sk != AK_SOCK_OPS)
        die("sock_ops_op / sock_ops_state are only available inside a sockops program,\n"
            "  because they read `struct bpf_sock_ops *ctx` (op = the BPF_SOCK_OPS_* event,\n"
            "  state = ctx->args[1], the new TCP state in a STATE_CB).\n"
            "  Contexts that can supply it:\n"
            "    def sock_ops__<name>      (or `on :sock_ops`)\n"
            "  You wrote it in", g_method ? g_method->name : "<none>");
      buf_puts(b, !strcmp(name, "sock_ops_op") ? "((__s64)ctx->op)" : "((__s64)ctx->args[1])");
      return;
    }
    if (name && !strcmp(name, "sock_addr_ip4"))  { buf_puts(b, "((__s64)(__u32)__builtin_bswap32(ctx->user_ip4))"); return; }
    if (name && !strcmp(name, "sock_addr_port")) { buf_puts(b, "((__s64)(__u32)__builtin_bswap16((__u16)ctx->user_port))"); return; }
    if (name && (!strcmp(name, "mim_inc") || !strcmp(name, "mim_get"))) {   /* map-in-map */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("mim_inc/mim_get expects 2 args (group, key)", name);
      char *g = cc_expr_str(ast, ids[0]), *k = cc_expr_str(ast, ids[1]);
      buf_printf(b, "spnl_%s(%s, %s)", name, g, k);
      free(g); free(k);
      return;
    }
    if (name && !strcmp(name, "off_cpu_observe")) {   /* come-back-on-CPU -> delta + keyed hist */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("off_cpu_observe expects 1 arg (pid)", NULL);
      char *pid = cc_expr_str(ast, ids[0]);
      buf_printf(b, "spnl_off_cpu_observe((__u32)(%s))", pid);
      free(pid);
      return;
    }
    if (name && !strcmp(name, "task_load")) { buf_puts(b, "spnl_task_load()"); return; }
    if (name && (!strcmp(name, "task_store") || !strcmp(name, "task_incr") || !strcmp(name, "task_swap"))) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("task_store/incr/swap expects 1 arg", name);
      char *v = cc_expr_str(ast, ids[0]);
      buf_printf(b, "spnl_%s(%s)", name, v);   /* spnl_task_store / _incr / _swap */
      free(v);
      return;
    }
    if (name && !strcmp(name, "queue_push")) {   /* FIFO qdisc enqueue (returns NET_XMIT_*) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("queue_push expects 2 args (skb, to_free)", NULL);
      char *skb = cc_expr_str(ast, ids[0]), *tf = cc_expr_str(ast, ids[1]);
      char *skb_c = msprintf("(struct sk_buff *)(unsigned long)(%s)", skb);
      char *tf_c  = msprintf("(struct bpf_sk_buff_ptr *)(unsigned long)(%s)", tf);
      char *r = cc_emit_queue_push(skb_c, tf_c);
      buf_puts(b, r);
      free(r); free(skb); free(tf); free(skb_c); free(tf_c);
      return;
    }
    if (name && !strcmp(name, "queue_pop")) {   /* FIFO qdisc dequeue (returns skb ptr as __s64) */
      char *r = cc_emit_queue_pop();
      buf_puts(b, r);
      free(r);
      return;
    }
    /* path_eq(file, "/usr/bin/curl") -- compare a `struct file *`'s full path
     * against a compile-time literal. An expression (so it can drive `if`), unlike
     * emit_path which is a statement.
     *
     * AOT is the whole trick: the literal's length and bytes are known at compile
     * time, so this lowers to an exactly-sized stack buffer + an unrolled byte
     * compare. Tetragon has to carry a string-map/LPM-trie machine because it
     * cannot recompile per policy; spinel-ebpf burns the literal into the program.
     *
     * Buffer sizing (measured): bpf_d_path memmoves the result to buf[0] and
     * returns strlen+1. Sizing the buffer to just the literal is not a limitation
     * but the correct semantics -- a real path longer than the literal makes
     * bpf_d_path fail (-ENAMETOOLONG) => no match, which is what we want anyway. */
    if (name && !strcmp(name, "path_eq")) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("path_eq expects (file, \"/literal/path\")", NULL);
      /* nt_str already yields decoded bytes in both builds: the text-mode AST
       * parser runs cc_unescape() on S-fields, and the in-process build reads the
       * upstream NodeTable directly. Decoding here would double-decode. */
      const char *lit = nt_str(ast, ids[1], "content");
      if (!lit)
        die("path_eq: the path must be a string literal (it is compiled into the compare)", NULL);
      const CcDpathHook *h = cc_require_dpath_ok("path_eq");
      char *fexpr = cc_expr_str(ast, ids[0]);
      /* how the gated arg becomes a `struct path *` is per-hook (file /
       * struct path * / linux_binprm), so ask the gate entry. */
      char *guard = NULL;
      char *pathexpr = cc_dpath_expr(h, fexpr, g_body, "", &guard);
      cc_emit_path_eq_g(b, pathexpr, guard, lit);
      free(guard); free(pathexpr); free(fexpr);
      return;
    }
    /* path_starts_with(file, "/etc/secret/") -- does a `struct file *`'s full
     * path begin with a compile-time literal PREFIX? The prefix sibling of path_eq
     *: an expression (drives `if`), same bpf_d_path kernel gate. Because a
     * matching path can be up to PATH_MAX long (prefix + suffix), it reads into a
     * per-CPU 4096B scratch map, not a stack buffer (a small buffer would MISS long
     * paths under the prefix = a bypass). See cc_emit_path_starts_with. */
    if (name && !strcmp(name, "path_starts_with")) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("path_starts_with expects (file, \"/literal/prefix/\")", NULL);
      const char *lit = nt_str(ast, ids[1], "content");
      if (!lit)
        die("path_starts_with: the prefix must be a string literal (it is compiled into the compare)", NULL);
      const CcDpathHook *h = cc_require_dpath_ok("path_starts_with");
      char *fexpr = cc_expr_str(ast, ids[0]);
      char *guard = NULL;
      char *pathexpr = cc_dpath_expr(h, fexpr, g_body, "", &guard);
      cc_emit_path_starts_with(b, pathexpr, guard, lit);
      free(guard); free(pathexpr); free(fexpr);
      return;
    }
    /* path_contains(file, "/.ssh/") -- does a `struct file *`'s full path
     * contain a compile-time literal SUBSTRING at ANY offset? The substring sibling
     * of path_eq (exact) / path_starts_with (prefix); same bpf_d_path
     * kernel gate. Because the literal can sit anywhere up to PATH_MAX, it is a
     * whole-path sliding search via bpf_loop over the 4096 window positions (reading
     * into the same per-CPU 4096B scratch as path_starts_with) -- a long path with the
     * substring near the end must NOT bypass the deny. See cc_emit_path_contains. */
    if (name && !strcmp(name, "path_contains")) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("path_contains expects (file, \"/literal/substr/\")", NULL);
      const char *lit = nt_str(ast, ids[1], "content");
      if (!lit)
        die("path_contains: the substring must be a string literal (it is compiled into the compare)", NULL);
      const CcDpathHook *h = cc_require_dpath_ok("path_contains");
      char *fexpr = cc_expr_str(ast, ids[0]);
      char *guard = NULL;
      char *pathexpr = cc_dpath_expr(h, fexpr, g_body, "", &guard);
      cc_emit_path_contains(b, pathexpr, guard, lit);
      free(guard); free(pathexpr); free(fexpr);
      return;
    }
    /* parent_path_eq("/usr/bin/curl") -- compare the CALLING process's PARENT
     * executable path against a literal. The parent version of path_eq;
     * Tetragon's matchParentBinaries equivalent.
     *
     * The hop chain t->real_parent->mm->exe_file->f_path uses DIRECT DEREF, not
     * BPF_CORE_READ: bpf_d_path needs a trusted/rcu pointer, and the trusted-ness
     * of bpf_get_current_task_btf() propagates through direct field derefs but is
     * lost through BPF_CORE_READ (which returns a scalar). This is the crux:
     * scalar reads (ppid) use BPF_CORE_READ, path reads (d_path) use direct deref. */
    if (name && !strcmp(name, "parent_path_eq")) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("parent_path_eq expects (\"/literal/path\")", NULL);
      const char *lit = nt_str(ast, ids[0], "content");
      if (!lit)
        die("parent_path_eq: the path must be a string literal", NULL);
      (void)cc_require_dpath_ok("parent_path_eq");   /* task chain: form is fixed */
      int pt = ++g_if_counter;
      lines_push(g_body, msprintf("struct task_struct *_pt%d = bpf_get_current_task_btf();", pt));
      /* direct deref chain (keeps trusted-ness for bpf_d_path) */
      char *pathexpr = msprintf("&_pt%d->real_parent->mm->exe_file->f_path", pt);
      cc_emit_path_eq(b, pathexpr, lit);
      free(pathexpr);
      return;
    }
    if (name && cc_pkt_canon(name)) {   /* pkt_* header access */
      cc_emit_pkt_call(b, name);
      return;
    }
    /* The same readers spelled as a chain (`pkt.l4.proto`). Resolved to the flat
     * name and emitted through the identical path, so the two spellings cannot
     * drift apart -- which is what the chain gate checks. */
    {
      char joined[64];
      int leaf_args = nt_ref(ast, nid, "arguments") >= 0;
      if (cc_pkt_chain_name(ast, nid, joined, sizeof joined)) {
        const char *canon = leaf_args ? NULL : cc_pkt_canon(joined);
        if (canon) { cc_emit_pkt_call(b, canon); return; }
        cc_die_bad_pkt_chain(joined, leaf_args);
      }
    }
    /* tcp_sock_<field>(sk) flat reader -> field value (expression). */
    {
      const char *rf = cc_tcp_sock_reader_field(name);
      if (rf) {
        if (!cc_in_tcp_cc()) die("tcp_sock_* is only valid inside tcp_cc__<member> methods", name);
        int args_id = nt_ref(ast, nid, "arguments");
        int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
        if (na != 1) die("tcp_sock_<field>(sk) expects 1 arg", name);
        char *sk = cc_expr_str(ast, ids[0]);
        cc_emit_tcp_sock_read(b, rf, sk);
        free(sk);
        return;
      }
    }
    /* A declared runtime parameter reads as a bare name. It is
     * matched LAST, after every builtin, so declaring `param :pid` can never
     * silently steal the meaning of the `pid` builtin -- the builtin wins and the
     * parameter is simply unreachable (reported as unused below). */
    {
      int pi = cc_param_index(name);
      if (pi >= 0) { g_param_used[pi] = 1; buf_printf(b, "spnl_param_%s", name); return; }
    }
    die("CallNode not yet ported (Stage 1)", name ? name : "?");
  }
  die("node type not yet ported (Stage 1)", ty);
}

/* expr node -> malloc'd C string. */
static char *cc_expr_str(AST *ast, int nid) {
  Buf b; memset(&b, 0, sizeof b);
  cc_lower_expr(ast, nid, &b);
  return b.p ? b.p : strdup("");
}

/* pre-order DFS collecting LocalVariableWriteNode names (first-occurrence order),
 * skipping nested def/class/module bodies (mirrors Ruby collect_locals). */
static void cc_collect_locals(AST *ast, int nid, Lines *names) {
  if (nid < 0) return;
  const char *ty = nt_type(ast, nid);
  if (!ty) return;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return;
  if (!strcmp(ty, "LocalVariableWriteNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm) { char *s = cc_safe_dup(nm); if (!lines_has(names, s)) lines_push(names, s); else free(s); }
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) cc_collect_locals(ast, n->r[i].ref, names);
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) cc_collect_locals(ast, n->a[i].ids[k], names);
}

static char *cc_lower_stmt(AST *ast, int nid, Lines *body);   /* mutually recursive */
static char *cc_times_call(AST *ast, int nid, Lines *body);   /* n.times { } -> bpf_loop */

/* lower a branch (then/else sub-tree) into `body`, assign its last value to
 * `result_var`, and indent every line this branch added by 4 (Ruby
 * emit_branch_lines). */
/* return a malloc'd copy of `s` with a 4-space prefix on EVERY line (no trailing
 * newline). Multi-line body elements (e.g. fib_lookup's `({...})` statement-expr)
 * keep their relative inner indentation; single-line elements are unchanged. */
static char *cc_indent_each(const char *s) {
  Buf o; memset(&o, 0, sizeof o);
  const char *p = s;
  for (;;) {
    const char *nl = strchr(p, '\n');
    buf_puts(&o, "    ");
    if (nl) { buf_putn(&o, p, (size_t)(nl - p) + 1); p = nl + 1; }
    else { buf_puts(&o, p); break; }
  }
  return o.p ? o.p : strdup("    ");
}

/* ---------- CStmt: structured statements with depth-based
 * indentation, replacing flat line strings + in-place post-indent. Minimal set
 * for control flow; not-yet-structured lowering rides as CS_RAW lines. cs_emit
 * appends (depth*4)-indented lines to a Lines, so it composes with the outer
 * method-body indent exactly like the old cc_emit_branch + cc_indent_each. ---------- */
typedef enum { CS_RAW, CS_BLOCK, CS_IF } CSKind;
typedef struct CStmt {
  CSKind kind;
  char *raw;                          /* CS_RAW: one (possibly multi-)line, un-indented */
  CExpr *cond;                        /* CS_IF predicate */
  struct CStmt **stmts; int nstmts;   /* CS_BLOCK */
  struct CStmt *then_b, *else_b;      /* CS_IF branches (CS_BLOCK; else_b may be NULL) */
} CStmt;

static CStmt *cs_new(CSKind k) { CStmt *s = calloc(1, sizeof *s); if (!s) die("oom", "CStmt"); s->kind = k; return s; }
static CStmt *cs_raw(char *line) { CStmt *s = cs_new(CS_RAW); s->raw = line; return s; }
static CStmt *cs_if(CExpr *cond, CStmt *t, CStmt *e) { CStmt *s = cs_new(CS_IF); s->cond = cond; s->then_b = t; s->else_b = e; return s; }
/* CS_BLOCK from a Lines of already-lowered (flat) statement strings; takes
 * ownership of the line strings (caller frees only the Lines array). */
static CStmt *cs_block_from_lines(Lines *lns) {
  CStmt *s = cs_new(CS_BLOCK);
  s->stmts = malloc(sizeof(CStmt *) * (lns->n > 0 ? lns->n : 1));
  for (int i = 0; i < lns->n; i++) s->stmts[i] = cs_raw(lns->v[i]);
  s->nstmts = lns->n;
  return s;
}
/* push `line` (consumed) indented `depth` levels (4 spaces each, per physical
 * line -- cc_indent_each handles the multi-line ({...}) entries). */
static void cs_push(Lines *out, char *line, int depth) {
  for (int d = 0; d < depth; d++) { char *t = cc_indent_each(line); free(line); line = t; }
  lines_push(out, line);
}
static void cs_emit(const CStmt *s, Lines *out, int depth) {
  switch (s->kind) {
    case CS_RAW:
      cs_push(out, strdup(s->raw), depth);
      return;
    case CS_BLOCK:
      for (int i = 0; i < s->nstmts; i++) cs_emit(s->stmts[i], out, depth);
      return;
    case CS_IF: {
      Buf cb; memset(&cb, 0, sizeof cb);
      buf_puts(&cb, "if ("); ce_print(s->cond, &cb); buf_puts(&cb, ") {");
      cs_push(out, cb.p ? cb.p : strdup("if () {"), depth);
      cs_emit(s->then_b, out, depth + 1);
      if (s->else_b) {
        cs_push(out, strdup("} else {"), depth);
        cs_emit(s->else_b, out, depth + 1);
      }
      cs_push(out, strdup("}"), depth);
      return;
    }
  }
}

/* lower a branch (then/else) into a CS_BLOCK: its statements + the
 * `result_var = <last value>;` assignment, captured as CS_RAW lines. */
static CStmt *cc_branch_block(AST *ast, int bid, const char *result_var) {
  Lines tmp; memset(&tmp, 0, sizeof tmp);
  /* Setup lines (ivar map lookups, etc.) are pushed to the global g_body, not the
   * `body` arg -- so redirect g_body into the branch's temp while lowering, or
   * they'd escape to the enclosing scope (the old cc_emit_branch lowered straight
   * into body == g_body). g_deferred (loop callbacks) stays method-level. */
  Lines *saved = g_body;
  g_body = &tmp;
  if (bid >= 0) {
    char *last = cc_lower_stmt(ast, bid, &tmp);
    if (last) { lines_push(&tmp, msprintf("%s = %s;", result_var, last)); free(last); }
  }
  g_body = saved;
  CStmt *blk = cs_block_from_lines(&tmp);
  free(tmp.v);   /* line strings are now owned by the CS_RAW nodes */
  return blk;
}

/* expression-position if -> `__s64 _ifN = 0; if (pred) { _ifN = ...; } else
 * { ...; _ifN = ...; }` ; the value is `_ifN`. elsif nests in the else branch. */
static char *cc_if_node(AST *ast, int nid, Lines *body) {
  int pred    = nt_ref(ast, nid, "predicate");
  int then_id = nt_ref(ast, nid, "statements");
  int else_id = nt_ref(ast, nid, "subsequent");
  if (pred < 0) die("IfNode missing predicate", NULL);
  /* Order matters for the fresh-counter (_kN/_pN/_ifN) sequence -- match the old
   * cc_if_node: lower the predicate FIRST (its ivar-read setup lines + counters),
   * THEN the _ifN temp, THEN the branches. */
  CExpr *cond = cc_build_expr(ast, pred);
  char *tmp = msprintf("_if%d", ++g_if_counter);
  lines_push(body, msprintf("__s64 %s = 0;", tmp));
  /* structured: CIf(cond, then, else) emitted with depth-based indentation.
   * branches are CS_BLOCKs of the lowered statements + the `_ifN = <value>;`
   * assignment; elsif nests as a CIf in the else block (cc_lower_stmt -> cc_if_node). */
  CStmt *then_b = cc_branch_block(ast, then_id, tmp);
  CStmt *else_b = (else_id >= 0) ? cc_branch_block(ast, else_id, tmp) : NULL;
  cs_emit(cs_if(cond, then_b, else_b), body, 0);
  return tmp;
}

/* lower one statement: push any emitted line(s) into `body`, return its value
 * expr (malloc'd, or NULL). Mirrors Ruby lower_stmt: writes emit `name = v;` and
 * yield the name; if/else emit a block and yield the temp; a StatementsNode
 * lowers each statement (non-last for side effects) and yields the last value;
 * a pure expression emits nothing and yields itself. */
static char *cc_lower_stmt(AST *ast, int nid, Lines *body) {
  const char *ty = nt_type(ast, nid);
  if (!ty) die("missing node", NULL);
  if (!strcmp(ty, "LocalVariableWriteNode")) {
    const char *nm = nt_str(ast, nid, "name");
    int v = nt_ref(ast, nid, "value");
    if (!nm || v < 0) die("LocalVariableWriteNode missing name/value", NULL);
    char *e = cc_expr_str(ast, v);               /* value lowered first (Ruby order) */
    char *s = cc_safe_dup(nm);                   /* C-keyword sanitize */
    /* `s = kptr(ptr, "struct")` records s's kernel struct so `s.field`
     * later dispatches to BPF_CORE_READ. */
    {
      const char *vt = nt_type(ast, v);
      if (vt && !strcmp(vt, "CallNode")) {
        const char *vn = nt_str(ast, v, "name");
        if (vn && !strcmp(vn, "kptr")) {
          int aid = nt_ref(ast, v, "arguments");
          int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
          if (na == 2) { const char *st = nt_str(ast, ids[1], "content");
            if (st && g_n_kptr < MAX_KPTR) { g_kptr_names[g_n_kptr] = strdup(s); g_kptr_structs[g_n_kptr] = strdup(st); g_n_kptr++; } }
        }
      }
    }
    if (cc_is_capture(s)) {                       /* write through the *_lc->name pointer */
      lines_push(body, msprintf("*_lc->%s = %s;", s, e));
      char *r = msprintf("(*_lc->%s)", s);
      free(e); free(s);
      return r;
    }
    lines_push(body, msprintf("%s = %s;", s, e));
    free(e);
    return s;   /* caller frees */
  }
  if (!strcmp(ty, "InstanceVariableWriteNode")) {   /* @x = rhs -> map update */
    const char *iv = nt_str(ast, nid, "name");
    int v = nt_ref(ast, nid, "value");
    if (!iv || v < 0) die("InstanceVariableWriteNode missing name/value", NULL);
    char *rhs = cc_expr_str(ast, v);                /* lowered first (its reads get earlier temps) */
    char *map = cc_ivar_map(iv);
    char *r = cc_emit_ivar_write(body, map, rhs);
    free(rhs); free(map);
    return r;
  }
  if (!strcmp(ty, "InstanceVariableOperatorWriteNode")) {   /* @x += rhs */
    const char *iv = nt_str(ast, nid, "name");
    const char *op = nt_str(ast, nid, "binary_operator");
    if (!iv || !op || !(!strcmp(op, "+") || !strcmp(op, "-") || !strcmp(op, "*")))
      die("ivar operator not supported (Stage 1)", op ? op : "?");
    int v = nt_ref(ast, nid, "value");
    char *rhs = cc_expr_str(ast, v);
    char *map = cc_ivar_map(iv);
    char *r = cc_emit_ivar_rmw(body, map, op, rhs);
    free(rhs); free(map);
    return r;
  }
  if (!strcmp(ty, "IfNode")) return cc_if_node(ast, nid, body);
  if (!strcmp(ty, "ElseNode")) {
    int s = nt_ref(ast, nid, "statements");
    return s >= 0 ? cc_lower_stmt(ast, s, body) : NULL;
  }
  if (!strcmp(ty, "StatementsNode")) {
    int nb; const int *ids = nt_arr(ast, nid, "body", &nb);
    char *last = NULL;
    for (int i = 0; i < nb; i++) {
      int before = body->n;
      free(last); last = cc_lower_stmt(ast, ids[i], body);
      /* a non-last pure expression that emitted no lines is a bare side
       * effect -- keep it as `(void)(expr);` so it isn't dropped (build_block). */
      if (i != nb - 1 && body->n == before && last && last[0])
        lines_push(body, msprintf("(void)(%s);", last));
    }
    return last;
  }
  if (!strcmp(ty, "CallOperatorWriteNode")) {   /* sk.<field> += v / -= v (dot compound) */
    int recv = nt_ref(ast, nid, "receiver");
    const char *read_name = nt_str(ast, nid, "name");   /* upstream stores read_name under "name" */
    const char *op = nt_str(ast, nid, "binary_operator");
    int v = nt_ref(ast, nid, "value");
    if (recv < 0) die("CallOperatorWriteNode missing receiver (Stage 1)", NULL);
    if (v < 0 || !read_name || !op)
      die("CallOperatorWriteNode missing value/name/operator (Stage 1)", read_name ? read_name : "?");
    if (!cc_in_tcp_cc() || !cc_tcp_sock_is_field(read_name))
      die("op-write only supported on tcp_sock fields in tcp_cc context (Stage 1)", read_name);
    const char *c_op = !strcmp(op, "+") ? "+=" : (!strcmp(op, "-") ? "-=" : NULL);
    if (!c_op) die("tcp_sock <field> op= : only += / -= supported (Stage 1)", op);
    char *rexpr = cc_expr_str(ast, recv), *ve = cc_expr_str(ast, v);
    cc_emit_tcp_sock_write(body, read_name, c_op, rexpr, ve);
    free(rexpr); free(ve);
    return strdup("0");
  }
  if (!strcmp(ty, "CallNode")) {
    const char *name = nt_str(ast, nid, "name");
    if (name && !strcmp(name, "spnl_emit")) {   /* ringbuf reserve/submit block */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("spnl_emit expects 1 arg", NULL);
      char *val = cc_expr_str(ast, ids[0]);
      if (g_amp) {   /* amp-m7: publish to the ring via the runtime helper */
        lines_push(body, msprintf("amp_emit(%s);", val));
        free(val);
        return strdup("0");
      }
      int e = ++g_if_counter;
      lines_push(body, strdup("{"));
      lines_push(body, msprintf("    struct %s_event *_e%d = bpf_ringbuf_reserve(&%s_events, sizeof(*_e%d), 0);", g_unit, e, g_unit, e));
      lines_push(body, msprintf("    if (_e%d) {", e));
      { char *var = msprintf("_e%d", e); cc_push_evt_hdr(body, "        ", var); free(var); }
      lines_push(body, msprintf("        _e%d->value = %s;", e, val));
      lines_push(body, msprintf("        bpf_ringbuf_submit(_e%d, 0);", e));
      lines_push(body, strdup("    } else spnl_lost_inc();   /* ring full -> account the dropped record */"));
      lines_push(body, strdup("}"));
      free(val);
      /* Ruby STMT_NO_VALUE: a side-effect statement with no value, but it prints
       * as "0" in value positions (branch result / return default). Returning "0"
       * (vs NULL) makes cc_emit_branch emit `result_var = 0;` like build_branch. */
      return strdup("0");
    }
    /* emit_str / emit_pair / emit3 / emit4 -- per-unit ringbuf
     * channels with N int (or 1 string) payload fields. Same 16B header block. */
    if (name && (!strcmp(name, "spnl_emit_str") || !strcmp(name, "spnl_emit_pair") ||
                 !strcmp(name, "spnl_emit3") || !strcmp(name, "spnl_emit4"))) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      int is_str = !strcmp(name, "spnl_emit_str");
      int want = is_str ? 1 : (!strcmp(name, "spnl_emit_pair") ? 2 : (!strcmp(name, "spnl_emit3") ? 3 : 4));
      if (na != want) die("emit arity mismatch (Stage 1)", name);
      const char *chan = is_str ? "str" : (want == 2 ? "pair" : (want == 3 ? "emit3" : "emit4"));
      const char *pfx  = is_str ? "se"  : (want == 2 ? "pe"   : "ne");
      int e = ++g_if_counter;
      lines_push(body, strdup("{"));
      lines_push(body, msprintf("    struct %s_%s_event *_%s%d = bpf_ringbuf_reserve(&%s_%s_events, sizeof(*_%s%d), 0);",
                                g_unit, chan, pfx, e, g_unit, chan, pfx, e));
      lines_push(body, msprintf("    if (_%s%d) {", pfx, e));
      { char *var = msprintf("_%s%d", pfx, e); cc_push_evt_hdr(body, "        ", var); free(var); }
      if (is_str) {
        char *p = cc_expr_str(ast, ids[0]);
        lines_push(body, msprintf("        bpf_probe_read_user_str(_%s%d->str, sizeof(_%s%d->str), (const void *)(%s));", pfx, e, pfx, e, p));
        free(p);
      } else {
        const char *fields = "abcd";
        for (int k = 0; k < want; k++) {
          char *v = cc_expr_str(ast, ids[k]);
          lines_push(body, msprintf("        _%s%d->%c = %s;", pfx, e, fields[k], v));
          free(v);
        }
      }
      lines_push(body, msprintf("        bpf_ringbuf_submit(_%s%d, 0);", pfx, e));
      lines_push(body, strdup("    } else spnl_lost_inc();   /* ring full -> account the dropped record */"));
      lines_push(body, strdup("}"));
      return strdup("0");   /* STMT_NO_VALUE */
    }
    if (name && !strcmp(name, "path_counter_inc")) {   /* emit the inc as a statement */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("path_counter_inc expects 1 arg (key)", NULL);
      char *k = cc_expr_str(ast, ids[0]);
      lines_push(body, msprintf("spnl_path_counter_inc(%s);", k));
      free(k);
      return strdup("0");   /* STMT_NO_VALUE */
    }
    if (name && !strcmp(name, "times") && nt_ref(ast, nid, "block") >= 0)   /* n.times { } */
      return cc_times_call(ast, nid, body);
    if (name && (!strcmp(name, "scx_dispatch") || !strcmp(name, "scx_kick_cpu") || !strcmp(name, "scx_create_dsq"))) {
      const char *kf; int arity; const char *c0 = NULL;   /* scx kfunc (side effect) */
      if      (!strcmp(name, "scx_dispatch")) { kf = "scx_bpf_dsq_insert"; arity = 4; c0 = "(struct task_struct *)(unsigned long)"; }
      else if (!strcmp(name, "scx_kick_cpu")) { kf = "scx_bpf_kick_cpu";   arity = 2; }
      else                                    { kf = "scx_bpf_create_dsq"; arity = 2; }
      char *cs = cc_kfunc_call_str(ast, nid, kf, arity, c0);
      lines_push(body, msprintf("%s;", cs));
      free(cs);
      return strdup("0");
    }
    if (name) {   /* qdisc kfuncs -- all side-effecting statements */
      const QdiscKf *qkf = cc_qdisc_kf(name);
      if (qkf) {
        char *cs = cc_qdisc_call_str(ast, nid, qkf);
        lines_push(body, msprintf("%s;", cs));
        free(cs);
        return strdup("0");
      }
    }
    /* histogram observers -- side-effecting statements. */
    if (name && (!strcmp(name, "hist_observe") || !strcmp(name, "hist_observe_linear"))) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("hist_observe expects 1 arg", name);
      char *v = cc_expr_str(ast, ids[0]);
      const char *helper = !strcmp(name, "hist_observe") ? "spnl_hist_observe" : "spnl_hist_observe_linear";
      lines_push(body, msprintf("%s(%s);", helper, v));
      free(v);
      return strdup("0");
    }
    if (name && !strcmp(name, "hist_observe_by")) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("hist_observe_by expects 2 args (key, value)", NULL);
      char *k = cc_expr_str(ast, ids[0]), *v = cc_expr_str(ast, ids[1]);
      lines_push(body, msprintf("spnl_hist_observe_by(%s, %s);", k, v));
      free(k); free(v);
      return strdup("0");
    }
    if (name && !strcmp(name, "latency_start")) {   /* BEGIN side effect */
      lines_push(body, strdup("spnl_latency_start();"));
      return strdup("0");
    }
    if (name && !strcmp(name, "off_cpu_start")) {   /* going-off-CPU capture */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("off_cpu_start expects 1 arg (pid)", NULL);
      char *pid = cc_expr_str(ast, ids[0]);
      lines_push(body, msprintf("spnl_off_cpu_start((__u32)(%s), ctx);", pid));
      free(pid);
      return strdup("0");
    }
    if (name && (!strcmp(name, "leak_record") || !strcmp(name, "leak_forget"))) {
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      int want = !strcmp(name, "leak_record") ? 3 : 1;
      if (na != want) die("leak_record/leak_forget arity", name);
      Buf call; memset(&call, 0, sizeof call);
      buf_printf(&call, "spnl_%s(", name);
      for (int k = 0; k < na; k++) { char *e = cc_expr_str(ast, ids[k]); buf_printf(&call, "%s%s", k ? ", " : "", e); free(e); }
      buf_puts(&call, ");");
      lines_push(body, call.p);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_argv")) {   /* emit each argv[] string */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("emit_argv expects 1 arg (argv pointer)", NULL);
      char *argv = cc_expr_str(ast, ids[0]);
      int ai = ++g_if_counter, ap = ++g_if_counter, ae = ++g_if_counter;
      lines_push(body, strdup("{"));
      lines_push(body, strdup("    #pragma unroll"));
      lines_push(body, msprintf("    for (int _ai%d = 0; _ai%d < 20; _ai%d++) {", ai, ai, ai));
      lines_push(body, msprintf("        const char *_ap%d = 0;", ap));
      lines_push(body, msprintf("        bpf_probe_read_user(&_ap%d, sizeof(_ap%d), &((const char *const *)(unsigned long)(%s))[_ai%d]);", ap, ap, argv, ai));
      lines_push(body, msprintf("        if (!_ap%d) break;", ap));
      lines_push(body, msprintf("        struct %s_str_event *_ae%d = bpf_ringbuf_reserve(&%s_str_events, sizeof(*_ae%d), 0);", g_unit, ae, g_unit, ae));
      lines_push(body, msprintf("        if (_ae%d) {", ae));
      { char *var = msprintf("_ae%d", ae); cc_push_evt_hdr(body, "            ", var); free(var); }
      lines_push(body, msprintf("            bpf_probe_read_user_str(_ae%d->str, sizeof(_ae%d->str), _ap%d);", ae, ae, ap));
      lines_push(body, msprintf("            bpf_ringbuf_submit(_ae%d, 0);", ae));
      lines_push(body, strdup("        } else spnl_lost_inc();   /* ring full -> account the dropped record */"));
      lines_push(body, strdup("    }"));
      lines_push(body, strdup("}"));
      free(argv);
      return strdup("0");
    }
    if (name && !strcmp(name, "lock_edge")) {   /* deadlock lock-order edge */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("lock_edge expects 2 args (a, b)", NULL);
      char *a = cc_expr_str(ast, ids[0]), *bb = cc_expr_str(ast, ids[1]);
      lines_push(body, msprintf("spnl_lock_edge(%s, %s);", a, bb));
      free(a); free(bb);
      return strdup("0");
    }
    if (name && !strcmp(name, "flow_set")) {   /* conntrack field write (lookup-or-insert) */
      int aid = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
      if (na != 3) die("flow_set(:name, :field, value) expects 3 args", NULL);
      const char *mn = nt_str(ast, ids[0], "value"), *fld = nt_str(ast, ids[1], "value");
      if (!mn || !fld) die("flow_set needs symbol args", NULL);
      char *val = cc_expr_str(ast, ids[2]);
      cc_emit_flow_set(body, mn, fld, val);
      free(val);
      return strdup("0");
    }
    if (name && !strcmp(name, "flow_del")) {   /* conntrack entry delete */
      int aid = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
      if (na < 1) die("flow_del(:name) expects 1 arg", NULL);
      const char *mn = nt_str(ast, ids[0], "value");
      if (!mn) die("flow_del needs symbol arg", NULL);
      cc_emit_flow_del(body, mn);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_path")) {   /* full path via bpf_d_path */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("emit_path expects 1 arg (the hook's file/path/binprm attach param)", NULL);
      /* bpf_d_path is kernel-gated -- see CC_DPATH_OK (shared with path_eq). */
      const CcDpathHook *h = cc_require_dpath_ok("emit_path");
      char *fexpr = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      lines_push(body, strdup("{"));
      /* per-hook path expression (its temporaries live inside this block). */
      char *guard = NULL;
      char *pathexpr = cc_dpath_expr(h, fexpr, body, "    ", &guard);
      lines_push(body, msprintf("    struct %s_str_event *_pe%d = bpf_ringbuf_reserve(&%s_str_events, sizeof(*_pe%d), 0);", g_unit, e, g_unit, e));
      lines_push(body, msprintf("    if (_pe%d) {", e));
      { char *var = msprintf("_pe%d", e); cc_push_evt_hdr(body, "        ", var); free(var); }
      /* measured: bpf_d_path writes back-to-front then memmoves the result to
       * buf[0] and returns strlen+1, but the pre-memmove copy is left in the tail.
       * Zero first so nothing past the NUL is emitted from the reserved ringbuf slot. */
      lines_push(body, msprintf("        __builtin_memset(_pe%d->str, 0, sizeof(_pe%d->str));", e, e));
      if (guard)   /* no path (NULL arg) -> emit the empty string, never a stale one */
        lines_push(body, msprintf("        if (%s) bpf_d_path(%s, _pe%d->str, sizeof(_pe%d->str));", guard, pathexpr, e, e));
      else
        lines_push(body, msprintf("        bpf_d_path(%s, _pe%d->str, sizeof(_pe%d->str));", pathexpr, e, e));
      lines_push(body, msprintf("        bpf_ringbuf_submit(_pe%d, 0);", e));
      lines_push(body, strdup("    } else spnl_lost_inc();   /* ring full -> account the dropped record */"));
      lines_push(body, strdup("}"));
      free(guard); free(pathexpr); free(fexpr);
      return strdup("0");
    }
    /* emit_kfield_str(ptr, "struct", "field"...) -- send a kernel struct's
     * STRING field to the per-unit str ringbuf. The statement form (a report), the
     * direct answer to Tetragon's `resolve:` + `type: string`, and the sibling of
     * emit_path / emit_comm on the same channel.
     *
     * Truncation is the channel's, not this builtin's: a value longer than the
     * 256-byte str payload arrives cut short with its NUL, like spnl_emit_str. The
     * COMPARE form cannot afford that ambiguity and sizes its own buffer. */
    if (name && !strcmp(name, "emit_kfield_str")) {
      char *ptr = NULL; const char *strct = NULL, *lit = NULL;
      char **fields = NULL; int nf = 0;
      cc_kstr_args(ast, nid, 0, &ptr, &strct, &fields, &nf, &lit);
      int e = ++g_if_counter;
      lines_push(body, strdup("{"));
      lines_push(body, msprintf("    struct %s_str_event *_kse%d = bpf_ringbuf_reserve(&%s_str_events, sizeof(*_kse%d), 0);", g_unit, e, g_unit, e));
      lines_push(body, msprintf("    if (_kse%d) {", e));
      { char *var = msprintf("_kse%d", e); cc_push_evt_hdr(body, "        ", var); free(var); }
      lines_push(body, msprintf("        __builtin_memset(_kse%d->str, 0, sizeof(_kse%d->str));", e, e));
      char *dst = msprintf("_kse%d->str", e);
      char *rc = cc_emit_kfield_str_read(body, "        ", dst, "emit_kfield_str", ptr, strct,
                                         fields, nf, NULL, NULL);
      /* A fault leaves the zeroed buffer: an empty string is emitted, never a stale
       * one (same rule as emit_path's guarded form). */
      lines_push(body, msprintf("        (void)%s;", rc));
      lines_push(body, msprintf("        bpf_ringbuf_submit(_kse%d, 0);", e));
      lines_push(body, strdup("    } else spnl_lost_inc();   /* ring full -> account the dropped record */"));
      lines_push(body, strdup("}"));
      free(rc); free(dst); free(fields); free(ptr);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_parent_path")) {   /* parent process exe path via bpf_d_path */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      (void)ids;
      if (na != 0) die("emit_parent_path expects no args (reads current task's parent)", NULL);
      /* same bpf_d_path kernel gate as emit_path; the task chain below
       * is the path source here, so the hook's arg form does not apply. */
      (void)cc_require_dpath_ok("emit_parent_path");
      int e = ++g_if_counter;
      /* direct-deref chain: task->real_parent->mm->exe_file->f_path stays trusted for bpf_d_path */
      lines_push(body, strdup("{"));
      lines_push(body, msprintf("    struct task_struct *_pt%d = bpf_get_current_task_btf();", e));
      lines_push(body, msprintf("    struct %s_str_event *_pe%d = bpf_ringbuf_reserve(&%s_str_events, sizeof(*_pe%d), 0);", g_unit, e, g_unit, e));
      lines_push(body, msprintf("    if (_pe%d) {", e));
      { char *var = msprintf("_pe%d", e); cc_push_evt_hdr(body, "        ", var); free(var); }
      lines_push(body, msprintf("        __builtin_memset(_pe%d->str, 0, sizeof(_pe%d->str));", e, e));
      lines_push(body, msprintf("        bpf_d_path(&_pt%d->real_parent->mm->exe_file->f_path, _pe%d->str, sizeof(_pe%d->str));", e, e, e));
      lines_push(body, msprintf("        bpf_ringbuf_submit(_pe%d, 0);", e));
      lines_push(body, strdup("    } else spnl_lost_inc();   /* ring full -> account the dropped record */"));
      lines_push(body, strdup("}"));
      return strdup("0");
    }
    if (name && !strcmp(name, "sock_owner_set")) {   /* record sock ptr -> owning process (process ctx) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* sock_owner_set(sk): called in a process-context probe (e.g. kprobe/tcp_v4_connect).
       * Keys the correlation map by sock ptr and stores the current pid/comm. emit_connect
       * (softirq ESTABLISHED, where the current task is swapper/0) recovers the owner via
       * this map. Same sock ptr appears as skaddr in inet_sock_set_state (verified). */
      if (na != 1) die("sock_owner_set expects (sk) -- the struct sock * from a connect probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_sock_owner_set, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk} }, 3);
      free(sk);
      return strdup("0");
    }
    if (name && !strcmp(name, "req_start")) {   /* record L7 request send time keyed by sock */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* req_start(sk): in a send probe (kprobe/tcp_sendmsg, process ctx). Records send ktime +
       * pid/comm keyed by sock, but ONLY for the first send of a request (does not overwrite
       * mid-request bursts). emit_l7 (in the recv probe) computes the round-trip and deletes.
       * A second send overlapping an open request marks outstanding+=1 / mux=1 (* multiplexing guard -- see emit_l7). */
      if (na != 1) die("req_start expects (sk) -- the struct sock * from a send probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_req_start, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk} }, 3);
      free(sk);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_l7")) {   /* emit L7 round-trip latency (send->recv) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* emit_l7(sk): in a recv probe (kprobe/tcp_cleanup_rbuf, process ctx, fires AFTER data is
       * copied to the app = "response visible"). Looks up req_start[sk]; if present, packs one
       * record {process, peer, start_ktime, duration_ns} and deletes the entry (next send = new
       * request). duration = time-to-first-response-byte = L7 round-trip (verified).
       * mux guard (in the template): once >1 requests were ever outstanding on this sock
       * (HTTP/2 / pipelining) it is poisoned (mux=1) -- control-frame sends would restart a bogus
       * 1-outstanding measurement, so the whole connection is suppressed for its life (drain
       * outstanding, keep the poisoned entry, never emit garbage). HTTP/1.x keep-alive never
       * multiplexes, so it keeps emitting clean per-request RTT. */
      if (na != 1) die("emit_l7 expects (sk) -- the struct sock * from a recv probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_emit_l7, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk} }, 3);
      free(sk);
      return strdup("0");
    }
    if (name && !strcmp(name, "http_req_start")) {   /* capture HTTP request (method/path) at send */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* http_req_start(sk, msg): in kprobe/tcp_sendmsg (process ctx). Reads the first 64 bytes of the
       * send buffer; if it looks like an HTTP request (real method, NOT an "HTTP" response), stores
       * {start, pid, comm, req[64]} keyed by sock (first request send only). Server-side response-sends
       * start with "HTTP" so they never match -> only the CLIENT request is captured. QNAME-style:
       * kernel does a bounded copy, method/path parsing is done in userspace. */
      if (na != 2) die("http_req_start expects (sk, msg) from a send probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      char *msg = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_http_req_start, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk}, {"@MSG@", msg} }, 4);
      free(sk); free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "http_resp_stash")) {   /* stash recv buffer at recvmsg entry */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* http_resp_stash(sk, msg): in kprobe/tcp_recvmsg ENTRY. The response bytes are only in the user
       * buffer AFTER the copy, so we stash {sk, buffer-start} keyed by tid and read it in the kretprobe
       * (tcp_recvmsg is static-linkage so fexit is denied). */
      if (na != 2) die("http_resp_stash expects (sk, msg) from a recv probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      char *msg = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_http_resp_stash, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk}, {"@MSG@", msg} }, 4);
      free(sk); free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "http_emit")) {   /* emit HTTP L7 RED span (method/path/status/duration) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* http_emit(ret): in kretprobe/tcp_recvmsg. Reads the stashed recv buffer (response bytes now
       * copied), correlates with the pending request by sock, and emits ONE combined record
       * {process, peer, start_ktime, duration, req[64], resp[16]}. Parsing (method/path/status) is
       * done in userspace. ret (int) uses i32-style read for the >0 guard. */
      if (na != 1) die("http_emit expects (ret) -- the tcp_recvmsg return value", NULL);
      char *ret = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_http_emit, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@RET@", ret} }, 3);
      free(ret);
      return strdup("0");
    }
    if (name && !strcmp(name, "redis_req_start")) {   /* capture Redis (RESP) request at send */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* redis_req_start(sk, msg, size): in kprobe/tcp_sendmsg (process ctx). Mirrors http_req_start but
       * the filter is a RESP command sniff (spnl_is_redis_cmd: array-of-bulk-strings "*<digit>").
       * Redis messages are SHORT ("SET foo bar" = 31B), so a fixed 64B bpf_probe_read_user -EFAULTs
       * past the send buffer (HTTP never hit this -- requests are long). Bound the read to the actual
       * send length (`size` = tcp_sendmsg PARM3, the reliable count -- msg_iter.count read wrong here),
       * like emit_tcp_stream. Stores {start, pid, comm, req[64], cgid} keyed by sock (first send
       * only). Command parsing is userspace. */
      if (na != 3) die("redis_req_start expects (sk, msg, size) from a tcp_sendmsg probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      char *msg = cc_expr_str(ast, ids[1]);
      char *size = cc_expr_str(ast, ids[2]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_redis_req_start, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk}, {"@MSG@", msg}, {"@SIZE@", size} }, 5);
      free(sk); free(msg); free(size);
      return strdup("0");
    }
    if (name && !strcmp(name, "redis_resp_stash")) {   /* stash recv buffer at recvmsg entry */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* redis_resp_stash(sk, msg): in kprobe/tcp_recvmsg ENTRY. Identical to http_resp_stash -- the reply
       * bytes are only in the user buffer AFTER the copy, so stash {sk, buffer-start} by tid and read it
       * in the kretprobe. */
      if (na != 2) die("redis_resp_stash expects (sk, msg) from a recv probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      char *msg = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_redis_resp_stash, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk}, {"@MSG@", msg} }, 4);
      free(sk); free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "redis_emit")) {   /* emit Redis L7 RED span (command/error/duration) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* redis_emit(ret): in kretprobe/tcp_recvmsg. Mirrors http_emit but the reply-type guard accepts any
       * RESP reply prefix (+ - : $ *) instead of "HTTP". Emits ONE combined record
       * {process, peer, start_ktime, duration, req[64], resp[16]}; command/error parsing is userspace.
       * The reply read is bounded to the bytes received (ret): short replies like "+OK\r\n" (5B)
       * would -EFAULT on a fixed 16B read past the recv buffer. */
      if (na != 1) die("redis_emit expects (ret) -- the tcp_recvmsg return value", NULL);
      char *ret = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_redis_emit, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@RET@", ret} }, 3);
      free(ret);
      return strdup("0");
    }
    if (name && !strcmp(name, "ssl_req_start")) {   /* capture TLS-plaintext HTTP request at SSL_write */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* ssl_req_start(ssl, buf): in uprobe/SSL_write (process ctx). buf (PARM2) is the PLAINTEXT
       * before encryption. Reuses the HTTP channel's http_pending map + spnl_is_http_req filter, keyed by the
       * SSL* connection object (PARM1) instead of a sock. No peer (daddr/dport=0 -> userspace marks
       * url.scheme=https). same parser, only the hook/key differ. */
      if (na != 2) die("ssl_req_start expects (ssl, buf) from an SSL_write uprobe", NULL);
      char *ssl = cc_expr_str(ast, ids[0]);
      char *buf = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_ssl_req_start, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SSL@", ssl}, {"@BUF@", buf} }, 4);
      free(ssl); free(buf);
      return strdup("0");
    }
    if (name && !strcmp(name, "ssl_resp_stash")) {   /* stash SSL_read buffer at uprobe entry */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* ssl_resp_stash(ssl, buf): in uprobe/SSL_read ENTRY. The decrypted plaintext lands in buf only
       * AFTER SSL_read returns, so stash {ssl, buf} by tid and read it in the uretprobe. */
      if (na != 2) die("ssl_resp_stash expects (ssl, buf) from an SSL_read uprobe", NULL);
      char *ssl = cc_expr_str(ast, ids[0]);
      char *buf = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_ssl_resp_stash, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SSL@", ssl}, {"@BUF@", buf} }, 4);
      free(ssl); free(buf);
      return strdup("0");
    }
    if (name && !strcmp(name, "ssl_emit")) {   /* emit TLS-plaintext HTTP L7 RED span at SSL_read return */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* ssl_emit(ret): in uretprobe/SSL_read. Reads the stashed (now-decrypted) buffer, correlates
       * with the pending request by SSL*, and emits ONE combined record into the HTTP channel's http_events.
       * daddr/dport/family = 0 (no sock) -> userspace sets url.scheme=https and omits peer. */
      if (na != 1) die("ssl_emit expects (ret) -- the SSL_read return value", NULL);
      char *ret = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_ssl_emit, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@RET@", ret} }, 3);
      free(ret);
      return strdup("0");
    }
    if (name && !strcmp(name, "go_tls_write")) {   /* Go crypto/tls.(*Conn).Write plaintext -> request span */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* go_tls_write(conn, ptr, len): in uprobe/crypto/tls.(*Conn).Write (Go client, process ctx). The Go
       * slice arg (b []byte) decomposes to ptr(=data)/len in registers; on arm64 PT_REGS_PARM reads them
       *. ptr is the PLAINTEXT before encryption. Reads min(len, 64) bytes (bound by len,
       * a fixed read -EFAULTs on short Go request buffers), and if it looks like an HTTP request emits ONE
       * request-only http_event into the HTTP channel's http_events (method/path parsed in userspace; no sock ->
       * daddr=0 -> url.scheme=https; status/duration=0 until (*Conn).Read is added).
       * conn (PARM1) is the *Conn; unused here (request-only), kept for future response correlation. */
      if (na != 3) die("go_tls_write expects (conn, ptr, len) from a Go crypto/tls.(*Conn).Write uprobe", NULL);
      char *conn = cc_expr_str(ast, ids[0]);
      char *ptr = cc_expr_str(ast, ids[1]);
      char *len = cc_expr_str(ast, ids[2]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_go_tls_write, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@PTR@", ptr}, {"@LEN@", len} }, 4);
      free(conn); free(ptr); free(len);
      return strdup("0");
    }
    if (name && !strcmp(name, "go_tls_req")) {   /* Go crypto/tls.(*Conn).Write -> len-bound request stash (full RED) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* go_tls_req(conn, ptr, len): stash the request in http_pending keyed by conn (the *Conn), with a
       * len-bounded read (fixed read -EFAULTs on short Go requests). The len-bound, Go-native
       * request half of the full RED flow (paired with go_tls_resp_stash + go_tls_emit). */
      if (na != 3) die("go_tls_req expects (conn, ptr, len) from a Go crypto/tls.(*Conn).Write uprobe", NULL);
      char *conn = cc_expr_str(ast, ids[0]);
      char *ptr = cc_expr_str(ast, ids[1]);
      char *len = cc_expr_str(ast, ids[2]);
      int e = ++g_if_counter; char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_go_tls_req, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@CONN@", conn}, {"@PTR@", ptr}, {"@LEN@", len} }, 5);
      free(conn); free(ptr); free(len);
      return strdup("0");
    }
    if (name && !strcmp(name, "go_tls_resp_stash")) {   /* Go (*Conn).Read entry -- stash recv buf by g register */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* go_tls_resp_stash(conn, ptr): in uprobe/(*Conn).Read ENTRY. The decrypted response lands in the
       * buffer only AFTER Read returns, so stash {conn, ptr} keyed by the GOROUTINE (g register,
       * ctx->regs[28]) -- not tid, which can migrate M during a blocking Read. Read it at the RET
       * (go_tls_emit via go_uret). Needs ctx forwarded (uses_go_gptr). */
      if (na != 2) die("go_tls_resp_stash expects (conn, ptr) from a Go (*Conn).Read uprobe", NULL);
      char *conn = cc_expr_str(ast, ids[0]);
      char *ptr = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter; char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_go_tls_resp_stash, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@CONN@", conn}, {"@PTR@", ptr} }, 4);
      free(conn); free(ptr);
      return strdup("0");
    }
    if (name && !strcmp(name, "go_tls_emit")) {   /* Go (*Conn).Read RET (go_uret) -- correlate + full RED span */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* go_tls_emit(ret): at a (*Conn).Read RET (attached via go_uret). Reads the g register to find the
       * stashed {conn, buf}, reads min(ret,16) of the response ("HTTP/1.1 NNN.."), correlates the request
       * by conn (http_pending), and emits ONE full RED span (method/path + status + duration). */
      if (na != 1) die("go_tls_emit expects (ret) -- the (*Conn).Read return value", NULL);
      char *ret = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter; char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_go_tls_emit, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@RET@", ret} }, 3);
      free(ret);
      return strdup("0");
    }
    if (name && !strcmp(name, "offcpu_recv_stash")) {   /* stash server recv buffer (request in) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* offcpu_recv_stash(sk, msg): kprobe/tcp_recvmsg entry on a SERVER. Stash the recv buffer by
       * tid so offcpu_begin can read the request (method/path) at the kretprobe. */
      if (na != 2) die("offcpu_recv_stash expects (sk, msg) from a recv probe", NULL);
      char *msg = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_offcpu_recv_stash, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@MSG@", msg} }, 3);
      free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "offcpu_begin")) {   /* open the request window when the server got a request */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* offcpu_begin(ret): kretprobe/tcp_recvmsg. Read the stashed request bytes; if it is an HTTP
       * request (spnl_is_http_req), open a per-tid off-CPU window {start, offcpu=0, req[64]}. The tid
       * is the SERVER handler thread whose sleep/io/spin we then measure until the response send.
       * hdr_ext also gets the request head (128B best-effort traceparent inheritance). */
      if (na != 1) die("offcpu_begin expects (ret) -- the tcp_recvmsg return value", NULL);
      char *ret = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_offcpu_begin, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@RET@", ret} }, 3);
      free(ret);
      return strdup("0");
    }
    if (name && !strcmp(name, "offcpu_account")) {   /* accumulate voluntary off-CPU per active window */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* offcpu_account(prev_pid, prev_state, next_pid): tp/sched/sched_switch. `ctx` is forwarded
       * (uses_stack_trace). prev going off-CPU voluntarily (prev_state != 0) records the sleep start
       * + the wait's kernel stack (why it sleeps); next coming back adds the delta. Only tids with an
       * open window are accounted. */
      if (na != 3) die("offcpu_account expects (prev_pid, prev_state, next_pid)", NULL);
      char *pprev = cc_expr_str(ast, ids[0]);
      char *pstate = cc_expr_str(ast, ids[1]);
      char *pnext = cc_expr_str(ast, ids[2]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_offcpu_account, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@PPREV@", pprev}, {"@PSTATE@", pstate}, {"@PNEXT@", pnext} }, 5);
      free(pprev); free(pstate); free(pnext);
      return strdup("0");
    }
    if (name && !strcmp(name, "offcpu_emit")) {   /* close the window at response send, emit breakdown */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* offcpu_emit(sk, msg): kprobe/tcp_sendmsg (server sends the response). If a window is open for
       * this tid and the buffer is an HTTP response, emit {method/path, status, duration, offcpu,
       * wait_stack} and close. duration - offcpu = on-CPU. */
      if (na != 2) die("offcpu_emit expects (sk, msg) from a send probe", NULL);
      char *msg = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_offcpu_emit, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@MSG@", msg} }, 3);
      free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_connect")) {   /* packed connect event (process + remote + srtt) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* emit_connect(skaddr, daddr, dport, family, oldstate): one socket-state event
       * becomes one packed record. A single tracepoint fire writes it atomically, so
       * there is no way for separate string records to desync. The pid and comm are
       * read internally; srtt_us comes from the socket through CO-RE, since the
       * pointer is untrusted. The record is about the remote end, and the previous
       * state is what lets userspace decide the direction
       * the raw previous TCP state. A six-argument handler gets past the five-register limit through the caps struct. */
      if (na != 7) die("emit_connect expects (skaddr, daddr, dport, family, oldstate, daddr6_hi, daddr6_lo)", NULL);
      char *skaddr = cc_expr_str(ast, ids[0]);
      char *daddr  = cc_expr_str(ast, ids[1]);
      char *dport  = cc_expr_str(ast, ids[2]);
      char *family = cc_expr_str(ast, ids[3]);
      char *oldstate = cc_expr_str(ast, ids[4]);
      char *daddr6_hi = cc_expr_str(ast, ids[5]);
      char *daddr6_lo = cc_expr_str(ast, ids[6]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_emit_connect_head, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb} }, 2);
      /* softirq ESTABLISHED for external connects runs as swapper/0; recover the
       * real owner recorded at connect time (process ctx) by sock-ptr lookup. */
      if (g_uses_sock_owner)
        tpl_emit_lines(body, tpl_bi_emit_connect_owner, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SKADDR@", skaddr} }, 3);
      tpl_emit_lines(body, tpl_bi_emit_connect_tail, (TplSlot[]){ {"@E@", _eb}, {"@SKADDR@", skaddr}, {"@DADDR@", daddr}, {"@DPORT@", dport}, {"@FAMILY@", family}, {"@OLDSTATE@", oldstate}, {"@DADDR6_HI@", daddr6_hi}, {"@DADDR6_LO@", daddr6_lo} }, 8);
      free(skaddr); free(daddr); free(dport); free(family); free(oldstate); free(daddr6_hi); free(daddr6_lo);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_dns")) {   /* resolver-independent DNS query (socket :53) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* emit_dns(msg): the first 64 bytes of the DNS payload -- the header and the
       * QNAME -- become one record. Turning the length-prefixed labels into a dotted
       * name happens in userspace; walking them in the kernel makes verifier state
       * explode. The pid and comm are read internally. Watching the socket rather
       * than a resolver library is what catches a program with its own resolver. */
      if (na != 1) die("emit_dns expects (msg) -- the udp_sendmsg msghdr", NULL);
      char *msg = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_emit_dns, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@MSG@", msg} }, 3);
      free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "dns_req_start")) {   /* record DNS query start keyed by (sock,txid) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* dns_req_start(sk, msg): in kprobe/udp_sendmsg (process ctx, filter :53 in the probe). Reads the
       * DNS transaction ID (payload bytes 0..1, big-endian) from the send buffer and records the send
       * ktime keyed by (sock<<16 | txid) so A+AAAA on one socket stay distinct. dns_emit correlates. */
      if (na != 2) die("dns_req_start expects (sk, msg) from a udp_sendmsg probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      char *msg = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_dns_req_start, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk}, {"@MSG@", msg} }, 4);
      free(sk); free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "dns_resp_stash")) {   /* stash DNS recv buffer at udp_recvmsg entry */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* dns_resp_stash(sk, msg): in kprobe/udp_recvmsg ENTRY. The response bytes are only in the user
       * buffer AFTER the copy, so we stash {sk, buffer-start} keyed by tid and read it in the kretprobe
       * (mirror of the HTTP channel's http_resp_stash). */
      if (na != 2) die("dns_resp_stash expects (sk, msg) from a udp_recvmsg probe", NULL);
      char *sk = cc_expr_str(ast, ids[0]);
      char *msg = cc_expr_str(ast, ids[1]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_dns_resp_stash, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk}, {"@MSG@", msg} }, 4);
      free(sk); free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "dns_emit")) {   /* emit DNS response with RTT at udp_recvmsg return */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* dns_emit(ret): in kretprobe/udp_recvmsg. Reads the stashed recv buffer (response bytes now
       * copied), takes the response transaction ID, correlates with the pending query by
       * (sock<<16 | txid), and emits ONE dns_event {process, raw[64] (QNAME echoed in the response),
       * duration_ns = RTT}. Reuses the dns_events ringbuf; the QNAME is parsed in userspace.
       * ret (int) uses the i32-style read for the >0 guard. */
      if (na != 1) die("dns_emit expects (ret) -- the udp_recvmsg return value", NULL);
      char *ret = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_dns_emit, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@RET@", ret} }, 3);
      free(ret);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_comm")) {   /* comm via str ringbuf */
      int e = ++g_if_counter;
      lines_push(body, strdup("{"));
      lines_push(body, msprintf("    struct %s_str_event *_se%d = bpf_ringbuf_reserve(&%s_str_events, sizeof(*_se%d), 0);", g_unit, e, g_unit, e));
      lines_push(body, msprintf("    if (_se%d) {", e));
      { char *var = msprintf("_se%d", e); cc_push_evt_hdr(body, "        ", var); free(var); }
      lines_push(body, msprintf("        bpf_get_current_comm(_se%d->str, sizeof(_se%d->str));", e, e));
      lines_push(body, msprintf("        bpf_ringbuf_submit(_se%d, 0);", e));
      lines_push(body, strdup("    } else spnl_lost_inc();   /* ring full -> account the dropped record */"));
      lines_push(body, strdup("}"));
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_tcp_payload")) {   /* generic L7 send-buffer capture via str ringbuf */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* emit_tcp_payload(msg): from a tcp_sendmsg (or udp_sendmsg) probe, copy the first 128
       * bytes of the send buffer to the str ringbuf for userspace L7 parsing (e.g. Redis RESP).
       * TCP sibling of emit_dns: kernel is PROTOCOL-AGNOSTIC (just grabs bytes), parsing
       * is userspace. Reuses the str_events ringbuf + the spnl_stream %s print path. The
       * 256B str[] is memset first so the copied 128B stay NUL-terminated (RESP has no NUL). */
      if (na != 1) die("emit_tcp_payload expects (msg) -- the tcp_sendmsg msghdr", NULL);
      char *msg = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_emit_tcp_payload, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@MSG@", msg} }, 3);
      free(msg);
      return strdup("0");
    }
    if (name && !strcmp(name, "emit_tcp_stream")) {   /* sock-keyed, length-bounded L7 stream capture */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      /* emit_tcp_stream(sk, msg, size): from a kprobe/tcp_sendmsg (sk=PARM1, msg=PARM2, size=PARM3),
       * emit ONE packed record {sock, len, raw[128]} so userspace can group L7 fragments PER
       * CONNECTION (by sock ptr) and reassemble byte-exactly (bounded by the real send length).
       * Sock-aware upgrade of emit_tcp_payload (the earlier form, which had no sock and no length -> multi-
       * connection interleaving broke reassembly). Length-bounded copy: `size` is an unbounded
       * scalar from tcp_sendmsg, so cap it to 128 (a proven bound the verifier accepts for
       * bpf_probe_read_user's size argument, dst = raw[128]). raw is NOT NUL-terminated; userspace
       * reads exactly `len` bytes (hex-printed to avoid CRLF/NUL mangling). */
      if (na != 3) die("emit_tcp_stream expects (sk, msg, size) from a tcp_sendmsg probe", NULL);
      char *sk   = cc_expr_str(ast, ids[0]);
      char *msg  = cc_expr_str(ast, ids[1]);
      char *size = cc_expr_str(ast, ids[2]);
      int e = ++g_if_counter;
      char _eb[16]; snprintf(_eb, sizeof _eb, "%d", e);
      tpl_emit_lines(body, tpl_bi_emit_tcp_stream, (TplSlot[]){ {"@UNIT@", g_unit}, {"@E@", _eb}, {"@SK@", sk}, {"@MSG@", msg}, {"@SIZE@", size} }, 5);
      free(sk); free(msg); free(size);
      return strdup("0");
    }
    /* tcp_sock_<field>_set(sk, v) / _add(sk, d) flat writers/adders (statement). */
    {
      const char *wf = cc_tcp_sock_writer_field(name);
      const char *af = wf ? NULL : cc_tcp_sock_adder_field(name);
      if (wf || af) {
        if (!cc_in_tcp_cc()) die("tcp_sock_* is only valid inside tcp_cc__<member> methods", name);
        int args_id = nt_ref(ast, nid, "arguments");
        int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
        if (na != 2) die("tcp_sock_<field>_set/_add(sk, value) expects 2 args", name);
        char *sk = cc_expr_str(ast, ids[0]), *v = cc_expr_str(ast, ids[1]);
        cc_emit_tcp_sock_write(body, wf ? wf : af, wf ? "=" : "+=", sk, v);
        free(sk); free(v);
        return strdup("0");
      }
    }
    /* sk.<field> = v dot-write sugar. Arrives as CallNode name="<field>=",
     * receiver=sk, 1 arg. Mirrors codegen_bpf.rb try_tcp_sock_dot_call (setter). */
    if (name) {
      size_t nl = strlen(name);
      int recv = nt_ref(ast, nid, "receiver");
      if (recv >= 0 && nl > 1 && name[nl - 1] == '=' && cc_in_tcp_cc()) {
        char *field = malloc(nl); memcpy(field, name, nl - 1); field[nl - 1] = '\0';
        if (cc_tcp_sock_is_field(field)) {
          int args_id = nt_ref(ast, nid, "arguments");
          int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
          if (na != 1) die("sk.<field>= expects 1 arg", name);
          char *rexpr = cc_expr_str(ast, recv), *v = cc_expr_str(ast, ids[0]);
          cc_emit_tcp_sock_write(body, field, "=", rexpr, v);
          free(rexpr); free(v); free(field);
          return strdup("0");
        }
        free(field);
      }
    }
  }
  return cc_expr_str(ast, nid);
}

/* lower a method body into the `body` line list: local declarations, then the
 * body statements, then `return <last-value>;`. Mirrors MethodEmitter#emit
 * (declare_locals + lower_body + finalize_return). */
static void cc_emit_method_body(AST *ast, const Method *me, Lines *body) {
  g_if_counter = 0;   /* per-method fresh counter */
  g_n_kptr = 0;       /* kptr-bound locals are method-scoped */
  g_body = body;      /* line accumulator for ivar reads emitted from cc_lower_expr */
  g_method = me;      /* for ivar map scope (class vs top-level) */
  int bid = me->body_id;
  const char *ty = nt_type(ast, bid);
  if (!ty || strcmp(ty, "StatementsNode")) die("body not StatementsNode (Stage 1)", ty ? ty : "?");

  /* declare_locals: collected write-targets minus params, in first-write order. */
  Lines locals; memset(&locals, 0, sizeof locals);
  cc_collect_locals(ast, bid, &locals);
  for (int i = 0; i < locals.n; i++) {
    int is_param = 0;
    for (int k = 0; k < me->nparams; k++) if (!strcmp(locals.v[i], me->pnames[k])) { is_param = 1; break; }
    if (!is_param) lines_push(body, msprintf("__s64 %s = 0;", locals.v[i]));
  }

  char *v = cc_lower_stmt(ast, bid, body);   /* lower_body (the StatementsNode) */
  /* finalize_return. struct_ops member _inners are always declared __s64 (the
   * BPF_PROG wrapper adapts to the real member return type), so they must always
   * return a value even when the body's inferred type is void/nil -- matching the
   * Ruby codegen, whose struct_ops _inner is likewise always __s64. */
  if (me->ret != CC_TY_VOID || me->so_kind != SO_NONE)
    lines_push(body, msprintf("return %s;", v ? v : "0"));
  free(v);
}

static void lines_free(Lines *L) { for (int i = 0; i < L->n; i++) free(L->v[i]); free(L->v); }

/* BlockParametersNode|ParametersNode -> first required block param (C-safe), or NULL. */
static char *cc_extract_block_param(AST *ast, int bp_id) {
  if (bp_id < 0) return NULL;
  const char *bt = nt_type(ast, bp_id);
  if (!bt) return NULL;
  int params_id;
  if (!strcmp(bt, "BlockParametersNode")) params_id = nt_ref(ast, bp_id, "parameters");
  else if (!strcmp(bt, "ParametersNode")) params_id = bp_id;
  else return NULL;
  if (params_id < 0) return NULL;
  const char *pt = nt_type(ast, params_id);
  if (!pt || strcmp(pt, "ParametersNode")) return NULL;
  int nr; const int *req = nt_arr(ast, params_id, "requireds", &nr);
  if (nr != 1) return NULL;
  const char *rt = nt_type(ast, req[0]);
  if (!rt || strcmp(rt, "RequiredParameterNode")) return NULL;
  const char *nm = nt_str(ast, req[0], "name");
  return nm ? cc_safe_dup(nm) : NULL;
}

/* collect every local read/written in a subtree (C-safe, first-encounter order). */
static void cc_collect_capture_refs(AST *ast, int nid, Lines *refs) {
  if (nid < 0) return;
  const char *ty = nt_type(ast, nid);
  if (!ty) return;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return;
  if (!strcmp(ty, "LocalVariableReadNode") || !strcmp(ty, "LocalVariableWriteNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm) { char *s = cc_safe_dup(nm); if (!lines_has(refs, s)) lines_push(refs, s); else free(s); }
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) cc_collect_capture_refs(ast, n->r[i].ref, refs);
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) cc_collect_capture_refs(ast, n->a[i].ids[k], refs);
}

/* outer-accessible names (g_method params + declared locals) referenced in
 * the block body, minus the block param, in block-body first-reference order. */
static void cc_collect_captures(AST *ast, int body_id, const char *block_param, Lines *out) {
  Lines outer; memset(&outer, 0, sizeof outer);
  for (int k = 0; k < g_method->nparams; k++) lines_push(&outer, strdup(g_method->pnames[k]));
  Lines outloc; memset(&outloc, 0, sizeof outloc);
  cc_collect_locals(ast, g_method->body_id, &outloc);
  for (int i = 0; i < outloc.n; i++) if (!lines_has(&outer, outloc.v[i])) lines_push(&outer, strdup(outloc.v[i]));
  Lines refs; memset(&refs, 0, sizeof refs);
  cc_collect_capture_refs(ast, body_id, &refs);
  for (int i = 0; i < refs.n; i++) {
    if (!strcmp(refs.v[i], block_param)) continue;
    if (lines_has(&outer, refs.v[i])) lines_push(out, strdup(refs.v[i]));
  }
  lines_free(&outer); lines_free(&outloc); lines_free(&refs);
}

/* lower `n.times { |i| ... }`. Dynamic N -> a deferred bpf_loop callback
 * (+ a capture struct if the block references outer locals); the call site emits
 * the optional caps instance and `bpf_loop(...)`. Mirrors Ruby times_call. */
static char *cc_times_call(AST *ast, int nid, Lines *body) {
  int recv = nt_ref(ast, nid, "receiver");
  int block_id = nt_ref(ast, nid, "block");
  if (recv < 0) die("times needs receiver", NULL);
  const char *bt = nt_type(ast, block_id);
  if (!bt || strcmp(bt, "BlockNode")) die("expected BlockNode", NULL);
  char *bp = cc_extract_block_param(ast, nt_ref(ast, block_id, "parameters"));
  if (!bp) die("n.times block must have single required param", NULL);
  int body_id = nt_ref(ast, block_id, "body");
  if (body_id < 0) die("block body missing", NULL);

  const char *rty = nt_type(ast, recv);
  if (rty && !strcmp(rty, "IntegerNode"))
    die("n.times open-coded iterator (literal N) not yet ported (Stage 1)", NULL);

  char *fn = cc_func_name(g_method), *qn = cc_qual_name(g_method);
  int lc = ++g_loop_counter;
  char *cb_name = msprintf("%s_loop%d_cb", fn, lc);

  Lines caps; memset(&caps, 0, sizeof caps);
  cc_collect_captures(ast, body_id, bp, &caps);

  /* lower the block body as a sub-function: fresh counter, capture set active. */
  int saved_if = g_if_counter; Lines *saved_body = g_body, *saved_caps = g_captures;
  g_if_counter = 0; g_captures = (caps.n > 0) ? &caps : NULL;
  Lines sub; memset(&sub, 0, sizeof sub); g_body = &sub;
  Lines blocals; memset(&blocals, 0, sizeof blocals);
  cc_collect_locals(ast, body_id, &blocals);
  for (int i = 0; i < blocals.n; i++) {
    if (!strcmp(blocals.v[i], bp) || lines_has(&caps, blocals.v[i])) continue;   /* skip block param + captures */
    lines_push(&sub, msprintf("__s64 %s = 0;", blocals.v[i]));
  }
  free(cc_lower_stmt(ast, body_id, &sub));
  lines_push(&sub, strdup("return 0;"));   /* bpf_loop callback contract */
  g_if_counter = saved_if; g_body = saved_body; g_captures = saved_caps;

  /* deferred: caps struct (if any), then the callback. */
  char *caps_struct = NULL;
  if (caps.n > 0) {
    caps_struct = msprintf("%s_caps", cb_name);
    Buf st; memset(&st, 0, sizeof st);
    buf_printf(&st, "/* loop captures for %s */\n", qn);
    buf_printf(&st, "struct %s {\n", caps_struct);
    for (int i = 0; i < caps.n; i++) buf_printf(&st, "    __s64 *%s;\n", caps.v[i]);
    buf_puts(&st, "};\n");
    lines_push(g_deferred, st.p);
  }
  {
    Buf cb; memset(&cb, 0, sizeof cb);
    buf_printf(&cb, "/* loop callback: emitted for %s */\n", qn);
    buf_printf(&cb, "static int %s(__u32 _raw_index, void *_raw_ctx)\n{\n", cb_name);
    buf_printf(&cb, "    __s64 %s = (__s64)_raw_index;\n", bp);
    if (caps.n > 0) buf_printf(&cb, "    struct %s *_lc = (struct %s *)_raw_ctx;\n", caps_struct, caps_struct);
    else            buf_puts(&cb, "    (void)_raw_ctx;\n");
    for (int i = 0; i < sub.n; i++) { char *t = cc_indent_each(sub.v[i]); buf_puts(&cb, t); buf_puts(&cb, "\n"); free(t); }
    buf_puts(&cb, "}\n");
    lines_push(g_deferred, cb.p);
  }

  /* call site: caps instance (if any) + bpf_loop. */
  char *cb_ctx_arg;
  if (caps.n > 0) {
    Buf inits; memset(&inits, 0, sizeof inits);
    for (int i = 0; i < caps.n; i++) buf_printf(&inits, "%s.%s = &%s", i ? ", " : "", caps.v[i], caps.v[i]);
    lines_push(body, msprintf("struct %s _loop%d_caps = { %s };", caps_struct, lc, inits.p));
    free(inits.p);
    cb_ctx_arg = msprintf("&_loop%d_caps", lc);
  } else {
    cb_ctx_arg = strdup("NULL");
  }
  char *bound = cc_expr_str(ast, recv);
  lines_push(body, msprintf("bpf_loop(%s, &%s, %s, 0);", bound, cb_name, cb_ctx_arg));

  free(bound); free(cb_ctx_arg); free(cb_name); free(fn); free(qn); free(caps_struct); free(bp);
  lines_free(&caps); lines_free(&sub); lines_free(&blocals);
  return strdup("0");   /* n.times: side-effecting, no expression value */
}

/* Stage 2: collect top-level ivar names by walking a method body for
 * InstanceVariable* nodes -- the AST-derived equivalent of Ruby
 * collect_toplevel_ivars_used. Names keep their leading '@' (the IR-field form);
 * deduped here, caller sorts. This removes the codegen's reliance on the
 * @toplevel_ivar_names IR field, which the upstream C compiler does not emit --
 * the prerequisite for reading the Compiler struct in-process. */
static void cc_collect_ivar_names(AST *ast, int nid, Lines *out) {
  if (nid < 0) return;
  const char *ty = nt_type(ast, nid);
  if (!ty) return;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return;
  if (!strncmp(ty, "InstanceVariable", 16)) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm && !lines_has(out, nm)) lines_push(out, strdup(nm));
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) cc_collect_ivar_names(ast, n->r[i].ref, out);
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) cc_collect_ivar_names(ast, n->a[i].ids[k], out);
}

/* does any node in this subtree call the builtin `name`? (drives per-unit
 * map+helper section flags: blocklist / cidr / path_counter / ...). */
static int cc_body_uses_call(AST *ast, int nid, const char *name) {
  if (nid < 0) return 0;
  const char *ty = nt_type(ast, nid);
  if (!ty) return 0;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return 0;
  if (!strcmp(ty, "CallNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm && !strcmp(nm, name)) return 1;
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) if (cc_body_uses_call(ast, n->r[i].ref, name)) return 1;
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) if (cc_body_uses_call(ast, n->a[i].ids[k], name)) return 1;
  return 0;
}

/* scan a subtree for emit-family calls, OR-ing the per-unit
 * ringbuf channels in use into *f (bit0=int spnl_emit, 1=str, 2=pair, 3=emit3,
 * 4=emit4). Pre-scan so the channel sections emit before the method bodies. */
enum { EMIT_INT = 1, EMIT_STR = 2, EMIT_PAIR = 4, EMIT_E3 = 8, EMIT_E4 = 16, EMIT_CONN = 32, EMIT_DNS = 64, EMIT_L7 = 128, EMIT_L7STREAM = 256 };
static void cc_scan_emit(AST *ast, int nid, int *f) {
  if (nid < 0) return;
  const char *ty = nt_type(ast, nid);
  if (!ty) return;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return;
  if (!strcmp(ty, "CallNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm) {
      if      (!strcmp(nm, "spnl_emit"))      *f |= EMIT_INT;
      else if (!strcmp(nm, "spnl_emit_str"))  *f |= EMIT_STR;
      else if (!strcmp(nm, "emit_comm"))      *f |= EMIT_STR;   /* comm via str ringbuf */
      else if (!strcmp(nm, "emit_argv"))      *f |= EMIT_STR;   /* argv via str ringbuf */
      else if (!strcmp(nm, "emit_path"))      *f |= EMIT_STR;   /* full path via bpf_d_path */
      else if (!strcmp(nm, "emit_parent_path")) *f |= EMIT_STR; /* parent exe path via bpf_d_path */
      else if (!strcmp(nm, "emit_kfield_str")) *f |= EMIT_STR;  /* kernel struct string field */
      else if (!strcmp(nm, "emit_tcp_payload")) *f |= EMIT_STR;  /* L7 send buffer via str ringbuf */
      else if (!strcmp(nm, "emit_tcp_stream")) *f |= EMIT_L7STREAM;  /* sock-keyed packed L7 stream record */
      else if (!strcmp(nm, "spnl_emit_pair")) *f |= EMIT_PAIR;
      else if (!strcmp(nm, "spnl_emit3"))     *f |= EMIT_E3;
      else if (!strcmp(nm, "spnl_emit4"))     *f |= EMIT_E4;
      else if (!strcmp(nm, "emit_connect"))   *f |= EMIT_CONN;  /* packed connect event */
      else if (!strcmp(nm, "emit_dns"))       *f |= EMIT_DNS;   /* DNS query event */
      else if (!strcmp(nm, "dns_emit"))       *f |= EMIT_DNS;   /* DNS RTT event reuses the same ringbuf */
      else if (!strcmp(nm, "emit_l7"))        *f |= EMIT_L7;    /* L7 latency event */
    }
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) cc_scan_emit(ast, n->r[i].ref, f);
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) cc_scan_emit(ast, n->a[i].ids[k], f);
}

/* ---------- attach (method-name prefix -> SEC + ctx). AttachKind / Attach
 * are declared earlier (cc_lower_expr needs them for pkt_* ctx-kind). ---------- */
/* tracing-family kinds that extract args from ctx (and so get ctx forwarded
 * into the inner only when the unit uses stack traces, for bpf_get_stackid). */
static int cc_is_tracing_kind(AttachKind k) {
  return k == AK_KPROBE || k == AK_KRETPROBE || k == AK_UPROBE || k == AK_URETPROBE ||
         k == AK_USDT || k == AK_TRACEPOINT || k == AK_FENTRY || k == AK_FEXIT ||
         k == AK_KPROBE_MULTI;
}

static int cc_starts(const char *s, const char *pfx, const char **rest) {
  size_t n = strlen(pfx);
  if (strncmp(s, pfx, n) == 0) { *rest = s + n; return 1; }
  return 0;
}

/* Attach kinds that the C-codegen port dropped and that are NOT coming back
 * without their companion machinery. Withdrawing them from the affordance
 * (Capabilities::WITHDRAWN_ATTACH) is only half the fix: an unported attach kind
 * is not a compile error, it is a method name that matches nothing, so the
 * codegen happily wraps it in SEC("syscall") and emits a program that loads,
 * attaches to nothing, and never fires. All four were measured that way: exit 0,
 * zero diagnostics, output byte-identical to a plain method.
 *
 * That is the failure mode this project exists to forbid, so they are refused
 * here -- at the layer that still knows which hook the author wrote. Each message
 * says what is missing, where it was measured, and what to write instead.
 *
 * `on :timer` / `on :user_cmd` (the reactor surface for two of these) are
 * refused in cc_synthesize_reactor, which is worse still without this: an
 * unknown reactor kind is skipped, so the whole handler body disappears. */
typedef struct { const char *prefix; const char *why; } CcWithdrawnAttach;
static const CcWithdrawnAttach CC_WITHDRAWN_ATTACH[] = {
  { "xdp__tcp_slice__",
    "the pure-XDP TCP slice generated a ~470-line state machine plus seven\n"
    "  builtins (tcp_syncookie_gen/_check, tcp_reply_header/_synack, tcp_synack_cookie,\n"
    "  tcp_reply_data, payload_starts). None of it survived the port to the C codegen, and\n"
    "  the seven builtins were withdrawn with it. This name used to compile to a plain\n"
    "  SEC(\"syscall\") wrapper: your marker body became the whole program.\n"
    "  Write a normal `def xdp__<name>` handler (SEC(\"xdp\"), pkt_* / pkt.* builtins) and\n"
    "  terminate the connection in userspace" },
  { "xdp_tail__",
    "a tail-call target needs the PROG_ARRAY the dispatcher jumps through, and\n"
    "  `tail_call_to` (the jump itself) was withdrawn as unported. The glue side\n"
    "  (_spnl_prog_array_populate) is still there and would populate `spnl_prog_array`,\n"
    "  but no codegen emits that map. This name used to compile to a plain\n"
    "  SEC(\"syscall\") wrapper -- not an XDP program at all.\n"
    "  Write the branches inside one `def xdp__<name>` (the 1M-instruction budget is per\n"
    "  program, and the split existed to get more of it)" },
  { "user_ringbuf__",
    "the host->kernel command channel needs three pieces that did not survive the\n"
    "  port to the C codegen: the USER_RINGBUF map, the SEC-less callback this method was\n"
    "  supposed to become, and `user_ringbuf_drain` (withdrawn with them). This name used\n"
    "  to compile to a plain SEC(\"syscall\") wrapper, so the \"callback\" was a program\n"
    "  nothing ever drained.\n"
    "  Push configuration through `param :name, default: N` or a HASH map written\n"
    "  from userspace instead" },
  { "spnl_timer__",
    "`on :timer, every: N` needs a bpf_timer map, an arm program and a re-arming\n"
    "  callback; none survived the port to the C codegen. The glue side\n"
    "  (_spnl_timer_arm_all) is still there and looks for `spnl_timer_arm_*`, which\n"
    "  no codegen emits. The reactor form measured worse than silent: the C reactor\n"
    "  table has no :timer, so the block was dropped and the body never reached the output.\n"
    "  Do periodic work in the userspace drain loop (`loop { sleep n; ... }`), which is\n"
    "  where every OTLP push in this tree already does it" },
  { NULL, NULL }
};
static void cc_refuse_withdrawn_attach(const char *name) {
  if (!name) return;
  for (int i = 0; CC_WITHDRAWN_ATTACH[i].prefix; i++) {
    const char *p = CC_WITHDRAWN_ATTACH[i].prefix;
    if (strncmp(name, p, strlen(p))) continue;
    char *msg = msprintf(
      "`%s...` is not an attach kind this codegen implements.\n"
      "  %s.\n"
      "  It is recorded in Capabilities::WITHDRAWN_ATTACH, so `spinel-ebpf capabilities`\n"
      "  no longer advertises it. Refused here rather than compiled into a program that\n"
      "  loads and never fires.\n"
      "  You wrote it as", p, CC_WITHDRAWN_ATTACH[i].why);
    die(msg, name);
  }
}

static AttachKind cc_detect_attach(const char *name, Attach *a) {
  const char *rest;
  memset(a, 0, sizeof *a);
  /* `on :kprobe, %w[...]` -- ONE body, N symbols. The SEC named here is
   * the multi lowering's; when the codegen picks expansion the wrapper loop
   * emits SEC("kprobe/<sym>") per symbol instead and never consults this field.
   * Checked before "kprobe__" only for reading order -- the prefixes do not
   * overlap ("kprobe_multi__" does not start with "kprobe__"). */
  if      (cc_starts(name, "kprobe_multi__", &rest)) { a->kind = AK_KPROBE_MULTI; a->sec = strdup("kprobe.multi"); a->ctx_type = "struct pt_regs *"; a->kname = "kprobe_multi"; }
  else if (cc_starts(name, "kprobe__", &rest))    { a->kind = AK_KPROBE;    a->sec = msprintf("kprobe/%s", rest);    a->ctx_type = "struct pt_regs *"; a->kname = "kprobe"; }
  else if (cc_starts(name, "kretprobe__", &rest)) { a->kind = AK_KRETPROBE; a->sec = msprintf("kretprobe/%s", rest); a->ctx_type = "struct pt_regs *"; a->kname = "kretprobe"; }
  else if (cc_starts(name, "fentry__", &rest))    { a->kind = AK_FENTRY;    a->sec = msprintf("fentry/%s", rest);    a->ctx_type = "__u64 *"; a->kname = "fentry"; }
  else if (cc_starts(name, "fexit__", &rest))     { a->kind = AK_FEXIT;     a->sec = msprintf("fexit/%s", rest);     a->ctx_type = "__u64 *"; a->kname = "fexit"; }
  else if (cc_starts(name, "tc__ingress__", &rest)) { a->kind = AK_TC; a->sec = strdup("tcx/ingress"); a->ctx_type = "struct __sk_buff *"; a->kname = "tc_ingress"; a->ctx_prefixed = 1; a->verdict = 1; }
  else if (cc_starts(name, "tc__egress__", &rest))  { a->kind = AK_TC; a->sec = strdup("tcx/egress");  a->ctx_type = "struct __sk_buff *"; a->kname = "tc_egress";  a->ctx_prefixed = 1; a->verdict = 1; }
  /* verdict-style socket programs (SK_PASS/SK_DROP), ctx-prefixed inner. */
  else if (cc_starts(name, "sk_reuseport__", &rest))   { a->kind = AK_SK_VERDICT; a->sec = strdup("sk_reuseport");        a->ctx_type = "struct sk_reuseport_md *"; a->kname = "sk_reuseport";    a->ctx_prefixed = 1; a->verdict = 1; }
  else if (cc_starts(name, "sk_msg__", &rest))         { a->kind = AK_SK_VERDICT; a->sec = strdup("sk_msg");              a->ctx_type = "struct sk_msg_md *";       a->kname = "sk_msg";          a->ctx_prefixed = 1; a->verdict = 1; }
  else if (cc_starts(name, "sk_skb__verdict__", &rest)){ a->kind = AK_SK_VERDICT; a->sec = strdup("sk_skb/stream_verdict"); a->ctx_type = "struct __sk_buff *";       a->kname = "sk_skb_verdict";  a->ctx_prefixed = 1; a->verdict = 1; }
  else if (cc_starts(name, "sk_skb__parser__", &rest)) { a->kind = AK_SK_VERDICT; a->sec = strdup("sk_skb/stream_parser");  a->ctx_type = "struct __sk_buff *";       a->kname = "sk_skb_parser";   a->ctx_prefixed = 1; a->verdict = 1; }
  /* socket_filter / flow_dissector / sk_lookup -- verdict + ctx-prefixed. */
  else if (cc_starts(name, "socket_filter__", &rest)) { a->kind = AK_SK_VERDICT; a->sec = strdup("socket");         a->ctx_type = "struct __sk_buff *";     a->kname = "socket_filter"; a->ctx_prefixed = 1; a->verdict = 1; }
  else if (cc_starts(name, "flow_dissector__", &rest)){ a->kind = AK_SK_VERDICT; a->sec = strdup("flow_dissector"); a->ctx_type = "struct __sk_buff *";     a->kname = "flow_dissector"; a->ctx_prefixed = 1; a->verdict = 1; }
  else if (cc_starts(name, "sk_lookup__", &rest))     { a->kind = AK_SK_VERDICT; a->sec = strdup("sk_lookup");      a->ctx_type = "struct bpf_sk_lookup *"; a->kname = "sk_lookup";     a->ctx_prefixed = 1; a->verdict = 1; }
  /* cgroup/connect4 / bind4 (sock_addr) -- verdict (1=allow/0=deny) + ctx-prefixed. */
  else if (cc_starts(name, "cgroup__connect4__", &rest)) { a->kind = AK_SK_VERDICT; a->sec = strdup("cgroup/connect4"); a->ctx_type = "struct bpf_sock_addr *"; a->kname = "cgroup_connect4"; a->ctx_prefixed = 1; a->verdict = 1; }
  else if (cc_starts(name, "cgroup__bind4__", &rest))    { a->kind = AK_SK_VERDICT; a->sec = strdup("cgroup/bind4");    a->ctx_type = "struct bpf_sock_addr *"; a->kname = "cgroup_bind4";    a->ctx_prefixed = 1; a->verdict = 1; }
  /* uprobe / uretprobe -- pt_regs args (like kprobe), SEC is the bare kind. */
  else if (cc_starts(name, "uprobe__", &rest))    { a->kind = AK_UPROBE;    a->sec = strdup("uprobe");    a->ctx_type = "struct pt_regs *"; a->kname = "uprobe"; }
  else if (cc_starts(name, "uretprobe__", &rest)) { a->kind = AK_URETPROBE; a->sec = strdup("uretprobe"); a->ctx_type = "struct pt_regs *"; a->kname = "uretprobe"; }
  /* USDT -- bpf_usdt_arg prologue, SEC("usdt"). usdt__<provider>__<probe>. */
  else if (cc_starts(name, "usdt__", &rest) && strstr(rest, "__")) { a->kind = AK_USDT; a->sec = strdup("usdt"); a->ctx_type = "struct pt_regs *"; a->kname = "usdt"; a->usdt = 1; }
  /* LSM / fmod_ret -- ctx[i] args (like fexit) + verdict propagate. */
  else if (cc_starts(name, "lsm__", &rest))       { a->kind = AK_LSM;      a->sec = msprintf("lsm/%s", rest);       a->ctx_type = "__u64 *"; a->kname = "lsm";      a->verdict = 1; }
  else if (cc_starts(name, "fmod_ret__", &rest))  { a->kind = AK_FMOD_RET; a->sec = msprintf("fmod_ret/%s", rest);  a->ctx_type = "__u64 *"; a->kname = "fmod_ret"; a->verdict = 1; }
  /* bpf_iter over tasks -- ctx-prefixed, NULL-terminator guard. */
  else if (cc_starts(name, "iter__task__", &rest)) { a->kind = AK_ITER_TASK; a->sec = strdup("iter/task"); a->ctx_type = "struct bpf_iter__task *"; a->kname = "iter_task"; a->ctx_prefixed = 1; a->iter_guard = 1; }
  /* SOCK_OPS -- cgroup-scoped TCP state observation. ctx-prefixed
   * (sock_ops_op / sock_ops_state read ctx), NOT verdict-propagating: the return
   * of a sockops program is not a policy decision, so the wrapper returns 0
   * (same rule the Ruby oracle applied -- :sock_ops is absent from its
   * propagating_retval list). The glue side (_spnl_sockops_attach_all)
   * survived the port to the C codegen and attaches every SEC("sockops") prog to
   * $SPNL_CGROUP_PATH; only this line was missing, so the whole kind degraded
   * to a plain SEC("syscall") wrapper that nothing ever attached. */
  else if (cc_starts(name, "sock_ops__", &rest)) { a->kind = AK_SOCK_OPS; a->sec = strdup("sockops"); a->ctx_type = "struct bpf_sock_ops *"; a->kname = "sock_ops"; a->ctx_prefixed = 1; }
  /* raw tracepoint -- ctx->args[i] extraction, auto-attach. */
  else if (cc_starts(name, "raw_tp__", &rest))    { a->kind = AK_RAW_TP; a->sec = msprintf("raw_tp/%s", rest); a->ctx_type = "struct bpf_raw_tracepoint_args *"; a->kname = "raw_tp"; }
  /* perf_event sampling -- ctx-prefixed (sample data + regs), non-verdict. */
  else if (cc_starts(name, "perf_event__", &rest)) { a->kind = AK_PERF_EVENT; a->sec = strdup("perf_event"); a->ctx_type = "struct bpf_perf_event_data *"; a->kname = "perf_event"; a->ctx_prefixed = 1; }
  else if (cc_starts(name, "xdp__", &rest)) {        /* plain XDP (not xdp__tcp_slice__/xdp_tail__, Stage 1) */
    if (strncmp(rest, "tcp_slice__", 11) != 0) { a->kind = AK_XDP; a->sec = strdup("xdp"); a->ctx_type = "struct xdp_md *"; a->kname = "xdp"; a->ctx_prefixed = 1; a->verdict = 1; }
  }
  else if (cc_starts(name, "tracepoint__", &rest)) {
    const char *sep = strstr(rest, "__");
    if (sep) {
      char cat[128]; size_t cl = (size_t)(sep - rest); if (cl >= sizeof cat) cl = sizeof cat - 1;
      memcpy(cat, rest, cl); cat[cl] = '\0';
      a->kind = AK_TRACEPOINT; a->sec = msprintf("tracepoint/%s/%s", cat, sep + 2);
      a->ctx_type = "void *"; a->kname = "tracepoint";
      const char *evt = sep + 2;   /* syscalls sys_enter_/sys_exit_ -> positional args[i] struct */
      a->tp_cat = strdup(cat); a->tp_event = strdup(evt);   /* named-field lookup */
      if (!strcmp(cat, "syscalls") && !strncmp(evt, "sys_enter_", 10)) a->tp_struct = "trace_event_raw_sys_enter";
      else if (!strcmp(cat, "syscalls") && !strncmp(evt, "sys_exit_", 9)) a->tp_struct = "trace_event_raw_sys_exit";
    }
  }
  return a->kind;
}

/* --------: BTF-driven tracepoint schema (Phase 1, production) ---------- */
/* Bring the BTF frontend that was built for the (retired) Ruby oracle into the
 * production C codegen. Shell `bpftool btf dump file <btf> format c` -- the SAME BTF
 * the build already dumps for vmlinux.h -- cache the text, and classify a
 * `trace_event_raw_<event>` struct member -> "int"/"ipv4"/"ipv6"/NULL. BEST-EFFORT:
 * on a host without bpftool / /sys/kernel/btf/vmlinux the reader is unavailable and
 * callers fall back to the hand-written TP_FIELDS tables below, so the host golden
 * gate (tools/golden.rb) stays table-based and BYTE-IDENTICAL. In the build container
 * BTF is the source of truth (validated == tables by tools/stage2_verify.sh).
 *   env SPNL_BTF=<path>|off   BTF source (default /sys/kernel/btf/vmlinux; off=disable)
 *   env SPNL_BPFTOOL=<path>   bpftool binary (default `bpftool`)
 * Mirrors src/spinel_ebpf/btf_schema.rb (parser + type classification). */
static int   g_btf_state = 0;     /* 0=unloaded, 1=available, 2=unavailable */
static char *g_btf_text  = NULL;  /* full `format c` dump (NUL-terminated) */

static int cc_btf_available(void) {
  if (g_btf_state) return g_btf_state == 1;
  g_btf_state = 2;                                   /* assume unavailable */
  const char *path = getenv("SPNL_BTF");
  if (path && !strcmp(path, "off")) return 0;
  if (!path || !*path) path = "/sys/kernel/btf/vmlinux";
  if (access(path, R_OK) != 0) return 0;             /* no BTF here (e.g. macOS host) */
  const char *tool = getenv("SPNL_BPFTOOL");
  if (!tool || !*tool) tool = "bpftool";
  char cmd[1024];
  snprintf(cmd, sizeof cmd, "%s btf dump file %s format c 2>/dev/null", tool, path);
  FILE *p = popen(cmd, "r");
  if (!p) return 0;
  size_t cap = 1u << 20, len = 0;
  char *buf = (char *)malloc(cap);
  if (!buf) { pclose(p); return 0; }
  for (;;) {
    if (len + 4096 > cap) { cap *= 2; char *nb = (char *)realloc(buf, cap);
                            if (!nb) { free(buf); pclose(p); return 0; } buf = nb; }
    size_t n = fread(buf + len, 1, cap - len, p);
    len += n;
    if (n == 0) break;
  }
  int rc = pclose(p);
  if (rc != 0 || len == 0) { free(buf); return 0; }
  char *fb = (char *)realloc(buf, len + 1);
  if (fb) buf = fb;
  buf[len] = '\0';
  g_btf_text = buf;
  g_btf_state = 1;
  return 1;
}

static int cc_str_in(const char *s, const char *const *list) {
  for (int i = 0; list[i]; i++) if (!strcmp(s, list[i])) return 1;
  return 0;
}
/* Type spellings bpftool emits, mirroring btf_schema.rb#scalar_int?/byte_type?. */
static const char *const CC_SCALAR_INTS[] = {
  "__u8","__u16","__u32","__u64","__s8","__s16","__s32","__s64",
  "u8","u16","u32","u64","s8","s16","s32","s64",
  "int","unsigned int","short","unsigned short","long","unsigned long",
  "long long","unsigned long long","char","unsigned char","signed char",
  "bool","_Bool","size_t","ssize_t","pid_t","uid_t","gid_t","loff_t",
  "sector_t","dev_t","umode_t","u_int","u_long","__kernel_pid_t",
  "long int","long unsigned int","short int","short unsigned int",
  "long long int","long long unsigned int", NULL };
static const char *const CC_BYTE_TYPES[]  = { "__u8","u8","unsigned char","char","__s8","s8","u_char", NULL };
static const char *const CC_UBYTE_TYPES[] = { "__u8","u8","unsigned char","u_char", NULL };

/* Collapse tabs+runs of spaces to single spaces and rtrim (in place). */
static void cc_squeeze_spaces(char *s) {
  char *w = s; int prev_sp = 0;
  for (char *r = s; *r; r++) {
    char c = (*r == '\t') ? ' ' : *r;
    if (c == ' ') { if (prev_sp) continue; prev_sp = 1; } else prev_sp = 0;
    *w++ = c;
  }
  while (w > s && w[-1] == ' ') w--;
  *w = '\0';
}

/* Parse a trimmed member decl (no leading ws, no trailing ';') into name/type/ptr/arr.
 * Returns 1 on success, 0 to skip (bitfield, fn ptr, malformed). */
static int cc_btf_parse_member(const char *decl, char *name, size_t ncap,
                               char *type, size_t tcap, int *is_ptr, int *arr) {
  if (strchr(decl, ':') || strchr(decl, '(')) return 0;   /* bitfield / fn ptr */
  char d[256];
  size_t L = strlen(decl);
  if (L == 0 || L >= sizeof d) return 0;
  memcpy(d, decl, L + 1);
  *arr = -1;
  char *lb = strrchr(d, '[');
  if (lb) { char *rb = strchr(lb, ']'); if (!rb) return 0; *arr = atoi(lb + 1); *lb = '\0'; }
  *is_ptr = 0;
  for (char *q = d; *q; q++) if (*q == '*') { *q = ' '; *is_ptr = 1; }
  size_t e = strlen(d);
  while (e > 0 && (d[e-1] == ' ' || d[e-1] == '\t')) d[--e] = '\0';
  if (e == 0) return 0;
  char *sp = d + e;
  while (sp > d && sp[-1] != ' ' && sp[-1] != '\t') sp--;
  if (*sp == '\0' || strlen(sp) >= ncap) return 0;
  strcpy(name, sp);
  size_t tl = (size_t)(sp - d);
  while (tl > 0 && (d[tl-1] == ' ' || d[tl-1] == '\t')) tl--;
  if (tl >= tcap) return 0;
  memcpy(type, d, tl); type[tl] = '\0';
  cc_squeeze_spaces(type);
  return 1;
}

/* Body between the braces of `struct <sname> { ... \n};`, or NULL. */
static const char *cc_btf_struct_body(const char *sname, size_t *out_len) {
  if (!cc_btf_available()) return NULL;
  char needle[256];
  int nn = snprintf(needle, sizeof needle, "struct %s {", sname);
  if (nn < 0 || (size_t)nn >= sizeof needle) return NULL;
  char *s = strstr(g_btf_text, needle);
  if (!s) return NULL;
  char *open = strchr(s, '{');
  if (!open) return NULL;
  char *close = strstr(open, "\n};");
  if (!close) return NULL;
  *out_len = (size_t)(close - (open + 1));
  return open + 1;
}
static int cc_btf_has_struct(const char *sname) { size_t l; return cc_btf_struct_body(sname, &l) != NULL; }

/* Classify a field of `sname` -> "int"/"ipv4"/"ipv6"/NULL (mirrors parse_member). */
static const char *cc_btf_field_type(const char *sname, const char *field) {
  size_t blen;
  const char *body = cc_btf_struct_body(sname, &blen);
  if (!body) return NULL;
  const char *p = body, *end = body + blen;
  while (p < end) {
    const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
    const char *lend = nl ? nl : end;
    const char *ls = p;
    while (ls < lend && (*ls == ' ' || *ls == '\t')) ls++;
    const char *semi = (const char *)memchr(ls, ';', (size_t)(lend - ls));
    if (semi) {
      size_t dl = (size_t)(semi - ls);
      char decl[256];
      if (dl > 0 && dl < sizeof decl) {
        memcpy(decl, ls, dl); decl[dl] = '\0';
        char nm[128], ty[200]; int is_ptr, arr;
        if (cc_btf_parse_member(decl, nm, sizeof nm, ty, sizeof ty, &is_ptr, &arr)
            && !strcmp(nm, field)) {
          if (is_ptr) return "int";
          if (arr >= 0) {
            if (cc_str_in(ty, CC_BYTE_TYPES)  && arr == 4)  return "ipv4";
            if (cc_str_in(ty, CC_UBYTE_TYPES) && arr == 16) return "ipv6";
            return NULL;
          }
          if (cc_str_in(ty, CC_SCALAR_INTS)) return "int";
          return NULL;
        }
      }
    }
    if (!nl) break;
    p = nl + 1;
  }
  return NULL;
}

/* Comma-joined member names of `sname` for a diagnostic (malloc'd), or NULL. */
static char *cc_btf_member_list(const char *sname) {
  size_t blen;
  const char *body = cc_btf_struct_body(sname, &blen);
  if (!body) return NULL;
  size_t cap = 1024, used = 0;
  char *out = (char *)malloc(cap); if (!out) return NULL; out[0] = '\0';
  const char *p = body, *end = body + blen;
  while (p < end) {
    const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
    const char *lend = nl ? nl : end;
    const char *ls = p;
    while (ls < lend && (*ls == ' ' || *ls == '\t')) ls++;
    const char *semi = (const char *)memchr(ls, ';', (size_t)(lend - ls));
    if (semi) {
      size_t dl = (size_t)(semi - ls);
      char decl[256];
      if (dl > 0 && dl < sizeof decl) {
        memcpy(decl, ls, dl); decl[dl] = '\0';
        char nm[128], ty[200]; int is_ptr, arr;
        if (cc_btf_parse_member(decl, nm, sizeof nm, ty, sizeof ty, &is_ptr, &arr)) {
          size_t nln = strlen(nm);
          if (used + nln + 3 > cap) { cap = (used + nln + 3) * 2; char *nb = (char *)realloc(out, cap);
                                      if (!nb) { free(out); return NULL; } out = nb; }
          if (used) { memcpy(out + used, ", ", 2); used += 2; }
          memcpy(out + used, nm, nln); used += nln; out[used] = '\0';
        }
      }
    }
    if (!nl) break;
    p = nl + 1;
  }
  return out;
}

/* hand-written tracepoint field schema -- the FALLBACK when BTF is
 * unavailable (host golden run) and the source of `--emit-ir`-era goldens. In the
 * build container the BTF reader above overrides these (validated byte-identical).
 * Each entry is "cat/event" + a NULL-terminated list of "field:type" (int / ipv4).
 * IPv6 (daddr_v6[16]) is handled by the <base>6_hi/<base>6_lo split convention in
 * cc_attach_extractor, so it needs no per-event entry here. */
typedef struct { const char *key; const char *fields[12]; } TpFields;
static const TpFields TP_FIELDS[] = {
  {"sched/sched_switch", {"prev_pid:int","prev_prio:int","prev_state:int","next_pid:int","next_prio:int", NULL}},
  {"sched/sched_wakeup", {"pid:int","prio:int","target_cpu:int", NULL}},
  {"sched/sched_process_exit", {"pid:int","prio:int", NULL}},
  {"kmem/kmalloc", {"call_site:int","ptr:int","bytes_req:int","bytes_alloc:int","gfp_flags:int","node:int", NULL}},
  {"kmem/kfree", {"call_site:int","ptr:int", NULL}},
  {"kmem/kmem_cache_alloc", {"call_site:int","ptr:int","bytes_req:int","bytes_alloc:int","gfp_flags:int","node:int", NULL}},
  {"sock/inet_sock_set_state", {"skaddr:int","oldstate:int","newstate:int","sport:int","dport:int","family:int","protocol:int","saddr:ipv4","daddr:ipv4", NULL}},
  {"irq/irq_handler_entry", {"irq:int", NULL}},
  {"irq/irq_handler_exit", {"irq:int","ret:int", NULL}},
  {"irq/softirq_entry", {"vec:int", NULL}},
  {"irq/softirq_exit", {"vec:int", NULL}},
  {NULL, {NULL}}
};
/* events declared via DECLARE_EVENT_CLASS use the class's struct. */
typedef struct { const char *key, *name; } TpOverride;
static const TpOverride TP_STRUCT_OVERRIDE[] = {
  {"sched/sched_wakeup", "trace_event_raw_sched_wakeup_template"},
  {"irq/softirq_entry", "trace_event_raw_softirq"},
  {"irq/softirq_exit",  "trace_event_raw_softirq"},
  {NULL, NULL}
};
/* field -> "int" / "ipv4" / NULL (unknown) for a named tracepoint. */
static const char *cc_tp_field_type(const char *key, const char *field) {
  for (int i = 0; TP_FIELDS[i].key; i++) {
    if (strcmp(TP_FIELDS[i].key, key)) continue;
    size_t fl = strlen(field);
    for (int j = 0; TP_FIELDS[i].fields[j]; j++) {
      const char *fe = TP_FIELDS[i].fields[j];
      if (!strncmp(fe, field, fl) && fe[fl] == ':') return fe + fl + 1;
    }
    return NULL;
  }
  return NULL;
}
/* struct to cast ctx to (malloc'd). a *complete* trace_event_raw_<event> in BTF
 * wins (source of truth); else the template-override table (DECLARE_EVENT_CLASS cases,
 * which BTF can't map event->template); else the default name. The output string is
 * identical to the pre-BTF path for every case, so goldens are unaffected -- BTF makes
 * this the source of truth in-container and enables validation. */
static char *cc_tp_struct(const char *key, const char *ev) {
  char *def = msprintf("trace_event_raw_%s", ev);
  if (cc_btf_has_struct(def)) return def;                 /* complete BTF struct */
  free(def);
  for (int i = 0; TP_STRUCT_OVERRIDE[i].key; i++)
    if (!strcmp(TP_STRUCT_OVERRIDE[i].key, key)) return strdup(TP_STRUCT_OVERRIDE[i].name);
  return msprintf("trace_event_raw_%s", ev);
}

/* extractor C expr for attach param i (typed cast from the kernel ctx).
 * `pname` is the declared param name (used for named-tracepoint field matching). */
static char *cc_attach_extractor(const Attach *a, const char *ctype, int i, const char *pname) {
  switch (a->kind) {
    case AK_KPROBE: case AK_KRETPROBE:
    case AK_KPROBE_MULTI:   /* fprobe hands the same pt_regs a kprobe gets */
    case AK_UPROBE: case AK_URETPROBE:               return msprintf("(%s)PT_REGS_PARM%d(ctx)", ctype, i + 1);
    case AK_FENTRY: case AK_FEXIT:
    case AK_LSM:    case AK_FMOD_RET:                return msprintf("(%s)ctx[%d]", ctype, i);
    case AK_RAW_TP:                                  return msprintf("(%s)ctx->args[%d]", ctype, i);
    case AK_USDT:                                    return msprintf("(%s)_usdt_arg%d", ctype, i);
    case AK_TRACEPOINT:
      if (a->tp_struct) return msprintf("(%s)((struct %s *)ctx)->args[%d]", ctype, a->tp_struct, i);
      else {   /* named tracepoint -- match the param name to a struct field. */
        char *key = msprintf("%s/%s", a->tp_cat, a->tp_event);
        char *st  = cc_tp_struct(key, a->tp_event);       /* BTF-first struct name */
        char *r;
        size_t pl = strlen(pname);
        /* IPv6 address split convention. A param `<base>6_hi`/`<base>6_lo` reads the
         * hi/lo 8 bytes of the kernel's `<base>_v6` __u8[16] field (daddr6_hi -> daddr_v6),
         * same hi/lo convention as the earlier pkt_ip6_*. Reading the array's second half off
         * ctx directly is rejected ("dereference of modified ctx ptr" -- clang CSEs the base
         * pointer), so copy the 16 bytes into a stack buffer with bpf_probe_read_kernel and
         * split (verifier-clean, offset-portable via the ctx->..._v6 field). Replaces the earlier
         * hand-written ipv6hi/ipv6lo TP_FIELDS entries; BTF validates <base>_v6 is a 16-byte
         * array when available. */
        int half = (pl >= 4 && !strcmp(pname + pl - 4, "6_hi")) ? 0
                 : (pl >= 4 && !strcmp(pname + pl - 4, "6_lo")) ? 1 : -1;
        if (half >= 0) {
          char base[128]; size_t bl = pl - 4;
          if (bl == 0 || bl >= sizeof base) die("named tracepoint ipv6 param malformed", pname);
          memcpy(base, pname, bl); base[bl] = '\0';
          char *v6 = msprintf("%s_v6", base);
          if (cc_btf_available()) {
            const char *ft6 = cc_btf_field_type(st, v6);
            if (!ft6 || strcmp(ft6, "ipv6"))
              die("named tracepoint ipv6 param: BTF field is not a 16-byte address", v6);
          }
          if (half == 0)
            r = msprintf("(__s64)({ __u8 _d6[16] = {}; bpf_probe_read_kernel(_d6, 16, ((struct %s *)ctx)->%s); *(__u64 *)_d6; })", st, v6);
          else
            r = msprintf("(__s64)({ __u8 _d6[16] = {}; bpf_probe_read_kernel(_d6, 16, ((struct %s *)ctx)->%s); *(__u64 *)(_d6 + 8); })", st, v6);
          free(v6); free(key); free(st);
          return r;
        }
        /* Non-v6: BTF-derived type wins; fall back to the hand-written table. */
        const char *ft = cc_btf_available() ? cc_btf_field_type(st, pname) : NULL;
        if (!ft) ft = cc_tp_field_type(key, pname);
        if (!ft) {                                        /* no silent fallback */
          if (cc_btf_available()) {
            char *avail = cc_btf_member_list(st);
            die(msprintf("named tracepoint %s has no field '%s' (BTF %s available: %s)",
                         key, pname, st, avail ? avail : "?"), NULL);
          }
          die("named tracepoint field schema unknown (Stage 1)", key);
        }
        if (!strcmp(ft, "ipv4")) r = msprintf("(__s64)(*(__u32 *)(((struct %s *)ctx)->%s))", st, pname);
        else                     r = msprintf("(%s)((struct %s *)ctx)->%s", ctype, st, pname);
        free(key); free(st);
        return r;
      }
    default: die("attach args not yet ported for this kind (Stage 1)", a->kname); return NULL;
  }
}

/* struct_ops member signature tables (kernel ABI). Each
 * member maps to a C return type + BPF_PROG typed-param list (+ sleepable SEC). */
typedef struct { const char *member, *ret, *typed_params; int sleepable; } SoMember;
static const SoMember SO_SCHED_EXT_MEMBERS[] = {
  {"select_cpu", "__s32", "struct task_struct *p, __s32 prev_cpu, __u64 wake_flags", 0},
  {"enqueue", "void", "struct task_struct *p, __u64 enq_flags", 0},
  {"dequeue", "void", "struct task_struct *p, __u64 deq_flags", 0},
  {"dispatch", "void", "__s32 cpu, struct task_struct *prev", 0},
  {"tick", "void", "struct task_struct *p", 0},
  {"runnable", "void", "struct task_struct *p, __u64 enq_flags", 0},
  {"running", "void", "struct task_struct *p", 0},
  {"stopping", "void", "struct task_struct *p, bool runnable", 0},
  {"init", "__s32", "void", 1},
  {"exit", "void", "struct scx_exit_info *info", 1},
  {NULL, NULL, NULL, 0}
};
static const SoMember SO_QDISC_MEMBERS[] = {
  {"enqueue", "int", "struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free", 0},
  {"dequeue", "struct sk_buff *", "struct Qdisc *sch", 0},
  {"peek", "struct sk_buff *", "struct Qdisc *sch", 0},
  {"init", "int", "struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack", 0},
  {"reset", "void", "struct Qdisc *sch", 0},
  {"destroy", "void", "struct Qdisc *sch", 0},
  {NULL, NULL, NULL, 0}
};
static const SoMember SO_TCP_CC_MEMBERS[] = {
  {"init", "void", "struct sock *sk", 0},
  {"release", "void", "struct sock *sk", 0},
  {"ssthresh", "__u32", "struct sock *sk", 0},
  {"cong_avoid", "void", "struct sock *sk, __u32 ack, __u32 acked", 0},
  {"undo_cwnd", "__u32", "struct sock *sk", 0},
  {"set_state", "void", "struct sock *sk, __u8 new_state", 0},
  {"min_tso_segs", "__u32", "struct sock *sk", 0},
  {NULL, NULL, NULL, 0}
};
/* per-kind registry: members table + bundle metadata (struct type / symbol / name field). */
typedef struct { const SoMember *members; const char *struct_type, *symbol, *name_field, *default_name, *section; } SoReg;
static SoReg cc_so_reg(int so_kind) {
  if (so_kind == SO_SCHED_EXT) return (SoReg){SO_SCHED_EXT_MEMBERS, "sched_ext_ops", "spnl_sched_ext_ops", "name", "spnl_sx", ".struct_ops.link"};
  if (so_kind == SO_QDISC)     return (SoReg){SO_QDISC_MEMBERS, "Qdisc_ops", "spnl_qdisc_ops", "id", "spnl_qdisc", ".struct_ops.link"};
  return (SoReg){SO_TCP_CC_MEMBERS, "tcp_congestion_ops", "spnl_tcp_cc_ops", "name", "spnl_cc", ".struct_ops"};
}
static const SoMember *cc_so_member(int so_kind, const char *member) {
  SoReg r = cc_so_reg(so_kind);
  for (int i = 0; r.members[i].member; i++) if (!strcmp(r.members[i].member, member)) return &r.members[i];
  return NULL;
}

/* emit a struct_ops member -- inner (always __s64) + BPF_PROG entry
 * with the kernel-typed params, casting each back to __s64 for the inner. */
static void cc_emit_struct_ops_member(Buf *out, const Method *me, Lines *body) {
  const SoMember *info = cc_so_member(me->so_kind, me->so_member);
  if (!info) die("struct_ops member unsupported (Stage 1)", me->so_member);
  SoReg reg = cc_so_reg(me->so_kind);
  char *fn = cc_func_name(me);
  /* inner */
  buf_printf(out, "/* impl: %s */\n", fn);
  buf_printf(out, "static __noinline __s64 %s_inner(", fn);
  if (me->nparams == 0) buf_puts(out, "void");
  else for (int k = 0; k < me->nparams; k++) buf_printf(out, "%s%s %s", k ? ", " : "", ty_to_c(me->ptypes[k]), me->pnames[k]);
  buf_puts(out, ")\n{\n");
  for (int k = 0; k < body->n; k++) { char *t = cc_indent_each(body->v[k]); buf_puts(out, t); buf_puts(out, "\n"); free(t); }
  buf_puts(out, "}\n\n");
  /* entry: BPF_PROG wrapper with kernel-typed params */
  const char *suffix = info->sleepable ? ".s" : "";
  buf_printf(out, "/* entry: SEC(\"struct_ops%s/%s\") for %s */\n", suffix, info->member, reg.struct_type);
  buf_printf(out, "SEC(\"struct_ops%s/%s\")\n", suffix, info->member);
  if (!strcmp(info->typed_params, "void")) buf_printf(out, "%s BPF_PROG(%s)\n{\n", info->ret, fn);
  else                                     buf_printf(out, "%s BPF_PROG(%s, %s)\n{\n", info->ret, fn, info->typed_params);
  Buf casts; memset(&casts, 0, sizeof casts);
  for (int k = 0; k < me->nparams; k++) buf_printf(&casts, "%s(__s64)(unsigned long)%s", k ? ", " : "", me->pnames[k]);
  if (!strcmp(info->ret, "void"))            buf_printf(out, "    (void)%s_inner(%s);\n", fn, casts.p ? casts.p : "");
  else if (info->ret[strlen(info->ret) - 1] == '*') buf_printf(out, "    return (%s)(unsigned long)%s_inner(%s);\n", info->ret, fn, casts.p ? casts.p : "");
  else                                       buf_printf(out, "    return (%s)%s_inner(%s);\n", info->ret, fn, casts.p ? casts.p : "");
  buf_puts(out, "}\n");
  free(casts.p); free(fn);
}

/* sched_ext SCX_* constant macros (the kfunc decls live in vmlinux.h).
 * Body is the pristine templates/sched_ext_preamble.template.c (no slots). */
static void cc_emit_sched_ext_preamble(Buf *out) {
  buf_puts(out, tpl_sched_ext_preamble);
}

/* bpf_list/bpf_obj/kptr machinery for FIFO BPF qdiscs (queue_push/pop).
 * Body is the pristine templates/qdisc_fifo_preamble.template.c (no slots). */
static void cc_emit_qdisc_fifo_preamble(Buf *out) {
  buf_puts(out, tpl_qdisc_fifo_preamble);
}

/* struct_ops bundle -- `SEC(<sec>) struct <type> <sym> = { .m = (void *)<prefix>__m, ..., .name = "..." };` */
static void cc_emit_struct_ops_bundle(Buf *out, IR *ir, int so_kind) {
  SoReg reg = cc_so_reg(so_kind);
  const char *prefix = so_kind == SO_SCHED_EXT ? "sched_ext" : (so_kind == SO_QDISC ? "qdisc" : "tcp_cc");
  buf_printf(out, "/* struct_ops registration for %s. */\n", reg.struct_type);
  buf_printf(out, "SEC(\"%s\")\n", reg.section);
  buf_printf(out, "struct %s %s = {\n", reg.struct_type, reg.symbol);
  for (int i = 0; i < ir->n; i++)   /* members in declaration order */
    if (ir->m[i].so_kind == so_kind && cc_method_eligible(&ir->m[i]))
      buf_printf(out, "    .%s = (void *)%s__%s,\n", ir->m[i].so_member, prefix, ir->m[i].so_member);
  buf_printf(out, "    .%s = \"%s\",\n};\n", reg.name_field, reg.default_name);
}

/* pre-scan a method body (pre-order DFS, skip nested defs) recording every
 * pkt_* builtin reference with the method's ctx kind (tc=1 / xdp=0). Run before
 * the helper-emit pass so emit_pkt_helpers sees them in first-reference order
 * (mirrors how Ruby populates ctx.pkt_builtins_used during method lowering). */
static void cc_scan_pkt(AST *ast, int nid, int tc) {
  if (nid < 0) return;
  const char *ty = nt_type(ast, nid);
  if (!ty) return;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return;
  if (!strcmp(ty, "CallNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm && cc_pkt_canon(nm)) cc_record_pkt(nm, tc);
    else {
      /* the chain spelling must reach the same helper-emit bookkeeping
       * as the flat one, or the reader is lowered to a call with no definition. */
      char joined[64];
      if (nt_ref(ast, nid, "arguments") < 0 && cc_pkt_chain_name(ast, nid, joined, sizeof joined)) {
        const char *canon = cc_pkt_canon(joined);
        if (canon) cc_record_pkt(canon, tc);
      }
    }
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) cc_scan_pkt(ast, n->r[i].ref, tc);
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) cc_scan_pkt(ast, n->a[i].ids[k], tc);
}

/* pre-scan flow_get/set/del(:name, :field) to infer conntrack maps + the
 * ctx kind they're used in (tc=1 / xdp=0). Mirrors Ruby collect_flow_maps. */
static void cc_scan_flow(AST *ast, int nid, int tc) {
  if (nid < 0) return;
  const char *ty = nt_type(ast, nid);
  if (!ty) return;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return;
  if (!strcmp(ty, "CallNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm && (!strcmp(nm, "flow_get") || !strcmp(nm, "flow_set") || !strcmp(nm, "flow_del")) &&
        nt_ref(ast, nid, "receiver") < 0) {
      int aid = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
      if (na >= 1) {
        const char *mapnm = nt_str(ast, ids[0], "value");
        if (mapnm) {
          int mi = cc_flow_idx(mapnm);
          g_flow_kinds[mi] |= tc ? 2 : 1;
          if (na >= 2) { const char *fld = nt_str(ast, ids[1], "value"); if (fld) cc_flow_add_field(mi, fld); }
        }
      }
    }
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) cc_scan_flow(ast, n->r[i].ref, tc);
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) cc_scan_flow(ast, n->a[i].ids[k], tc);
}

/* emit one pkt_* helper. `tc` selects ctx type (struct __sk_buff)
 * and the spnl_tc_ prefix; xdp uses struct xdp_md and spnl_. Byte-identical to
 * Ruby emit_pkt_helper. The function name is always <prefix>_<name>. */
static void cc_emit_pkt_helper(Buf *o, const char *name, int tc) {
  const char *cd = tc ? "struct __sk_buff *ctx" : "struct xdp_md *ctx";
  const char *fp = tc ? "spnl_tc" : "spnl";
  if (!strcmp(name, "pkt_len")) {   /* templates/pkt_len.template.c */
    char *sig = msprintf("%s_%s(%s)", fp, name, cd);
    tpl_emit(o, tpl_pkt_len, (TplSlot[]){ {"@SIG@", sig} }, 1);
    free(sig);
    return;
  }
  if (!strcmp(name, "pkt_eth_proto")) {   /* templates/pkt_eth_proto.template.c */
    char *sig = msprintf("%s_%s(%s)", fp, name, cd);
    tpl_emit(o, tpl_pkt_eth_proto, (TplSlot[]){ {"@SIG@", sig} }, 1);
    free(sig);
    return;
  }
  if (!strcmp(name, "pkt_l4_proto")) {   /* templates/pkt_l4_proto.template.c */
    char *sig = msprintf("%s_%s(%s)", fp, name, cd);
    tpl_emit(o, tpl_pkt_l4_proto, (TplSlot[]){ {"@SIG@", sig} }, 1);
    free(sig);
    return;
  }
  if (!strcmp(name, "pkt_ip4_src") || !strcmp(name, "pkt_ip4_dst")) {   /* templates/pkt_ip4_addr.template.c */
    int dst = !strcmp(name, "pkt_ip4_dst");
    char *sig = msprintf("%s_%s(%s)", fp, name, cd);
    tpl_emit(o, tpl_pkt_ip4_addr, (TplSlot[]){
      {"@SIG@", sig}, {"@DIR@", dst ? "destination" : "source"}, {"@ADDR@", dst ? "daddr" : "saddr"} }, 3);
    free(sig);
    return;
  }
  if (!strcmp(name, "pkt_l4_sport") || !strcmp(name, "pkt_l4_dport")) {   /* templates/pkt_l4_port.template.c */
    int dport = !strcmp(name, "pkt_l4_dport");
    const char *suffix = dport ? "dport" : "sport";
    char *sig = msprintf("%s_pkt_l4_%s(%s)", fp, suffix, cd);
    tpl_emit(o, tpl_pkt_l4_port, (TplSlot[]){
      {"@SIG@", sig}, {"@SUFFIX@", suffix}, {"@OFF@", dport ? "2" : "0"} }, 3);
    free(sig);
    return;
  }
  if (!strcmp(name, "pkt_tcp_flags")) {   /* templates/pkt_tcp_flags.template.c */
    char *sig = msprintf("%s_%s(%s)", fp, name, cd);
    tpl_emit(o, tpl_pkt_tcp_flags, (TplSlot[]){ {"@SIG@", sig} }, 1);
    free(sig);
    return;
  }
  if (!strcmp(name, "pkt_tcp_seq") || !strcmp(name, "pkt_tcp_ack")) {   /* templates/pkt_tcp_seqack.template.c */
    const char *field = name + strlen("pkt_tcp_");   /* "seq" / "ack" */
    int offset = !strcmp(field, "seq") ? 4 : 8;
    char *sig = msprintf("%s_%s(%s)", fp, name, cd);
    char off[8], endoff[8];
    snprintf(off, sizeof off, "%d", offset);
    snprintf(endoff, sizeof endoff, "%d", offset + 4);
    tpl_emit(o, tpl_pkt_tcp_seqack, (TplSlot[]){
      {"@SIG@", sig}, {"@FIELD@", field}, {"@OFF@", off}, {"@ENDOFF@", endoff} }, 4);
    free(sig);
    return;
  }
  if (!strcmp(name, "pkt_l4_payload_len")) {   /* see templates/pkt_l4_payload_len.template.c */
    char *sig = msprintf("%s_%s(%s)", fp, name, cd);
    tpl_emit(o, tpl_pkt_l4_payload_len, (TplSlot[]){ {"@SIG@", sig} }, 1);
    free(sig);
    return;
  }
  if (!strncmp(name, "pkt_ip6_", 8)) {   /* pkt_ip6_{src,dst}_{hi,lo}: templates/pkt_ip6_addr.template.c */
    const char *which = !strncmp(name + 8, "src", 3) ? "src" : "dst";
    const char *half  = name[strlen(name) - 2] == 'h' ? "hi" : "lo";
    const char *ip6_field = !strcmp(which, "src") ? "saddr" : "daddr";
    int i0 = !strcmp(half, "hi") ? 0 : 2;
    char i0s[8], i1s[8];
    snprintf(i0s, sizeof i0s, "%d", i0);
    snprintf(i1s, sizeof i1s, "%d", i0 + 1);
    char *sig = msprintf("%s_pkt_ip6_%s_%s(%s)", fp, which, half, cd);
    tpl_emit(o, tpl_pkt_ip6_addr, (TplSlot[]){
      {"@SIG@", sig}, {"@WHICH@", which}, {"@HALF@", half},
      {"@FIELD@", ip6_field}, {"@I0@", i0s}, {"@I1@", i1s} }, 6);
    free(sig);
    return;
  }
  die("emit_pkt_helper: unknown builtin (Stage 1)", name);
}

/* --------: reactor DSL (module + include BPF::EventLoop + `on :kind`).
 * The module's `on` blocks aren't `def`s, so spinel's IR omits them; the Ruby
 * partition synthesizes a top-level method per `on` by walking the AST. We mirror
 * that here, appending synthesized Method entries to ir->m. ---------- */

/* build a "A::B::C" path string (root-first) from a Constant(Path|Read)Node. */
static void cc_build_const_path(AST *ast, int nid, char *out, size_t outsz) {
  const char *parts[8]; int np = 0; int cur = nid;
  out[0] = '\0';
  for (int g = 0; g < 8 && cur >= 0; g++) {
    const char *ct = nt_type(ast, cur), *nm = nt_str(ast, cur, "name");
    if (!ct || !nm) return;
    if (!strcmp(ct, "ConstantPathNode")) { parts[np++] = nm; cur = nt_ref(ast, cur, "parent"); }
    else if (!strcmp(ct, "ConstantReadNode")) { parts[np++] = nm; cur = -1; }
    else return;
  }
  for (int i = np - 1; i >= 0; i--) {
    if (strlen(out) + strlen(parts[i]) + 2 >= outsz) return;
    strcat(out, parts[i]); if (i) strcat(out, "::");
  }
}

/* fill me->pnames/ptypes/nparams from a BlockNode's required block params (C-safe). */
static void cc_extract_block_params(AST *ast, int block_id, Method *me) {
  me->nparams = 0; me->pnames = NULL; me->ptypes = NULL;
  int bp = nt_ref(ast, block_id, "parameters");
  if (bp < 0) return;
  const char *bt = nt_type(ast, bp);
  int params_id = -1;
  if (bt && !strcmp(bt, "BlockParametersNode")) params_id = nt_ref(ast, bp, "parameters");
  else if (bt && !strcmp(bt, "ParametersNode")) params_id = bp;
  if (params_id < 0) return;
  const char *pt = nt_type(ast, params_id);
  if (!pt || strcmp(pt, "ParametersNode")) return;
  int nr; const int *req = nt_arr(ast, params_id, "requireds", &nr);
  if (nr <= 0) return;
  me->pnames = calloc(nr, sizeof(char *));
  me->ptypes = calloc(nr, sizeof(CcTy));
  for (int i = 0; i < nr; i++) {
    const char *rt = nt_type(ast, req[i]);
    const char *nm = (rt && !strcmp(rt, "RequiredParameterNode")) ? nt_str(ast, req[i], "name") : NULL;
    me->pnames[me->nparams] = cc_safe_dup(nm ? nm : "");
    me->ptypes[me->nparams] = CC_TY_INT;
    me->nparams++;
  }
}

/* reactor kind table (Ruby BPF_EVENT_LOOP_KINDS): prefix, arity, joiner, is-react. */
typedef struct { const char *kind, *prefix, *joiner; int arity; int react; } ReactorKind;
static const ReactorKind *cc_reactor_kind(const char *k) {
  static const ReactorKind K[] = {
    {"xdp", "xdp__main", "", 0, 0}, {"sock_ops", "sock_ops__main", "", 0, 0},
    {"tc_ingress", "tc__ingress__main", "", 0, 0}, {"tc_egress", "tc__egress__main", "", 0, 0},
    {"kprobe", "kprobe__", "", 1, 0}, {"kretprobe", "kretprobe__", "", 1, 0},
    {"fentry", "fentry__", "", 1, 0}, {"fexit", "fexit__", "", 1, 0},
    {"tracepoint", "tracepoint__", "__", 2, 0},
    {"user_cmd", "user_ringbuf__cmd_handler", "", 0, 0},
    {"uprobe", "uprobe__react", "", 1, 1}, {"uretprobe", "uretprobe__react", "", 1, 1},
    /* go_uret shares the uprobe SEC/codegen (SEC("uprobe"), method
     * uprobe__react<N>); glue.c attaches it at every RET offset (see go_ret flag). */
    {"go_uret", "uprobe__react", "", 1, 1},
    {"usdt", "usdt__react__", "", 3, 1}, {"perf_event", "perf_event__main", "", 0, 0},
    {NULL, NULL, NULL, 0, 0}
  };
  for (int i = 0; K[i].kind; i++) if (!strcmp(K[i].kind, k)) return &K[i];
  return NULL;
}

/* Collect top-level `param :name, default: N` declarations.
 *
 * Walks ProgramNode(0).statements.body[] -- the same top-level walk
 * cc_synthesize_reactor does -- because a bare top-level call is a statement of
 * `<main>`, never a Scope, so it cannot arrive through the IR.
 *
 * Everything about a declaration is checked here rather than deferred to clang
 * or to the loader: a `param` whose shape the codegen does not
 * understand is a mis-declared contract, and a contract that fails at run time
 * fails in front of an operator who cannot fix it.
 *
 * `default:` is optional and means 0. That is not a convenience: 0 is the value
 * that makes a filter vanish (S3-7 -- the verifier folds `if (p != 0)` away when
 * .rodata is frozen at 0), so "unset" and "off" are deliberately the same word. */
static void cc_scan_params(AST *ast) {
  int stmts = nt_ref(ast, 0, "statements");
  if (stmts < 0) return;
  int nb; const int *body = nt_arr(ast, stmts, "body", &nb);
  for (int bi = 0; bi < nb; bi++) {
    const char *ty = nt_type(ast, body[bi]);
    if (!ty || strcmp(ty, "CallNode")) continue;
    const char *cn = nt_str(ast, body[bi], "name");
    if (!cn || strcmp(cn, "param")) continue;
    if (nt_ref(ast, body[bi], "receiver") >= 0) continue;   /* foo.param(...) is not ours */

    int aid = nt_ref(ast, body[bi], "arguments");
    int na = 0; const int *args = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
    if (na < 1 || na > 2 || !args)
      die("param expects `param :name` or `param :name, default: <int>`", cn);
    if (strcmp(nt_type(ast, args[0]) ? nt_type(ast, args[0]) : "", "SymbolNode"))
      die("param: the name must be a symbol literal, e.g. `param :target_pid` "
          "(it becomes a C identifier at compile time, so it cannot be computed)", NULL);
    const char *pname = nt_str(ast, args[0], "value");
    if (!pname || !pname[0]) die("param: empty name", NULL);
    /* Restricted on purpose: the name is spent three times -- a C identifier in
     * the .bpf.c, a field of the skeleton's rodata struct, and the tail of the
     * SPNL_PARAM_<NAME> environment variable. Only a lowercase Ruby-ish
     * identifier survives all three unmangled. */
    if (!((pname[0] >= 'a' && pname[0] <= 'z') || pname[0] == '_'))
      die("param: name must start with a lowercase letter or underscore", pname);
    for (const char *p = pname; *p; p++)
      if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_'))
        die("param: name must be lowercase [a-z0-9_] (it also names the "
            "SPNL_PARAM_<NAME> environment variable)", pname);
    if (cc_param_index(pname) >= 0)
      die("param: declared twice", pname);
    if (g_n_params >= CC_MAX_PARAMS)
      die("param: too many parameters (limit 32 -- raise CC_MAX_PARAMS)", pname);

    long long dflt = 0;
    if (na == 2) {
      const char *kt = nt_type(ast, args[1]);
      if (!kt || strcmp(kt, "KeywordHashNode"))
        die("param: the second argument must be `default: <int literal>`", pname);
      int ne = 0; const int *els = nt_arr(ast, args[1], "elements", &ne);
      if (ne != 1) die("param: `default:` is the only keyword accepted", pname);
      int key = nt_ref(ast, els[0], "key"), val = nt_ref(ast, els[0], "value");
      const char *kn = key >= 0 ? nt_str(ast, key, "value") : NULL;
      if (!kn || strcmp(kn, "default"))
        die("param: `default:` is the only keyword accepted", pname);
      const char *vt = val >= 0 ? nt_type(ast, val) : NULL;
      if (!vt || strcmp(vt, "IntegerNode"))
        die("param: `default:` must be an integer literal (it is baked into "
            ".rodata at compile time, so it cannot be an expression)", pname);
      dflt = nt_int(ast, val, "value", 0);
    }
    g_param_names[g_n_params] = strdup(pname);
    g_param_defaults[g_n_params] = dflt;
    g_param_used[g_n_params] = 0;
    g_n_params++;
  }
}

/* Top-level `filter_by :pid, :comm`. Same shape of scan as
 * cc_scan_params (a bare top-level CallNode, invisible to the IR), same rule
 * about refusing here rather than later: a filter the codegen does not
 * understand is a filter that silently does not narrow. */
static void cc_scan_common_filter(AST *ast) {
  int stmts = nt_ref(ast, 0, "statements");
  if (stmts < 0) return;
  int nb; const int *body = nt_arr(ast, stmts, "body", &nb);
  for (int bi = 0; bi < nb; bi++) {
    const char *ty = nt_type(ast, body[bi]);
    if (!ty || strcmp(ty, "CallNode")) continue;
    const char *cn = nt_str(ast, body[bi], "name");
    if (!cn || strcmp(cn, "filter_by")) continue;
    if (nt_ref(ast, body[bi], "receiver") >= 0) continue;   /* foo.filter_by(...) is not ours */
    if (g_filter_declared)
      die("filter_by: declared twice -- one declaration lists every key "
          "(`filter_by :pid, :comm`), because it applies to the whole unit", NULL);
    g_filter_declared = 1;

    int aid = nt_ref(ast, body[bi], "arguments");
    int na = 0; const int *args = aid >= 0 ? nt_arr(ast, aid, "arguments", &na) : NULL;
    if (na < 1 || !args)
      die("filter_by expects at least one key, e.g. `filter_by :pid`. Keys: "
          "pid tid uid gid cgroup_id comm", NULL);
    for (int i = 0; i < na; i++) {
      const char *at = nt_type(ast, args[i]);
      if (!at || strcmp(at, "SymbolNode"))
        die("filter_by: every key must be a symbol literal, e.g. `filter_by :pid, :comm` "
            "(the keys become C identifiers at compile time, so they cannot be computed)", NULL);
      const char *k = nt_str(ast, args[i], "value");
      int ki = cc_filter_key_index(k);
      if (ki < 0)
        die("filter_by: unknown key (accepted: pid tid uid gid cgroup_id comm). "
            "Anything else is probe-specific and belongs in a `param` you test yourself "
            " -- the common filter is only for what every process-context hook has", k);
      if (CC_FILTER_HAS(ki)) die("filter_by: key listed twice", k);
      g_filter_mask |= 1u << ki;
    }
  }
}

/* The attach kinds the common filter is defined for: process context (so
 * bpf_get_current_* describes the task that caused the event) AND no verdict on
 * the wrapper's return (so "skip this event" is expressible as `return 0`).
 *
 * Everything else is refused rather than left unfiltered -- see cc_filter_gate. */
static int cc_filter_kind_ok(AttachKind k) {
  return k == AK_KPROBE || k == AK_KRETPROBE || k == AK_TRACEPOINT || k == AK_RAW_TP ||
         k == AK_FENTRY || k == AK_FEXIT || k == AK_UPROBE || k == AK_URETPROBE ||
         k == AK_USDT   || k == AK_PERF_EVENT ||
         k == AK_KPROBE_MULTI;   /* kernel-function entry, same as AK_KPROBE */
}

/* Why a mixed unit is refused instead of partly filtered:
 *
 *   - on a verdict hook (lsm / fmod_ret / xdp / tc / cgroup-sock-addr) "discard
 *     this event" has no meaning. Returning 0 there is a SECURITY DECISION
 *     (allow, or XDP_ABORTED), not a skip.
 *   - on a non-process hook (xdp / tc / sk_*) bpf_get_current_pid_tgid() reports
 *     whatever task happens to be on the CPU, so the filter would not be wrong
 *     so much as meaningless.
 *   - and leaving those handlers unfiltered while filtering the others produces
 *     exactly the artefact this feature exists to prevent: a probe that looks
 *     narrowed and is not.
 *
 * A unit that needs both writes two probes. */
static void cc_filter_gate(IR *ir) {
  if (!g_filter_declared) return;
  int eligible = 0;
  for (int i = 0; i < ir->n; i++) {
    if (!cc_method_eligible(&ir->m[i])) continue;
    Attach a = {0};
    AttachKind k = cc_detect_attach(ir->m[i].name, &a);
    if (k == AK_NONE) continue;          /* SEC("syscall") test-run entry: not an event */
    if (cc_filter_kind_ok(k)) { eligible++; continue; }
    char *msg = msprintf(
      "filter_by cannot cover `%s` (%s). The common filter means \"skip this event\", "
      "which on a verdict hook would be a security decision and on a packet hook would "
      "read whichever task happens to be on the CPU. Filtering the other handlers and "
      "leaving this one open would give you a probe that looks narrowed and is not -- so "
      "the declaration is refused. Covered kinds: kprobe kretprobe tracepoint raw_tp "
      "fentry fexit uprobe uretprobe usdt kprobe_multi perf_event. Put `%s` in its own probe, or drop "
      "filter_by and narrow by hand (`if pid == target_pid`, with `param :target_pid`)",
      ir->m[i].name, a.kname, ir->m[i].name);
    die(msg, NULL);
  }
  if (!eligible)
    die("filter_by is declared but this unit has no attach handler it can cover, so "
        "setting SPNL_FILTER_* would change nothing. Add a process-context handler "
        "(kprobe/tracepoint/fentry/uprobe/usdt/perf_event), or delete the declaration", NULL);
}

/* The .rodata declarations + spnl_filter_discard(), emitted once per unit.
 *
 * The shape is IG's (include/gadget/filter.h): each key's test is guarded by
 * "is this key set", so an unset key costs nothing -- the verifier folds the
 * guard away together with the helper call inside it, once libbpf has frozen
 * .rodata. Keys that share a helper (pid/tid, uid/gid) share one call. */
static void cc_emit_common_filter(Buf *out) {
  buf_puts(out,
    "/* === in-kernel common filter ===\n"
    " * Declared once as `filter_by ...` at the top level and injected at the head\n"
    " * of every attach handler in this unit -- look for the spnl_filter_discard()\n"
    " * line in each entry wrapper below.\n"
    " *\n"
    " * An event survives only if it matches EVERY key that is set; a key left unset\n"
    " * does not constrain. Unset is also free: .rodata is frozen before load, so the\n"
    " * verifier removes the guard AND the bpf_get_current_* call inside it from the\n"
    " * accepted program (`bpftool prog dump xlated`).\n"
    " *\n"
    " * Set at load from the environment: */\n");
  for (int i = 0; i < CC_N_FILTER_KEYS; i++)
    if (CC_FILTER_HAS(i))
      buf_printf(out, "/*   %-22s %s */\n", CC_FILTER_KEYS[i].env, CC_FILTER_KEYS[i].desc);
  for (int i = 0; i < CC_N_FILTER_KEYS; i++) {
    if (!CC_FILTER_HAS(i)) continue;
    if (!strcmp(CC_FILTER_KEYS[i].key, "comm"))
      buf_printf(out, "volatile const char %s[16] = {};   /* \"\" = unset */\n", CC_FILTER_KEYS[i].sym);
    else
      buf_printf(out, "volatile const __s64 %s = %s;   /* %s = unset */\n",
                 CC_FILTER_KEYS[i].sym, CC_FILTER_KEYS[i].init, CC_FILTER_KEYS[i].init);
  }
  buf_puts(out, "\nstatic __always_inline int spnl_filter_discard(void)\n{\n");

  /* pid/tid and uid/gid come in pairs from one helper call each, so the "is it
   * set" guard is hoisted to the pair (IG does the same). When only one of a
   * pair is declared the guard has already established that it is set, so the
   * inner test is the mismatch alone -- no `x != 0 && x != v` on one line. */
  static const struct { const char *a, *b, *helper, *var; } GROUPS[] = {
    { "pid", "tid", "bpf_get_current_pid_tgid", "_pt" },
    { "uid", "gid", "bpf_get_current_uid_gid",  "_ug" },
  };
  static const char *const CMP[] = {
    "spnl_filter_pid != (__s64)(__u32)(_pt >> 32)",
    "spnl_filter_tid != (__s64)(__u32)_pt",
    "spnl_filter_uid != (__s64)(__u32)_ug",
    "spnl_filter_gid != (__s64)(__u32)(_ug >> 32)",
  };
  for (int g = 0; g < 2; g++) {
    int ia = cc_filter_key_index(GROUPS[g].a), ib = cc_filter_key_index(GROUPS[g].b);
    int ha = CC_FILTER_HAS(ia), hb = CC_FILTER_HAS(ib);
    if (!ha && !hb) continue;
    buf_printf(out, "    if (%s%s%s) {\n        __u64 %s = %s();\n",
               ha ? CC_FILTER_KEYS[ia].unset_c : "", (ha && hb) ? " || " : "",
               hb ? CC_FILTER_KEYS[ib].unset_c : "", GROUPS[g].var, GROUPS[g].helper);
    if (ha) buf_printf(out, "        if (%s%s%s) return 1;\n",
                       hb ? CC_FILTER_KEYS[ia].unset_c : "", hb ? " && " : "", CMP[g * 2]);
    if (hb) buf_printf(out, "        if (%s%s%s) return 1;\n",
                       ha ? CC_FILTER_KEYS[ib].unset_c : "", ha ? " && " : "", CMP[g * 2 + 1]);
    buf_puts(out, "    }\n");
  }
  int i_cg = cc_filter_key_index("cgroup_id");
  if (CC_FILTER_HAS(i_cg))
    buf_puts(out, "    if (spnl_filter_cgroup_id != 0 &&\n"
                  "        spnl_filter_cgroup_id != (__s64)bpf_get_current_cgroup_id()) return 1;\n");
  int i_comm = cc_filter_key_index("comm");
  if (CC_FILTER_HAS(i_comm))
    /* All 16 bytes, not strncmp: comm is NUL-padded by the kernel and the loader
     * writes into a zeroed .rodata, so a full compare is both exact (no prefix
     * match) and unrollable to a straight line of byte tests. */
    buf_puts(out, "    if (spnl_filter_comm[0] != '\\0') {\n"
                  "        char _c[16] = {};\n"
                  "        bpf_get_current_comm(&_c, sizeof(_c));\n"
                  "        for (int _i = 0; _i < 16; _i++)\n"
                  "            if (_c[_i] != spnl_filter_comm[_i]) return 1;\n"
                  "    }\n");
  buf_puts(out, "    return 0;\n}\n");
}

/* resolve `auto` into a concrete lowering.
 *
 * `via:` on the handler wins outright -- it is a deployment statement (see the
 * CcMulti comment: the multi lowering raises the kernel floor). SPNL_ATTACH_MULTI
 * only redirects handlers that did NOT say, which is what makes the two-lowerings
 * control experiment possible from one unmodified source file. */
static int cc_multi_resolve_mode(int declared, int n) {
  if (declared != CC_MA_AUTO) return declared;
  const char *e = getenv("SPNL_ATTACH_MULTI");
  if (e && *e) {
    if (!strcmp(e, "expand")) return CC_MA_EXPAND;
    if (!strcmp(e, "multi"))  return CC_MA_MULTI;
    if (strcmp(e, "auto"))
      die("SPNL_ATTACH_MULTI: expected auto|expand|multi (it only redirects handlers "
          "that did not declare `via:`)", e);
  }
  return n >= CC_MULTI_AUTO_THRESHOLD ? CC_MA_MULTI : CC_MA_EXPAND;
}

/* `on :kprobe, %w[a b c][, via: :expand|:multi] do ... end`.
 * Returns 1 when this `on` was a multi-symbol form (handled here), 0 otherwise. */
static int cc_synthesize_multi(IR *ir, AST *ast, int cid, const int *args, int na,
                               const char *kind) {
  if (strcmp(kind, "kprobe")) return 0;
  if (na < 2) return 0;
  const char *t1 = nt_type(ast, args[1]);
  if (!t1 || strcmp(t1, "ArrayNode")) return 0;

  int ne = 0; const int *els = nt_arr(ast, args[1], "elements", &ne);
  if (ne <= 0)
    die("on :kprobe, %w[...]: the symbol list is empty -- a handler bound to nothing "
        "is a program that loads and never fires", NULL);
  if (ne > CC_MULTI_MAX_SYMS)
    die("on :kprobe, %w[...]: too many symbols (limit 512)", NULL);
  if (g_n_multi >= CC_MULTI_MAX_SETS)
    die("too many multi-symbol handlers in one unit (limit 64)", NULL);

  char **syms = calloc((size_t)ne, sizeof(char *));
  for (int i = 0; i < ne; i++) {
    const char *et = nt_type(ast, els[i]);
    const char *sv = (et && !strcmp(et, "StringNode")) ? nt_str(ast, els[i], "content") : NULL;
    if (!sv || !*sv)
      die("on :kprobe, %w[...]: every element must be a non-empty string literal "
          "(the names are compiled into SEC()s / a symbol array, so they cannot be computed; "
          "note that `%w[].each { define_method ... }` does not work either -- this pass "
          "reads the AST, so methods that only exist at run time are invisible)", NULL);
    /* A duplicate would attach twice and double-count, and with the multi
     * lowering libbpf refuses the whole link -- fail the same way in both. */
    for (int j = 0; j < i; j++)
      if (!strcmp(syms[j], sv)) die("on :kprobe, %w[...]: duplicate symbol", sv);
    syms[i] = strdup(sv);
  }

  int declared = CC_MA_AUTO;
  for (int i = 2; i < na; i++) {
    const char *kt = nt_type(ast, args[i]);
    if (!kt || strcmp(kt, "KeywordHashNode")) continue;
    int nk = 0; const int *as = nt_arr(ast, args[i], "elements", &nk);
    for (int j = 0; j < nk; j++) {
      int key = nt_ref(ast, as[j], "key"), val = nt_ref(ast, as[j], "value");
      const char *kn = key >= 0 ? nt_str(ast, key, "value") : NULL;
      if (!kn || strcmp(kn, "via"))
        die("on :kprobe, %w[...]: `via:` is the only keyword accepted", kn ? kn : "?");
      const char *vt = val >= 0 ? nt_type(ast, val) : NULL;
      const char *vn = (vt && !strcmp(vt, "SymbolNode")) ? nt_str(ast, val, "value") : NULL;
      if (vn && !strcmp(vn, "expand"))     declared = CC_MA_EXPAND;
      else if (vn && !strcmp(vn, "multi")) declared = CC_MA_MULTI;
      else die("on :kprobe, %w[...]: `via:` must be :expand or :multi (omit it to let the "
               "codegen choose from the list size -- see `spinel-ebpf describe`)", vn ? vn : "?");
    }
  }

  char *mname = msprintf("kprobe_multi__set%d", g_n_multi);
  int block = nt_ref(ast, cid, "block");
  int hbody = block >= 0 ? nt_ref(ast, block, "body") : -1;
  if (hbody < 0) { free(mname); for (int i = 0; i < ne; i++) free(syms[i]); free(syms); return 1; }

  g_multi[g_n_multi].mname         = strdup(mname);
  g_multi[g_n_multi].syms          = syms;
  g_multi[g_n_multi].nsyms         = ne;
  g_multi[g_n_multi].declared_mode = declared;
  g_multi[g_n_multi].mode          = cc_multi_resolve_mode(declared, ne);
  g_n_multi++;

  ir->m = realloc(ir->m, (size_t)(ir->n + 1) * sizeof(Method));
  Method *me = &ir->m[ir->n]; memset(me, 0, sizeof *me);
  me->name = mname; me->cls = NULL; me->ret = CC_TY_INT; me->body_id = hbody;
  cc_extract_block_params(ast, block, me);
  ir->n++;
  return 1;
}

static void cc_synthesize_reactor(IR *ir, AST *ast) {
  int stmts = nt_ref(ast, 0, "statements");   /* ProgramNode(0).statements */
  if (stmts < 0) return;
  int nb; const int *body = nt_arr(ast, stmts, "body", &nb);
  for (int bi = 0; bi < nb; bi++) {
    int modid = body[bi];
    const char *mt = nt_type(ast, modid);
    if (!mt || strcmp(mt, "ModuleNode")) continue;
    int modbody = nt_ref(ast, modid, "body");
    if (modbody < 0) continue;
    int nmb; const int *mb = nt_arr(ast, modbody, "body", &nmb);
    int event_loop = 0, on_ids[64], n_on = 0;
    for (int i = 0; i < nmb; i++) {
      const char *ct = nt_type(ast, mb[i]);
      if (!ct || strcmp(ct, "CallNode")) continue;
      const char *cn = nt_str(ast, mb[i], "name");
      if (cn && (!strcmp(cn, "include") || !strcmp(cn, "extend"))) {
        int aid = nt_ref(ast, mb[i], "arguments");
        if (aid >= 0) { int na; const int *args = nt_arr(ast, aid, "arguments", &na);
          for (int a = 0; a < na; a++) { char path[128]; cc_build_const_path(ast, args[a], path, sizeof path);
            if (!strcmp(path, "BPF::EventLoop")) event_loop = 1; } }
      } else if (cn && !strcmp(cn, "on") && n_on < 64) on_ids[n_on++] = mb[i];
    }
    if (!event_loop) continue;
    int react = 0;
    for (int oi = 0; oi < n_on; oi++) {
      int cid = on_ids[oi];
      int aid = nt_ref(ast, cid, "arguments"); if (aid < 0) continue;
      int na; const int *args = nt_arr(ast, aid, "arguments", &na); if (na < 1) continue;
      const char *st = nt_type(ast, args[0]);
      if (!st || strcmp(st, "SymbolNode")) continue;
      const char *kind = nt_str(ast, args[0], "value"); if (!kind) continue;
      /* `on :timer` is the one withdrawn attach kind with no `def` form,
       * so cc_refuse_withdrawn_attach (which keys on a method name) never sees
       * it. Left alone it is the worst case measured: an unknown reactor
       * kind is skipped, so the handler body does not merely attach to nothing --
       * it never reaches the output at all. Refuse it by name.
       * (Any OTHER unknown `on :kind` is still skipped silently: the same bug
       * class, not yet adjudicated.) */
      if (!strcmp(kind, "timer")) cc_refuse_withdrawn_attach("spnl_timer__main");
      /* the multi-symbol form takes an ArrayNode where the 1-to-1 form
       * takes a StringNode, so it is decided before the target collection below. */
      if (cc_synthesize_multi(ir, ast, cid, args, na, kind)) continue;
      const ReactorKind *rk = cc_reactor_kind(kind); if (!rk) continue;
      /* collect `arity` StringNode targets */
      const char *tg[3]; int ntg = 0;
      for (int i = 1; i <= rk->arity && i < na; i++) {
        const char *tt = nt_type(ast, args[i]);
        if (tt && !strcmp(tt, "StringNode")) { const char *tv = nt_str(ast, args[i], "content"); if (tv && tv[0]) tg[ntg++] = tv; }
      }
      if (ntg != rk->arity) continue;
      char *mname;
      if (rk->arity == 0)      mname = strdup(rk->prefix);
      else if (rk->arity == 2) mname = msprintf("%s%s%s%s", rk->prefix, tg[0], rk->joiner, tg[1]);
      else if (rk->react)      mname = msprintf("%s%d", rk->prefix, react++);   /* uprobe/uretprobe/usdt */
      else                     mname = msprintf("%s%s", rk->prefix, tg[0]);      /* kprobe/kretprobe/fentry/fexit */
      int block = nt_ref(ast, cid, "block"); if (block < 0) { free(mname); continue; }
      int hbody = nt_ref(ast, block, "body"); if (hbody < 0) { free(mname); continue; }
      ir->m = realloc(ir->m, (size_t)(ir->n + 1) * sizeof(Method));
      Method *me = &ir->m[ir->n]; memset(me, 0, sizeof *me);
      me->name = mname; me->cls = NULL; me->ret = CC_TY_INT; me->body_id = hbody;
      cc_extract_block_params(ast, block, me);
      ir->n++;
    }
  }
}

/* `class N < BPF::XDP` and `module N; include BPF::XDP` bind every method of N
 * to an attach kind. Both are pure surface: the emitted .bpf.c is byte-identical
 * to the flat `def <prefix><member>`, so this pass does exactly that rename and
 * then gets out of the way.
 *
 * WHY A POST-PASS AND NOT THE IR BUILD. The struct_ops trio (TcpCC/SchedExt/
 * Qdisc) is bound during IR construction, in two places -- ir_parse for the text
 * path and fill_ir_from_compiler for the in-process one. Six of the nine class
 * parents were never added there, and the module form was never handled at all
 * (a module has no superclass, so `cls_parents` is empty and there was nothing
 * to key on). The result was measured: fifteen of the eighteen class/module
 * surfaces compiled to a plain SEC("syscall") wrapper -- the same silent
 * degradation the withdrawn attach kinds had, in a vocabulary that earlier
 * sweep did not look at because it probed every attach kind through its FLAT
 * spelling.
 *
 * Running after the IR is built and before cc_tag_flat_struct_ops means one site
 * covers both IR paths, and the module form of the struct_ops trio needs no
 * special case: rename to `tcp_cc__cong_avoid` and the flat tagger does the rest.
 * The CLASS form of the trio is already `cls == NULL` by now, so it is untouched. */
typedef struct { const char *path, *prefix; } CcDslParent;
static const CcDslParent CC_DSL_PARENTS[] = {
  { "BPF::XDP",         "xdp__" },
  { "BPF::SockOps",     "sock_ops__" },
  { "BPF::TcIngress",   "tc__ingress__" },
  { "BPF::TcEgress",    "tc__egress__" },
  { "BPF::SkReuseport", "sk_reuseport__" },
  { "BPF::SkMsg",       "sk_msg__" },
  { "BPF::TcpCC",       "tcp_cc__" },
  { "BPF::SchedExt",    "sched_ext__" },
  { "BPF::Qdisc",       "qdisc__" },
  { NULL, NULL }
};

static const char *cc_dsl_parent_prefix(const char *path) {
  if (!path || !*path) return NULL;
  for (int i = 0; CC_DSL_PARENTS[i].path; i++)
    if (!strcmp(CC_DSL_PARENTS[i].path, path)) return CC_DSL_PARENTS[i].prefix;
  return NULL;
}

static void cc_bind_dsl_class_attach(IR *ir, AST *ast) {
  int stmts = nt_ref(ast, 0, "statements");   /* ProgramNode(0).statements */
  if (stmts < 0) return;
  int nb; const int *body = nt_arr(ast, stmts, "body", &nb);
  for (int bi = 0; bi < nb; bi++) {
    int nid = body[bi];
    const char *ty = nt_type(ast, nid);
    if (!ty) continue;
    int is_class = !strcmp(ty, "ClassNode"), is_module = !strcmp(ty, "ModuleNode");
    if (!is_class && !is_module) continue;
    /* Neither node carries `name`: both name themselves through `constant_path`
     * (a ConstantReadNode for `class Foo`, a ConstantPathNode for `class A::Foo`). */
    char cname[128];
    cc_build_const_path(ast, nt_ref(ast, nid, "constant_path"), cname, sizeof cname);
    if (!cname[0]) continue;

    char path[128]; path[0] = '\0';
    if (is_class) {
      int sup = nt_ref(ast, nid, "superclass");
      if (sup >= 0) cc_build_const_path(ast, sup, path, sizeof path);
    } else {
      int mbody = nt_ref(ast, nid, "body");
      if (mbody < 0) continue;
      int nmb; const int *mb = nt_arr(ast, mbody, "body", &nmb);
      for (int i = 0; i < nmb; i++) {
        const char *ct = nt_type(ast, mb[i]);
        if (!ct || strcmp(ct, "CallNode")) continue;
        const char *cn = nt_str(ast, mb[i], "name");
        /* `extend` too: cc_synthesize_reactor already accepts it for
         * BPF::EventLoop, and a surface that is accepted in one DSL and silently
         * ignored in its sibling is exactly the shape this pass removes. */
        if (!cn || (strcmp(cn, "include") && strcmp(cn, "extend"))) continue;
        int aid = nt_ref(ast, mb[i], "arguments");
        if (aid < 0) continue;
        int na; const int *args = nt_arr(ast, aid, "arguments", &na);
        for (int a = 0; a < na; a++) {
          char p[128];
          cc_build_const_path(ast, args[a], p, sizeof p);
          if (cc_dsl_parent_prefix(p)) snprintf(path, sizeof path, "%s", p);
        }
      }
    }
    const char *prefix = cc_dsl_parent_prefix(path);
    if (!prefix) continue;   /* not a BPF DSL parent (plain class/module, or BPF::EventLoop) */

    for (int m = 0; m < ir->n; m++) {
      Method *me = &ir->m[m];
      if (!me->cls || !me->name || strcmp(me->cls, cname)) continue;
      me->name = msprintf("%s%s", prefix, me->name);
      me->cls  = NULL;   /* now indistinguishable from the flat `def <prefix><member>` */
    }
  }
}

/* tag flat top-level struct_ops methods. The class form
 * (`class X < BPF::Qdisc/SchedExt/TcpCC`) sets so_kind/so_member during IR build
 * (ir_parse / fill_ir_from_compiler). The flat form `def qdisc__enqueue(...)` at
 * top level is a plain method whose name already carries the `<prefix>__<member>`
 * shape but was left so_kind == SO_NONE -- so it fell through to a regular method
 * (SEC("syscall"), no bundle). Mirror cc_in_tcp_cc's NAME-prefix approach: for any
 * UNTAGGED method (so_kind == SO_NONE) whose name is `<prefix>__<member>` where
 * <member> is a REAL member of that kind (present in SO_*_MEMBERS), tag it exactly
 * as the class form does. Prefix-matches-but-not-a-member (e.g. `def qdisc__helper`)
 * stays SO_NONE = a normal method (no die -- only well-formed struct_ops registers).
 * ADDITIVE: only fires for SO_NONE, so the already-tagged class form is untouched. */
static void cc_tag_flat_struct_ops(IR *ir) {
  static const struct { const char *prefix; size_t plen; int kind; } K[] = {
    { "tcp_cc__",    8,  SO_TCP_CC    },
    { "sched_ext__", 11, SO_SCHED_EXT },
    { "qdisc__",     7,  SO_QDISC     },
  };
  for (int i = 0; i < ir->n; i++) {
    Method *me = &ir->m[i];
    if (me->so_kind != SO_NONE || !me->name) continue;
    for (int k = 0; k < 3; k++) {
      if (strncmp(me->name, K[k].prefix, K[k].plen)) continue;
      const char *member = me->name + K[k].plen;   /* points into me->name (stable) */
      if (cc_so_member(K[k].kind, member)) {        /* only real members register */
        me->so_kind = K[k].kind;
        me->so_member = member;
      }
      break;   /* prefix matched (member or not); no other prefix can match */
    }
  }
}

/* amp-m7 trigger DSL (convention over method name).
 *   timer_<ms>  -> AMP_TRIG_TIMER, param = ms       (M7 runtime calls every <ms> ms)
 *   irq_<n>     -> AMP_TRIG_IRQ,   param = NVIC IRQ  (call on IRQ n; TPM4=74)
 *   cmd         -> AMP_TRIG_CMD,   param = 0         (the command ring from the application core, equivalent to a user ring buffer)
 *   otherwise   -> AMP_TRIG_MANUAL (runtime calls explicitly)
 * The trigger table rides in the same .bpf.c under #ifdef SPNL_AMP_MANIFEST so
 * clang -target bpf ignores it; the M7 loader compiles the file with that macro
 * to learn which handler fires on which source. */
enum { AMP_TRIG_MANUAL = 0, AMP_TRIG_TIMER = 1, AMP_TRIG_IRQ = 2, AMP_TRIG_CMD = 3 };
static int amp_all_digits(const char *s) {
  if (!*s) return 0;
  for (; *s; s++) if (*s < '0' || *s > '9') return 0;
  return 1;
}
static int amp_trigger_of(const char *name, unsigned *param) {
  *param = 0;
  if (!strncmp(name, "timer_", 6) && amp_all_digits(name + 6)) { *param = (unsigned)strtoul(name + 6, 0, 10); return AMP_TRIG_TIMER; }
  if (!strncmp(name, "irq_", 4)   && amp_all_digits(name + 4)) { *param = (unsigned)strtoul(name + 4, 0, 10); return AMP_TRIG_IRQ; }
  if (!strcmp(name, "cmd")) return AMP_TRIG_CMD;
  return AMP_TRIG_MANUAL;
}
static const char *amp_trigger_kw(int kind) {
  switch (kind) { case AMP_TRIG_TIMER: return "AMP_TRIG_TIMER"; case AMP_TRIG_IRQ: return "AMP_TRIG_IRQ";
                  case AMP_TRIG_CMD: return "AMP_TRIG_CMD"; default: return "AMP_TRIG_MANUAL"; }
}

/* amp-m7 allowlist. v0 lowers only ivar RMW, integer arithmetic,
 * `if`/locals and `spnl_emit`. Any other builtin/method call would lower to an
 * `spnl_*`/`bpf_*` symbol the amp preamble never defines and fail at clang; catch
 * it at codegen time with a clear message (partition failure is a loud,
 * immediate error, never a silent/late fallback). CallNodes that ARE allowed:
 * binary operators (a + b, @x > 5, ...) and spnl_emit. */
static void amp_scan_supported(AST *ast, int nid) {
  if (nid < 0) return;
  const char *ty = nt_type(ast, nid);
  if (!ty) return;
  if (!strcmp(ty, "DefNode") || !strcmp(ty, "ClassNode") || !strcmp(ty, "ModuleNode")) return;
  if (!strcmp(ty, "CallNode")) {
    const char *nm = nt_str(ast, nid, "name");
    if (nm && !cc_is_binary_op(nm) && strcmp(nm, "spnl_emit") != 0 && strcmp(nm, "ktime_ns") != 0) {
      char msg[256];
      snprintf(msg, sizeof msg,
        "amp-m7 (--target amp-m7) does not support '%s' in v0. "
        "Supported: ivar RMW (@x/@x += n), integer arithmetic, if/locals, spnl_emit, ktime_ns. "
        "Move this logic to the A55 side, or extend the amp helper set", nm);
      die(msg, nm);
    }
  }
  SpNode *n = node_at(ast, nid);
  for (int i = 0; i < n->nr; i++) amp_scan_supported(ast, n->r[i].ref);
  for (int i = 0; i < n->na; i++)
    for (int k = 0; k < n->a[i].n; k++) amp_scan_supported(ast, n->a[i].ids[k]);
}

/* amp-m7 .bpf.c. Emits an h2.c-shaped translation unit (no
 * vmlinux/maps/SEC) -- each eligible method becomes a plain `int f(void *ctx)`,
 * ivar -> static-memory RMW at a baked carveout address, spnl_emit -> amp_emit().
 * clang -target bpf compiles this to bytecode the micro-bpf ARMv7E-M JIT AOTs.
 * Kept fully separate from the Linux path so golden output stays byte-identical. */
static char *amp_codegen_program(IR *ir, AST *ast, const char *base) {
  g_ir = ir;
  /* the AMP target has no BPF helpers, so `filter_by` cannot be honoured
   * here. Say so rather than emitting a probe whose declared narrowing quietly
   * does nothing -- that is the exact failure the common filter exists to close. */
  g_filter_mask = 0; g_filter_declared = 0;
  cc_scan_common_filter(ast);
  if (g_filter_declared)
    die("filter_by is not available on the AMP target: there is no "
        "bpf_get_current_pid_tgid/uid_gid/comm on an M-core, so the declaration "
        "could not narrow anything. Narrow in the handler body instead", base);
  g_unit = cc_sanitize(base);
  g_amp = 1;
  g_amp_nivars = 0;
  int n = 0;
  for (int i = 0; i < ir->n; i++) if (cc_method_eligible(&ir->m[i])) n++;
  if (n == 0) die("amp-m7: no eBPF-eligible handler method found", base);

  /* lower every handler body first (populates the ivar registry via cc_ivar_map). */
  Lines *m_bodies = calloc(ir->n > 0 ? ir->n : 1, sizeof(Lines));
  for (int i = 0; i < ir->n; i++) {
    if (!cc_method_eligible(&ir->m[i])) continue;
    if (ir->m[i].nparams != 0) die("amp-m7 handler takes no params (v0)", ir->m[i].name);
    amp_scan_supported(ast, ir->m[i].body_id);   /* loud die on unsupported builtins */
    cc_emit_method_body(ast, &ir->m[i], &m_bodies[i]);
  }

  Buf out; memset(&out, 0, sizeof out);
  buf_printf(&out,
    "/* generated by spinel-ebpf --target amp-m7. Build:\n"
    " *   clang -O2 -target bpf -c %s.bpf.c -o %s.bpf.o\n"
    " * then host-AOT to ARMv7E-M via the micro-bpf JIT. */\n"
    "typedef unsigned int __u32;\n"
    "typedef long long __s64;\n"
    "#ifndef SPNL_AMP_IVARS_BASE\n"
    "#define SPNL_AMP_IVARS_BASE %#010xu   /* = AMP_IVARS_BASE (spnl/amp_abi_imx95m7.h); single-pass default, override at build */\n"
    "#endif\n"
    "/* spnl_emit -> amp_emit(): helper id 1; the M7 runtime publishes to the DDR ring. */\n"
    "static unsigned long long (*amp_emit)(unsigned long long) = (void *)1;\n"
    "/* ktime_ns -> amp_ktime(): helper id 2; the M7 runtime returns NETC PHC ns (gPTP-synced). */\n"
    "static unsigned long long (*amp_ktime)(void) = (void *)2;\n",
    base, base, AMP_IVARS_BASE_MIRROR);

  for (int i = 0; i < ir->n; i++) {
    if (!cc_method_eligible(&ir->m[i])) continue;
    char *fn = cc_func_name(&ir->m[i]);
    buf_printf(&out, "\nint %s(void *ctx)\n{\n    (void)ctx;\n", fn);
    for (int k = 0; k < m_bodies[i].n; k++)
      buf_printf(&out, "    %s\n", m_bodies[i].v[k]);
    if (ir->m[i].ret == CC_TY_VOID) buf_printf(&out, "    return 0;\n");
    buf_printf(&out, "}\n");
    free(fn);
    lines_free(&m_bodies[i]);
  }
  free(m_bodies);

  /* trigger manifest. Rides under #ifdef SPNL_AMP_MANIFEST so the probe
   * build (clang -target bpf) ignores it; the M7 loader compiles this same file
   * with -DSPNL_AMP_MANIFEST to wire each handler to its trigger source. */
  buf_printf(&out,
    "\n#ifdef SPNL_AMP_MANIFEST   /* M7 loader reads this; clang -target bpf skips it */\n"
    "enum { AMP_TRIG_MANUAL = 0, AMP_TRIG_TIMER = 1, AMP_TRIG_IRQ = 2, AMP_TRIG_CMD = 3 };\n"
    "/* fixed-ABI manifest fields the M7 loader gates on.\n"
    " *   amp_abi_version -- must equal the board profile's AMP_ABI_VERSION\n"
    " *                     (spnl/amp_abi.h); the loader rejects a mismatch loudly,\n"
    " *                     so neither a firmware/blob ABI revision nor a blob built\n"
    " *                     for another board's address map goes through silently.\n"
    " *                     Override with -DSPNL_AMP_ABI_VERSION when building for a\n"
    " *                     board other than the default profile.\n"
    " *   amp_ivars_size  -- bytes of the IVARS carveout this probe uses (= 4 * #ivars);\n"
    " *                     the loader zeroes exactly this span per slot-install so a\n"
    " *                     hot-swapped probe never reads the previous probe's ivars. */\n"
    "#ifndef SPNL_AMP_ABI_VERSION\n"
    "#define SPNL_AMP_ABI_VERSION %uu\n"
    "#endif\n"
    "static const unsigned amp_abi_version = SPNL_AMP_ABI_VERSION;\n"
    "static const unsigned amp_ivars_size  = %uu;\n"
    "struct amp_trigger { const char *fn; int kind; unsigned param; };\n"
    "static const struct amp_trigger amp_triggers[] = {\n",
    AMP_ABI_VERSION_MIRROR, (unsigned)(g_amp_nivars * 4));
  for (int i = 0; i < ir->n; i++) {
    if (!cc_method_eligible(&ir->m[i])) continue;
    char *fn = cc_func_name(&ir->m[i]);
    unsigned param = 0;
    int kind = amp_trigger_of(fn, &param);
    buf_printf(&out, "    { \"%s\", %s, %u },\n", fn, amp_trigger_kw(kind), param);
    free(fn);
  }
  buf_printf(&out,
    "};\n"
    "static const unsigned amp_triggers_n = sizeof(amp_triggers)/sizeof(amp_triggers[0]);\n"
    "#endif /* SPNL_AMP_MANIFEST */\n");

  g_amp = 0;
  return out.p ? out.p : strdup("");
}

/* Build the full .bpf.c text (mirrors Ruby CodegenBpf.emit). Returns malloc'd
 * string; this is the function the Stage-2 in-process plugin will hook. */
static char *ebpf_codegen_program(IR *ir, AST *ast, const char *base) {
  if (getenv("SPNL_AMP_M7")) return amp_codegen_program(ir, ast, base);
  { const char *ef = getenv("SPNL_ENFORCEMENT"); g_monitor = (ef && !strcmp(ef, "monitor")); }
  g_ir = ir;
  cc_bind_dsl_class_attach(ir, ast);   /* class/module DSL -> flat <prefix><member> */
  cc_tag_flat_struct_ops(ir);   /* flat `def <prefix>__<member>` -> struct_ops member */
  for (int i = 0; i < g_n_params; i++) free(g_param_names[i]);
  g_n_params = 0;
  cc_scan_params(ast);          /* top-level `param :x, default: N` */
  g_filter_mask = 0; g_filter_declared = 0;
  cc_scan_common_filter(ast);   /* top-level `filter_by :pid, ...` */
  cc_filter_gate(ir);           /* ... and refuse a unit it cannot cover in full */
  g_unit = cc_sanitize(base);
  g_uses_sock_owner = 0;   /* reset per unit */
  g_uses_l7 = 0;           /* reset per unit */
  g_uses_http_l7 = 0;      /* reset per unit */
  g_uses_offcpu = 0;       /* reset per unit */
  g_uses_dns_lat = 0;      /* reset per unit */
  g_uses_redis_l7 = 0;     /* reset per unit */
  int n_ebpf = 0, uses_pt_regs = 0, uses_usdt = 0, emit_flags = 0;
  int uses_blocklist = 0, uses_cidr = 0, uses_path_counter = 0;
  int uses_path_scratch = 0;  /* path_starts_with -> per-unit PERCPU_ARRAY d_path scratch (PATH_MAX) */
  int uses_histogram = 0, uses_latency = 0, uses_hist_keyed = 0, uses_hist_linear = 0;
  int uses_stack_trace = 0;
  int uses_go_gptr = 0;      /* go_tls_resp_stash/emit read the g register (ctx->regs[28]) -> ctx forward + go_recv_stash */
  int uses_off_cpu = 0;      /* off_cpu_start/observe */
  int uses_sched_ext = 0, uses_qdisc = 0, uses_tcp_cc = 0;   /* struct_ops kinds */
  int uses_qdisc_fifo = 0;   /* queue_push/queue_pop */
  int uses_kfield = 0;       /* kfield/kptr -> BPF_CORE_READ (bpf_core_read.h) */
  int uses_kfield_str = 0;   /* emit_kfield_str/kfield_str_eq -> SPNL_KFIELD_STR preamble */
  int uses_sock_endian = 0;  /* a converting sock_* accessor -> bpf_ntohs/ntohl */
  int uses_task_attrs = 0;   /* has_cap/cap_effective/ns_id/in_host_ns -> SPNL_CAPS preamble */
  int uses_host_ns = 0;      /* in_host_ns -> the init_* ksym externs (separate: unused ksyms still resolve) */
  int uses_task_storage = 0; /* task_load/store/incr/swap */
  int uses_map_in_map = 0;   /* mim_inc/mim_get */
  int uses_fifo = 0, uses_lifo = 0;   /* QUEUE / STACK maps */
  int uses_xskmap = 0, uses_devmap = 0;   /* xsk_redirect / dev_redirect */
  int uses_cpumap = 0;                    /* cpumap_redirect */
  int uses_leak_track = 0;   /* leak_record / leak_forget */
  int uses_lock_edge = 0;    /* lock_edge */
  int uses_keyed_lat = 0;    /* lat_start/lat_end */
  int uses_depth = 0;        /* depth_inc/depth_dec (--instrument depth-collapse) */
  int uses_fib = 0;          /* fib_lookup/fib_lookup6 (needs bpf_endian.h) */
  int uses_csum = 0;         /* skb_load/store u16/u32 + csum_replace (bpf_endian.h) */
  int uses_arena = 0;        /* arena_set/get (flat array) */
  g_n_pkt = 0;
  g_n_flow = 0;
  for (int i = 0; i < ir->n; i++) {
    if (!cc_method_eligible(&ir->m[i])) continue;
    /* before anything else, refuse a method named after an attach kind
     * this codegen dropped. Done in the eligibility pass so it fires whether the
     * name was typed (`def xdp_tail__x`) or synthesised by the reactor. */
    cc_refuse_withdrawn_attach(ir->m[i].name);
    n_ebpf++;
    int bdy = ir->m[i].body_id;
    cc_scan_emit(ast, bdy, &emit_flags);
    if (cc_body_uses_call(ast, bdy, "blocklist_match"))      uses_blocklist = 1;
    if (cc_body_uses_call(ast, bdy, "cidr_blocklist_match")) uses_cidr = 1;
    if (cc_body_uses_call(ast, bdy, "path_counter_inc"))     uses_path_counter = 1;
    if (cc_body_uses_call(ast, bdy, "path_starts_with") ||
        cc_body_uses_call(ast, bdy, "path_contains"))        uses_path_scratch = 1;
    /* histogram + latency. hist_observe_by also needs spnl_hist_log2
     * from the plain histogram section, so it sets uses_histogram too. */
    if (cc_body_uses_call(ast, bdy, "hist_observe") || cc_body_uses_call(ast, bdy, "hist_observe_by")) uses_histogram = 1;
    if (cc_body_uses_call(ast, bdy, "hist_observe_by"))     uses_hist_keyed = 1;
    if (cc_body_uses_call(ast, bdy, "hist_observe_linear")) uses_hist_linear = 1;
    if (cc_body_uses_call(ast, bdy, "latency_start") || cc_body_uses_call(ast, bdy, "latency_end")) uses_latency = 1;
    /* stack_id() / user_stack_id() (and off_cpu_start) need bpf_stacks
     * + ctx forwarded into the tracing-family inner (bpf_get_stackid wants ctx). */
    if (cc_body_uses_call(ast, bdy, "stack_id") || cc_body_uses_call(ast, bdy, "user_stack_id") ||
        cc_body_uses_call(ast, bdy, "off_cpu_start")) uses_stack_trace = 1;
    /* off_cpu_start/observe pull in off_cpu map + histogram + keyed hist + stacks. */
    if (cc_body_uses_call(ast, bdy, "off_cpu_start") || cc_body_uses_call(ast, bdy, "off_cpu_observe")) {
      uses_off_cpu = 1; uses_histogram = 1; uses_hist_keyed = 1; uses_stack_trace = 1;
    }
    /* sock_owner_set -> per-unit socket->owner correlation map (emit_connect correlates). */
    if (cc_body_uses_call(ast, bdy, "sock_owner_set")) g_uses_sock_owner = 1;
    /* req_start/emit_l7 -> per-unit send-time correlation map (L7 round-trip latency). */
    if (cc_body_uses_call(ast, bdy, "req_start") || cc_body_uses_call(ast, bdy, "emit_l7")) g_uses_l7 = 1;
    /* http_req_start/http_resp_stash/http_emit -> HTTP L7 RED (method/path/status/duration).
     * ssl_req_start/ssl_resp_stash/ssl_emit reuse the SAME maps/struct/filter (TLS plaintext). */
    if (cc_body_uses_call(ast, bdy, "http_req_start") || cc_body_uses_call(ast, bdy, "http_resp_stash") ||
        cc_body_uses_call(ast, bdy, "http_emit") ||
        cc_body_uses_call(ast, bdy, "ssl_req_start") || cc_body_uses_call(ast, bdy, "ssl_resp_stash") ||
        cc_body_uses_call(ast, bdy, "ssl_emit") ||
        cc_body_uses_call(ast, bdy, "go_tls_write") ||
        cc_body_uses_call(ast, bdy, "go_tls_req") || cc_body_uses_call(ast, bdy, "go_tls_resp_stash") ||
        cc_body_uses_call(ast, bdy, "go_tls_emit")) g_uses_http_l7 = 1;   /* Go crypto/tls plaintext -> http_events */
    /* go_tls_resp_stash/emit key the recv-stash by the Go g register (goroutine),
     * not tid (which migrates on a blocking Read). Needs ctx forwarded (regs[28]). */
    if (cc_body_uses_call(ast, bdy, "go_tls_resp_stash") || cc_body_uses_call(ast, bdy, "go_tls_emit"))
        uses_go_gptr = 1;
    /* redis_req_start/redis_resp_stash/redis_emit -> Redis L7 RED (command/error/duration).
     * Mirrors the HTTP channel with its own dedicated maps (RESP != HTTP filter/parse). */
    if (cc_body_uses_call(ast, bdy, "redis_req_start") || cc_body_uses_call(ast, bdy, "redis_resp_stash") ||
        cc_body_uses_call(ast, bdy, "redis_emit")) g_uses_redis_l7 = 1;
    /* off-CPU-during-request correlation. Reuses spnl_is_http_req; the sched_switch
     * accounting needs bpf_stacks + ctx (uses_stack_trace, like off_cpu_start). */
    if (cc_body_uses_call(ast, bdy, "offcpu_recv_stash") || cc_body_uses_call(ast, bdy, "offcpu_begin") ||
        cc_body_uses_call(ast, bdy, "offcpu_account") || cc_body_uses_call(ast, bdy, "offcpu_emit")) g_uses_offcpu = 1;
    if (cc_body_uses_call(ast, bdy, "offcpu_account")) uses_stack_trace = 1;
    /* dns_req_start/dns_resp_stash/dns_emit -> DNS RTT. Query (udp_sendmsg) records the
     * start keyed by (sock,txid); recv (udp_recvmsg entry-stash + kretprobe) correlates by the
     * response txid -> duration. Reuses the dns_events ringbuf (dns_emit sets EMIT_DNS). */
    if (cc_body_uses_call(ast, bdy, "dns_req_start") || cc_body_uses_call(ast, bdy, "dns_resp_stash") ||
        cc_body_uses_call(ast, bdy, "dns_emit")) g_uses_dns_lat = 1;
    /* struct_ops kinds (from class X < BPF::SchedExt/Qdisc/TcpCC synthesis). */
    if (ir->m[i].so_kind == SO_SCHED_EXT) uses_sched_ext = 1;
    else if (ir->m[i].so_kind == SO_QDISC) uses_qdisc = 1;
    else if (ir->m[i].so_kind == SO_TCP_CC) uses_tcp_cc = 1;
    if (cc_body_uses_call(ast, bdy, "queue_push") || cc_body_uses_call(ast, bdy, "queue_pop")) uses_qdisc_fifo = 1;
    if (cc_body_uses_call(ast, bdy, "kfield") || cc_body_uses_call(ast, bdy, "kptr") ||
        cc_body_uses_call(ast, bdy, "field_exists") ||
        cc_body_uses_call(ast, bdy, "ppid") ||
        cc_body_uses_call(ast, bdy, "emit_connect") ||
        cc_body_uses_call(ast, bdy, "emit_dns") ||
        cc_body_uses_call(ast, bdy, "emit_l7") ||
        cc_body_uses_call(ast, bdy, "http_req_start") || cc_body_uses_call(ast, bdy, "http_resp_stash") ||
        cc_body_uses_call(ast, bdy, "http_emit") ||
        cc_body_uses_call(ast, bdy, "dns_req_start") || cc_body_uses_call(ast, bdy, "dns_resp_stash") ||
        cc_body_uses_call(ast, bdy, "emit_tcp_payload") ||
        cc_body_uses_call(ast, bdy, "emit_tcp_stream") ||
        cc_body_uses_call(ast, bdy, "redis_req_start") || cc_body_uses_call(ast, bdy, "redis_resp_stash") ||
        cc_body_uses_call(ast, bdy, "offcpu_recv_stash") || cc_body_uses_call(ast, bdy, "offcpu_emit")) uses_kfield = 1;  /* ppid + the srtt + the msg + the peer + the http + the offcpu msg + the dns req/resp msg + the tcp payload msg + the tcp stream msg + the redis msg -> BPF_CORE_READ */
    /* kfield_str family -- the SPNL_KFIELD_STR preamble, and BPF_CORE_READ*
     * from the same header kfield needs. */
    if (cc_body_uses_call(ast, bdy, "emit_kfield_str") || cc_body_uses_call(ast, bdy, "kfield_str_eq")) {
      uses_kfield_str = 1; uses_kfield = 1;
    }
    /* Capability / namespace / file-type reads. All of them are CO-RE
     * chains, so they need the same header kfield does; the two macro preambles
     * come in separately because in_host_ns is the only one that declares ksyms
     * (an extern nobody references is still an extern libbpf must resolve). */
    if (cc_body_uses_call(ast, bdy, "has_cap") || cc_body_uses_call(ast, bdy, "has_cap_permitted") ||
        cc_body_uses_call(ast, bdy, "has_cap_inheritable") ||
        cc_body_uses_call(ast, bdy, "cap_effective") ||
        cc_body_uses_call(ast, bdy, "ns_id") || cc_body_uses_call(ast, bdy, "in_host_ns")) {
      uses_task_attrs = 1; uses_kfield = 1;
    }
    if (cc_body_uses_call(ast, bdy, "in_host_ns")) { uses_host_ns = 1; uses_kfield = 1; }
    if (cc_body_uses_call(ast, bdy, "file_type"))  uses_kfield = 1;
    /* sock_* accessors read through BPF_CORE_READ (same header as kfield);
     * only the ones that actually convert pull in bpf_endian.h. */
    for (int s = 0; CC_SOCK_ACC[s].name; s++) {
      if (!cc_body_uses_call(ast, bdy, CC_SOCK_ACC[s].name)) continue;
      uses_kfield = 1;
      if (CC_SOCK_ACC[s].conv != SK_RAW) uses_sock_endian = 1;
    }
    if (cc_body_uses_call(ast, bdy, "task_load") || cc_body_uses_call(ast, bdy, "task_store") ||
        cc_body_uses_call(ast, bdy, "task_incr") || cc_body_uses_call(ast, bdy, "task_swap")) uses_task_storage = 1;
    if (cc_body_uses_call(ast, bdy, "mim_inc") || cc_body_uses_call(ast, bdy, "mim_get")) uses_map_in_map = 1;
    if (cc_body_uses_call(ast, bdy, "fifo_push") || cc_body_uses_call(ast, bdy, "fifo_pop")) uses_fifo = 1;
    if (cc_body_uses_call(ast, bdy, "lifo_push") || cc_body_uses_call(ast, bdy, "lifo_pop")) uses_lifo = 1;
    if (cc_body_uses_call(ast, bdy, "xsk_redirect")) uses_xskmap = 1;
    if (cc_body_uses_call(ast, bdy, "cpumap_redirect")) uses_cpumap = 1;
    if (cc_body_uses_call(ast, bdy, "dev_redirect")) uses_devmap = 1;
    if (cc_body_uses_call(ast, bdy, "leak_record") || cc_body_uses_call(ast, bdy, "leak_forget")) uses_leak_track = 1;
    if (cc_body_uses_call(ast, bdy, "lock_edge")) uses_lock_edge = 1;
    if (cc_body_uses_call(ast, bdy, "lat_start") || cc_body_uses_call(ast, bdy, "lat_end")) uses_keyed_lat = 1;
    if (cc_body_uses_call(ast, bdy, "depth_inc") || cc_body_uses_call(ast, bdy, "depth_dec")) uses_depth = 1;
    if (cc_body_uses_call(ast, bdy, "fib_lookup") || cc_body_uses_call(ast, bdy, "fib_lookup6")) uses_fib = 1;
    if (cc_body_uses_call(ast, bdy, "skb_load_u16") || cc_body_uses_call(ast, bdy, "skb_load_u32") ||
        cc_body_uses_call(ast, bdy, "skb_store_u16") || cc_body_uses_call(ast, bdy, "skb_store_u32") ||
        cc_body_uses_call(ast, bdy, "l3_csum_replace") || cc_body_uses_call(ast, bdy, "l4_csum_replace") ||
        cc_body_uses_call(ast, bdy, "l3_csum_replace_ip") || cc_body_uses_call(ast, bdy, "l4_csum_replace_ip") ||
        cc_body_uses_call(ast, bdy, "sk_lookup_tcp") || cc_body_uses_call(ast, bdy, "sk_assign_tcp")) uses_csum = 1;
    if (cc_body_uses_call(ast, bdy, "arena_set") || cc_body_uses_call(ast, bdy, "arena_get") ||
        cc_body_uses_call(ast, bdy, "arena_hash_set") || cc_body_uses_call(ast, bdy, "arena_hash_get") ||
        cc_body_uses_call(ast, bdy, "arena_hash_del") || cc_body_uses_call(ast, bdy, "arena_list_push") ||
        cc_body_uses_call(ast, bdy, "arena_list_sum")) uses_arena = 1;
    Attach ai;
    cc_detect_attach(ir->m[i].name, &ai);
    /* PT_REGS_PARM<N> macros (bpf_tracing.h) for probe-family with params. */
    if (ir->m[i].nparams && (ai.kind == AK_KPROBE || ai.kind == AK_KRETPROBE ||
                             ai.kind == AK_UPROBE || ai.kind == AK_URETPROBE ||
                             ai.kind == AK_KPROBE_MULTI)) uses_pt_regs = 1;
    if (ai.usdt) uses_usdt = 1;   /* usdt.bpf.h + bpf_tracing.h */
    /* record pkt_* builtins + flow conntrack maps for the helper pass. */
    if (ai.kind == AK_XDP || ai.kind == AK_TC) {
      cc_scan_pkt(ast, ir->m[i].body_id, ai.kind == AK_TC);
      cc_scan_flow(ast, ir->m[i].body_id, ai.kind == AK_TC);
    }
    if (ai.sec) free(ai.sec);
  }
  /* classes_used: a class with >=1 eligible method (drops builtin/internal classes
   * whose methods are all body<0 stubs). */
  char *cls_used = calloc(ir->ncls > 0 ? ir->ncls : 1, 1);
  for (int i = 0; i < ir->n; i++) {
    if (!cc_method_eligible(&ir->m[i]) || !ir->m[i].cls) continue;
    for (int c = 0; c < ir->ncls; c++)
      if (!strcmp(ir->cls_names[c], ir->m[i].cls)) { cls_used[c] = 1; break; }
  }
  int n_classes = 0;
  for (int c = 0; c < ir->ncls; c++) if (cls_used[c]) n_classes++;

  int uses_ringbuf = (emit_flags & EMIT_INT) != 0;   /* int-event channel */

  /* pre-lower every method body into its own line list BEFORE assembling
   * sections, so loop-callback "deferred functions" (which a body produces as a
   * side effect) are known when we emit them -- they sit between the ctx structs
   * and the inner functions. Ruby lowers all bodies in a first pass too. */
  Lines deferred; memset(&deferred, 0, sizeof deferred);
  g_deferred = &deferred;
  g_loop_counter = 0;
  g_pc_counter = 0;   /* path_contains callback ids, unit scope */
  Lines *m_bodies = calloc(ir->n > 0 ? ir->n : 1, sizeof(Lines));
  for (int i = 0; i < ir->n; i++) {
    if (!cc_method_eligible(&ir->m[i])) continue;
    cc_emit_method_body(ast, &ir->m[i], &m_bodies[i]);
  }

  /* sections are joined by "\n"; each section text ends with "\n" (Ruby heredoc),
   * so the join yields a blank line between sections. */
  Buf out; memset(&out, 0, sizeof out);
  int first = 1;
  #define SECTION_SEP() do { if (!first) buf_puts(&out, "\n"); first = 0; } while (0)

  /* header */
  SECTION_SEP();
  buf_puts(&out, "// SPDX-License-Identifier: GPL-2.0 OR MIT\n//\n");
  buf_puts(&out, "// GENERATED by spinel-ebpf. Do not edit by hand.\n");
  buf_printf(&out, "// Source unit: %s.rb\n", base);
  buf_printf(&out, "// ebpf-eligible methods: %d, classes touched: %d\n", n_ebpf, n_classes);
  if (g_monitor)   /* only in monitor builds, so enforce stays byte-identical */
    buf_puts(&out, "// ENFORCEMENT=monitor: observe only. lsm/fmod_ret/cgroup verdicts\n"
                   "//   are neutralized to allow (handlers still run for their side effects).\n");

  /* license_and_includes: the extras line, or a blank line when there are none
   * (Ruby heredoc interpolates `extras.join("\n")` as one line). */
  SECTION_SEP();
  buf_puts(&out, "#include \"vmlinux.h\"\n#include <bpf/bpf_helpers.h>\n");
  {
    const char *extras[6]; int ne = 0;
    if (emit_flags || g_uses_http_l7 || g_uses_redis_l7 || g_uses_offcpu) extras[ne++] = "#include \"spnl/types.h\"";   /* any emit-family channel, plus the HTTP, Redis and off-CPU event headers */
    if (g_n_pkt > 0 || uses_fib || uses_csum || g_n_flow > 0 || g_uses_l7 || g_uses_http_l7 || g_uses_redis_l7 || uses_sock_endian) extras[ne++] = "#include <bpf/bpf_endian.h>";   /* bpf_ntohs and bpf_htonl: the pkt_* builtins, fib lookups, skb checksums, flows, the peer port of the L7, HTTP and Redis channels, and the converting sock_* accessors */
    if (uses_pt_regs || uses_usdt || uses_sched_ext || uses_qdisc || uses_tcp_cc)
      extras[ne++] = "#include <bpf/bpf_tracing.h>";  /* PT_REGS_PARM / usdt / BPF_PROG */
    if (uses_usdt) extras[ne++] = "#include <bpf/usdt.bpf.h>";       /* bpf_usdt_arg */
    if (uses_qdisc_fifo || uses_kfield) extras[ne++] = "#include <bpf/bpf_core_read.h>";   /* bpf_core_type_id_local / BPF_CORE_READ */
    if (ne == 0) buf_puts(&out, "\n");
    else for (int e = 0; e < ne; e++) buf_printf(&out, "%s\n", extras[e]);
  }
  buf_puts(&out, "char LICENSE[] SEC(\"license\") = \"Dual MIT/GPL\";\n");

  /* Runtime parameters, from top-level `param :name, default: N`.
   *
   * `volatile` is load-bearing, not decoration. Without it -O2 (which the CLI
   * pins) proves the object is never written and folds it at COMPILE time -- the
   * variable stops existing, the skeleton has nothing to patch, and the switch
   * silently does nothing. With `volatile` clang must emit a real load; libbpf
   * then puts the section in a read-only map and BPF_MAP_FREEZEs it before load,
   * which is what lets the VERIFIER do the folding instead -- after the loader has
   * had its say. That inversion is the whole feature.
   *
   * The consequence is deliberate: .rodata is frozen, so a parameter is settable
   * once, at load. Live retuning is a different mechanism with a different price
   * (a writable map, no dead-code elimination, kernel floor 5.5); the codegen already
   * has it. */
  if (g_n_params) {
    SECTION_SEP();
    buf_puts(&out,
      "/* === runtime parameters ===\n"
      " * Patched by the loader between skeleton __open() and __load(); frozen\n"
      " * thereafter. Unset means the declared default, and a default of 0 is what\n"
      " * makes a guard on it disappear from the verified program entirely. */\n");
    for (int i = 0; i < g_n_params; i++)
      buf_printf(&out, "volatile const __s64 spnl_param_%s = %lld;\n",
                 g_param_names[i], g_param_defaults[i]);
  }

  /* The common filter's own .rodata + spnl_filter_discard().
   * Same mechanism as `param` above (that is the whole reason S10 waited for
   * S3), separate vocabulary: these keys are fixed, so they are enumerable by
   * `describe` and `capabilities --json` without reading the probe. */
  if (g_filter_declared) {
    SECTION_SEP();
    cc_emit_common_filter(&out);
  }

  /* sched_ext preamble (SCX_* macros) -- Ruby inserts it at section index 2
   * (right after header + includes), before any map/ringbuf section. */
  if (uses_sched_ext) {
    SECTION_SEP();
    cc_emit_sched_ext_preamble(&out);
  }
  /* FIFO qdisc preamble (bpf_list/kptr machinery) -- same section slot. */
  if (uses_qdisc_fifo) {
    SECTION_SEP();
    cc_emit_qdisc_fifo_preamble(&out);
  }
  /* kernel string-field preamble (SPNL_KSTR_IS_PTR / SPNL_KFIELD_STR). */
  if (uses_kfield_str) {
    SECTION_SEP();
    tpl_emit(&out, tpl_kfield_str, NULL, 0);
  }
  /* capability / namespace preamble, and the initial-namespace ksyms
   * (only when in_host_ns is actually written -- see host_ns.template.c). */
  if (uses_task_attrs) {
    SECTION_SEP();
    tpl_emit(&out, tpl_task_attrs, NULL, 0);
  }
  if (uses_host_ns) {
    SECTION_SEP();
    tpl_emit(&out, tpl_host_ns, NULL, 0);
  }

  /* Ringbuf lost-sample counter + spnl_lost_inc() helper.
   * Emitted once, ahead of every ringbuf channel, whenever the unit has any
   * emit-family channel -- the same condition (line above) that pulls in the
   * ringbuf event header. Every emit else-branch bumps it so a reserve failure
   * (ring full) is counted instead of dropped silently. The map + helper must
   * precede the method bodies that reference them (all maps do). */
  int any_emit = emit_flags || g_uses_http_l7 || g_uses_redis_l7 || g_uses_offcpu;
  if (any_emit) {
    SECTION_SEP();
    tpl_emit(&out, tpl_ringbuf_lost, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }

  /* per-unit int-event ringbuf channel. */
  if (uses_ringbuf) {
    SECTION_SEP();
    tpl_emit(&out, tpl_emit_int, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }

  /* per-unit string-event channel (char str[256] payload). */
  if (emit_flags & EMIT_STR) {
    SECTION_SEP();
    tpl_emit(&out, tpl_emit_str, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }

  /* per-unit pair-event channel (two __s64 values per event). */
  if (emit_flags & EMIT_PAIR) {
    SECTION_SEP();
    tpl_emit(&out, tpl_emit_pair, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }

  /* per-unit N-tuple event channels (3-tuple a,b,c / 4-tuple a,b,c,d). */
  for (int n = 3; n <= 4; n++) {
    if (!(emit_flags & (n == 3 ? EMIT_E3 : EMIT_E4))) continue;
    SECTION_SEP();
    buf_printf(&out, "/* === per-unit %d-tuple-event channel === */\n", n);
    buf_printf(&out, "struct %s_emit%d_event {\n", g_unit, n);
    buf_puts(&out, "    struct spnl_event_hdr hdr;\n");
    const char *fields = "abcd";
    for (int k = 0; k < n; k++) buf_printf(&out, "    __s64 %c;\n", fields[k]);
    buf_puts(&out, "};\n\n");
    buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_RINGBUF);\n    __uint(max_entries, 256 * 1024);\n");
    buf_printf(&out, "} %s_emit%d_events SEC(\".maps\");\n", g_unit, n);
  }

  /* per-unit packed connect-event channel (1 socket-state event = 1 record).
   * declared in record_schema.h (cc_rec_conn), like DNS -- field provenance
   * (cgid = pod attribution, oldstate = direction, daddr6_* = IPv6)
   * now lives with the fields, and the userspace mirror is generated from the same
   * table instead of hand-typed offsets. */
  if (emit_flags & EMIT_CONN) {
    SECTION_SEP();
    cc_rec_emit_channel(&out, &cc_rec_conn, g_unit);
  }

  /* per-unit sock-keyed L7 stream channel (1 tcp_sendmsg fragment = 1 packed record).
   * The sock-aware upgrade of the earlier str channel: {sock, len, raw[128]} lets userspace group
   * fragments per connection (by sock ptr) and reassemble byte-exactly (bounded by the real send
   * length). raw is length-bounded, NOT NUL-terminated (userspace reads exactly `len` bytes). */
  if (emit_flags & EMIT_L7STREAM) {
    SECTION_SEP();
    cc_rec_emit_channel(&out, &cc_rec_l7stream, g_unit);   /* record_schema.h */
  }

  /* per-unit socket->owner correlation map. connect (process ctx) records
   * sock ptr -> owning process; emit_connect (softirq ESTABLISHED -> swapper/0)
   * recovers the real process by sock-ptr lookup. Reused by the send/recv latency correlation.
   * cgid field: k8s pod attribution. */
  if (g_uses_sock_owner) {
    SECTION_SEP();
    tpl_emit(&out, tpl_sock_owner, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }

  /* per-unit DNS-event channel (raw DNS payload; QNAME parsed in userspace).
   * the layout is declared in record_schema.h (cc_rec_dns) instead of a
   * template -- field provenance (cgid = pod attribution, duration_ns =
   * RTT) now lives with the fields themselves. */
  if (emit_flags & EMIT_DNS) {
    SECTION_SEP();
    cc_rec_emit_channel(&out, &cc_rec_dns, g_unit);
  }

  /* DNS request/response latency correlation. dns_req_start (udp_sendmsg) records the
   * query start keyed by (sock<<16 | txid) so A+AAAA on one socket stay distinct; the recv side
   * (udp_recvmsg entry-stash by tid + kretprobe) reads the response txid and computes the RTT.
   * Response payload is only in the user buffer after the copy, so -- like the HTTP channel's tcp_recvmsg --
   * we stash {sk, buf} at entry and read it at the kretprobe. */
  if (g_uses_dns_lat) {
    SECTION_SEP();
    tpl_emit(&out, tpl_dns_latency, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);   /* dns_pending value: (sock<<16|txid) -> start_ns */
  }

  /* per-unit L7 send-time correlation map + round-trip latency channel.
   * req_start (send probe, process ctx) records send ktime keyed by sock ptr;
   * emit_l7 (recv probe) computes the round-trip and emits one packed record.
   * Same sock-ptr key space as the earlier sock_owner (adjacent map). Field provenance:
   * cgid = k8s pod attribution; outstanding/mux = multiplexing guard
   * (pending map value, not an emit record). */
  if (g_uses_l7) {
    SECTION_SEP();
    tpl_emit(&out, tpl_l7_req_state, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }
  if (emit_flags & EMIT_L7) {
    SECTION_SEP();
    /* record_schema.h (cc_rec_l7); cgid field = k8s pod attribution. */
    cc_rec_emit_channel(&out, &cc_rec_l7, g_unit);
  }

  /* HTTP L7 RED -- pending request (send) + recv-buffer stash (recvmsg entry) +
   * combined event (kretprobe). method/path/status parsed in userspace (kernel bounded copy).
   * cgid fields: k8s pod attribution. */
  if (g_uses_http_l7) {
    SECTION_SEP();
    buf_puts(&out, "/* === per-unit HTTP L7 RED === */\n");
    /* verifier-safe HTTP request-method check (fixed comparisons, no loop). Excludes "HTTP"
     * responses and non-HTTP traffic, so only client request-sends are captured. */
    buf_puts(&out, tpl_http_req_check);
    tpl_emit(&out, tpl_http_l7, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);   /* pending + recv-stash maps */
    cc_rec_emit_channel(&out, &cc_rec_http, g_unit);                     /* the record itself */
  }

  /* Go g-keyed recv stash -- go_tls_resp_stash/emit correlate a Read's entry->RET by the
   * goroutine (g register, ctx->regs[28]) instead of tid (which migrates on a blocking Read). Reuses
   * the http_stash_st {sk, buf} value; keyed by __u64 g-pointer. Only emitted when uses_go_gptr. */
  if (uses_go_gptr) {
    SECTION_SEP();
    buf_puts(&out, "/* === per-unit Go g-keyed recv stash === */\n");
    buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_HASH);\n    __uint(max_entries, 4096);\n");
    buf_printf(&out, "    __type(key, __u64);\n    __type(value, struct %s_http_stash_st);\n", g_unit);
    buf_printf(&out, "} %s_go_recv_stash SEC(\".maps\");\n", g_unit);
  }

  /* Redis RED metrics -- the same shape as the HTTP channel, with its own maps, since RESP is not HTTP. pending request (send) +
   * recv-buffer stash (recvmsg entry) + combined event (kretprobe). command/error parsed in userspace.
   * The template's spnl_is_redis_cmd is the verifier-safe RESP request sniff: array-of-bulk-strings
   * header "*<1-9>" (Redis commands are always multi-bulk arrays) reliably marks client request-sends.
   * cgid fields: k8s pod attribution. */
  if (g_uses_redis_l7) {
    SECTION_SEP();
    tpl_emit(&out, tpl_redis_l7, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);   /* sniff + pending/stash maps */
    cc_rec_emit_channel(&out, &cc_rec_redis, g_unit);                     /* the record itself */
  }

  /* off-CPU-during-request correlation. Server request window (recv->send) per tid;
   * sched_switch accumulates voluntary off-CPU + captures the wait's kernel stack. Reuses
   * spnl_is_http_req + bpf_stacks (uses_stack_trace). "why is this L7 span slow".
   * Field provenance: cgid = k8s pod attribution; start_ktime = request-window
   * the real start time of the window, used both to correlate children from other
   * records and to place the span accurately; hdr_ext holds the first 128 bytes of
   * the request, a bounded copy from which userspace parses any traceparent. */
  if (g_uses_offcpu) {
    SECTION_SEP();
    buf_puts(&out, "/* === per-unit off-CPU L7 correlation === */\n");
    if (!g_uses_http_l7)   /* spnl_is_http_req is otherwise emitted by the HTTP L7 block */
      buf_puts(&out, tpl_http_req_check);
    tpl_emit(&out, tpl_offcpu_l7, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);   /* stash + window maps */
    cc_rec_emit_channel(&out, &cc_rec_offcpu, g_unit);                     /* the record itself */
  }

  /* per-class ivar HASH maps (one section per used class). */
  for (int c = 0; c < ir->ncls; c++) {
    if (!cls_used[c]) continue;
    const char *ivn = (ir->cls_ivar_names && ir->cls_ivar_names[c]) ? ir->cls_ivar_names[c] : "";
    const char *ivt = (ir->cls_ivar_types && ir->cls_ivar_types[c]) ? ir->cls_ivar_types[c] : "";
    if (!ivn[0]) continue;
    char **names; int nn = split(ivn, ';', &names);
    char **types; int nt = split(ivt, ';', &types);
    char *lc = cc_lower(ir->cls_names[c]);
    SECTION_SEP();
    for (int j = 0; j < nn; j++) {
      const char *ct = ty_to_c(ty_from_legacy(j < nt ? types[j] : ""));
      if (!ct) die("ivar type not supported (Stage 1)", j < nt ? types[j] : "?");
      const char *bare = names[j][0] == '@' ? names[j] + 1 : names[j];
      if (j) buf_puts(&out, "\n");
      buf_printf(&out, "/* class %s ivar %s : %s */\n", ir->cls_names[c], names[j], j < nt ? types[j] : "");
      buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_HASH);\n    __type(key, __u32);\n");
      buf_printf(&out, "    __type(value, %s);\n    __uint(max_entries, 1);\n} %s_at_%s SEC(\".maps\");\n", ct, lc, bare);
    }
    free(lc);
  }

  /* top-level ivar HASH maps (one section, emitted in sorted name order).
   * Stage 2: the names come from an AST scan of eligible top-level
   * (cls==NULL) method bodies -- the port of Ruby collect_toplevel_ivars_used --
   * rather than the @toplevel_ivar_names IR field, which upstream's C compiler
   * cannot produce. Value type is always __s64 and the comment always reads
   * ": int", matching Ruby emit_toplevel_ivar_maps (which hardcodes both). */
  {
    Lines tiv = {0};
    for (int i = 0; i < ir->n; i++)
      if (cc_method_eligible(&ir->m[i]) && !ir->m[i].cls)
        cc_collect_ivar_names(ast, ir->m[i].body_id, &tiv);
    for (int i = 0; i < tiv.n; i++)   /* insertion sort by ivar name (small n) */
      for (int j = i + 1; j < tiv.n; j++)
        if (strcmp(tiv.v[j], tiv.v[i]) < 0) { char *tmp = tiv.v[i]; tiv.v[i] = tiv.v[j]; tiv.v[j] = tmp; }
    for (int s = 0; s < tiv.n; s++) {
      const char *iv = tiv.v[s];
      const char *bare = iv[0] == '@' ? iv + 1 : iv;
      if (s == 0) { SECTION_SEP(); } else buf_puts(&out, "\n");
      buf_printf(&out, "/* top-level ivar %s : int */\n", iv);
      buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_HASH);\n    __type(key, __u32);\n");
      buf_printf(&out, "    __type(value, __s64);\n    __uint(max_entries, 1);\n} %s_top_%s SEC(\".maps\");\n", g_unit, bare);
    }
    lines_free(&tiv);
  }

  /* bpf_arena map + in-arena data array (after top-ivar maps, before pkt). */
  if (uses_arena) {   /* templates/arena.template.c (@UNIT@ = unit prefix) */
    SECTION_SEP();
    tpl_emit(&out, tpl_arena, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }

  /* pkt_* header-access helpers (only what was used). One section; the
   * helpers within are blank-line-separated (Ruby emit_pkt_helpers join). xdp
   * comes before tc for any name used in both (bit0 then bit1). */
  if (g_n_pkt > 0) {
    SECTION_SEP();
    int emitted = 0;
    for (int i = 0; i < g_n_pkt; i++) {
      if (g_pkt_kinds[i] & 1) { if (emitted) buf_puts(&out, "\n"); cc_emit_pkt_helper(&out, g_pkt_names[i], 0); emitted = 1; }
      if (g_pkt_kinds[i] & 2) { if (emitted) buf_puts(&out, "\n"); cc_emit_pkt_helper(&out, g_pkt_names[i], 1); emitted = 1; }
    }
  }

  /* per-flow conntrack maps (key/value structs + LRU_HASH + key-extract
   * helpers). One section; maps sorted by name, fields sorted, kinds xdp-then-tc. */
  if (g_n_flow > 0) {
    int idx[MAX_FLOW_MAPS]; for (int i = 0; i < g_n_flow; i++) idx[i] = i;
    for (int i = 0; i < g_n_flow; i++) for (int j = i + 1; j < g_n_flow; j++)
      if (strcmp(g_flow_names[idx[j]], g_flow_names[idx[i]]) < 0) { int t = idx[i]; idx[i] = idx[j]; idx[j] = t; }
    int first_fm = 1;
    for (int s = 0; s < g_n_flow; s++) {
      int m = idx[s]; const char *nm = g_flow_names[m];
      if (first_fm) { SECTION_SEP(); first_fm = 0; } else buf_puts(&out, "\n");
      buf_printf(&out, "/* Roadmap #2: per-flow state map :%s (4-tuple key, u64 fields). */\n", nm);
      buf_printf(&out, "struct spnl_flow_%s_%s_k {\n    __be32 saddr;\n    __be32 daddr;\n    __be16 sport;\n    __be16 dport;\n};\n", g_unit, nm);
      /* value struct: fields sorted; `_unused` if none. */
      char *fs[MAX_FLOW_FIELDS]; int nf = g_flow_nf[m];
      for (int i = 0; i < nf; i++) fs[i] = g_flow_fields[m][i];
      for (int i = 0; i < nf; i++) for (int j = i + 1; j < nf; j++)
        if (strcmp(fs[j], fs[i]) < 0) { char *t = fs[i]; fs[i] = fs[j]; fs[j] = t; }
      buf_printf(&out, "struct spnl_flow_%s_%s_v {\n", g_unit, nm);
      if (nf == 0) buf_puts(&out, "    __u64 _unused;\n");
      else for (int i = 0; i < nf; i++) buf_printf(&out, "    __u64 %s;\n", fs[i]);
      buf_puts(&out, "};\n");
      buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_LRU_HASH);\n");
      buf_printf(&out, "    __type(key, struct spnl_flow_%s_%s_k);\n", g_unit, nm);
      buf_printf(&out, "    __type(value, struct spnl_flow_%s_%s_v);\n    __uint(max_entries, 65536);\n} spnl_flow_%s_%s SEC(\".maps\");\n", g_unit, nm, g_unit, nm);
      /* key-extract helper(s): xdp (bit0) then tc (bit1). */
      for (int kb = 0; kb < 2; kb++) {
        if (!(g_flow_kinds[m] & (kb == 0 ? 1 : 2))) continue;
        const char *kind = kb == 0 ? "xdp" : "tc";
        const char *cd = kb == 0 ? "struct xdp_md *ctx" : "struct __sk_buff *ctx";
        buf_printf(&out, "\n/* Fill :%s flow key (saddr,daddr,sport,dport) from the packet. */\n", nm);
        buf_printf(&out, "static __noinline int spnl_flow_%s_%s_key_%s(%s, struct spnl_flow_%s_%s_k *k)\n{\n", g_unit, nm, kind, cd, g_unit, nm);
        buf_puts(&out, "    void *data     = (void *)(long)ctx->data;\n    void *data_end = (void *)(long)ctx->data_end;\n");
        buf_puts(&out, "    struct ethhdr *eth = data;\n    if ((void *)(eth + 1) > data_end) return -1;\n");
        buf_puts(&out, "    if (eth->h_proto != bpf_htons(0x0800)) return -1;\n");
        buf_puts(&out, "    struct iphdr *iph = (void *)(eth + 1);\n    if ((void *)(iph + 1) > data_end) return -1;\n");
        buf_puts(&out, "    if (iph->protocol != 6) return -1;  /* IPPROTO_TCP */\n");
        buf_puts(&out, "    __u32 ihl = iph->ihl * 4;\n    if (ihl < sizeof(*iph)) return -1;\n");
        buf_puts(&out, "    struct tcphdr *tcp = (struct tcphdr *)((char *)iph + ihl);\n    if ((void *)(tcp + 1) > data_end) return -1;\n");
        buf_puts(&out, "    k->saddr = iph->saddr;\n    k->daddr = iph->daddr;\n    k->sport = tcp->source;\n    k->dport = tcp->dest;\n    return 0;\n}\n");
      }
    }
  }

  /* SECTION_REGISTRY: per-unit map+helper sections, gated by
   * builtin usage. Registry order: blocklist, cidr, path_counter (Ruby order). */
  if (uses_blocklist) {
    SECTION_SEP();
    buf_puts(&out, tpl_blocklist);
  }
  if (uses_cidr) {
    SECTION_SEP();
    buf_puts(&out, tpl_cidr_blocklist);
  }
  if (uses_path_counter) {
    SECTION_SEP();
    buf_puts(&out, tpl_path_counter);
  }

  /* per-unit d_path scratch for path_starts_with. A path under the prefix
   * can be up to PATH_MAX (4096) long; a small stack buffer would -ENAMETOOLONG
   * and MISS it = a deny/audit bypass. 4096 doesn't fit the 512B BPF stack,
   * so use a per-CPU array (one char[4096] slot). Declared once per unit even when
   * path_starts_with is used multiple times (gated on the single uses flag). */
  if (uses_path_scratch) {
    SECTION_SEP();
    tpl_emit(&out, tpl_path_scratch, (TplSlot[]){ {"@UNIT@", g_unit} }, 1);
  }

  /* outstanding-allocation map (memleak) + record/forget helpers. */
  if (uses_leak_track) {
    SECTION_SEP();
    buf_puts(&out, tpl_leak_track);
  }

  /* lock-order edge map (deadlock detection) + spnl_lock_edge. */
  if (uses_lock_edge) {
    SECTION_SEP();
    buf_puts(&out, tpl_lock_edge);
  }

  /* arbitrary-key latency map (runqlat/biolatency) + lat_start/end helpers. */
  if (uses_keyed_lat) {
    SECTION_SEP();
    buf_puts(&out, tpl_keyed_lat);
  }

  /* per-(tid,method) recursion depth map + depth_inc/depth_dec helpers
   * (--instrument depth-collapse: record only the outermost recursive call). */
  if (uses_depth) {
    SECTION_SEP();
    buf_puts(&out, tpl_depth);
  }

  /* log2 histogram (64 buckets) + verifier-safe spnl_hist_log2. */
  if (uses_histogram) {
    SECTION_SEP();
    buf_puts(&out, tpl_histogram);
  }

  /* kprobe->kretprobe latency timing (per-tid entry timestamp). */
  if (uses_latency) {
    SECTION_SEP();
    buf_puts(&out, tpl_latency);
  }

  /* per-task local storage (TASK_STORAGE) + load/store/incr/swap helpers. */
  if (uses_task_storage) {
    SECTION_SEP();
    buf_puts(&out, tpl_task_storage);
  }

  /* map-in-map -- 4 inner ARRAY maps + an ARRAY_OF_MAPS outer (libbpf
   * populates .values at load time) + spnl_mim_at/inc/get. */
  if (uses_map_in_map) {
    SECTION_SEP();
    /* The 4 inner maps are identical except for the trailing index, so the
     * loop is unrolled into the pristine template (templates/map_in_map.template.c). */
    buf_puts(&out, tpl_map_in_map);
  }

  /* QUEUE (FIFO) / STACK (LIFO) maps. One section; fifo block then lifo. */
  if (uses_fifo || uses_lifo) {
    SECTION_SEP();
    int wrote = 0;
    if (uses_fifo) {
      buf_puts(&out, tpl_fifo);
      wrote = 1;
    }
    if (uses_lifo) {
      if (wrote) buf_puts(&out, "\n");
      buf_puts(&out, tpl_lifo);
    }
  }

  /* keyed log2 histogram (HASH<u64 -> struct{u64 buckets[64]}> + per-CPU zero). */
  if (uses_hist_keyed) {
    SECTION_SEP();
    buf_puts(&out, tpl_hist_keyed);
  }

  /* linear histogram (256 caller-bucketed slots). */
  if (uses_hist_linear) {
    SECTION_SEP();
    buf_puts(&out, tpl_hist_linear);
  }

  /* STACK_TRACE map for stack_id() / user_stack_id(). */
  if (uses_stack_trace) {
    SECTION_SEP();
    buf_puts(&out, tpl_stack_trace);
  }

  /* off-CPU tracking map + start/observe helpers (depends on bpf_stacks,
   * bpf_hist_keyed, spnl_hist_log2 -- all gated on above). */
  if (uses_off_cpu) {
    SECTION_SEP();
    buf_puts(&out, tpl_off_cpu);
  }

  /* XSKMAP (AF_XDP) / DEVMAP redirect targets for xsk_redirect/dev_redirect. */
  if (uses_xskmap) {
    SECTION_SEP();
    buf_puts(&out, tpl_xskmap);
  }
  if (uses_devmap) {
    SECTION_SEP();
    buf_puts(&out, tpl_devmap);
  }
  /* CPUMAP fanout target for cpumap_redirect. */
  if (uses_cpumap) {
    SECTION_SEP();
    buf_puts(&out, tpl_cpumap);
  }

  /* per-method ctx struct for ANY eligible method with params (emit_ctx_struct is
   * unconditional on params>0 in Ruby -- attach handlers get one too, though their
   * wrapper reads the kernel ctx instead). */
  for (int i = 0; i < ir->n; i++) {
    Method *me = &ir->m[i];
    if (!cc_method_eligible(me) || me->nparams == 0) continue;
    char *fn = cc_func_name(me), *qn = cc_qual_name(me);
    SECTION_SEP();
    buf_printf(&out, "/* ctx for %s \xe2\x80\x94 userspace fills before bpf_prog_test_run */\n", qn);
    buf_printf(&out, "struct %s_ctx {\n", fn);
    for (int k = 0; k < me->nparams; k++) {
      const char *ct = ty_to_c(me->ptypes[k]);
      if (!ct) die("param type not supported", ty_legacy_name(me->ptypes[k]));
      buf_printf(&out, "    %s %s;\n", ct, me->pnames[k]);
    }
    buf_puts(&out, "};\n");
    free(fn); free(qn);
  }

  /* loop-callback functions (+ capture structs) must appear before the
   * inner functions that bpf_loop()-reference them (Ruby: sections.concat
   * (ctx.deferred_functions)). Each is its own section. */
  for (int i = 0; i < deferred.n; i++) {
    SECTION_SEP();
    buf_puts(&out, deferred.v[i]);
  }

  /* per-method inner + wrapper (emit_method: inner + "\n" + wrapper) */
  for (int i = 0; i < ir->n; i++) {
    Method *me = &ir->m[i];
    if (!cc_method_eligible(me)) continue;
    if (me->so_kind) {   /* struct_ops member uses its own inner + BPF_PROG entry */
      SECTION_SEP();
      cc_emit_struct_ops_member(&out, me, &m_bodies[i]);
      continue;
    }
    const char *cret = ty_to_c(me->ret);
    if (!cret) die("return type not supported", ty_legacy_name(me->ret));
    char *fn = cc_func_name(me);   /* C identifier (class -> counter_incr) */
    char *qn = cc_qual_name(me);   /* comment label (class -> Counter#incr) */

    Attach a; int is_attach = cc_detect_attach(me->name, &a);
    /* the inner takes the kernel ctx first when it's a ctx-prefixed attach
     * (xdp/tc/sk/iter) OR a tracing-family handler in a unit that uses stack traces. */
    int ctx_first = is_attach && (a.ctx_prefixed || ((uses_stack_trace || uses_go_gptr) && cc_is_tracing_kind(a.kind)));
    /* caps struct at the wrapper->inner boundary. BPF passes call args in
     * r1-r5, so the effective register count (ctx forward + N extracted params)
     * caps at 5. When it would exceed 5, pack every extracted arg into a stack
     * struct and pass its pointer (1 reg); the inner expands them back to
     * param-named locals in a prologue so the body codegen is unchanged. Fires
     * only when nreg > 5 -- <=5 keeps the scalar form byte-identical (H2). */
    /* A multi-symbol handler's inner carries one extra scalar -- the symbol
     * index -- so `attached_index` has something to lower to that does not know
     * which mechanism filled it. Counted as a register like any other arg. */
    CcMulti *mu = (a.kind == AK_KPROBE_MULTI) ? cc_multi_for(me->name) : NULL;
    int nreg = (ctx_first ? 1 : 0) + (mu ? 1 : 0) + me->nparams;
    int use_caps = is_attach && !a.ctx_prefixed && me->nparams > 0 && nreg > 5;
    if (use_caps && me->nparams > 16) die("attach handler exceeds 16 args (caps cap of 16)", me->name);

    SECTION_SEP();
    /* inner */
    if (me->nparams) {
      buf_printf(&out, "/* impl: %s : %s  params: ", qn, ty_legacy_name(me->ret));
      for (int k = 0; k < me->nparams; k++)
        buf_printf(&out, "%s%s: %s", k ? ", " : "", me->pnames[k], ty_legacy_name(me->ptypes[k]));
      buf_puts(&out, " */\n");
    } else {
      buf_printf(&out, "/* impl: %s : %s */\n", qn, ty_legacy_name(me->ret));
    }
    if (use_caps) {   /* struct packing the extracted args (declared before the inner) */
      buf_printf(&out, "struct %s_args {\n", fn);
      for (int k = 0; k < me->nparams; k++)
        buf_printf(&out, "    %s p%d;\n", ty_to_c(me->ptypes[k]), k);
      buf_puts(&out, "};\n");
    }
    buf_printf(&out, "static __noinline %s %s_inner(", cret, fn);
    if (use_caps) {   /* (ctx?, struct <fn>_args *__a) -- 1 pointer instead of N args */
      if (ctx_first) buf_printf(&out, "%sctx, ", a.ctx_type);
      if (mu) buf_puts(&out, "__s64 __spnl_sym, ");
      buf_printf(&out, "struct %s_args *__a", fn);
    } else {                             /* ctx-prefixed (xdp/tc) take the kernel ctx first */
      int wrote = 0;
      if (ctx_first) { buf_printf(&out, "%sctx", a.ctx_type); wrote = 1; }
      if (mu) { buf_printf(&out, "%s__s64 __spnl_sym", wrote ? ", " : ""); wrote = 1; }
      for (int k = 0; k < me->nparams; k++) {
        buf_printf(&out, "%s%s %s", wrote ? ", " : "", ty_to_c(me->ptypes[k]), me->pnames[k]);
        wrote = 1;
      }
      if (!wrote) buf_puts(&out, "void");
    }
    buf_puts(&out, ")\n{\n");
    if (mu) buf_puts(&out, "    (void)__spnl_sym;\n");   /* unused when the body never asks */
    if (use_caps)   /* expand the packed args back to param-named locals */
      for (int k = 0; k < me->nparams; k++)
        buf_printf(&out, "    %s %s = __a->p%d;\n", ty_to_c(me->ptypes[k]), me->pnames[k], k);
    for (int k = 0; k < m_bodies[i].n; k++) { char *t = cc_indent_each(m_bodies[i].v[k]); buf_puts(&out, t); buf_puts(&out, "\n"); free(t); }   /* pre-lowered */
    buf_puts(&out, "}\n");

    /* multi-symbol wrapper(s). The inner above was emitted exactly once and
     * is byte-identical between the two lowerings; everything that differs is
     * here. The machine-readable line is what glue.c reads to learn that a
     * program wants a kprobe_multi link and with which symbols -- the decision is
     * made once, here, so the Ruby side never has to re-derive the threshold. */
    if (mu) {
      Buf syml; memset(&syml, 0, sizeof syml);
      for (int s = 0; s < mu->nsyms; s++) buf_printf(&syml, "%s%s", s ? "," : "", mu->syms[s]);
      buf_puts(&out, "\n");
      buf_printf(&out, "/* spnl:attach-multi kind=kprobe mode=%s n=%d prog=%s syms=%s */\n",
                 mu->mode == CC_MA_MULTI ? "multi" : "expand", mu->nsyms, fn, syml.p);
      free(syml.p);
      int nprog = (mu->mode == CC_MA_MULTI) ? 1 : mu->nsyms;
      for (int s = 0; s < nprog; s++) {
        char *pname = (mu->mode == CC_MA_MULTI) ? strdup(fn) : msprintf("%s__s%d", fn, s);
        if (s) buf_puts(&out, "\n");
        if (mu->mode == CC_MA_MULTI) {
          buf_printf(&out, "/* entry wrapper: %s [kprobe_multi -> kprobe.multi, %d symbols, "
                           "index from bpf_get_attach_cookie] */\n", qn, mu->nsyms);
          buf_puts(&out, "SEC(\"kprobe.multi\")\n");
        } else {
          buf_printf(&out, "/* entry wrapper: %s [kprobe -> kprobe/%s, index %d of %d] */\n",
                     qn, mu->syms[s], s, mu->nsyms);
          buf_printf(&out, "SEC(\"kprobe/%s\")\n", mu->syms[s]);
        }
        buf_printf(&out, "int %s(%sctx)\n{\n", pname, a.ctx_type);
        buf_puts(&out, "    (void)ctx;\n");
        if (g_filter_declared)
          buf_puts(&out, "    if (spnl_filter_discard()) return 0;   /* declared `filter_by` */\n");
        char *symexpr = (mu->mode == CC_MA_MULTI)
                        ? strdup("(__s64)bpf_get_attach_cookie(ctx)")
                        : msprintf("%d", s);
        Buf call; memset(&call, 0, sizeof call);
        buf_printf(&call, "%s_inner(", fn);
        if (ctx_first) buf_puts(&call, "ctx, ");
        buf_printf(&call, "%s", symexpr);
        if (use_caps) {
          buf_printf(&out, "    struct %s_args __a = {};\n", fn);
          for (int k = 0; k < me->nparams; k++) {
            char *ex = cc_attach_extractor(&a, ty_to_c(me->ptypes[k]), k, me->pnames[k]);
            buf_printf(&out, "    __a.p%d = %s;\n", k, ex);
            free(ex);
          }
          buf_puts(&call, ", &__a");
        } else {
          for (int k = 0; k < me->nparams; k++) {
            char *ex = cc_attach_extractor(&a, ty_to_c(me->ptypes[k]), k, me->pnames[k]);
            buf_printf(&call, ", %s", ex);
            free(ex);
          }
        }
        buf_puts(&call, ")");
        if (me->ret == CC_TY_VOID) buf_printf(&out, "    %s;\n    return 0;\n}\n", call.p);
        else                       buf_printf(&out, "    (void)%s;\n    return 0;\n}\n", call.p);
        free(call.p); free(symexpr); free(pname);
      }
      if (a.sec) free(a.sec);
      free(fn); free(qn);
      continue;
    }

    /* wrapper (preceded by a blank line) */
    buf_puts(&out, "\n");
    if (is_attach) {   /* attach handler (SEC + kernel ctx) */
      if (a.ctx_prefixed && me->nparams) die("ctx-prefixed attach with params not yet ported (Stage 1)", me->name);
      buf_printf(&out, "/* entry wrapper: %s [%s -> %s] */\n", qn, a.kname, a.sec);
      buf_printf(&out, "SEC(\"%s\")\n", a.sec);
      buf_printf(&out, "int %s(%sctx)\n{\n", fn, a.ctx_type);
      buf_puts(&out, "    (void)ctx;\n");
      /* The declared common filter, injected here rather than
       * into the _inner, for two reasons: a BPF-to-BPF call to this handler's
       * body must not be filtered twice, and discarding before the
       * argument extractors runs skips their probe_reads too. */
      if (g_filter_declared)
        buf_puts(&out, "    if (spnl_filter_discard()) return 0;   /* declared `filter_by` */\n");
      /* USDT prologue -- declare + fill each arg temp before the inner call. */
      if (a.usdt)
        for (int k = 0; k < me->nparams; k++)
          buf_printf(&out, "    long _usdt_arg%d = 0; (void)bpf_usdt_arg(ctx, %d, &_usdt_arg%d);\n", k, k, k);
      /* bpf_iter is invoked once per object + a final NULL terminator;
       * skip the body on that terminator so counters don't over-count. */
      if (a.iter_guard) buf_puts(&out, "    if (!ctx->task) return 0;\n");
      if (use_caps) {   /* fill the caps struct, pass its pointer to the inner (1 reg) */
        buf_printf(&out, "    struct %s_args __a = {};\n", fn);
        for (int k = 0; k < me->nparams; k++) {
          char *ex = cc_attach_extractor(&a, ty_to_c(me->ptypes[k]), k, me->pnames[k]);
          buf_printf(&out, "    __a.p%d = %s;\n", k, ex);
          free(ex);
        }
        Buf call; memset(&call, 0, sizeof call);
        buf_printf(&call, "%s_inner(", fn);
        if (ctx_first) buf_puts(&call, "ctx, ");
        buf_puts(&call, "&__a)");
        const char *mallow_caps = a.verdict ? cc_monitor_allow(&a) : NULL;
        if (mallow_caps)             buf_printf(&out, "    (void)%s;  /* monitor: verdict neutralized to allow */\n    return %s;\n}\n", call.p, mallow_caps);
        else if (a.verdict)          buf_printf(&out, "    return (int)%s;\n}\n", call.p);  /* lsm/fmod (verdict) */
        else if (me->ret == CC_TY_VOID) buf_printf(&out, "    %s;\n    return 0;\n}\n", call.p);
        else                         buf_printf(&out, "    (void)%s;\n    return 0;\n}\n", call.p);
        free(call.p);
        free(fn); free(qn);
        continue;
      }
      /* inner call: ctx-first kinds forward ctx; tracing kinds also pass extracted
       * args (ctx_prefixed attach kinds have no params, so they pass ctx only). */
      Buf call; memset(&call, 0, sizeof call);
      buf_printf(&call, "%s_inner(", fn);
      int wrote_arg = 0;
      if (ctx_first) { buf_puts(&call, "ctx"); wrote_arg = 1; }
      if (!a.ctx_prefixed) {
        for (int k = 0; k < me->nparams; k++) {
          char *ex = cc_attach_extractor(&a, ty_to_c(me->ptypes[k]), k, me->pnames[k]);
          buf_printf(&call, "%s%s", wrote_arg ? ", " : "", ex);
          free(ex);
          wrote_arg = 1;
        }
      }
      buf_puts(&call, ")");
      const char *mallow = a.verdict ? cc_monitor_allow(&a) : NULL;
      if (mallow)                  buf_printf(&out, "    (void)%s;  /* monitor: verdict neutralized to allow */\n    return %s;\n}\n", call.p, mallow);
      else if (a.verdict)          buf_printf(&out, "    return (int)%s;\n}\n", call.p);  /* xdp/tc/sk/lsm/fmod */
      else if (me->ret == CC_TY_VOID) buf_printf(&out, "    %s;\n    return 0;\n}\n", call.p);
      else                         buf_printf(&out, "    (void)%s;\n    return 0;\n}\n", call.p);
      free(call.p);
    } else {
      buf_printf(&out, "/* entry wrapper: %s */\n", qn);
      buf_puts(&out, "SEC(\"syscall\")\n");
      if (me->nparams) buf_printf(&out, "int %s(struct %s_ctx *ctx)\n{\n", fn, fn);
      else             buf_printf(&out, "int %s(void *ctx)\n{\n", fn);
      if (me->ret == CC_TY_VOID) {   /* void inner: call then `return 0;` */
        buf_printf(&out, "    %s_inner(", fn);
        for (int k = 0; k < me->nparams; k++) buf_printf(&out, "%sctx->%s", k ? ", " : "", me->pnames[k]);
        buf_puts(&out, ");\n    return 0;\n}\n");
      } else {
        buf_printf(&out, "    return (int)%s_inner(", fn);
        for (int k = 0; k < me->nparams; k++) buf_printf(&out, "%sctx->%s", k ? ", " : "", me->pnames[k]);
        buf_puts(&out, ");\n}\n");
      }
    }
    free(fn); free(qn);
  }

  /* struct_ops bundles last (after the member functions they
   * point at). Order: tcp_cc, sched_ext, qdisc (Ruby emit() order). */
  if (uses_tcp_cc)    { SECTION_SEP(); cc_emit_struct_ops_bundle(&out, ir, SO_TCP_CC); }
  if (uses_sched_ext) { SECTION_SEP(); cc_emit_struct_ops_bundle(&out, ir, SO_SCHED_EXT); }
  if (uses_qdisc)     { SECTION_SEP(); cc_emit_struct_ops_bundle(&out, ir, SO_QDISC); }

  /* A parameter nothing reads is a switch wired to nothing --
   * the operator sets SPNL_PARAM_<NAME>, the probe behaves identically, and
   * nobody is told. Checked after lowering (not by a name pre-scan) so the
   * answer is "did the emitter actually reach it", which is also what catches a
   * parameter whose name a builtin already owns. */
  for (int i = 0; i < g_n_params; i++) {
    if (g_param_used[i]) continue;
    char up[64]; int ui = 0;
    for (const char *p = g_param_names[i]; *p && ui < 63; p++)
      up[ui++] = (*p >= 'a' && *p <= 'z') ? (char)(*p - 32) : *p;
    up[ui] = '\0';
    char *msg = msprintf(
      "param :%s is declared but no eBPF method reads it, so setting SPNL_PARAM_%s "
      "would change nothing. Reference it by name inside a handler (e.g. "
      "`if %s == 0 || pid == %s ... end`), or delete the declaration. If the name is "
      "also a builtin (pid/tgid/tid/cpu_id/ktime_ns/cgroup_id/ppid/comm_hash) the "
      "builtin wins and the parameter is unreachable -- rename the parameter",
      g_param_names[i], up, g_param_names[i], g_param_names[i]);
    die(msg, NULL);
  }

  #undef SECTION_SEP
  return out.p;
}

#ifndef SPNL_INPROCESS
int main(int argc, char **argv) {
  if (argc != 4) { fprintf(stderr, "usage: %s <ir> <ast> <base_name>\n", argv[0]); return 1; }
  IR ir; ir_parse(slurp(argv[1]), &ir);
  AST ast; ast_parse(slurp(argv[2]), &ast);
  cc_synthesize_reactor(&ir, &ast);   /* append module `on :kind` handlers */
  char *src = ebpf_codegen_program(&ir, &ast, argv[3]);
  fputs(src, stdout);
  return 0;
}
#else  /* SPNL_INPROCESS: Stage 2 in-process entry */

/* ---------- Compiler* -> IR (no text round-trip) ----------
 * Reproduces build_ir_text (codegen.c) + ir_parse together: build the SAME
 * per-field legacy tag strings the text path would, then feed them through the
 * SAME helpers (method_set_params, ty_from_legacy). Identity is by construction
 * -- we never hand-map TyKind, so e.g. ty_from_legacy("nil")==CC_TY_VOID and the
 * verdict-handler return rule stay in exactly one place. */

/* mirror codegen.c ir_is_verdict_handler */
static int cc_verdict_handler(const char *name) {
  if (!name) return 0;
  static const char *const pre[] = {
    "xdp__", "xdp_tail__", "tc__", "sk_reuseport__", "sk_msg__", "sk_skb__",
    "lsm__", "fmod_ret__", "cgroup__", "socket_filter__", "flow_dissector__",
    "sk_lookup__", "iter__",
    "kprobe__", "kretprobe__", "tracepoint__", "fentry__", "fexit__",
    "uprobe__", "uretprobe__", "usdt__", "raw_tp__", "sock_ops__",
    "perf_event__", "user_ringbuf__", "spnl_timer__", 0
  };
  for (int i = 0; pre[i]; i++) { size_t n = strlen(pre[i]); if (!strncmp(name, pre[i], n)) return 1; }
  return 0;
}

/* mirror codegen.c ty_tag_into: object -> "obj_<name>"/"object", else ty_name. */
static void cc_ty_tag_into(Compiler *c, TyKind t, Buf *b) {
  if (ty_is_object(t)) {
    int cid = ty_object_class(t);
    if (cid >= 0 && cid < sce_nclasses(c) && sce_class_name(sce_class(c, cid)))
      buf_printf(b, "obj_%s", sce_class_name(sce_class(c, cid)));
    else buf_puts(b, "object");
    return;
  }
  buf_puts(b, ty_name(t));
}

/* mirror codegen.c ir_emit_parent: registered superclass name, else walk the
 * ClassNode's superclass ConstantPath/ConstantRead in the AST (BPF::Qdisc -> "BPF_Qdisc"). */
static void cc_emit_parent_tag(Compiler *c, ClassInfo *cl, Buf *b) {
  int par_idx = sce_class_parent(cl);
  if (par_idx >= 0 && par_idx < sce_nclasses(c) && sce_class_name(sce_class(c, par_idx))) {
    buf_puts(b, sce_class_name(sce_class(c, par_idx))); return;
  }
  int def = sce_class_def_node(cl); if (def < 0) return;
  int sup = nt_ref(sce_nt(c), def, "superclass"); if (sup < 0) return;
  const char *tt = nt_type(sce_nt(c), sup); if (!tt) return;
  if (!strcmp(tt, "ConstantPathNode")) {
    int par = nt_ref(sce_nt(c), sup, "parent");
    const char *pn = (par >= 0) ? nt_str(sce_nt(c), par, "name") : NULL;
    if (pn && *pn) { buf_puts(b, pn); buf_puts(b, "_"); }
    const char *nm = nt_str(sce_nt(c), sup, "name"); if (nm) buf_puts(b, nm);
  } else if (!strcmp(tt, "ConstantReadNode")) {
    const char *nm = nt_str(sce_nt(c), sup, "name"); if (nm) buf_puts(b, nm);
  }
}

/* one method's params: build the text path's comma-lists then reuse method_set_params. */
static void cc_fill_params(Compiler *c, Scope *s, Method *me) {
  Buf pnb; memset(&pnb, 0, sizeof pnb);
  Buf ptb; memset(&ptb, 0, sizeof ptb);
  for (int i = 0; i < sce_scope_nparams(s); i++) {
    if (i) { buf_puts(&pnb, ","); buf_puts(&ptb, ","); }
    char *pname = sce_scope_pname(s, i);
    buf_puts(&pnb, pname ? pname : "");
    LocalVar *p = scope_local(s, pname);
    TyKind pt = (p && sce_local_type(p) != TY_UNKNOWN && sce_local_type(p) != TY_POLY) ? sce_local_type(p) : TY_INT;
    cc_ty_tag_into(c, pt, &ptb);
  }
  method_set_params(me, pnb.p ? pnb.p : "", ptb.p ? ptb.p : "");
  free(pnb.p); free(ptb.p);
}

/* synthesized userspace consumer/driver/named-handler methods (__spnl_*,
 * lowered from the `on_emit` / `on_emit :name` DSL) run in userspace draining
 * the emit ringbuf via FFI. They must never enter the eBPF IR -- exclude them
 * from both the in-process IR (fill_ir_from_compiler) and the .ir text.
 *
 * --instrument --instrument-self combines the workload + the agent in one
 * unit. The workload methods (the self-uprobe *targets*) are eBPF-eligible (pure
 * int) but must stay native. The CLI passes their names in $SPNL_EBPF_EXCLUDE
 * (comma-separated); exclude them here too so they don't enter the eBPF IR. */
static int cc_name_in_env_list(const char *name, const char *env) {
  const char *ex = getenv(env);
  if (!ex || !*ex || !name) return 0;
  size_t nl = strlen(name);
  const char *p = ex;
  while (*p) {
    const char *comma = strchr(p, ',');
    size_t seg = comma ? (size_t)(comma - p) : strlen(p);
    if (seg == nl && strncmp(p, name, nl) == 0) return 1;
    if (!comma) break;
    p = comma + 1;
  }
  return 0;
}
static int cc_is_consumer_fn(const char *name) {
  return name && (strncmp(name, "__spnl_", 7) == 0 ||
                  cc_name_in_env_list(name, "SPNL_EBPF_EXCLUDE"));
}

static void fill_ir_from_compiler(Compiler *c, IR *ir) {
  memset(ir, 0, sizeof *ir);

  /* ---- classes (skip the spinel-injected "Method" class, like build_rbs_text) ---- */
  int ncls = 0;
  for (int ci = 0; ci < sce_nclasses(c); ci++) {
    const char *nm = sce_class_name(sce_class(c, ci));
    if (nm && *nm && strcmp(nm, "Method")) ncls++;
  }
  ir->ncls = ncls;
  if (ncls) {
    ir->cls_names      = calloc(ncls, sizeof(char *));
    ir->cls_parents    = calloc(ncls, sizeof(char *));
    ir->cls_ivar_names = calloc(ncls, sizeof(char *));
    ir->cls_ivar_types = calloc(ncls, sizeof(char *));
  }
  int *kept = malloc((sce_nclasses(c) > 0 ? sce_nclasses(c) : 1) * sizeof(int));
  for (int ci = 0, k = 0; ci < sce_nclasses(c); ci++) {
    ClassInfo *cl = sce_class(c, ci);
    const char *nm = sce_class_name(cl);
    if (!(nm && *nm && strcmp(nm, "Method"))) { kept[ci] = -1; continue; }
    kept[ci] = k;
    ir->cls_names[k] = strdup(nm);
    Buf pb; memset(&pb, 0, sizeof pb); cc_emit_parent_tag(c, cl, &pb);
    ir->cls_parents[k] = pb.p ? pb.p : strdup("");
    Buf nb; memset(&nb, 0, sizeof nb);
    for (int j = 0; j < sce_class_nivars(cl); j++) { if (j) buf_puts(&nb, ";"); buf_puts(&nb, sce_class_ivar_name(cl, j)); }
    ir->cls_ivar_names[k] = nb.p ? nb.p : strdup("");
    Buf tb; memset(&tb, 0, sizeof tb);
    for (int j = 0; j < sce_class_nivars(cl); j++) {
      if (j) buf_puts(&tb, ";");
      TyKind it = sce_class_ivar_type(cl, j);
      if (it == TY_UNKNOWN || it == TY_POLY) buf_puts(&tb, "int"); else cc_ty_tag_into(c, it, &tb);
    }
    ir->cls_ivar_types[k] = tb.p ? tb.p : strdup("");
    k++;
  }

  /* ---- count methods (free fns + kept-class methods), then fill in the SAME
   *      order build_ir_text emits them: free fns si-asc, then per kept class
   *      (ci-asc) its methods si-asc. ir_parse builds top-level first, then class. ---- */
  int total = 0;
  for (int si = 1; si < sce_nscopes(c); si++) {
    Scope *s = sce_scope(c, si);
    const char *snm = sce_scope_name(s);
    if (!snm || !*snm) continue;
    if (sce_scope_class_id(s) < 0) total++;
    else if (kept[sce_scope_class_id(s)] >= 0) total++;
  }
  ir->m = calloc(total > 0 ? total : 1, sizeof(Method));
  int mi = 0;

  for (int si = 1; si < sce_nscopes(c); si++) {        /* free functions (top-level) */
    Scope *s = sce_scope(c, si);
    const char *snm = sce_scope_name(s);
    if (!(sce_scope_class_id(s) < 0 && snm && *snm) || cc_is_consumer_fn(snm)) continue;
    Method *me = &ir->m[mi++];
    me->name = strdup(snm);
    Buf rb; memset(&rb, 0, sizeof rb);
    TyKind sret = sce_scope_ret(s);
    if ((sret == TY_UNKNOWN || sret == TY_POLY) && cc_verdict_handler(snm)) buf_puts(&rb, "int");
    else if (sret == TY_UNKNOWN || sret == TY_POLY) buf_puts(&rb, "nil");
    else cc_ty_tag_into(c, sret, &rb);
    me->ret = ty_from_legacy(rb.p ? rb.p : "");
    free(rb.p);
    me->body_id = sce_scope_body(s);
    cc_fill_params(c, s, me);
    me->cls = NULL;
  }

  for (int ci = 0; ci < sce_nclasses(c); ci++) {       /* class methods */
    if (kept[ci] < 0) continue;
    int k = kept[ci];
    const char *parent = ir->cls_parents[k] ? ir->cls_parents[k] : "";
    int so_kind = SO_NONE; const char *so_prefix = NULL;
    if      (!strcmp(parent, "BPF_SchedExt")) { so_kind = SO_SCHED_EXT; so_prefix = "sched_ext"; }
    else if (!strcmp(parent, "BPF_Qdisc"))    { so_kind = SO_QDISC;     so_prefix = "qdisc"; }
    else if (!strcmp(parent, "BPF_TcpCC"))    { so_kind = SO_TCP_CC;    so_prefix = "tcp_cc"; }
    for (int si = 1; si < sce_nscopes(c); si++) {
      Scope *s = sce_scope(c, si);
      const char *snm = sce_scope_name(s);
      if (sce_scope_class_id(s) != ci || !snm || !*snm) continue;
      Method *me = &ir->m[mi++];
      Buf rb; memset(&rb, 0, sizeof rb);
      TyKind sret = sce_scope_ret(s);
      if (!strcmp(snm, "initialize")) buf_puts(&rb, "void");
      else if (sret == TY_UNKNOWN || sret == TY_POLY) buf_puts(&rb, "nil");
      else cc_ty_tag_into(c, sret, &rb);
      me->ret = ty_from_legacy(rb.p ? rb.p : "");
      free(rb.p);
      me->body_id = sce_scope_body(s);
      cc_fill_params(c, s, me);
      if (so_kind) {
        me->cls = NULL;
        me->name = msprintf("%s__%s", so_prefix, snm);
        me->so_kind = so_kind;
        me->so_member = strdup(snm);
      } else {
        me->cls = ir->cls_names[k];
        me->name = strdup(snm);
      }
    }
  }
  ir->n = mi;
  free(kept);
}

/* Relocated build_ir_text (codegen.c): serialize the analyzed Compiler to legacy
 * SPINEL-IR v1 text, byte-for-byte as upstream's --emit-ir did. This moves the
 * IR serialization OUT of upstream (Patch A removal) and INTO spinel-ebpf, so
 * the Ruby partition / dispatch shim keep reading the exact .ir they always did.
 * A faithful copy of build_ir_text, reusing cc_ty_tag_into / cc_verdict_handler /
 * cc_emit_parent_tag (the same helpers fill_ir_from_compiler uses). Verified
 * byte-identical to `build/spinel --emit-ir` over every fixture (stage2_verify.sh). */
static int cc_is_free_fn(Scope *s) { return sce_scope_class_id(s) < 0 && sce_scope_name(s) && *sce_scope_name(s) && !cc_is_consumer_fn(sce_scope_name(s)); }

char *cc_build_ir_text(Compiler *c) {
  Buf b; memset(&b, 0, sizeof b);
  buf_puts(&b, "SPINEL-IR v1\n");

  int nmeth = 0;
  for (int si = 1; si < sce_nscopes(c); si++) if (cc_is_free_fn(sce_scope(c, si))) nmeth++;

  buf_printf(&b, "SA @meth_names %d ", nmeth);
  { int j = 0; for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si);
      if (!cc_is_free_fn(s)) continue;
      if (j++) buf_puts(&b, "|");
      buf_puts(&b, sce_scope_name(s)); } }
  buf_puts(&b, "\n");
  buf_printf(&b, "SA @meth_param_names %d ", nmeth);
  { int j = 0; for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si);
      if (!cc_is_free_fn(s)) continue;
      if (j++) buf_puts(&b, "|");
      for (int i = 0; i < sce_scope_nparams(s); i++) { if (i) buf_puts(&b, ","); buf_puts(&b, sce_scope_pname(s, i) ? sce_scope_pname(s, i) : ""); } } }
  buf_puts(&b, "\n");
  buf_printf(&b, "SA @meth_param_types %d ", nmeth);
  { int j = 0; for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si);
      if (!cc_is_free_fn(s)) continue;
      if (j++) buf_puts(&b, "|");
      for (int i = 0; i < sce_scope_nparams(s); i++) { if (i) buf_puts(&b, ",");
        LocalVar *p = scope_local(s, sce_scope_pname(s, i)); TyKind pt = (p && sce_local_type(p) != TY_UNKNOWN && sce_local_type(p) != TY_POLY) ? sce_local_type(p) : TY_INT;
        cc_ty_tag_into(c, pt, &b); } } }
  buf_puts(&b, "\n");
  buf_printf(&b, "SA @meth_return_types %d ", nmeth);
  { int j = 0; for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si);
      if (!cc_is_free_fn(s)) continue;
      if (j++) buf_puts(&b, "|");
      TyKind sret = sce_scope_ret(s);
      if ((sret == TY_UNKNOWN || sret == TY_POLY) && cc_verdict_handler(sce_scope_name(s))) buf_puts(&b, "int");
      else if (sret == TY_UNKNOWN || sret == TY_POLY) buf_puts(&b, "nil");
      else cc_ty_tag_into(c, sret, &b); } }
  buf_puts(&b, "\n");
  buf_printf(&b, "IA @meth_body_ids %d ", nmeth);
  { int j = 0; for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si);
      if (!cc_is_free_fn(s)) continue;
      if (j++) buf_puts(&b, ",");
      buf_printf(&b, "%d", sce_scope_body(s)); } }
  buf_puts(&b, "\n");

  int ncls = 0;
  for (int ci = 0; ci < sce_nclasses(c); ci++) {
    const char *nm = sce_class_name(sce_class(c, ci));
    if (nm && *nm && strcmp(nm, "Method") != 0) ncls++;
  }
  #define IR_FOR_CLS(var) for (int ci = 0; ci < sce_nclasses(c); ci++) { ClassInfo *var = sce_class(c, ci); \
      if (!(sce_class_name(var) && *sce_class_name(var) && strcmp(sce_class_name(var), "Method") != 0)) continue;
  buf_printf(&b, "SA @cls_names %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) if (j++) buf_puts(&b, "|"); buf_puts(&b, sce_class_name(cl)); } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_parents %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) if (j++) buf_puts(&b, "|");
      cc_emit_parent_tag(c, cl, &b); } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_ivar_names %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) if (j++) buf_puts(&b, "|");
      for (int k = 0; k < sce_class_nivars(cl); k++) { if (k) buf_puts(&b, ";"); buf_puts(&b, sce_class_ivar_name(cl, k)); } } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_ivar_types %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) if (j++) buf_puts(&b, "|");
      for (int k = 0; k < sce_class_nivars(cl); k++) { if (k) buf_puts(&b, ";"); TyKind it = sce_class_ivar_type(cl, k); if (it == TY_UNKNOWN || it == TY_POLY) buf_puts(&b, "int"); else cc_ty_tag_into(c, it, &b); } } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_meth_names %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) (void)cl; if (j++) buf_puts(&b, "|"); int m = 0;
      for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si); if (sce_scope_class_id(s) != ci || !sce_scope_name(s) || !*sce_scope_name(s)) continue; if (m++) buf_puts(&b, ";"); buf_puts(&b, sce_scope_name(s)); } } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_meth_returns %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) (void)cl; if (j++) buf_puts(&b, "|"); int m = 0;
      for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si); if (sce_scope_class_id(s) != ci || !sce_scope_name(s) || !*sce_scope_name(s)) continue; if (m++) buf_puts(&b, ";"); if (!strcmp(sce_scope_name(s), "initialize")) buf_puts(&b, "void"); else if (sce_scope_ret(s) == TY_UNKNOWN || sce_scope_ret(s) == TY_POLY) buf_puts(&b, "nil"); else cc_ty_tag_into(c, sce_scope_ret(s), &b); } } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_meth_ptypes %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) (void)cl; if (j++) buf_puts(&b, "|"); int m = 0;
      for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si); if (sce_scope_class_id(s) != ci || !sce_scope_name(s) || !*sce_scope_name(s)) continue; if (m++) buf_puts(&b, "%7C");
        for (int i = 0; i < sce_scope_nparams(s); i++) { if (i) buf_puts(&b, ","); LocalVar *p = scope_local(s, sce_scope_pname(s, i)); TyKind pt = (p && sce_local_type(p) != TY_UNKNOWN && sce_local_type(p) != TY_POLY) ? sce_local_type(p) : TY_INT; cc_ty_tag_into(c, pt, &b); } } } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_meth_params %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) (void)cl; if (j++) buf_puts(&b, "|"); int m = 0;
      for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si); if (sce_scope_class_id(s) != ci || !sce_scope_name(s) || !*sce_scope_name(s)) continue; if (m++) buf_puts(&b, "%7C");
        for (int i = 0; i < sce_scope_nparams(s); i++) { if (i) buf_puts(&b, ","); buf_puts(&b, sce_scope_pname(s, i) ? sce_scope_pname(s, i) : ""); } } } } buf_puts(&b, "\n");
  buf_printf(&b, "SA @cls_meth_bodies %d ", ncls);
  { int j = 0; IR_FOR_CLS(cl) (void)cl; if (j++) buf_puts(&b, "|"); int m = 0;
      for (int si = 1; si < sce_nscopes(c); si++) { Scope *s = sce_scope(c, si); if (sce_scope_class_id(s) != ci || !sce_scope_name(s) || !*sce_scope_name(s)) continue; if (m++) buf_puts(&b, ";"); buf_printf(&b, "%d", sce_scope_body(s)); } } } buf_puts(&b, "\n");
  #undef IR_FOR_CLS

  for (int si = 0; si < sce_nscopes(c); si++) {
    Scope *s = sce_scope(c, si);
    if (sce_scope_body(s) < 0 || sce_scope_nlocals(s) <= 0) continue;
    buf_printf(&b, "SN %d ", sce_scope_body(s));
    for (int k = 0; k < sce_scope_nlocals(s); k++) { if (k) buf_puts(&b, "|"); buf_puts(&b, sce_local_name(s, k) ? sce_local_name(s, k) : ""); }
    buf_puts(&b, "\n");
    buf_printf(&b, "ST %d ", sce_scope_body(s));
    for (int k = 0; k < sce_scope_nlocals(s); k++) { if (k) buf_puts(&b, "|"); cc_ty_tag_into(c, sce_local_type_at(s, k), &b); }
    buf_puts(&b, "\n");
  }

  buf_puts(&b, "INT @needs_regexp 0\nINT @needs_rand 0\nINT @needs_lambda 0\n");
  buf_puts(&b, "INT @needs_file_io 0\nINT @needs_fiber 0\nINT @needs_bigint 0\n");
  return b.p ? b.p : strdup("");
}

/* Stage 2 entry: emit the .bpf.c (malloc'd) from the analyzed Compiler (for the
 * IR signatures) + a PRISTINE NodeTable for the AST. analyze_program rewrites
 * c->nt in place (rename_shadowing_block_params alpha-renames block params that
 * shadow an outer local: `i` -> `i__bp<id>`), but the production eBPF codegen
 * and the Stage-1 oracle both read the pre-analyze `--dump-ast`. So the caller
 * passes an un-analyzed parse of the same source (identical node ids) as `ast`;
 * pass NULL to fall back to c->nt (only safe when no block-param shadowing). */
char *spnl_ebpf_codegen_str(Compiler *c, const NodeTable *ast_nt, const char *base) {
  IR ir; fill_ir_from_compiler(c, &ir);
  AST *ast = (AST *)(ast_nt ? ast_nt : sce_nt(c));
  cc_synthesize_reactor(&ir, ast);
  return ebpf_codegen_program(&ir, ast, base);
}
#endif  /* SPNL_INPROCESS */
