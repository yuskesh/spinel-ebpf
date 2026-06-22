/* spinel_ebpf_cc -- C port of spinel-ebpf's eBPF codegen (Stage 1).
 *
 * Reads the SPINEL-IR v1 text (`--emit-ir`) + AST dump (`--dump-ast`) and emits
 * the .bpf.c, aiming to be byte-identical to the Ruby `CodegenBpf.emit`. The Ruby
 * co-process stays the regression oracle (tools/cgen_oracle.rb diffs the two).
 *
 * Stage 1 scope grows one feature at a time, each verified byte-identical;
 * the first ported feature was int-param methods, arithmetic-expr bodies, and
 * SEC("syscall").
 *
 * Conventions follow upstream spinel src/: 2-space indent, K&R braces, block
 * comments only, `Buf`/`nt_*`/`ty_*` types mirror upstream so the Stage-2
 * in-process plugin can swap our text parsers for the real NodeTable/Compiler.
 * Anything not yet ported is a hard error (no silent fallback). Pure host text
 * processing -- builds with cc on macOS/Linux.
 *
 *   spinel_ebpf_cc <unit.ir> <unit.ast> <base_name>   # -> .bpf.c on stdout
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* Fixed hand-written BPF C helpers live as pristine .template.c files under
 * templates/, embedded here at build time (tools/embed_templates.rb). Each is a
 * `static const char tpl_<name>[]` with an @SIG@ slot for the function signature.
 * Keeps big fixed snippets out of the codegen logic without a runtime file dep. */
#include "templates_gen.h"

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
 * tool; Stage-2 in-process must add free discipline. */
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

typedef struct {
  Method *m; int n;
  /* class ivar tables (for emit_ivar_maps), one entry per class. */
  int ncls; char **cls_names; char **cls_ivar_names; char **cls_ivar_types;
  char **cls_parents;          /* class superclass (BPF_SchedExt etc.), one per class */
  /* NOTE: top-level ivars are no longer carried in the IR -- Stage 2 derives
   * them from an AST scan (cc_collect_ivar_names), since the upstream C
   * compiler does not emit @toplevel_ivar_names. */
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
  /* Sanitize param names at the parse leaf so every downstream use
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
    /* A `class X < BPF::SchedExt/Qdisc/TcpCC` maps its methods to struct_ops
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
static int g_if_counter = 0;   /* fresh temp counter (`fresh`), reset per method */
static const Method *g_method = NULL;  /* method being lowered (for ivar map scope) */
static Lines *g_body = NULL;   /* current method's line accumulator (Ruby @lines) */
static int g_loop_counter = 0;     /* per-unit loop-callback id (cb names), not reset per method */
static Lines *g_deferred = NULL;   /* complete callback/struct blocks, emitted before the inners */
static Lines *g_captures = NULL;   /* capture names active while lowering a loop-callback body */
/* is `name` (already C-safe) an outer local captured by the current loop callback? */
static int cc_is_capture(const char *name) { return g_captures && lines_has(g_captures, name); }

/* Locals bound via `t = kptr(ptr, "struct")` -- `t.field` then reads via
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

/* KNOWN_CONSTANTS subset: ConstantReadNode names the codegen resolves to a
 * literal int. */
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
/* Module-style constant path (XDP::PASS / IP::Proto::TCP) -> integer.
 * Map the module path prefix to the flat constant prefix (Ruby CONSTANT_PATH_PREFIXES),
 * then resolve the flat name in KNOWN_CONSTANTS. */
static int cc_const_path_value(const char *path, long long *out) {
  static const struct { const char *pp, *fp; } T[] = {
    {"BPF::SockOps::", "BPF_SOCK_OPS_"}, {"TCP::Flag::", "TCP_FLAG_"}, {"TCP::State::", "TCP_STATE_"},
    {"IP::Proto::", "IPPROTO_"}, {"TC::Act::", "TC_ACT_"}, {"Eth::P::", "ETH_P_"},
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

/* a same-unit :ebpf method by this name? (BPF-to-BPF call target). */
static int cc_is_ebpf_method(const char *name) {
  if (!g_ir || !name) return 0;
  for (int i = 0; i < g_ir->n; i++)
    if (cc_method_eligible(&g_ir->m[i]) && !strcmp(g_ir->m[i].name, name)) return 1;
  return 0;
}

/* pkt_* header-access builtins. Each lowers to a no-arg call
 * `spnl_<name>(ctx)` (XDP) or `spnl_tc_<name>(ctx)` (TC) backed by a __noinline
 * helper with verifier-safe bounds checks. Mirrors Ruby PKT_BUILTINS. */
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

/* Per-flow conntrack maps, inferred from flow_get/set/del
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
               AK_ITER_TASK, AK_RAW_TP, AK_PERF_EVENT } AttachKind;
/* ctx_prefixed: the inner takes the kernel ctx as its first arg (xdp/tc, for pkt_*).
 * verdict: the wrapper propagates the inner's int return (XDP_ / TC_ACT_ values).
 * iter_guard: emit `if (!ctx->task) return 0;` (bpf_iter NULL terminator).
 * usdt: emit bpf_usdt_arg prologue + pull in usdt.bpf.h. */
typedef struct { AttachKind kind; char *sec; const char *ctx_type; const char *kname;
                 int ctx_prefixed; int verdict; const char *tp_struct;
                 int iter_guard; int usdt;
                 char *tp_cat; char *tp_event; } Attach;   /* named tracepoint field extraction */
static AttachKind cc_detect_attach(const char *name, Attach *a);
static char *cc_expr_str(AST *ast, int nid);   /* expr node -> malloc'd C string (defined below) */
static char *cc_lower_stmt(AST *ast, int nid, Lines *body);   /* defined below (StatementsNode in expr pos) */
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
    return ce_binop(ty[0] == 'O' ? "||" : "&&", cc_build_expr(ast, l), cc_build_expr(ast, r));
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
      return ce_binop(name, cc_build_expr(ast, recv), cc_build_expr(ast, ids[0]));
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

/* ivar map idioms (key=__u32 singleton). These factor the multi-line
 * lines_push idioms -- the only value is keeping the fresh-counter (g_if_counter)
 * bookkeeping in one place so the `_kN`/`_pN`/`_vN` indices can't drift between
 * the declaration and its uses. Counter allocation order is preserved exactly,
 * so the emitted text is byte-identical to the former inline sequences. */

/* @x read: emit `_kN`+lookup prelude into `pre`, return the read expression
 * "(_pN ? *_pN : 0)" (caller frees). Counter order: k, p. */
static char *cc_emit_ivar_read(Lines *pre, const char *map) {
  int kk = ++g_if_counter, pp = ++g_if_counter;
  lines_push(pre, msprintf("__u32 _k%d = 0;", kk));
  lines_push(pre, msprintf("__s64 *_p%d = bpf_map_lookup_elem(&%s, &_k%d);", pp, map, kk));
  return msprintf("(_p%d ? *_p%d : 0)", pp, pp);
}

/* @x = rhs: emit key + value-temp + update into `body`, return "_vN" (caller
 * frees). Counter order: k, v. */
static char *cc_emit_ivar_write(Lines *body, const char *map, const char *rhs) {
  int kk = ++g_if_counter, vv = ++g_if_counter;
  lines_push(body, msprintf("__u32 _k%d = 0;", kk));
  lines_push(body, msprintf("__s64 _v%d = %s;", vv, rhs));
  lines_push(body, msprintf("bpf_map_update_elem(&%s, &_k%d, &_v%d, BPF_ANY);", map, kk, vv));
  return msprintf("_v%d", vv);
}

/* @x op= rhs: lookup-compute-update into `body`, return "_vN" (caller frees).
 * Counter order: k, p, v. */
static char *cc_emit_ivar_rmw(Lines *body, const char *map, const char *op, const char *rhs) {
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

/* The common 16-byte event header: the 4 hdr.* assignments shared verbatim by
 * every ringbuf emit idiom (spnl_emit / emit_str|pair|3|4 / emit_argv / emit_comm).
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
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("redirect expects 1 arg (ifindex)", NULL);
      char *oif = cc_expr_str(ast, ids[0]);
      buf_printf(b, "(__s64)bpf_redirect((__u32)(%s), 0)", oif);
      free(oif);
      return;
    }
    if (name && (!strcmp(name, "sk_lookup_tcp") || !strcmp(name, "sk_assign_tcp"))) {   /* socket lookup / steer */
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
    if (name && !strcmp(name, "ktime_ns"))     { buf_puts(b, "((__s64)bpf_ktime_get_ns())"); return; }
    if (name && (!strcmp(name, "pid") || !strcmp(name, "tgid")))
      { buf_puts(b, "((__s64)(bpf_get_current_pid_tgid() >> 32))"); return; }
    if (name && !strcmp(name, "tid"))          { buf_puts(b, "((__s64)(__u32)bpf_get_current_pid_tgid())"); return; }
    if (name && !strcmp(name, "cpu_id"))        { buf_puts(b, "((__s64)bpf_get_smp_processor_id())"); return; }
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
    if (name && !strcmp(name, "stack_id"))      { buf_puts(b, "((__s64)bpf_get_stackid(ctx, &bpf_stacks, 0))"); return; }   /* kernel stack */
    if (name && !strcmp(name, "user_stack_id")) { buf_puts(b, "((__s64)bpf_get_stackid(ctx, &bpf_stacks, (1ULL << 8)))"); return; }  /* user stack */
    if (name && !strcmp(name, "divu")) {   /* (__s64)((__u64)(a) / (__u64)(b)) */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 2) die("divu expects 2 args (a, b)", NULL);
      CExpr *q = ce_binop("/", ce_cast("__u64", ce_paren(ce_raw(cc_expr_str(ast, ids[0])))),
                               ce_cast("__u64", ce_paren(ce_raw(cc_expr_str(ast, ids[1])))));
      ce_print(ce_paren(ce_cast("__s64", ce_paren(q))), b);
      return;
    }
    if (name && !strcmp(name, "comm_hash")) {   /* 16B comm on stack, return first 8 bytes */
      int ch = ++g_if_counter;
      lines_push(g_body, msprintf("char _ch%d[16] = {0};", ch));
      lines_push(g_body, msprintf("bpf_get_current_comm(_ch%d, sizeof(_ch%d));", ch, ch));
      buf_printf(b, "((__s64)(*((__u64 *)_ch%d)))", ch);
      return;
    }
    if (name && (!strcmp(name, "xsk_redirect") || !strcmp(name, "dev_redirect"))) {   /* AF_XDP / DEVMAP redirect */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("xsk_redirect/dev_redirect expects 1 arg", name);
      char *q = cc_expr_str(ast, ids[0]);
      if (!strcmp(name, "xsk_redirect")) buf_printf(b, "(__s64)bpf_redirect_map(&bpf_xskmap, (__u32)(%s), XDP_PASS)", q);
      else                               buf_printf(b, "(__s64)bpf_redirect_map(&bpf_devmap, (__u32)(%s), 0)", q);
      free(q);
      return;
    }
    if (name && !strcmp(name, "fifo_pop"))  { buf_puts(b, "spnl_fifo_pop()"); return; }   /* QUEUE map pop */
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
    if (name && !strcmp(name, "sock_addr_ip4"))  { buf_puts(b, "((__s64)(__u32)__builtin_bswap32(ctx->user_ip4))"); return; }   /* sock_addr */
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
    if (name && !strcmp(name, "task_load")) { buf_puts(b, "spnl_task_load()"); return; }   /* per-task local storage */
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
    if (name && cc_pkt_canon(name)) {   /* pkt_* header access */
      Attach a = {0}; AttachKind k = g_method ? cc_detect_attach(g_method->name, &a) : AK_NONE;
      if (a.sec) free(a.sec);
      int is_tc = (k == AK_TC);
      if (k != AK_XDP && !is_tc)
        die("pkt_* builtins are only available inside xdp__ or tc__* methods", name);
      cc_record_pkt(name, is_tc);
      buf_printf(b, "%s_%s(ctx)", is_tc ? "spnl_tc" : "spnl", name);
      return;
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
  if (!strcmp(ty, "CallNode")) {
    const char *name = nt_str(ast, nid, "name");
    if (name && !strcmp(name, "spnl_emit")) {   /* ringbuf reserve/submit block */
      int args_id = nt_ref(ast, nid, "arguments");
      int na = 0; const int *ids = args_id >= 0 ? nt_arr(ast, args_id, "arguments", &na) : NULL;
      if (na != 1) die("spnl_emit expects 1 arg", NULL);
      char *val = cc_expr_str(ast, ids[0]);
      int e = ++g_if_counter;
      lines_push(body, strdup("{"));
      lines_push(body, msprintf("    struct %s_event *_e%d = bpf_ringbuf_reserve(&%s_events, sizeof(*_e%d), 0);", g_unit, e, g_unit, e));
      lines_push(body, msprintf("    if (_e%d) {", e));
      { char *var = msprintf("_e%d", e); cc_push_evt_hdr(body, "        ", var); free(var); }
      lines_push(body, msprintf("        _e%d->value = %s;", e, val));
      lines_push(body, msprintf("        bpf_ringbuf_submit(_e%d, 0);", e));
      lines_push(body, strdup("    }"));
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
      lines_push(body, strdup("    }"));
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
    if (name && (!strcmp(name, "leak_record") || !strcmp(name, "leak_forget"))) {   /* memleak track */
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
      lines_push(body, strdup("        }"));
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
    if (name && !strcmp(name, "emit_comm")) {   /* comm via str ringbuf */
      int e = ++g_if_counter;
      lines_push(body, strdup("{"));
      lines_push(body, msprintf("    struct %s_str_event *_se%d = bpf_ringbuf_reserve(&%s_str_events, sizeof(*_se%d), 0);", g_unit, e, g_unit, e));
      lines_push(body, msprintf("    if (_se%d) {", e));
      { char *var = msprintf("_se%d", e); cc_push_evt_hdr(body, "        ", var); free(var); }
      lines_push(body, msprintf("        bpf_get_current_comm(_se%d->str, sizeof(_se%d->str));", e, e));
      lines_push(body, msprintf("        bpf_ringbuf_submit(_se%d, 0);", e));
      lines_push(body, strdup("    }"));
      lines_push(body, strdup("}"));
      return strdup("0");
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
    die("n.times open-coded iterator (literal N) not yet ported (Stage 1)", NULL);   /* literal-N open-coded iterator */

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
enum { EMIT_INT = 1, EMIT_STR = 2, EMIT_PAIR = 4, EMIT_E3 = 8, EMIT_E4 = 16 };
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
      else if (!strcmp(nm, "spnl_emit_pair")) *f |= EMIT_PAIR;
      else if (!strcmp(nm, "spnl_emit3"))     *f |= EMIT_E3;
      else if (!strcmp(nm, "spnl_emit4"))     *f |= EMIT_E4;
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
         k == AK_USDT || k == AK_TRACEPOINT || k == AK_FENTRY || k == AK_FEXIT;
}

static int cc_starts(const char *s, const char *pfx, const char **rest) {
  size_t n = strlen(pfx);
  if (strncmp(s, pfx, n) == 0) { *rest = s + n; return 1; }
  return 0;
}

static AttachKind cc_detect_attach(const char *name, Attach *a) {
  const char *rest;
  memset(a, 0, sizeof *a);
  if      (cc_starts(name, "kprobe__", &rest))    { a->kind = AK_KPROBE;    a->sec = msprintf("kprobe/%s", rest);    a->ctx_type = "struct pt_regs *"; a->kname = "kprobe"; }
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

/* hand-written tracepoint field schema (mirrors Ruby TRACEPOINT_FIELDS).
 * Host has no BTF (the oracle), so codegen uses these tables exactly. Each entry
 * is "cat/event" + a NULL-terminated list of "field:type" (type int / ipv4). */
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
/* struct to cast ctx to: override table, else trace_event_raw_<event> (malloc'd). */
static char *cc_tp_struct(const char *key, const char *ev) {
  for (int i = 0; TP_STRUCT_OVERRIDE[i].key; i++)
    if (!strcmp(TP_STRUCT_OVERRIDE[i].key, key)) return strdup(TP_STRUCT_OVERRIDE[i].name);
  return msprintf("trace_event_raw_%s", ev);
}

/* extractor C expr for attach param i (typed cast from the kernel ctx).
 * `pname` is the declared param name (used for named-tracepoint field matching). */
static char *cc_attach_extractor(const Attach *a, const char *ctype, int i, const char *pname) {
  switch (a->kind) {
    case AK_KPROBE: case AK_KRETPROBE:
    case AK_UPROBE: case AK_URETPROBE:               return msprintf("(%s)PT_REGS_PARM%d(ctx)", ctype, i + 1);
    case AK_FENTRY: case AK_FEXIT:
    case AK_LSM:    case AK_FMOD_RET:                return msprintf("(%s)ctx[%d]", ctype, i);
    case AK_RAW_TP:                                  return msprintf("(%s)ctx->args[%d]", ctype, i);
    case AK_USDT:                                    return msprintf("(%s)_usdt_arg%d", ctype, i);
    case AK_TRACEPOINT:
      if (a->tp_struct) return msprintf("(%s)((struct %s *)ctx)->args[%d]", ctype, a->tp_struct, i);
      else {   /* named tracepoint -- match the param name to a struct field. */
        char *key = msprintf("%s/%s", a->tp_cat, a->tp_event);
        const char *ft = cc_tp_field_type(key, pname);
        if (!ft) { die("named tracepoint field schema unknown (Stage 1)", key); }
        char *st = cc_tp_struct(key, a->tp_event);
        char *r;
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

/* ---------- reactor DSL (module + include BPF::EventLoop + `on :kind`).
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
    {"usdt", "usdt__react__", "", 3, 1}, {"perf_event", "perf_event__main", "", 0, 0},
    {NULL, NULL, NULL, 0, 0}
  };
  for (int i = 0; K[i].kind; i++) if (!strcmp(K[i].kind, k)) return &K[i];
  return NULL;
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

/* Build the full .bpf.c text (mirrors Ruby CodegenBpf.emit). Returns malloc'd
 * string; this is the function the Stage-2 in-process plugin will hook. */
static char *ebpf_codegen_program(IR *ir, AST *ast, const char *base) {
  g_ir = ir;
  g_unit = cc_sanitize(base);
  int n_ebpf = 0, uses_pt_regs = 0, uses_usdt = 0, emit_flags = 0;
  int uses_blocklist = 0, uses_cidr = 0, uses_path_counter = 0;
  int uses_histogram = 0, uses_latency = 0, uses_hist_keyed = 0, uses_hist_linear = 0;
  int uses_stack_trace = 0;
  int uses_off_cpu = 0;      /* off_cpu_start/observe */
  int uses_sched_ext = 0, uses_qdisc = 0, uses_tcp_cc = 0;   /* struct_ops kinds */
  int uses_qdisc_fifo = 0;   /* queue_push/queue_pop */
  int uses_kfield = 0;       /* kfield/kptr -> BPF_CORE_READ (bpf_core_read.h) */
  int uses_task_storage = 0; /* task_load/store/incr/swap */
  int uses_map_in_map = 0;   /* mim_inc/mim_get */
  int uses_fifo = 0, uses_lifo = 0;   /* QUEUE / STACK maps */
  int uses_xskmap = 0, uses_devmap = 0;   /* xsk_redirect / dev_redirect */
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
    n_ebpf++;
    int bdy = ir->m[i].body_id;
    cc_scan_emit(ast, bdy, &emit_flags);
    if (cc_body_uses_call(ast, bdy, "blocklist_match"))      uses_blocklist = 1;
    if (cc_body_uses_call(ast, bdy, "cidr_blocklist_match")) uses_cidr = 1;
    if (cc_body_uses_call(ast, bdy, "path_counter_inc"))     uses_path_counter = 1;
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
    /* struct_ops kinds (from class X < BPF::SchedExt/Qdisc/TcpCC synthesis). */
    if (ir->m[i].so_kind == SO_SCHED_EXT) uses_sched_ext = 1;
    else if (ir->m[i].so_kind == SO_QDISC) uses_qdisc = 1;
    else if (ir->m[i].so_kind == SO_TCP_CC) uses_tcp_cc = 1;
    if (cc_body_uses_call(ast, bdy, "queue_push") || cc_body_uses_call(ast, bdy, "queue_pop")) uses_qdisc_fifo = 1;  /* FIFO qdisc */
    if (cc_body_uses_call(ast, bdy, "kfield") || cc_body_uses_call(ast, bdy, "kptr") ||
        cc_body_uses_call(ast, bdy, "field_exists")) uses_kfield = 1;  /* CO-RE field access */
    if (cc_body_uses_call(ast, bdy, "task_load") || cc_body_uses_call(ast, bdy, "task_store") ||
        cc_body_uses_call(ast, bdy, "task_incr") || cc_body_uses_call(ast, bdy, "task_swap")) uses_task_storage = 1;  /* task storage */
    if (cc_body_uses_call(ast, bdy, "mim_inc") || cc_body_uses_call(ast, bdy, "mim_get")) uses_map_in_map = 1;  /* map-in-map */
    if (cc_body_uses_call(ast, bdy, "fifo_push") || cc_body_uses_call(ast, bdy, "fifo_pop")) uses_fifo = 1;  /* QUEUE map */
    if (cc_body_uses_call(ast, bdy, "lifo_push") || cc_body_uses_call(ast, bdy, "lifo_pop")) uses_lifo = 1;
    if (cc_body_uses_call(ast, bdy, "xsk_redirect")) uses_xskmap = 1;   /* AF_XDP redirect */
    if (cc_body_uses_call(ast, bdy, "dev_redirect")) uses_devmap = 1;
    if (cc_body_uses_call(ast, bdy, "leak_record") || cc_body_uses_call(ast, bdy, "leak_forget")) uses_leak_track = 1;  /* memleak track */
    if (cc_body_uses_call(ast, bdy, "lock_edge")) uses_lock_edge = 1;  /* deadlock detection */
    if (cc_body_uses_call(ast, bdy, "lat_start") || cc_body_uses_call(ast, bdy, "lat_end")) uses_keyed_lat = 1;  /* keyed latency */
    if (cc_body_uses_call(ast, bdy, "depth_inc") || cc_body_uses_call(ast, bdy, "depth_dec")) uses_depth = 1;  /* depth-collapse */
    if (cc_body_uses_call(ast, bdy, "fib_lookup") || cc_body_uses_call(ast, bdy, "fib_lookup6")) uses_fib = 1;  /* FIB route lookup */
    if (cc_body_uses_call(ast, bdy, "skb_load_u16") || cc_body_uses_call(ast, bdy, "skb_load_u32") ||
        cc_body_uses_call(ast, bdy, "skb_store_u16") || cc_body_uses_call(ast, bdy, "skb_store_u32") ||
        cc_body_uses_call(ast, bdy, "l3_csum_replace") || cc_body_uses_call(ast, bdy, "l4_csum_replace") ||
        cc_body_uses_call(ast, bdy, "l3_csum_replace_ip") || cc_body_uses_call(ast, bdy, "l4_csum_replace_ip") ||
        cc_body_uses_call(ast, bdy, "sk_lookup_tcp") || cc_body_uses_call(ast, bdy, "sk_assign_tcp")) uses_csum = 1;  /* skb csum + socket lookup/steer */
    if (cc_body_uses_call(ast, bdy, "arena_set") || cc_body_uses_call(ast, bdy, "arena_get") ||
        cc_body_uses_call(ast, bdy, "arena_hash_set") || cc_body_uses_call(ast, bdy, "arena_hash_get") ||
        cc_body_uses_call(ast, bdy, "arena_hash_del") || cc_body_uses_call(ast, bdy, "arena_list_push") ||
        cc_body_uses_call(ast, bdy, "arena_list_sum")) uses_arena = 1;  /* arena data structures */
    Attach ai;
    cc_detect_attach(ir->m[i].name, &ai);
    /* PT_REGS_PARM<N> macros (bpf_tracing.h) for probe-family with params. */
    if (ir->m[i].nparams && (ai.kind == AK_KPROBE || ai.kind == AK_KRETPROBE ||
                             ai.kind == AK_UPROBE || ai.kind == AK_URETPROBE)) uses_pt_regs = 1;
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

  /* license_and_includes: the extras line, or a blank line when there are none
   * (Ruby heredoc interpolates `extras.join("\n")` as one line). */
  SECTION_SEP();
  buf_puts(&out, "#include \"vmlinux.h\"\n#include <bpf/bpf_helpers.h>\n");
  {
    const char *extras[6]; int ne = 0;
    if (emit_flags) extras[ne++] = "#include \"spnl/types.h\"";   /* any emit-family channel */
    if (g_n_pkt > 0 || uses_fib || uses_csum || g_n_flow > 0) extras[ne++] = "#include <bpf/bpf_endian.h>";   /* bpf_ntohs/htonl: pkt_* / fib / skb csum / flow */
    if (uses_pt_regs || uses_usdt || uses_sched_ext || uses_qdisc || uses_tcp_cc)
      extras[ne++] = "#include <bpf/bpf_tracing.h>";  /* PT_REGS_PARM / usdt / BPF_PROG */
    if (uses_usdt) extras[ne++] = "#include <bpf/usdt.bpf.h>";       /* bpf_usdt_arg */
    if (uses_qdisc_fifo || uses_kfield) extras[ne++] = "#include <bpf/bpf_core_read.h>";   /* bpf_core_type_id_local / BPF_CORE_READ */
    if (ne == 0) buf_puts(&out, "\n");
    else for (int e = 0; e < ne; e++) buf_printf(&out, "%s\n", extras[e]);
  }
  buf_puts(&out, "char LICENSE[] SEC(\"license\") = \"Dual MIT/GPL\";\n");

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

  /* per-unit int-event ringbuf channel. */
  if (uses_ringbuf) {
    SECTION_SEP();
    buf_puts(&out, "/* === per-unit int-event channel === */\n");
    buf_printf(&out, "struct %s_event {\n", g_unit);
    buf_puts(&out, "    struct spnl_event_hdr hdr;\n    __s64 value;\n};\n\n");
    buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_RINGBUF);\n    __uint(max_entries, 256 * 1024);\n");
    buf_printf(&out, "} %s_events SEC(\".maps\");\n", g_unit);
  }

  /* per-unit string-event channel (char str[256] payload). */
  if (emit_flags & EMIT_STR) {
    SECTION_SEP();
    buf_puts(&out, "/* === per-unit string-event channel === */\n");
    buf_printf(&out, "struct %s_str_event {\n", g_unit);
    buf_puts(&out, "    struct spnl_event_hdr hdr;\n    char str[256];\n};\n\n");
    buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_RINGBUF);\n    __uint(max_entries, 256 * 1024);\n");
    buf_printf(&out, "} %s_str_events SEC(\".maps\");\n", g_unit);
  }

  /* per-unit pair-event channel (two __s64 values per event). */
  if (emit_flags & EMIT_PAIR) {
    SECTION_SEP();
    buf_puts(&out, "/* === per-unit pair-event channel === */\n");
    buf_printf(&out, "struct %s_pair_event {\n", g_unit);
    buf_puts(&out, "    struct spnl_event_hdr hdr;\n    __s64 a;\n    __s64 b;\n};\n\n");
    buf_puts(&out, "struct {\n    __uint(type, BPF_MAP_TYPE_RINGBUF);\n    __uint(max_entries, 256 * 1024);\n");
    buf_printf(&out, "} %s_pair_events SEC(\".maps\");\n", g_unit);
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
    int ctx_first = is_attach && (a.ctx_prefixed || (uses_stack_trace && cc_is_tracing_kind(a.kind)));

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
    buf_printf(&out, "static __noinline %s %s_inner(", cret, fn);
    {                                    /* ctx-prefixed (xdp/tc) take the kernel ctx first */
      int wrote = 0;
      if (ctx_first) { buf_printf(&out, "%sctx", a.ctx_type); wrote = 1; }
      for (int k = 0; k < me->nparams; k++) {
        buf_printf(&out, "%s%s %s", (wrote || k) ? ", " : "", ty_to_c(me->ptypes[k]), me->pnames[k]);
        wrote = 1;
      }
      if (!wrote) buf_puts(&out, "void");
    }
    buf_puts(&out, ")\n{\n");
    for (int k = 0; k < m_bodies[i].n; k++) { char *t = cc_indent_each(m_bodies[i].v[k]); buf_puts(&out, t); buf_puts(&out, "\n"); free(t); }   /* pre-lowered */
    buf_puts(&out, "}\n");

    /* wrapper (preceded by a blank line) */
    buf_puts(&out, "\n");
    if (is_attach) {   /* attach handler (SEC + kernel ctx) */
      if (a.ctx_prefixed && me->nparams) die("ctx-prefixed attach with params not yet ported (Stage 1)", me->name);
      buf_printf(&out, "/* entry wrapper: %s [%s -> %s] */\n", qn, a.kname, a.sec);
      buf_printf(&out, "SEC(\"%s\")\n", a.sec);
      buf_printf(&out, "int %s(%sctx)\n{\n", fn, a.ctx_type);
      buf_puts(&out, "    (void)ctx;\n");
      /* USDT prologue -- declare + fill each arg temp before the inner call. */
      if (a.usdt)
        for (int k = 0; k < me->nparams; k++)
          buf_printf(&out, "    long _usdt_arg%d = 0; (void)bpf_usdt_arg(ctx, %d, &_usdt_arg%d);\n", k, k, k);
      /* bpf_iter is invoked once per object + a final NULL terminator;
       * skip the body on that terminator so counters don't over-count. */
      if (a.iter_guard) buf_puts(&out, "    if (!ctx->task) return 0;\n");
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
      if (a.verdict)               buf_printf(&out, "    return (int)%s;\n}\n", call.p);  /* xdp/tc/sk/lsm/fmod */
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

/* Synthesized userspace consumer/driver/named-handler methods (__spnl_*,
 * lowered from the `on_emit` / `on_emit :name` DSL) run in userspace draining
 * the emit ringbuf via FFI. They must never enter the eBPF IR -- exclude them
 * from both the in-process IR (fill_ir_from_compiler) and the .ir text.
 *
 * For --instrument --instrument-self, the workload + the agent live in one
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
