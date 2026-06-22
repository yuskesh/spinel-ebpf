/* spinel_upstream_contract.h -- the COMPLETE dependency surface of upstream
 * spinel internal structs that spinel-ebpf's in-process eBPF codegen reads
 * (Stage 2).
 *
 * Every layout-dependent field read of the upstream Compiler / Scope /
 * ClassInfo / LocalVar structs goes through ONE accessor here, so that:
 *   (1) if upstream renames or moves a field, this is the SINGLE file to fix;
 *   (2) a reviewer sees the entire spinel-ebpf -> upstream-internals coupling
 *       at a glance (previously ~31 scattered `c->` / `s->` / `cl->` / `p->`
 *       reads inside spinel_ebpf_cc.c's fill_ir_from_compiler + cc_build_ir_text).
 *
 * Also part of the coupling surface, but already in function-/enum-form (no
 * struct-layout fragility, so kept inline at the call sites):
 *   - upstream functions: scope_local(Scope*, name); nt_ref/nt_type/nt_str(nt,..);
 *     ty_name(TyKind); ty_is_object/ty_object_class(TyKind).
 *   - upstream TyKind enum values: TY_UNKNOWN / TY_POLY / TY_INT.
 *
 * Only the -DSPNL_INPROCESS build links upstream and defines these structs; the
 * host text codegen never does. Include this ONLY from inside that guard.
 */
#ifndef SPINEL_EBPF_UPSTREAM_CONTRACT_H
#define SPINEL_EBPF_UPSTREAM_CONTRACT_H

#include "compiler.h"  /* Compiler / Scope / ClassInfo / LocalVar / TyKind / NodeTable */

/* ---- Compiler (analyzed program state) ---- */
static inline const NodeTable *sce_nt(Compiler *c)         { return c->nt; }
static inline int         sce_nscopes(Compiler *c)         { return c->nscopes; }
static inline Scope      *sce_scope(Compiler *c, int i)    { return &c->scopes[i]; }
static inline int         sce_nclasses(Compiler *c)        { return c->nclasses; }
static inline ClassInfo  *sce_class(Compiler *c, int i)    { return &c->classes[i]; }

/* ---- Scope (one per `def`; scope[0] is the top level) ---- */
static inline const char *sce_scope_name(Scope *s)         { return s->name; }
static inline int         sce_scope_class_id(Scope *s)     { return s->class_id; }
static inline TyKind      sce_scope_ret(Scope *s)          { return s->ret; }
static inline int         sce_scope_body(Scope *s)         { return s->body; }
static inline int         sce_scope_nparams(Scope *s)      { return s->nparams; }
static inline char       *sce_scope_pname(Scope *s, int i) { return s->pnames[i]; }
static inline int         sce_scope_nlocals(Scope *s)      { return s->nlocals; }
static inline const char *sce_local_name(Scope *s, int k)  { return s->locals[k].name; }
static inline TyKind      sce_local_type_at(Scope *s, int k){ return s->locals[k].type; }

/* ---- ClassInfo ---- */
static inline const char *sce_class_name(ClassInfo *cl)         { return cl->name; }
static inline int         sce_class_parent(ClassInfo *cl)       { return cl->parent; }
static inline int         sce_class_def_node(ClassInfo *cl)     { return cl->def_node; }
static inline int         sce_class_nivars(ClassInfo *cl)       { return cl->nivars; }
static inline char       *sce_class_ivar_name(ClassInfo *cl, int j) { return cl->ivars[j]; }
static inline TyKind      sce_class_ivar_type(ClassInfo *cl, int j) { return cl->ivar_types[j]; }

/* ---- LocalVar (resolved via upstream scope_local) ---- */
static inline TyKind      sce_local_type(LocalVar *p)      { return p->type; }

#endif /* SPINEL_EBPF_UPSTREAM_CONTRACT_H */
