/* gen_record_mirror.c -- generate the userspace mirror of the ringbuf record
 * contracts from the declarative schema table.
 *
 * A packed-record emit builtin is one contract with two ends: the kernel
 * producer struct (also generated from src/codegen_c/record_schema.h)
 * and the userspace consumer in src/runtime/otlp/otlp_agent.c, which used to
 * hand-type both a mirror struct and its byte offsets (`memcpy(data + H + 88,
 * ...)`). This program removes the second hand-writing: it reads the same table
 * and prints a header with
 *
 *   - the byte offsets, computed (running offset + alignment padding), never typed
 *   - the mirror struct, named/typed from the same fields
 *   - _Static_assert()s tying the two together (host layout == wire layout)
 *   - an unpack() that decodes one ringbuf record into the mirror
 *   - the egress attribute keys the runtime puts on the span, as
 *     SPNL_EGRESS_* macros, so otlp_agent.c spells them once -- in the table
 *   - the typed-consumer accessors: the C functions a Ruby
 *     `on_emit :dns do |ev| ... end` block calls when it reads `ev.<prop>`
 *   - the value-map lookups: for a CODE (a value from a closed set whose
 *     members have names) the declaration IS the implementation, so this program
 *     generates the switch instead of the runtime hand-writing it
 *
 * so an offset desync between producer and consumer is no longer expressible.
 *
 * There is a second output, `--json`: the same table rendered for the Ruby
 * affordance surface (src/spinel_ebpf/capabilities.rb). The offsets there are
 * the ones layout() computes below -- Ruby never re-derives alignment rules,
 * which would be the third hand-written copy this generator exists to prevent.
 *
 * Both outputs are committed derived artifacts (like templates_gen.h and
 * tests/golden/): the runtime build never invokes this generator, it just
 * #includes the checked-in header, and the Ruby lib just reads the checked-in
 * JSON.
 *
 *   make -C src/codegen_c mirror     # build + run + write both artifacts
 *
 * or by hand:
 *
 *   cc -O2 -Wall -Wextra -o /tmp/gen_record_mirror tools/gen_record_mirror.c
 *   /tmp/gen_record_mirror        > src/runtime/otlp/record_mirror_gen.h
 *   /tmp/gen_record_mirror --json > src/spinel_ebpf/record_schema_gen.json
 *
 * Deterministic: no timestamps, no paths, no hash ordering -- same table in,
 * same bytes out (re-running must produce an empty diff).
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/codegen_c/record_schema.h"

/* Channels mirrored here: whatever record_schema.h publishes (the list lives in
 * the header so the codegen, this generator and the append-only gate
 * all walk the same registry). */
static const CcRecSchema *const *g_channels;
static int g_nchannels;

/* The declared value maps (type-driven derivations). Same registry the
 * codegen and the authority test walk. */
static const CcValueMap *const *g_valmaps;
static int g_nvalmaps;

/* Kernel spelling -> host spelling. An unknown type aborts rather than being
 * passed through: guessing a width is precisely the desync this generator
 * exists to remove. */
static const struct { const char *kern, *host; } g_ctype_map[] = {
    { "__u8",  "uint8_t"  }, { "__u16", "uint16_t" },
    { "__u32", "uint32_t" }, { "__u64", "uint64_t" },
    { "__s8",  "int8_t"   }, { "__s16", "int16_t"  },
    { "__s32", "int32_t"  }, { "__s64", "int64_t"  },
    { "char", "char" }, { "unsigned char", "unsigned char" },
    { "struct spnl_event_hdr", "struct spnl_event_hdr" },
};

static void die(const char *msg, const char *what) {
    fprintf(stderr, "gen_record_mirror: %s: %s\n", msg, what);
    exit(1);
}

static const char *host_ctype(const char *kern) {
    for (size_t i = 0; i < sizeof g_ctype_map / sizeof g_ctype_map[0]; i++)
        if (strcmp(g_ctype_map[i].kern, kern) == 0) return g_ctype_map[i].host;
    die("no host spelling for kernel type", kern);
    return NULL;
}

/* "duration_ns" -> "DURATION_NS" (non-alphanumerics become '_'). */
static void upcase(const char *s, char *out, size_t cap) {
    size_t i = 0;
    for (; s[i] && i + 1 < cap; i++) {
        unsigned char c = (unsigned char)s[i];
        out[i] = (char)(isalnum(c) ? toupper(c) : '_');
    }
    out[i] = '\0';
}

/* "dns.question.name" -> "DNS_QUESTION_NAME" (macro tail for an attribute key). */
static void key_macro_tail(const char *key, char *out, size_t cap) {
    upcase(key, out, cap);
}

/* Render a span-name format for humans/JSON: each printf conversion becomes
 * {<arg>}, taking the args in order from the comma-separated span_name_arg.
 * Derived, so the format string stays the one the C runtime actually uses
 * (SPNL_EGRESS_<ID>_SPAN_NAME_FMT); a mismatch between the number of
 * conversions and the number of named sources is a generator abort, because it
 * would mean the published span name does not describe the emitted one. */
static void span_name_template(const CcEgressSpan *e, char *out, size_t cap) {
    const char *args[8]; int nargs = 0;
    static char argbuf[512];
    size_t o = 0;

    snprintf(argbuf, sizeof argbuf, "%s", e->span_name_arg ? e->span_name_arg : "");
    for (char *p = argbuf; *p; ) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (nargs >= (int)(sizeof args / sizeof args[0])) die("too many span-name args", e->span_name_fmt);
        args[nargs++] = p;
        char *c = strchr(p, ',');
        if (!c) break;
        *c = '\0';
        p = c + 1;
    }

    int used = 0;
    for (const char *p = e->span_name_fmt; *p && o + 1 < cap; ) {
        if (*p != '%') { out[o++] = *p++; continue; }
        if (p[1] == '%') { out[o++] = '%'; p += 2; continue; }
        const char *q = p + 1;   /* skip flags/width, land on the specifier letter */
        while (*q && !((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z'))) q++;
        if (!*q) die("span_name_fmt has an unterminated conversion", e->span_name_fmt);
        if (used >= nargs) die("span_name_fmt has more conversions than span_name_arg names", e->span_name_fmt);
        int n = snprintf(out + o, cap - o, "{%s}", args[used++]);
        if (n < 0 || (size_t)n >= cap - o) die("span name template does not fit", e->span_name_fmt);
        o += (size_t)n;
        p = q + 1;
    }
    out[o] = '\0';
    if (used != nargs) die("span_name_arg names more sources than span_name_fmt consumes", e->span_name_fmt);
}

/* The layout rule, once: pad each field up to its own alignment, then pad the
 * record up to the widest member's alignment. Identical to what the C compiler
 * does on both ends, which is why the generated _Static_assert()s hold. */
static void layout(const CcRecSchema *s, int *offs, int *total) {
    int off = 0, maxalign = 1;
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        if (f->size <= 0 || f->align <= 0) die("field has non-positive size/align", f->name);
        if (off % f->align) off += f->align - (off % f->align);
        offs[i] = off;
        off += f->size * (f->count > 0 ? f->count : 1);
        if (f->align > maxalign) maxalign = f->align;
    }
    if (off % maxalign) off += maxalign - (off % maxalign);
    *total = off;
}

/* How many bytes a record must have to be accepted. `required_through`
 * names the last field a producer of ANY published generation must have written;
 * fields after it read as zero when absent (the append-only reading rule). NULL
 * = every field is required, the strict form. */
static int required_bytes(const CcRecSchema *s, const int *offs, int total) {
    if (!s->required_through) return total;
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        if (strcmp(f->name, s->required_through) != 0) continue;
        return offs[i] + f->size * (f->count > 0 ? f->count : 1);
    }
    die("required_through names no field of this record", s->required_through);
    return total;
}

/* The egress (semantic) half -- the attribute keys the userspace
 * consumer puts on the span. Emitting them as macros makes otlp_agent.c a
 * consumer of the declaration instead of a second place where the keys are
 * spelled, which is what let `capabilities --json` drift from the wire. */
static void emit_egress(const CcRecSchema *s, const char *ID) {
    const CcEgressSpan *e = s->egress;
    char tails[64][96], name[256], fmtname[256], tmpl[256];
    int w;

    if (e->nattrs > (int)(sizeof tails / sizeof tails[0])) die("too many egress attrs", s->id);
    snprintf(fmtname, sizeof fmtname, "SPNL_EGRESS_%s_SPAN_NAME_FMT", ID);
    w = (int)strlen(fmtname);
    for (int i = 0; i < e->nattrs; i++) {
        key_macro_tail(e->attrs[i].key, tails[i], sizeof tails[i]);
        for (int j = 0; j < i; j++)
            if (strcmp(tails[i], tails[j]) == 0) die("two egress keys collide as one macro", e->attrs[i].key);
        int l = (int)strlen("SPNL_EGRESS_") + (int)strlen(ID) + (int)strlen("_ATTR_") + (int)strlen(tails[i]);
        if (l > w) w = l;
    }

    span_name_template(e, tmpl, sizeof tmpl);
    printf("\n/* --- egress contract for channel \"%s\" ---\n", s->id);
    printf(" * %s() turns one record into a span named \"%s\"\n", e->push_fn, tmpl);
    printf(" * (SpanKind %s; %s).\n", e->span_kind, e->timing);
    if (e->note) printf(" * Note: %s.\n", e->note);
    printf(" * The runtime spells these keys via the macros below, so the attribute\n");
    printf(" * contract has exactly one author: the schema table. */\n");
    printf("#define %-*s \"%s\"\n", w, fmtname, e->span_name_fmt);
    for (int i = 0; i < e->nattrs; i++) {
        /* explicit precisions: `tails` is a 2-D array, so a bare %s leaves the
         * compiler assuming the whole thing could be copied (-Wformat-truncation) */
        snprintf(name, sizeof name, "SPNL_EGRESS_%.63s_ATTR_%.95s", ID, tails[i]);
        printf("#define %-*s \"%s\"   /* %s <- %s */\n",
               w, name, e->attrs[i].key, e->attrs[i].stability, e->attrs[i].source);
    }
}

/* --- The typed consumer's accessor set ------------------------------------
 *
 * `expose` says what a property looks like in Ruby; these two tables say what it
 * looks like at the FFI boundary. `long`/`const char *` are the only two shapes
 * spinel's ffi_func can carry for a value read (`:long` / `:str`), and both must
 * match the extern prototype spinel emits or the C compiler rejects the TU --
 * which is why the mapping lives here once instead of in the Ruby transform. */
static const char *expose_ctype(const char *expose, const char *what) {
    if (strcmp(expose, "int") == 0) return "long";
    if (strcmp(expose, "str") == 0) return "const char *";
    die("unknown expose type", what);
    return NULL;
}

static const char *expose_ffi(const char *expose, const char *what) {
    if (strcmp(expose, "int") == 0) return ":long";
    if (strcmp(expose, "str") == 0) return ":str";
    die("unknown expose type", what);
    return NULL;
}

/* --- how a declared derivation is CALLED ---------------------------------
 *
 * The table declares a derivation's EXISTENCE, never its implementation:
 * a DNS QNAME walk or an HTTP request-line parse is domain logic that already
 * lives -- and is tested -- in C. This is where the generator learns how to call
 * it. Four conventions, and an unknown one aborts the generator, so a fifth
 * cannot appear by accident:
 *
 *   bytes_to_str   void f(const unsigned char *src, char *out, int cap)
 *   bytes_to_int   long f(const unsigned char *src)
 *   record_to_str  void f(const spnl_rec_<id>_t *r, char *out, int cap)
 *   record_to_int  long f(const spnl_rec_<id>_t *r)
 *
 * Four, because there are two independent axes and the form names the pair:
 *
 *   WHAT IT IS HANDED   bytes_*  = one field's bytes, named by `from`: the
 *                                  derivation is a parse and the rest of the
 *                                  record is irrelevant (dns qname, http status)
 *                       record_* = the whole record, because what it derives is
 *                                  not a parse of one field -- conn's `peer` has
 *                                  to read `family` to know whether the address
 *                                  is in `daddr` or in `daddr6_hi/lo`
 *   WHAT IT RETURNS     *_to_str / *_to_int, the only two shapes spinel's
 *                       ffi_func can carry for a value read
 *
 * Keeping the derivation in C is the point: the v4/v6 branch, and the fact that
 * the kernel reports srtt in units of 1/8 us, are *meaning*, and meaning is
 * owned by the runtime layer, not by the probe. Ruby reads `ev.peer` / `ev.srtt_us`
 * without learning what AF_INET6 is or that it should divide by 8 -- and because
 * the span builder calls the same function, what Ruby sees and what goes on the
 * wire cannot be two spellings of the same idea that drift. */
enum { DERIV_BYTES_STR, DERIV_BYTES_INT, DERIV_RECORD_STR, DERIV_RECORD_INT, DERIV_CODE_NAME };

static int derived_form(const CcRecDerived *d) {
    if (strcmp(d->impl_form, "bytes_to_str")  == 0) return DERIV_BYTES_STR;
    if (strcmp(d->impl_form, "bytes_to_int")  == 0) return DERIV_BYTES_INT;
    if (strcmp(d->impl_form, "record_to_str") == 0) return DERIV_RECORD_STR;
    if (strcmp(d->impl_form, "record_to_int") == 0) return DERIV_RECORD_INT;
    /* The odd one out on purpose: the four above name a C function the
     * runtime must define, and the generator only learns how to CALL it. This one
     * names a CcValueMap, and the function below is generated from it -- because a
     * code's mapping is not domain logic, it is the table. See record_schema.h. */
    if (strcmp(d->impl_form, "code_to_name")  == 0) return DERIV_CODE_NAME;
    die("unknown derivation impl_form", d->impl_form);
    return -1;
}

/* the two axes above, read back off the form (the generator only ever asks these
 * two questions: what to hand the function, and what shape comes back) */
static int derived_takes_record(int form) {
    return form == DERIV_RECORD_STR || form == DERIV_RECORD_INT;
}
static int derived_returns_int(int form) {
    return form == DERIV_BYTES_INT || form == DERIV_RECORD_INT;
}

/* --- value maps ------------------------------------------------------------
 *
 * A code_to_name derivation's `impl` names one of these instead of a C function,
 * and the lookup is generated below. Everything here exists to make the one
 * failure such a table has -- a wrong entry, which downstream cannot detect
 * because a wrong name is still a name -- either impossible or loud. */

static const CcValueMap *find_valmap(const char *id, const char *what) {
    for (int i = 0; i < g_nvalmaps; i++)
        if (strcmp(g_valmaps[i]->id, id) == 0) return g_valmaps[i];
    die("code_to_name derivation names an undeclared value map", what);
    return NULL;
}

/* Width, in characters, of the widest decimal rendering of one value of this
 * field's type, sign included. A code is an integer; anything else is a
 * declaration mistake, and one that would otherwise reach the C compiler as a
 * pointer-to-long cast rather than as a sentence about the table. */
static int scalar_decimal_width(const char *ctype, const char *what) {
    static const struct { const char *t; int w; } tbl[] = {
        { "__u8", 3 }, { "__u16", 5 }, { "__u32", 10 }, { "__u64", 20 },
        { "__s8", 4 }, { "__s16", 6 }, { "__s32", 11 }, { "__s64", 20 },
    };
    for (size_t i = 0; i < sizeof tbl / sizeof tbl[0]; i++)
        if (strcmp(tbl[i].t, ctype) == 0) return tbl[i].w;
    die("a code_to_name derivation reads a field whose type is not an integer", what);
    return 0;
}

/* Widest string the map's `unknown` rendering can produce, given how wide the
 * source field's decimal form is. Also the place that refuses any conversion
 * other than a single %ld: an unnamed code must keep its number and must not be
 * able to come out shaped like a name (or run off the buffer). */
static int unknown_width(const CcValueMap *m, int dec_width) {
    int lit = 0, conv = 0;
    for (const char *p = m->unknown; *p; ) {
        if (*p != '%') { lit++; p++; continue; }
        if (p[1] == '%') { lit++; p += 2; continue; }
        if (p[1] == 'l' && p[2] == 'd') { conv++; p += 3; continue; }
        die("a value map's `unknown` rendering may only use %ld (or %%)", m->id);
    }
    if (conv > 1) die("a value map's `unknown` rendering uses %ld more than once", m->id);
    return lit + conv * dec_width;
}

static void check_valmap(const CcValueMap *m) {
    if (!m->id || !*m->id)               die("a value map has no id", "(anonymous)");
    if (!m->authority || !*m->authority) die("a value map declares no authority", m->id);
    if (!m->unknown || !*m->unknown)     die("a value map declares no `unknown` rendering", m->id);
    if (m->nvalues <= 0)                 die("a value map declares no values", m->id);
    /* The refusal this check exists for. A table that differs per architecture
     * cannot be a committed artifact: baked on one it renders a plausible wrong
     * name on the next (syscall 2 is io_submit / open / fork depending on where
     * you ask), which is the very failure the layer removes. */
    if (!m->arch_invariant)
        die("a value map that is not architecture-invariant cannot be baked into a committed "
            "artifact -- on another architecture it would render a plausible WRONG name "
            "(measured: syscall 2 = io_submit on aarch64, open on x86_64, fork on "
            "i386/arm/ppc/s390x). Resolve it at RUNTIME on the machine that produced the record "
            "(glibc's strerrorname_np / sigabbrev_np do that for errno and signal), or carry the "
            "architecture in the portability contract. The map is", m->id);
    for (int i = 0; i < m->nvalues; i++) {
        if (!m->values[i].name || !*m->values[i].name) die("a value map entry has no name", m->id);
        for (int j = 0; j < i; j++) {
            if (m->values[i].value == m->values[j].value)
                die("a value map gives one value two names", m->id);
            if (strcmp(m->values[i].name, m->values[j].name) == 0)
                die("a value map gives one name to two values", m->id);
        }
    }
    if (m->btf_mode) {
        if (strcmp(m->btf_mode, "names") != 0 && strcmp(m->btf_mode, "keys") != 0)
            die("unknown value map btf_mode (expected \"names\" or \"keys\")", m->btf_mode);
        if (!m->btf_anchor || !*m->btf_anchor)
            die("a value map declares a btf_mode but no btf_anchor to find the enum by", m->id);
    }
}

/* Wrap prose into a block comment body. The declarations' notes are sentences,
 * and a generated header nobody can read is a generated header nobody reviews. */
static void emit_wrapped(const char *lead, const char *text) {
    const char *cont = " * ";
    int col, first = 1;
    if (!text || !*text) return;
    if (strstr(text, "*/")) die("declared prose closes the generated block comment", text);
    printf(" * %s", lead);
    col = 3 + (int)strlen(lead);
    for (const char *p = text; *p; ) {
        const char *e = p;
        while (*e && *e != ' ') e++;
        int w = (int)(e - p);
        if (!first && col + 1 + w > 78) { printf("\n%s", cont); col = (int)strlen(cont); }
        else if (!first) { putchar(' '); col++; }
        fwrite(p, 1, (size_t)w, stdout);
        col += w;
        first = 0;
        p = e;
        while (*p == ' ') p++;
    }
    putchar('\n');
}

/* Emit one map as a lookup. Generated, so the switch and the declaration cannot
 * be two different tables -- which is what the hand-typed TCP_STATE_* list in the
 * codegen became (measured three enumerators behind the kernel). */
static void emit_valmap(const CcValueMap *m) {
    int has_conv = strstr(m->unknown, "%ld") != NULL;
    printf("\n/* --- value map \"%s\" ---\n", m->id);
    emit_wrapped("authority: ", m->authority);
    emit_wrapped("", m->note);
    emit_wrapped("", "An unnamed value renders as shown in the default branch. "
                     "Architecture-invariant: a map that cannot say so does not compile "
                     "(check_valmap() in tools/gen_record_mirror.c).");
    printf(" */\n");
    printf("static inline void spnl_valmap_%s(long v, char *out, int cap) {\n", m->id);
    printf("    const char *name = 0;\n");
    printf("    switch (v) {\n");
    for (int i = 0; i < m->nvalues; i++)
        printf("    case %ldL: name = \"%s\"; break;\n", m->values[i].value, m->values[i].name);
    printf("    default: break;\n");
    printf("    }\n");
    printf("    if (!out || cap <= 0) return;\n");
    printf("    if (name) snprintf(out, (size_t)cap, \"%%s\", name);\n");
    if (has_conv) printf("    else      snprintf(out, (size_t)cap, \"%s\", v);\n", m->unknown);
    else          printf("    else      snprintf(out, (size_t)cap, \"%%s\", \"%s\");\n", m->unknown);
    printf("}\n");
}

static void emit_valmaps(void) {
    printf("/* ===================== declared value maps =====================\n");
    printf(" * A CODE -- a value from a closed set whose members have names -- is the one\n");
    printf(" * derivation whose implementation IS its declaration, so these lookups are\n");
    printf(" * generated from src/codegen_c/record_schema.h rather than written in the\n");
    printf(" * runtime. They live outside SPNL_REC_CONSUME_IMPL because BOTH ends call\n");
    printf(" * them: the typed consumer's accessor (`ev.tcp_state`) and the span builder\n");
    printf(" * that fills the attribute -- one function, so the two cannot drift. */\n");
    for (int i = 0; i < g_nvalmaps; i++) emit_valmap(g_valmaps[i]);
    printf("\n");
}

/* The macro a string derivation's output capacity is published as. Both ends pass
 * it -- the accessor below and the runtime's span builder -- so a long value
 * cannot truncate differently on the two sides. The number is per-derivation so
 * it can be an actual bound (see the `cap` comment on CcRecDerived) instead of
 * one value shared by everybody. */
static void derived_cap_macro(const char *ID, const CcRecDerived *d, char *out, size_t cap) {
    char NUP[96];
    upcase(d->name, NUP, sizeof NUP);
    snprintf(out, cap, "SPNL_REC_DERIVED_%.63s_%.95s_CAP", ID, NUP);
}

/* Three things the form fixes, checked here rather than left to the runtime TU's
 * compiler (where the message would point at generated text, not at the table):
 *   - the Ruby type: a *_to_str derivation is a String, a *_to_int an Integer;
 *   - the property name is claimed once: a derivation named like an exposed field
 *     would emit spnl_rec_<id>_<name>() twice. Shadowing is not a mistake to
 *     forbid outright, it is a legitimate MOVE -- conn's raw `srtt_us` field
 *     became a derived one (us instead of the kernel's 1/8 us) -- so the rule
 *     is "not both at once", and taking `expose` off the field is what makes room;
 *   - `from`: for the single-field forms it is dereferenced as `r-><from>`, so it
 *     must name a real field. For the record_* forms the function receives the
 *     record itself, so `from` is prose naming what the derivation reads (it is
 *     what `describe` / `capabilities --json` show as the property's source);
 *   - `cap`: a str derivation must declare its output capacity and an int
 *     one must not. A capacity is meaningless for a `long`, and a str derivation
 *     that inherits somebody else's number is how the two sides end up truncating
 *     at different widths -- so "forgot to state the bound" is a generator abort,
 *     not a default. */
static void check_derived(const CcRecSchema *s, const CcRecDerived *d) {
    int form = derived_form(d);
    const char *want = derived_returns_int(form) ? "int" : "str";
    if (strcmp(d->expose, want) != 0)
        die("derivation's expose type does not match its impl_form", d->name);
    if (derived_returns_int(form)) {
        if (d->cap != 0) die("an int derivation declares an output cap (capacity is for strings)", d->name);
    } else {
        if (d->cap <= 1) die("a str derivation must declare its output cap (bytes, incl. NUL)", d->name);
    }
    for (int i = 0; i < s->nfields; i++)
        if (s->fields[i].expose && strcmp(s->fields[i].name, d->name) == 0)
            die("a derivation and an exposed field claim the same property name", d->name);
    if (derived_takes_record(form)) return;
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        if (strcmp(f->name, d->from) != 0) continue;
        /* For a code the source must be one integer, and -- alone among the
         * forms -- the declared cap is CHECKED rather than argued, because a
         * closed set has an actual longest member and the unnamed rendering has
         * an actual widest number. "The bound I stated" becomes "the bound". */
        if (form == DERIV_CODE_NAME) {
            const CcValueMap *m = find_valmap(d->impl, d->name);
            int dec = 0, need = 0, n;
            if (f->count > 0)
                die("a code_to_name derivation reads an array field (a code is one integer)", d->from);
            dec = scalar_decimal_width(f->ctype, d->from);
            need = unknown_width(m, dec) + 1;
            for (int k = 0; k < m->nvalues; k++) {
                n = (int)strlen(m->values[k].name) + 1;
                if (n > need) need = n;
            }
            if (d->cap < need)
                die("a code_to_name derivation declares a cap smaller than its own closed set "
                    "needs (widest name, or the unnamed rendering of the widest value of the "
                    "source field, + NUL)", d->name);
        }
        return;
    }
    die("derivation reads a field this record does not declare", d->from);
}

/* --- metrics ---------------------------------------------------------------
 *
 * A metric's labels are its cost, and a label chosen from a field whose value
 * set is wide produces one time series per distinct value, forever, at exit 0.
 * Everything below exists so that the bound on that number is COMPUTED here,
 * from declarations, before any data exists -- see record_schema.h for why
 * measuring it instead cannot work.
 *
 * The runtime's series capacity. The generator refuses a file whose declared
 * bounds sum above it, so the accumulator array cannot overflow at run time:
 * a declaration that could not be exported is not expressible. (Contrast
 * otlp_httpspan.c's hand-written aggregation, which caps at 64 and discovers the
 * 65th series by dropping it with a warning -- the failure this replaces.) */
#define SPNL_RECMETRIC_MAX_SERIES 256

static const CcBoundsSet *const *g_bounds;
static int g_nbounds;

static const CcBoundsSet *find_bounds(const char *id, const char *what) {
    for (int i = 0; i < g_nbounds; i++)
        if (strcmp(g_bounds[i]->id, id) == 0) return g_bounds[i];
    die("a histogram metric names an undeclared bounds set", what);
    return NULL;
}

/* Unit conversion, as a closed list. A record carries nanoseconds and the
 * OBI-aligned boundaries are seconds, so exactly one conversion is real; the
 * identity is the other. An unlisted pair aborts, because the alternative is a
 * nanosecond value silently bucketed against second boundaries -- every request
 * landing in the +inf bucket, and a histogram that is wrong rather than absent. */
enum { MSCALE_IDENTITY, MSCALE_NS_TO_S };

static int metric_scale(const char *from_unit, const char *to_unit, const char *what) {
    if (strcmp(from_unit, to_unit) == 0)                              return MSCALE_IDENTITY;
    if (strcmp(from_unit, "ns") == 0 && strcmp(to_unit, "s") == 0)    return MSCALE_NS_TO_S;
    die("a histogram metric declares a unit conversion the generator does not know "
        "(known: identity, ns -> s)", what);
    return -1;
}

/* A metric may only read a PUBLISHED property -- an exposed field or a declared
 * derivation. That is the D4 rule made structural: the number in the histogram
 * and the number on the span are the same function's output, so a dashboard and
 * a trace waterfall cannot disagree, for the same reason ev.srtt_us and
 * net.peer.srtt_us cannot. Returns the property's expose type. */
static const char *find_property(const CcRecSchema *s, const char *name,
                                 const CcRecDerived **out_derived) {
    if (out_derived) *out_derived = NULL;
    for (int i = 0; i < s->nfields; i++)
        if (s->fields[i].expose && strcmp(s->fields[i].name, name) == 0)
            return s->fields[i].expose;
    for (int i = 0; i < s->nderived; i++)
        if (strcmp(s->derived[i].name, name) == 0) {
            if (out_derived) *out_derived = &s->derived[i];
            return s->derived[i].expose;
        }
    return NULL;
}

/* The bound on one label, and the only place a label is allowed to exist.
 *
 *   route (1)  values + fallback   -> nvalues + 1, ENFORCED when the metric is
 *                                     emitted (a value outside the set is emitted
 *                                     as the fallback), so this is a fact about
 *                                     the metric, not a claim about the data
 *   route (2)  a code_to_name derivation over a map whose `unknown` is a LITERAL
 *                                  -> map nvalues + 1, computed from the map
 *
 * Everything else is refused, with the property named and the span pointed at:
 * `ev.path` is not lost when it is refused as a label, it is simply still on the
 * span, which is the shape that can carry an unbounded value. */
static int label_bound(const CcRecSchema *s, const CcMetricLabel *l, const char *mwhat) {
    const CcRecDerived *d = NULL;
    const char *expose;
    char what[256];

    snprintf(what, sizeof what, "%s.%s (label %s)", s->id, mwhat, l->key);
    if (!l->key || !*l->key)   die("a metric label has no key", what);
    if (!l->from || !*l->from) die("a metric label names no source property", what);
    if (!l->stability || (strcmp(l->stability, "semconv") != 0 && strcmp(l->stability, "spinel") != 0))
        die("a metric label's stability must be \"semconv\" or \"spinel\"", what);

    expose = find_property(s, l->from, &d);
    if (!expose)
        die("a metric label reads a property this channel does not publish "
            "(a label may only read an exposed field or a declared derivation, so that the label "
            "and the span attribute are the same function's output)", what);

    if (l->values) {
        if (l->nvalues <= 0)
            die("a metric label declares an empty permitted set", what);
        if (!l->fallback || !*l->fallback)
            die("a metric label declares a permitted set but no fallback (a value outside the set "
                "has to become something, and that something is what bounds the label)", what);
        for (int i = 0; i < l->nvalues; i++) {
            if (!l->values[i] || !*l->values[i])
                die("a metric label's permitted set contains an empty value", what);
            for (int k = 0; k < i; k++)
                if (strcmp(l->values[i], l->values[k]) == 0)
                    die("a metric label's permitted set repeats a value", l->values[i]);
            if (strcmp(l->values[i], l->fallback) == 0)
                die("a metric label's fallback is also one of its permitted values (the bound "
                    "would then be one larger than the set can actually produce)", what);
        }
        return l->nvalues + 1;
    }

    /* route (2): no set written here, so the property must already be closed. */
    if (l->fallback)
        die("a metric label declares a fallback without a permitted set", what);
    if (!d || derived_form(d) != DERIV_CODE_NAME)
        die("a metric label has no permitted set and does not read a code_to_name derivation, so "
            "nothing bounds how many time series it can create. Either declare the permitted set "
            "(values + fallback), or label on a property whose value map is closed. The unbounded "
            "value is still available on the span, which is the shape that can carry it", what);
    {
        const CcValueMap *m = find_valmap(d->impl, d->name);
        /* The discriminator, and the reason this is a property of the declaration
         * rather than of the field: `conn_direction` renders an unnamed code as
         * the literal "other" (closed: 2 names + 1), while `tcp_state` renders it
         * as "unnamed(%ld)" -- which is the right answer for a span attribute
         * (the number survives) and means the set is NOT closed, because
         * every unnamed code becomes its own string. Same field, two readings,
         * one safe label. */
        for (const char *p = m->unknown; *p; p++)
            if (p[0] == '%' && p[1] == 'l' && p[2] == 'd')
                die("a metric label reads a value map whose `unknown` rendering keeps the number "
                    "(\"%ld\"), so its value set is not closed: every code the map does not name "
                    "becomes its own time series. That rendering is correct for a span attribute "
                    "and disqualifying for a label -- declare a permitted set instead", what);
        return m->nvalues + 1;
    }
}

/* Series a metric can produce = the product of its label bounds (no labels = the
 * one unlabelled series). Overflow-safe because the total is checked against the
 * runtime capacity, which is small. */
static int metric_series_bound(const CcRecSchema *s, const CcRecMetric *m) {
    long b = 1;
    for (int i = 0; i < m->nlabels; i++) {
        b *= label_bound(s, &m->labels[i], m->id);
        if (b > 1000000L) b = 1000000L;   /* saturate; the cap check below rejects it anyway */
    }
    return (int)b;
}

static int metric_is_hist(const CcRecMetric *m, const CcRecSchema *s) {
    char what[128];
    snprintf(what, sizeof what, "%s.%s", s->id, m->id ? m->id : "(anonymous)");
    if (!m->id || !*m->id)     die("a metric has no id", s->id);
    if (!m->name || !*m->name) die("a metric has no name", what);
    if (!m->unit || !*m->unit) die("a metric declares no unit", what);
    if (!m->kind) die("a metric has no kind", what);
    if (strcmp(m->kind, "counter") == 0)   return 0;
    if (strcmp(m->kind, "histogram") == 0) return 1;
    /* Two kinds, because two encoders exist (a monotonic Sum and an
     * explicit-bounds Histogram, in protobuf and in JSON). A third word would be
     * declarable and not exportable, which is the failure this file forbids. */
    die("unknown metric kind (known: counter, histogram)", m->kind);
    return -1;
}

static void check_metric(const CcRecSchema *s, const CcRecMetric *m) {
    char what[128];
    int hist = metric_is_hist(m, s);
    snprintf(what, sizeof what, "%s.%s", s->id, m->id);

    if (!s->typed_consumer)
        die("a channel declares metrics without publishing its typed consumer (a metric reads "
            "published properties, so there have to be some)", s->id);
    if (hist) {
        const CcRecDerived *d = NULL;
        const char *expose;
        if (!m->value_from || !m->value_unit || !m->bounds)
            die("a histogram metric must declare value_from, value_unit and bounds", what);
        expose = find_property(s, m->value_from, &d);
        if (!expose)
            die("a histogram metric's value_from is not a published property of this channel", what);
        if (strcmp(expose, "int") != 0)
            die("a histogram metric's value_from is not numeric", what);
        {
            const CcBoundsSet *b = find_bounds(m->bounds, what);
            if (strcmp(b->unit, m->unit) != 0)
                die("a histogram metric's unit differs from the unit its bounds set is expressed in",
                    what);
            (void)metric_scale(m->value_unit, m->unit, what);
        }
    } else {
        if (m->value_from || m->value_unit || m->bounds)
            die("a counter metric declares a value (a counter counts records; declare a histogram "
                "if the value matters)", what);
    }
    for (int i = 0; i < m->nlabels; i++)
        for (int k = 0; k < i; k++)
            if (strcmp(m->labels[i].key, m->labels[k].key) == 0)
                die("a metric declares the same label key twice", m->labels[i].key);
    (void)metric_series_bound(s, m);   /* validates every label */
}

/* Emit the C expression that renders one property into `dst` (a char buffer).
 * The rendering is where a metric's label and a span's attribute are made to be
 * the same function's output: a derivation is CALLED, never re-implemented. */
static void emit_label_render(const CcRecSchema *s, const char *from, int idx) {
    const CcRecDerived *d = NULL;
    const char *expose = find_property(s, from, &d);
    char DID[64], DPROP[96];

    if (!d) {   /* a plain exposed field */
        if (strcmp(expose, "int") == 0)
            printf("        snprintf(lb%d, sizeof lb%d, \"%%ld\", (long)r->%s);\n", idx, idx, from);
        else
            printf("        snprintf(lb%d, sizeof lb%d, \"%%s\", r->%s);\n", idx, idx, from);
        return;
    }
    upcase(s->id, DID, sizeof DID);
    upcase(d->name, DPROP, sizeof DPROP);
    switch (derived_form(d)) {
        case DERIV_BYTES_STR:
            printf("        %s(r->%s, lb%d, (int)sizeof lb%d);\n", d->impl, d->from, idx, idx);
            break;
        case DERIV_RECORD_STR:
            printf("        %s(r, lb%d, (int)sizeof lb%d);\n", d->impl, idx, idx);
            break;
        case DERIV_BYTES_INT:
            printf("        snprintf(lb%d, sizeof lb%d, \"%%ld\", %s(r->%s));\n",
                   idx, idx, d->impl, d->from);
            break;
        case DERIV_RECORD_INT:
            printf("        snprintf(lb%d, sizeof lb%d, \"%%ld\", %s(r));\n", idx, idx, d->impl);
            break;
        case DERIV_CODE_NAME:
            printf("        spnl_valmap_%s((long)r->%s, lb%d, (int)sizeof lb%d);\n",
                   d->impl, d->from, idx, idx);
            break;
        default: break;
    }
}

/* Buffer width for one rendered label value: the derivation's declared cap where
 * there is one, otherwise wide enough for the widest decimal / the field. */
static int label_buf_cap(const CcRecSchema *s, const CcMetricLabel *l) {
    const CcRecDerived *d = NULL;
    const char *expose = find_property(s, l->from, &d);
    int cap = 24;
    if (d) {
        if (d->cap > 0) cap = d->cap;
    } else if (strcmp(expose, "str") == 0) {
        for (int i = 0; i < s->nfields; i++)
            if (strcmp(s->fields[i].name, l->from) == 0 && s->fields[i].count > 0)
                cap = s->fields[i].count + 1;
    }
    /* the fallback has to fit too, or a collapsed value would be truncated */
    if (l->fallback && (int)strlen(l->fallback) + 1 > cap) cap = (int)strlen(l->fallback) + 1;
    return cap;
}

static void emit_metric_observe(const CcRecSchema *s, int base_index) {
    printf("\n/* --- metric intake for channel \"%s\" ---\n", s->id);
    printf(" * Called once per drained record, on the one path every record of this channel\n");
    printf(" * takes (the ringbuf callback), so the concise push and the typed consumer feed\n");
    printf(" * the same aggregate. Every label value below is produced by CALLING the\n");
    printf(" * declared derivation the span attribute calls, so the metric cannot describe a\n");
    printf(" * different request from the span built out of the same bytes; projecting a\n");
    printf(" * value onto its declared set is the runtime's job, in one place. */\n");
    printf("static inline void spnl_recmetric_observe_%s(const spnl_rec_%s_t *r) {\n", s->id, s->id);
    printf("    if (!r) return;\n");
    for (int mi = 0; mi < s->nmetrics; mi++) {
        const CcRecMetric *m = &s->metrics[mi];
        int hist = metric_is_hist(m, s);
        printf("    {   /* %s */\n", m->name);
        for (int li = 0; li < m->nlabels; li++)
            printf("        char lb%d[%d];\n", li, label_buf_cap(s, &m->labels[li]));
        if (m->nlabels) {
            printf("        const char *lv[%d];\n", m->nlabels);
            for (int li = 0; li < m->nlabels; li++) {
                emit_label_render(s, m->labels[li].from, li);
                printf("        lv[%d] = lb%d;\n", li, li);
            }
        }
        if (hist) {
            const CcRecDerived *d = NULL;
            (void)find_property(s, m->value_from, &d);
            printf("        double v = (double)(");
            if (d) {
                if (derived_form(d) == DERIV_RECORD_INT) printf("%s(r)", d->impl);
                else                                     printf("%s(r->%s)", d->impl, d->from);
            } else {
                printf("r->%s", m->value_from);
            }
            printf(")%s;\n", metric_scale(m->value_unit, m->unit, m->id) == MSCALE_NS_TO_S
                             ? " / 1e9" : "");
            printf("        spnl_recmetric_observe(%d, %s, %d, 1, v);\n",
                   base_index + mi, m->nlabels ? "lv" : "((const char *const *)0)", m->nlabels);
        } else {
            printf("        spnl_recmetric_observe(%d, %s, %d, 0, 0.0);\n",
                   base_index + mi, m->nlabels ? "lv" : "((const char *const *)0)", m->nlabels);
        }
        printf("    }\n");
    }
    printf("}\n");
}

/* Metrics are numbered once, across all channels, in publication order: the
 * runtime walks one table and the generated intake passes an index into it. */
static int metric_base_index(const CcRecSchema *s) {
    int base = 0;
    for (int i = 0; i < g_nchannels; i++) {
        if (g_channels[i] == s) return base;
        base += g_channels[i]->nmetrics;
    }
    die("channel not in the registry", s->id);
    return -1;
}

static int metric_total(void) {
    int n = 0;
    for (int i = 0; i < g_nchannels; i++) n += g_channels[i]->nmetrics;
    return n;
}

/* The declared table, and the numbers that make it safe. Emitted under its own
 * impl guard so exactly one TU (src/runtime/otlp/otlp_recmetric.c) instantiates
 * it -- the same arrangement the typed-consumer accessors use. */
/* Histogram boundaries, as macros, in a block that depends on NOTHING -- no
 * types, no includes. The HTTP server span's http.server.request.duration lives
 * in otlp_httpspan.c, which is deliberately libbpf-free (the native HTTP server
 * links it without a BPF object), so it cannot include the rest of this
 * header. Emitting the numbers as an initializer macro is what lets that file
 * and the record metrics share ONE declaration instead of two arrays that agree
 * until somebody edits one -- the same reason a value map is generated rather
 * than written twice. A TU that wants only this block defines
 * SPNL_RECORD_MIRROR_MACROS_ONLY before including. */
/* Shortest decimal that reads back as exactly this double.
 *
 * The default %g is 6 significant digits, which is not enough to round-trip a
 * value -- and a bucket boundary *is* a value. The log2 ruler exposed it:
 * 1048575 (the exclusive upper edge of slot 20) printed as 1.04858e+06 =
 * 1048580, which moves five integers into the neighbouring bucket and quietly
 * falsifies the "a bucket is a whole number of slots" property that set is
 * built on. %.17g always round-trips but spells 0.005 as 0.0050000000000000001,
 * so try increasing precision and stop at the first spelling that reads back
 * identical -- exact, and still readable in the affordance JSON. */
static const char *dbl_exact(double v) {
    static char buf[64];
    for (int prec = 6; prec <= 17; prec++) {
        snprintf(buf, sizeof buf, "%.*g", prec, v);
        if (strtod(buf, NULL) == v) return buf;
    }
    snprintf(buf, sizeof buf, "%.17g", v);
    return buf;
}

static void emit_bounds_macros(void) {
    printf("#ifndef SPNL_RECORD_MIRROR_BOUNDS_H\n#define SPNL_RECORD_MIRROR_BOUNDS_H\n");
    for (int i = 0; i < g_nbounds; i++) {
        const CcBoundsSet *b = g_bounds[i];
        char BID[96];
        upcase(b->id, BID, sizeof BID);
        printf("\n/* bounds set \"%s\", in %s -- %s */\n", b->id, b->unit, b->authority);
        printf("#define SPNL_BOUNDS_%s_N %d\n", BID, b->nvalues);
        printf("#define SPNL_BOUNDS_%s_INIT {", BID);
        for (int k = 0; k < b->nvalues; k++) printf("%s%s", k ? ", " : " ", dbl_exact(b->values[k]));
        printf(" }\n");
    }
    printf("#endif /* SPNL_RECORD_MIRROR_BOUNDS_H */\n");
}

static void emit_metric_tables(void) {
    int total = metric_total(), grand = 0, idx = 0;

    printf("\n/* ========================== metrics ==========================\n");
    printf(" * Declared in record_schema.h; the bounds below are COMPUTED from those\n");
    printf(" * declarations, so \"how many time series can this binary ever produce\" is a\n");
    printf(" * compile-time constant rather than something a backend discovers.\n");
    printf(" *\n");
    printf(" * A label's bound comes from one of exactly two places: a permitted set declared\n");
    printf(" * on the label (and enforced when the metric is emitted -- anything outside it is\n");
    printf(" * emitted as the fallback), or a code_to_name value map whose unnamed rendering is\n");
    printf(" * a literal, i.e. already closed. Nothing else compiles. */\n\n");

    printf("typedef struct {\n");
    printf("    const char        *key;        /* attribute key, verbatim */\n");
    printf("    const char *const *values;     /* permitted set, or NULL when the property is closed */\n");
    printf("    int                nvalues;\n");
    printf("    const char        *fallback;   /* what a value outside the set is emitted as */\n");
    printf("    int                bound;      /* distinct values this label can ever take */\n");
    printf("} spnl_metric_label_t;\n\n");
    printf("typedef struct {\n");
    printf("    const char                *channel;\n");
    printf("    const char                *id;\n");
    printf("    const char                *name;       /* OTel metric name */\n");
    printf("    const char                *unit;\n");
    printf("    int                        is_hist;    /* 0 = monotonic Sum, 1 = explicit-bounds Histogram */\n");
    printf("    const double              *bounds;\n");
    printf("    int                        nbounds;\n");
    printf("    const spnl_metric_label_t *labels;\n");
    printf("    int                        nlabels;\n");
    printf("    int                        series_bound;\n");
    printf("} spnl_metric_desc_t;\n\n");

    for (int i = 0; i < g_nchannels; i++)
        for (int k = 0; k < g_channels[i]->nmetrics; k++)
            grand += metric_series_bound(g_channels[i], &g_channels[i]->metrics[k]);

    {   /* Widths the runtime sizes its storage by. Derived here so the
         * accumulator cannot be too small for a declaration that compiled --
         * the same reason the series bound is computed rather than assumed. */
        int maxlab = 0, maxbnd = 0, maxval = 1;
        for (int i = 0; i < g_nchannels; i++)
            for (int k = 0; k < g_channels[i]->nmetrics; k++) {
                const CcRecMetric *m = &g_channels[i]->metrics[k];
                if (m->nlabels > maxlab) maxlab = m->nlabels;
                for (int li = 0; li < m->nlabels; li++) {
                    const CcMetricLabel *l = &m->labels[li];
                    int n;
                    if (l->values) {
                        for (int vi = 0; vi < l->nvalues; vi++) {
                            n = (int)strlen(l->values[vi]) + 1;
                            if (n > maxval) maxval = n;
                        }
                        n = (int)strlen(l->fallback) + 1;
                        if (n > maxval) maxval = n;
                    } else {
                        const CcRecDerived *d = NULL;
                        (void)find_property(g_channels[i], l->from, &d);
                        if (d && d->cap > maxval) maxval = d->cap;
                    }
                }
            }
        for (int i = 0; i < g_nbounds; i++)
            if (g_bounds[i]->nvalues > maxbnd) maxbnd = g_bounds[i]->nvalues;
        printf("#define SPNL_RECMETRIC_MAX_LABELS         %d\n", maxlab ? maxlab : 1);
        printf("#define SPNL_RECMETRIC_MAX_BOUNDS         %d\n", maxbnd ? maxbnd : 1);
        printf("#define SPNL_RECMETRIC_LABEL_VAL_MAX      %d\n", maxval);
    }
    printf("#define SPNL_RECMETRIC_COUNT              %d\n", total);
    printf("#define SPNL_RECMETRIC_MAX_SERIES         %d\n", SPNL_RECMETRIC_MAX_SERIES);
    printf("/* The sum of every declared metric's series bound. The runtime sizes its\n");
    printf(" * accumulator by SPNL_RECMETRIC_MAX_SERIES and this is proof it fits. */\n");
    printf("#define SPNL_RECMETRIC_TOTAL_SERIES_BOUND %d\n", grand);
    for (int i = 0; i < g_nchannels; i++) {
        char CH[64], MI[64];
        upcase(g_channels[i]->id, CH, sizeof CH);
        for (int k = 0; k < g_channels[i]->nmetrics; k++) {
            upcase(g_channels[i]->metrics[k].id, MI, sizeof MI);
            printf("#define SPNL_RECMETRIC_%s_%s %d\n", CH, MI, metric_base_index(g_channels[i]) + k);
        }
    }

    printf("\n#ifdef SPNL_RECMETRIC_IMPL\n");
    for (int i = 0; i < g_nbounds; i++) {
        char BID[96];
        upcase(g_bounds[i]->id, BID, sizeof BID);
        printf("static const double spnl_bounds_%s[SPNL_BOUNDS_%s_N] = SPNL_BOUNDS_%s_INIT;\n",
               g_bounds[i]->id, BID, BID);
    }
    for (int i = 0; i < g_nchannels; i++) {
        const CcRecSchema *s = g_channels[i];
        for (int k = 0; k < s->nmetrics; k++) {
            const CcRecMetric *m = &s->metrics[k];
            for (int li = 0; li < m->nlabels; li++) {
                const CcMetricLabel *l = &m->labels[li];
                if (!l->values) continue;
                printf("\nstatic const char *const spnl_mlv_%s_%s_%d[%d] = {\n   ",
                       s->id, m->id, li, l->nvalues);
                for (int vi = 0; vi < l->nvalues; vi++) {
                    printf(" \"%s\",", l->values[vi]);
                    if (vi % 8 == 7) printf("\n   ");
                }
                printf("\n};\n");
            }
            if (m->nlabels) {
                printf("static const spnl_metric_label_t spnl_ml_%s_%s[%d] = {\n", s->id, m->id, m->nlabels);
                for (int li = 0; li < m->nlabels; li++) {
                    const CcMetricLabel *l = &m->labels[li];
                    printf("    { \"%s\", ", l->key);
                    if (l->values) printf("spnl_mlv_%s_%s_%d, %d, \"%s\", ",
                                          s->id, m->id, li, l->nvalues, l->fallback);
                    else           printf("(const char *const *)0, 0, (const char *)0, ");
                    printf("%d },\n", label_bound(s, l, m->id));
                }
                printf("};\n");
            }
        }
    }
    printf("\nstatic const spnl_metric_desc_t spnl_recmetrics[%d] = {\n", total ? total : 1);
    for (int i = 0; i < g_nchannels; i++) {
        const CcRecSchema *s = g_channels[i];
        for (int k = 0; k < s->nmetrics; k++) {
            const CcRecMetric *m = &s->metrics[k];
            int hist = metric_is_hist(m, s);
            printf("    { \"%s\", \"%s\", \"%s\", \"%s\", %d, ", s->id, m->id, m->name, m->unit, hist);
            if (hist) {
                const CcBoundsSet *b = find_bounds(m->bounds, m->id);
                printf("spnl_bounds_%s, %d, ", b->id, b->nvalues);
            } else {
                printf("(const double *)0, 0, ");
            }
            if (m->nlabels) printf("spnl_ml_%s_%s, %d, ", s->id, m->id, m->nlabels);
            else            printf("(const spnl_metric_label_t *)0, 0, ");
            printf("%d },\n", metric_series_bound(s, m));
            idx++;
        }
    }
    if (!total) printf("    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },\n");
    printf("};\n");
    printf("#endif /* SPNL_RECMETRIC_IMPL */\n");
    (void)idx;
}

/* One accessor: `<ctype> spnl_rec_<id>_<prop>(int i)`, reading record i of the
 * last drain. Out-of-range (or a record that vanished) reads as the zero value
 * rather than crashing the consumer -- Ruby has no way to hold a bad handle. */
static void emit_accessor_head(const CcRecSchema *s, const char *expose,
                               const char *prop, const char *what) {
    const char *ct = expose_ctype(expose, what);
    printf("%s%sspnl_rec_%s_%s(int i) {\n", ct, ct[strlen(ct) - 1] == '*' ? "" : " ", s->id, prop);
    printf("    const spnl_rec_%s_t *r = spnl_rec_%s_at(i);\n", s->id, s->id);
}

static void emit_consumer(const CcRecSchema *s) {
    char ID[64], capname[192];
    upcase(s->id, ID, sizeof ID);

    printf("\n/* --- typed consumer for channel \"%s\" ---\n", s->id);
    printf(" * `on_emit :%s do |ev| ... end` lowers `ev.<prop>` to these accessors, so the\n", s->id);
    printf(" * property set a Ruby consumer sees is generated from the same table as the\n");
    printf(" * record struct. `i` is the record's index in the last drain (the opaque handle\n");
    printf(" * Ruby holds); the byte image itself never crosses the FFI boundary.\n");
    printf(" *\n");
    printf(" * Expanded in exactly one TU: the one that #defines SPNL_REC_CONSUME_IMPL before\n");
    printf(" * including this header (src/runtime/otlp/otlp_agent.c). That TU must define the\n");
    printf(" * two functions declared below -- the drained-record lookup and each declared\n");
    printf(" * derivation -- and a missing one is a link error, not a silent wrong value. */\n");

    /* The declared output capacity of each string derivation, published
     * OUTSIDE the impl guard: the accessor below passes it, and so does the
     * runtime's span builder, which is what keeps `ev.<prop>` and the attribute
     * the same function's output at the same width. Per derivation, so the
     * number is that derivation's bound rather than a shared default. */
    {
        int nstr = 0;
        for (int i = 0; i < s->nderived; i++)
            if (!derived_returns_int(derived_form(&s->derived[i]))) nstr++;
        if (nstr) {
            printf("\n/* Declared output capacity of each string derivation, in bytes\n");
            printf(" * including the NUL, and >= the longest value that derivation can return\n");
            printf(" * (the schema table says why). Handed to the impl by the accessor below AND\n");
            printf(" * by the runtime's span builder, so `ev.<prop>` and the attribute it feeds\n");
            printf(" * are the same function's output at the same width. */\n");
        }
        for (int i = 0; i < s->nderived; i++) {
            const CcRecDerived *d = &s->derived[i];
            if (derived_returns_int(derived_form(d))) continue;
            derived_cap_macro(ID, d, capname, sizeof capname);
            printf("#define %-*s %d\n", 40, capname, d->cap);
        }
        if (nstr) printf("\n");
    }

    printf("#ifdef SPNL_REC_CONSUME_IMPL\n");
    printf("const spnl_rec_%s_t *spnl_rec_%s_at(int i);\n", s->id, s->id);
    for (int i = 0; i < s->nderived; i++) {
        const CcRecDerived *d = &s->derived[i];
        check_derived(s, d);   /* form / expose / `from` agree -- see derived_form() */
        switch (derived_form(d)) {
            case DERIV_CODE_NAME:   /* generated above; the runtime defines nothing */
                printf("/* %s <- %s via the generated value map spnl_valmap_%s() */\n",
                       d->name, d->from, d->impl);
                break;
            case DERIV_BYTES_STR:
                printf("void %s(const unsigned char *src, char *out, int cap);   /* %s <- %s */\n",
                       d->impl, d->name, d->from);
                break;
            case DERIV_BYTES_INT:
                printf("long %s(const unsigned char *src);   /* %s <- %s */\n", d->impl, d->name, d->from);
                break;
            case DERIV_RECORD_STR:   /* the derivation reads the whole record */
                printf("void %s(const spnl_rec_%s_t *r, char *out, int cap);   /* %s <- %s */\n",
                       d->impl, s->id, d->name, d->from);
                break;
            default:   /* DERIV_RECORD_INT */
                printf("long %s(const spnl_rec_%s_t *r);   /* %s <- %s */\n",
                       d->impl, s->id, d->name, d->from);
                break;
        }
    }
    printf("\n");

    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        if (!f->expose) continue;
        emit_accessor_head(s, f->expose, f->name, f->name);
        if (strcmp(f->expose, "str") == 0) {
            if (f->count <= 0 || strcmp(f->ctype, "char") != 0)
                die("expose \"str\" needs a char[] field", f->name);
            printf("    return r ? r->%s : \"\";   /* %s */\n", f->name, f->note ? f->note : "");
        } else {
            printf("    return r ? (long)r->%s : 0;   /* %s */\n", f->name, f->note ? f->note : "");
        }
        printf("}\n");
    }
    for (int i = 0; i < s->nderived; i++) {
        const CcRecDerived *d = &s->derived[i];
        int form = derived_form(d);
        char arg[160];
        /* axis 1: what the derivation is handed (one field's bytes, or the record) */
        if (derived_takes_record(form)) snprintf(arg, sizeof arg, "r");
        else                            snprintf(arg, sizeof arg, "r->%s", d->from);
        emit_accessor_head(s, d->expose, d->name, d->name);
        if (derived_returns_int(form)) {   /* axis 2: what shape comes back */
            printf("    return r ? (long)%s(%s) : 0;   /* derived: %s */\n", d->impl, arg, d->name);
            printf("}\n");
        } else {
            derived_cap_macro(ID, d, capname, sizeof capname);
            printf("    static char buf[%s];\n", capname);
            printf("    if (!r) return \"\";\n");
            if (form == DERIV_CODE_NAME)   /* the table, not a runtime function */
                printf("    spnl_valmap_%s((long)%s, buf, (int)sizeof buf);   /* derived: %s */\n",
                       d->impl, arg, d->name);
            else
                printf("    %s(%s, buf, (int)sizeof buf);   /* derived: %s */\n", d->impl, arg, d->name);
            printf("    return buf;\n}\n");
        }
    }
    if (s->nmetrics) emit_metric_observe(s, metric_base_index(s));
    printf("#endif /* SPNL_REC_CONSUME_IMPL */\n");
}

static void emit_channel(const CcRecSchema *s) {
    char ID[64], UP[128];
    int offs[128], total = 0;

    if (s->nfields > (int)(sizeof offs / sizeof offs[0])) die("too many fields", s->id);
    upcase(s->id, ID, sizeof ID);
    layout(s, offs, &total);
    int req = required_bytes(s, offs, total);

    /* widest generated macro name, for column alignment in the generated text */
    int w = (int)strlen("SPNL_REC_") + (int)strlen(ID) + (int)strlen("_SIZE");
    for (int i = 0; i < s->nfields; i++) {
        int l = (int)strlen("SPNL_REC_") + (int)strlen(ID) + (int)strlen("_OFF_")
              + (int)strlen(s->fields[i].name);
        if (l > w) w = l;
    }

    printf("/* ===================== channel \"%s\" =====================\n", s->id);
    printf(" * record struct: <unit>_%s   ringbuf map: <unit>_%s (%s)\n",
           s->struct_suffix, s->map_suffix, s->ringbuf_size);
    printf(" * %d fields, %d bytes on the wire. */\n\n", s->nfields, total);

    printf("enum {\n");
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        char FUP[64], type[96];
        int bytes = f->size * (f->count > 0 ? f->count : 1);
        upcase(f->name, FUP, sizeof FUP);
        snprintf(UP, sizeof UP, "SPNL_REC_%s_OFF_%s", ID, FUP);
        if (f->count > 0) snprintf(type, sizeof type, "%s[%d]", f->ctype, f->count);
        else              snprintf(type, sizeof type, "%s", f->ctype);
        printf("    %-*s = %3d,   /* %s, %d B */\n", w, UP, offs[i], type, bytes);
    }
    snprintf(UP, sizeof UP, "SPNL_REC_%s_SIZE", ID);
    printf("    %-*s = %3d,   /* whole record, incl. trailing pad */\n", w, UP, total);
    snprintf(UP, sizeof UP, "SPNL_REC_%s_MIN", ID);
    if (req < total)
        printf("    %-*s = %3d,   /* accepted prefix: through `%s` (later fields read as zero) */\n",
               w, UP, req, s->required_through);
    else
        printf("    %-*s = %3d,   /* the whole record is required */\n", w, UP, req);
    printf("};\n\n");

    printf("typedef struct spnl_rec_%s {\n", s->id);
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        char decl[160];
        if (f->count > 0) snprintf(decl, sizeof decl, "%s %s[%d];", host_ctype(f->ctype), f->name, f->count);
        else              snprintf(decl, sizeof decl, "%s %s;", host_ctype(f->ctype), f->name);
        printf("    %-40s /* @%-3d  %s */\n", decl, offs[i], f->note ? f->note : "");
    }
    printf("} spnl_rec_%s_t;\n\n", s->id);

    printf("/* The mirror is a byte image of the wire record: these assertions fail the\n");
    printf(" * build if the host layout ever drifts from the schema's computed offsets. */\n");
    for (int i = 0; i < s->nfields; i++) {
        char FUP[64];
        upcase(s->fields[i].name, FUP, sizeof FUP);
        printf("_Static_assert(offsetof(spnl_rec_%s_t, %s) == SPNL_REC_%s_OFF_%s,\n"
               "               \"spnl_rec_%s_t.%s moved away from the schema offset\");\n",
               s->id, s->fields[i].name, ID, FUP, s->id, s->fields[i].name);
    }
    printf("_Static_assert(sizeof(spnl_rec_%s_t) == SPNL_REC_%s_SIZE,\n"
           "               \"spnl_rec_%s_t size differs from the record contract\");\n\n",
           s->id, ID, s->id);

    printf("/* Decode one ringbuf record into the mirror. Returns 0, or -1 when the\n");
    printf(" * record is shorter than the contract (producer older than this header). */\n");
    printf("static inline int spnl_rec_%s_unpack(const void *data, size_t size, spnl_rec_%s_t *out) {\n",
           s->id, s->id);
    printf("    const unsigned char *p = (const unsigned char *)data;\n");
    printf("    if (!data || !out || size < (size_t)SPNL_REC_%s_MIN) return -1;\n", ID);
    if (req < total)
        printf("    memset(out, 0, sizeof *out);   /* appended fields read as zero on an older producer */\n");
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        char FUP[64];
        int end = offs[i] + f->size * (f->count > 0 ? f->count : 1);
        int optional = end > req;
        upcase(f->name, FUP, sizeof FUP);
        if (optional)
            printf("    if (size >= (size_t)%d) ", end);
        else
            printf("    ");
        if (f->count > 0)
            printf("memcpy(out->%s, p + SPNL_REC_%s_OFF_%s, sizeof out->%s);\n",
                   f->name, ID, FUP, f->name);
        else
            printf("memcpy(&out->%s, p + SPNL_REC_%s_OFF_%s, sizeof out->%s);\n",
                   f->name, ID, FUP, f->name);
        /* `char[]` is this codebase's C-string convention (comm, paths); raw byte
         * payloads are spelled `unsigned char[]` and stay untouched. */
        if (f->count > 0 && strcmp(f->ctype, "char") == 0)
            printf("    out->%s[sizeof out->%s - 1] = '\\0';   /* char[] = C string */\n",
                   f->name, f->name);
    }
    printf("    return 0;\n}\n");

    if (s->egress) emit_egress(s, ID);
    /* The typed consumer is opt-in per channel: a channel that has not published
     * one gets no accessors, and `on_emit :<id>` keeps its plain, untyped
     * named-event meaning in Ruby. */
    if (s->typed_consumer) emit_consumer(s);
    else if (s->nderived) die("derived properties declared without typed_consumer", s->id);

    /* `kfilter` names the in-kernel filter key that selects on the same
     * value. It is only meaningful on a field a consumer can actually read --
     * declaring it on an unexposed field would be a claim nobody can act on --
     * and only on a channel whose consumer exists at all. */
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        if (!f->kfilter) continue;
        if (!s->typed_consumer)
            die("kfilter declared on a channel with no typed consumer", s->id);
        if (!f->expose)
            die("kfilter declared on a field that is not exposed to Ruby", f->name);
    }
}

/* ---------------- JSON view ----------------
 *
 * Same table, rendered for the Ruby affordance surface. The point is that the
 * offsets/sizes below come from layout() -- the one implementation -- so
 * `capabilities --json` reports the bytes the kernel actually writes rather than
 * a Ruby re-derivation of the C alignment rules. */

static void json_str(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\n': fputs("\\n", stdout);  break;
            case '\t': fputs("\\t", stdout);  break;
            default:
                if (*p < 0x20) printf("\\u%04x", *p);
                else putchar((char)*p);
        }
    }
    putchar('"');
}

static void json_kv(const char *k, const char *v, const char *tail) {
    json_str(k); fputs(": ", stdout); json_str(v); fputs(tail, stdout);
}

static void json_strlist(const char *const *items, int n) {
    putchar('[');
    for (int i = 0; i < n; i++) { if (i) fputs(", ", stdout); json_str(items[i]); }
    putchar(']');
}

/* The metrics a channel's records aggregate into, with the numbers that
 * make each one safe. `bound` per label and `series_bound` per metric are what
 * the affordance surface prints -- so "how many time series can this cost" is
 * answerable by reading `describe`, not by watching a bill. */
static void json_metrics(const CcRecSchema *s) {
    if (!s->nmetrics) return;
    fputs(",\n      \"metrics\": [\n", stdout);
    for (int i = 0; i < s->nmetrics; i++) {
        const CcRecMetric *m = &s->metrics[i];
        int hist = metric_is_hist(m, s);
        fputs("        { ", stdout);
        json_kv("id", m->id, ", ");
        json_kv("name", m->name, ", ");
        json_kv("kind", m->kind, ", ");
        json_kv("unit", m->unit, ", ");
        json_kv("value_from", m->value_from ? m->value_from : "", ", ");
        json_kv("value_unit", m->value_unit ? m->value_unit : "", ", ");
        json_kv("bounds", m->bounds ? m->bounds : "", ", ");
        if (hist) {
            const CcBoundsSet *b = find_bounds(m->bounds, m->id);
            fputs("\"boundaries\": [", stdout);
            for (int k = 0; k < b->nvalues; k++) printf("%s%s", k ? ", " : "", dbl_exact(b->values[k]));
            fputs("], ", stdout);
            json_kv("bounds_authority", b->authority, ", ");
        }
        printf("\"series_bound\": %d, \"labels\": [", metric_series_bound(s, m));
        for (int li = 0; li < m->nlabels; li++) {
            const CcMetricLabel *l = &m->labels[li];
            const CcRecDerived *d = NULL;
            fputs(li ? ",\n            " : "\n            ", stdout);
            fputs("{ ", stdout);
            json_kv("key", l->key, ", ");
            json_kv("from", l->from, ", ");
            json_kv("stability", l->stability, ", ");
            printf("\"bound\": %d, ", label_bound(s, l, m->id));
            /* WHERE the bound comes from, because the two routes have different
             * consequences for a reader: a declared set means values outside it
             * are emitted as `fallback` (the span still has the exact one), while
             * a closed value map means the property already cannot produce
             * anything else. Printing "bound: 3" without which of the two it is
             * would leave the coarsening invisible -- and an invisible coarsening
             * is how somebody ends up debugging why a dashboard says _OTHER. */
            (void)find_property(s, l->from, &d);
            if (l->values) {
                json_kv("bound_from", "declared_set", ", ");
                json_kv("fallback", l->fallback, ", ");
                fputs("\"values\": ", stdout);
                json_strlist(l->values, l->nvalues);
                fputs(", ", stdout);
            } else {
                json_kv("bound_from", "value_map", ", ");
                json_kv("value_map", d ? d->impl : "", ", ");
                json_kv("fallback", d ? find_valmap(d->impl, d->name)->unknown : "", ", ");
            }
            json_kv("note", l->note ? l->note : "", " }");
        }
        fputs(m->nlabels ? "\n          ], " : "], ", stdout);
        json_kv("note", m->note ? m->note : "", " }");
        fputs(i + 1 < s->nmetrics ? ",\n" : "\n", stdout);
    }
    fputs("      ]", stdout);
}

static void json_channel(const CcRecSchema *s) {
    int offs[128], total = 0;
    char buf[256];

    if (s->nfields > (int)(sizeof offs / sizeof offs[0])) die("too many fields", s->id);
    layout(s, offs, &total);

    printf("    {\n      ");
    json_kv("id", s->id, ",\n      ");
    snprintf(buf, sizeof buf, "<unit>_%s", s->struct_suffix);
    json_kv("record_struct", buf, ",\n      ");
    snprintf(buf, sizeof buf, "<unit>_%s", s->map_suffix);
    json_kv("ringbuf_map", buf, ",\n      ");
    json_kv("ringbuf_size", s->ringbuf_size, ",\n      ");
    printf("\"record_bytes\": %d,\n      ", total);
    printf("\"record_min_bytes\": %d,\n      ", required_bytes(s, offs, total));
    json_kv("required_through", s->required_through ? s->required_through : "", ",\n      ");
    fputs("\"producers\": ", stdout);
    json_strlist(s->producers, s->nproducers);
    fputs(",\n      \"fields\": [\n", stdout);
    for (int i = 0; i < s->nfields; i++) {
        const CcRecField *f = &s->fields[i];
        int bytes = f->size * (f->count > 0 ? f->count : 1);
        printf("        { ");
        json_kv("name", f->name, ", ");
        json_kv("ctype", f->ctype, ", ");
        printf("\"count\": %d, \"offset\": %d, \"bytes\": %d, ", f->count, offs[i], bytes);
        /* `expose` travels with the field so the append-only gate can
         * fail a change that silently alters what Ruby sees, not just where the
         * bytes sit. "" = not exposed. */
        json_kv("expose", f->expose ? f->expose : "", ", ");
        json_kv("note", f->note ? f->note : "", " }");
        printf("%s\n", i + 1 < s->nfields ? "," : "");
    }
    fputs("      ]", stdout);

    if (s->egress) {
        const CcEgressSpan *e = s->egress;
        char tmpl[256];
        span_name_template(e, tmpl, sizeof tmpl);
        fputs(",\n      \"egress\": {\n        ", stdout);
        json_kv("push_fn", e->push_fn, ",\n        ");
        json_kv("span_name", tmpl, ",\n        ");
        json_kv("span_kind", e->span_kind, ",\n        ");
        json_kv("timing", e->timing, ",\n        ");
        json_kv("note", e->note ? e->note : "", ",\n        ");
        fputs("\"attributes\": [\n", stdout);
        for (int i = 0; i < e->nattrs; i++) {
            const CcEgressAttr *a = &e->attrs[i];
            printf("          { ");
            json_kv("key", a->key, ", ");
            json_kv("source", a->source, ", ");
            json_kv("stability", a->stability, ", ");
            json_kv("condition", a->condition, ", ");
            json_kv("note", a->note ? a->note : "", " }");
            printf("%s\n", i + 1 < e->nattrs ? "," : "");
        }
        fputs("        ],\n        \"enrichers\": ", stdout);
        json_strlist(e->enrichers, e->nenrichers);
        fputs("\n      }", stdout);
    }

    /* The typed consumer's contract. `properties` is the exact set of
     * `ev.<name>` a Ruby consumer may read (the transform rejects anything else
     * with this list), and the *_fn names are the FFI symbols it lowers to.
     * Absent for a channel that has not opted in -- and its absence is
     * what tells Ruby that `on_emit :<id>` still means a plain named event. */
    if (!s->typed_consumer) { fputs("\n    }", stdout); return; }
    fputs(",\n      \"consumer\": {\n        ", stdout);
    snprintf(buf, sizeof buf, "on_emit :%s do |ev| ... end", s->id);
    json_kv("form", buf, ",\n        ");
    snprintf(buf, sizeof buf, "spnl_rec_%s_drain", s->id);
    json_kv("drain_fn", buf, ",\n        ");
    snprintf(buf, sizeof buf, "spnl_rec_%s_to_span", s->id);
    json_kv("to_span_fn", buf, ",\n        ");
    json_kv("send_fn", "spnl_otlp_span_send", ",\n        ");
    json_kv("flush_fn", "spnl_otlp_span_flush", ",\n        ");
    fputs("\"properties\": [\n", stdout);
    {
        int nprop = s->nderived;
        for (int i = 0; i < s->nfields; i++) if (s->fields[i].expose) nprop++;
        int emitted = 0;
        for (int i = 0; i < s->nfields; i++) {
            const CcRecField *f = &s->fields[i];
            if (!f->expose) continue;
            printf("          { ");
            json_kv("name", f->name, ", ");
            json_kv("kind", "field", ", ");
            json_kv("expose", f->expose, ", ");
            json_kv("ffi_ret", expose_ffi(f->expose, f->name), ", ");
            snprintf(buf, sizeof buf, "spnl_rec_%s_%s", s->id, f->name);
            json_kv("ffi", buf, ", ");
            json_kv("source", f->name, ", ");
            /* "" = no in-kernel filter key sees this value, so a consumer
             * filter on it is the only place the narrowing can happen. Non-empty
             * = `filter_by :<key>` selects the same set earlier and cheaper, and
             * the consumer transform refuses the redundant `:eq` spelling. */
            json_kv("kfilter", f->kfilter ? f->kfilter : "", ", ");
            json_kv("note", f->note ? f->note : "", " }");
            printf("%s\n", ++emitted < nprop ? "," : "");
        }
        for (int i = 0; i < s->nderived; i++) {
            const CcRecDerived *d = &s->derived[i];
            printf("          { ");
            json_kv("name", d->name, ", ");
            json_kv("kind", "derived", ", ");
            json_kv("expose", d->expose, ", ");
            json_kv("ffi_ret", expose_ffi(d->expose, d->name), ", ");
            snprintf(buf, sizeof buf, "spnl_rec_%s_%s", s->id, d->name);
            json_kv("ffi", buf, ", ");
            if (derived_form(d) == DERIV_CODE_NAME)
                snprintf(buf, sizeof buf, "%s -> value map `%s`", d->from, d->impl);
            else
                snprintf(buf, sizeof buf, "%s -> %s()", d->from, d->impl);
            json_kv("source", buf, ", ");
            /* Present only on a type-driven property, and it is the join to
             * the `value_maps` table below -- which is what lets `describe` show
             * the closed set an attribute can actually contain, instead of the
             * reader having to run the probe to find out. */
            if (derived_form(d) == DERIV_CODE_NAME) json_kv("value_map", d->impl, ", ");
            /* Always "" for a derivation -- the value does not exist until
             * userspace computes it, which is the reason the consumer filter had
             * to exist at all: a DNS QNAME walk cannot run in the kernel. */
            json_kv("kfilter", "", ", ");
            /* The declared output capacity (bytes incl. NUL) of a str
             * derivation -- both the accessor and the span builder pass it, so it
             * is the width `ev.<name>` and the attribute share. 0 for an int. */
            printf("\"cap\": %d, ", d->cap);
            json_kv("note", d->note ? d->note : "", " }");
            printf("%s\n", ++emitted < nprop ? "," : "");
        }
    }
    fputs("        ]\n      }", stdout);
    json_metrics(s);
    fputs("\n    }", stdout);
}

static void emit_json(void) {
    printf("{\n  ");
    json_kv("schema", "spinel-ebpf.record-schema/1", ",\n  ");
    json_kv("generated_by", "tools/gen_record_mirror.c (make -C src/codegen_c mirror)", ",\n  ");
    json_kv("generated_from", "src/codegen_c/record_schema.h", ",\n  ");
    json_kv("note",
            "Ringbuf record contracts. offset/record_bytes are computed by the "
            "generator's layout rule -- the same one the kernel struct and the userspace "
            "mirror come from -- so nothing downstream re-derives C alignment. `egress` is "
            "what the userspace push_fn makes of one record; layer-2 enrichers (env-gated) "
            "may add more attributes. `consumer` is the typed-consumer contract: the "
            "exact `ev.<name>` set a Ruby `on_emit :<id>` block may read, and the FFI symbols "
            "it lowers to. A derived property carries `cap`: the output capacity, in "
            "bytes incl. NUL, that BOTH the accessor and the span builder hand the derivation, "
            "declared >= the longest value it can return. A field property has none -- it reads "
            "the record's bytes directly, so its width is the field's `bytes`. `value_maps` "
            "is the type-driven half: a property that carries `value_map` draws its "
            "value from exactly that closed set, `authority` says where the names come from "
            "and `btf_*` is how a test goes and checks that claim against the running kernel.", ",\n  ");
    /* The type-driven half. A property whose `value_map` is set draws its
     * value from exactly one of these closed sets, so an author (or an AI) can
     * read the attribute's possible values here instead of guessing them from a
     * number seen once in a dashboard. `authority` says where the names come
     * from and `btf_*` is how the test goes and checks that claim. */
    fputs("\"value_maps\": [\n", stdout);
    for (int i = 0; i < g_nvalmaps; i++) {
        const CcValueMap *m = g_valmaps[i];
        if (i) fputs(",\n", stdout);
        printf("    {\n      ");
        json_kv("id", m->id, ",\n      ");
        json_kv("authority", m->authority, ",\n      ");
        json_kv("unknown", m->unknown, ",\n      ");
        printf("\"arch_invariant\": %s,\n      ", m->arch_invariant ? "true" : "false");
        json_kv("btf_mode", m->btf_mode ? m->btf_mode : "", ",\n      ");
        json_kv("btf_anchor", m->btf_anchor ? m->btf_anchor : "", ",\n      ");
        json_kv("btf_prefix", m->btf_prefix ? m->btf_prefix : "", ",\n      ");
        json_kv("btf_omit", m->btf_omit ? m->btf_omit : "", ",\n      ");
        json_kv("note", m->note ? m->note : "", ",\n      ");
        fputs("\"values\": [\n", stdout);
        for (int k = 0; k < m->nvalues; k++) {
            printf("        { \"value\": %ld, ", m->values[k].value);
            json_kv("name", m->values[k].name, " }");
            printf("%s\n", k + 1 < m->nvalues ? "," : "");
        }
        fputs("      ]\n    }", stdout);
    }
    fputs("\n  ],\n  ", stdout);
    /* Histogram bucket boundaries, declared once and shared. Published so
     * that "are these comparable with an OBI histogram" is answerable from the
     * affordance surface rather than by diffing two C files. */
    fputs("\"bounds_sets\": [\n", stdout);
    for (int i = 0; i < g_nbounds; i++) {
        const CcBoundsSet *b = g_bounds[i];
        if (i) fputs(",\n", stdout);
        printf("    { ");
        json_kv("id", b->id, ", ");
        json_kv("unit", b->unit, ", ");
        json_kv("authority", b->authority, ", ");
        fputs("\"values\": [", stdout);
        for (int k = 0; k < b->nvalues; k++) printf("%s%s", k ? ", " : "", dbl_exact(b->values[k]));
        fputs("], ", stdout);
        json_kv("note", b->note ? b->note : "", " }");
    }
    fputs("\n  ],\n  ", stdout);
    fputs("\"channels\": [\n", stdout);
    for (int i = 0; i < g_nchannels; i++) {
        if (i) fputs(",\n", stdout);
        json_channel(g_channels[i]);
    }
    fputs("\n  ]\n}\n", stdout);
}

/* No map without a consumer. A declared type that no derivation names is
 * a table nobody reads -- and a table nobody reads is what this layer replaces,
 * not what it produces. (It is also the rule that kept errno/signal/file_mode
 * out: none of the 63 declared fields carries one, m03.) */
static void check_valmaps_are_used(void) {
    for (int i = 0; i < g_nvalmaps; i++) {
        for (int c = 0; c < g_nchannels; c++) {
            const CcRecSchema *s = g_channels[c];
            for (int k = 0; k < s->nderived; k++)
                if (strcmp(s->derived[k].impl_form, "code_to_name") == 0 &&
                    strcmp(s->derived[k].impl, g_valmaps[i]->id) == 0) goto used;
        }
        die("a declared value map is named by no derivation (a type with no consumer is dead "
            "code; delete it or give it the property it exists for)", g_valmaps[i]->id);
    used:;
    }
}

int main(int argc, char **argv) {
    g_channels = cc_rec_all(&g_nchannels);
    g_valmaps  = cc_valmap_all(&g_nvalmaps);
    for (int i = 0; i < g_nvalmaps; i++) {
        check_valmap(g_valmaps[i]);
        for (int j = 0; j < i; j++)
            if (strcmp(g_valmaps[i]->id, g_valmaps[j]->id) == 0)
                die("two value maps share an id", g_valmaps[i]->id);
    }
    /* Resolve every code_to_name derivation BEFORE asking which maps are unused:
     * a derivation naming a map that does not exist is a typo in the derivation,
     * and reporting it as "this map has no consumer" would point at the wrong
     * line. Order the two so the message names the thing that is wrong. */
    for (int c = 0; c < g_nchannels; c++) {
        const CcRecSchema *s = g_channels[c];
        for (int k = 0; k < s->nderived; k++)
            if (strcmp(s->derived[k].impl_form, "code_to_name") == 0)
                (void)find_valmap(s->derived[k].impl, s->derived[k].name);
    }
    check_valmaps_are_used();

    /* The bounds sets, then every declared metric. Validation runs for BOTH
     * output modes (header and --json) and before either, so a refused label is a
     * refused build rather than a header that compiles and a JSON that lies. */
    g_bounds = cc_bounds_all(&g_nbounds);
    for (int i = 0; i < g_nbounds; i++) {
        const CcBoundsSet *b = g_bounds[i];
        if (!b->id || !*b->id)               die("a bounds set has no id", "(anonymous)");
        if (!b->unit || !*b->unit)           die("a bounds set declares no unit", b->id);
        if (!b->authority || !*b->authority) die("a bounds set declares no authority", b->id);
        if (b->nvalues <= 0)                 die("a bounds set declares no boundaries", b->id);
        for (int k = 1; k < b->nvalues; k++)
            if (!(b->values[k] > b->values[k - 1]))
                die("a bounds set's boundaries are not strictly ascending", b->id);
        for (int j = 0; j < i; j++)
            if (strcmp(b->id, g_bounds[j]->id) == 0) die("two bounds sets share an id", b->id);
    }
    {
        int grand = 0;
        for (int c = 0; c < g_nchannels; c++) {
            const CcRecSchema *s = g_channels[c];
            for (int k = 0; k < s->nmetrics; k++) {
                check_metric(s, &s->metrics[k]);
                grand += metric_series_bound(s, &s->metrics[k]);
                for (int j = 0; j < k; j++)
                    if (strcmp(s->metrics[k].id, s->metrics[j].id) == 0)
                        die("a channel declares two metrics with the same id", s->metrics[k].id);
            }
            for (int d = 0; d < c; d++)
                for (int k = 0; k < s->nmetrics; k++)
                    for (int j = 0; j < g_channels[d]->nmetrics; j++)
                        if (strcmp(s->metrics[k].name, g_channels[d]->metrics[j].name) == 0)
                            die("two channels declare the same metric name", s->metrics[k].name);
        }
        /* The whole point of computing bounds: a file that could produce more
         * series than the runtime can hold does not build. The runtime therefore
         * never has to decide what to do with the series that would not fit --
         * the failure otlp_httpspan.c handles by dropping the 65th with a warning. */
        if (grand > SPNL_RECMETRIC_MAX_SERIES) {
            char b[128];
            snprintf(b, sizeof b, "%d declared, %d available", grand, SPNL_RECMETRIC_MAX_SERIES);
            die("the declared metrics can produce more time series than the runtime can hold; "
                "narrow a label's permitted set or drop a label", b);
        }
    }

    if (argc > 2) die("usage", "gen_record_mirror [--json]");
    if (argc == 2) {
        if (strcmp(argv[1], "--json") != 0) die("unknown argument", argv[1]);
        emit_json();
        return 0;
    }

    printf("/* GENERATED by tools/gen_record_mirror.c from src/codegen_c/record_schema.h.\n");
    printf(" * Do not edit by hand -- edit the schema table and re-run\n");
    printf(" *     make -C src/codegen_c mirror\n");
    printf(" * then commit this file (a derived artifact, like templates_gen.h).\n");
    printf(" *\n");
    printf(" * Userspace mirror of the ringbuf record contracts. Both ends now\n");
    printf(" * derive from one declaration: the kernel producer struct is generated from the\n");
    printf(" * schema table and so are the offsets below, so a producer/consumer\n");
    printf(" * offset desync is not expressible.\n");
    printf(" *\n");
    printf(" * The SPNL_EGRESS_* macros are the other half of the same contract:\n");
    printf(" * the OpenTelemetry attribute keys the consumer puts on the span it builds. The\n");
    printf(" * runtime uses these macros so the keys have one author (the schema table) and\n");
    printf(" * `capabilities --json` cannot drift from what actually goes on the wire.\n");
    printf(" *\n");
    printf(" * The spnl_rec_<id>_<prop>() accessors are what a Ruby typed consumer\n");
    printf(" * (`on_emit :<id> do |ev| ... end`) calls for `ev.<prop>`; they are compiled only\n");
    printf(" * in the TU that #defines SPNL_REC_CONSUME_IMPL. Their SPNL_REC_DERIVED_*_CAP\n");
    printf(" * macros are not: the runtime's span builder passes the same capacity to the same\n");
    printf(" * derivation, so a long value cannot truncate differently on the two sides\n");
    printf(" * (each capacity is that derivation's own bound, not a shared default).\n");
    printf(" *\n");
    printf(" * The spnl_valmap_<id>() lookups are the type-driven half: a CODE -- a\n");
    printf(" * value from a closed set whose members have names -- has no domain logic to\n");
    printf(" * keep in C, only a table, so the table is the declaration and this is its\n");
    printf(" * generated form. They sit OUTSIDE the impl guard because both the accessor\n");
    printf(" * and the span builder call them, which is what makes `ev.tcp_state` and\n");
    printf(" * spnl.conn.tcp_state one function's output rather than two switches.\n");
    printf(" *\n");
    printf(" * Prerequisite: __u16/__u32/__u64 must already be visible (host side that means\n");
    printf(" * <bpf/libbpf.h> or <linux/types.h>), because the record header field has type\n");
    printf(" * `struct spnl_event_hdr` from include/spnl/types.h. */\n");
    emit_bounds_macros();
    printf("\n#ifndef SPNL_RECORD_MIRROR_MACROS_ONLY\n");
    printf("#ifndef SPNL_RECORD_MIRROR_GEN_H\n#define SPNL_RECORD_MIRROR_GEN_H\n\n");
    printf("#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\n");
    printf("#include \"spnl/types.h\"\n\n");

    emit_valmaps();   /* before the channels -- their accessors call these */

    /* The accumulator the generated per-channel intake calls. Declared here,
     * before the channels, because that intake is emitted inside each channel's
     * consumer block; its definition is src/runtime/otlp/otlp_recmetric.c. */
    if (metric_total()) {
        printf("\nextern void spnl_recmetric_observe(int metric, const char *const *label_values,\n");
        printf("                                   int nlabels, int has_value, double value);\n");
    }

    for (int i = 0; i < g_nchannels; i++) {
        if (i) printf("\n");
        emit_channel(g_channels[i]);
    }

    emit_metric_tables();

    printf("\n#endif /* SPNL_RECORD_MIRROR_GEN_H */\n");
    printf("#endif /* SPNL_RECORD_MIRROR_MACROS_ONLY */\n");
    return 0;
}
