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
enum { DERIV_BYTES_STR, DERIV_BYTES_INT, DERIV_RECORD_STR, DERIV_RECORD_INT };

static int derived_form(const CcRecDerived *d) {
    if (strcmp(d->impl_form, "bytes_to_str")  == 0) return DERIV_BYTES_STR;
    if (strcmp(d->impl_form, "bytes_to_int")  == 0) return DERIV_BYTES_INT;
    if (strcmp(d->impl_form, "record_to_str") == 0) return DERIV_RECORD_STR;
    if (strcmp(d->impl_form, "record_to_int") == 0) return DERIV_RECORD_INT;
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
    for (int i = 0; i < s->nfields; i++)
        if (strcmp(s->fields[i].name, d->from) == 0) return;
    die("derivation reads a field this record does not declare", d->from);
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
            printf("    %s(%s, buf, (int)sizeof buf);   /* derived: %s */\n", d->impl, arg, d->name);
            printf("    return buf;\n}\n");
        }
    }
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
            snprintf(buf, sizeof buf, "%s -> %s()", d->from, d->impl);
            json_kv("source", buf, ", ");
            /* The declared output capacity (bytes incl. NUL) of a str
             * derivation -- both the accessor and the span builder pass it, so it
             * is the width `ev.<name>` and the attribute share. 0 for an int. */
            printf("\"cap\": %d, ", d->cap);
            json_kv("note", d->note ? d->note : "", " }");
            printf("%s\n", ++emitted < nprop ? "," : "");
        }
    }
    fputs("        ]\n      }", stdout);
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
            "the record's bytes directly, so its width is the field's `bytes`.", ",\n  ");
    fputs("\"channels\": [\n", stdout);
    for (int i = 0; i < g_nchannels; i++) {
        if (i) fputs(",\n", stdout);
        json_channel(g_channels[i]);
    }
    fputs("\n  ]\n}\n", stdout);
}

int main(int argc, char **argv) {
    g_channels = cc_rec_all(&g_nchannels);

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
    printf(" * Prerequisite: __u16/__u32/__u64 must already be visible (host side that means\n");
    printf(" * <bpf/libbpf.h> or <linux/types.h>), because the record header field has type\n");
    printf(" * `struct spnl_event_hdr` from include/spnl/types.h. */\n");
    printf("#ifndef SPNL_RECORD_MIRROR_GEN_H\n#define SPNL_RECORD_MIRROR_GEN_H\n\n");
    printf("#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\n");
    printf("#include \"spnl/types.h\"\n\n");

    for (int i = 0; i < g_nchannels; i++) {
        if (i) printf("\n");
        emit_channel(g_channels[i]);
    }

    printf("\n#endif /* SPNL_RECORD_MIRROR_GEN_H */\n");
    return 0;
}
