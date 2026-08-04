/* === kernel string fields ===
 *
 * kfield reads a kernel struct field as a SCALAR, because BPF_CORE_READ returns
 * one. A string is not a scalar, and the last hop of a string field comes in two
 * shapes that need different code:
 *
 *   inline array   task_struct->comm            char[16]
 *                  the field IS the characters -> read AT its address
 *   pointer        dentry->d_name.name          const unsigned char *
 *                  the field POINTS AT them    -> fetch the pointer, then read
 *
 * Getting that backwards does not fail: reading the pointer field "as bytes"
 * yields the eight bytes of the pointer, which the verifier is happy with and
 * which arrives as garbage (measured -- libbpf's own BPF_CORE_READ_STR_INTO does
 * exactly this if you hand it a pointer field).
 *
 * So the choice is not left to whoever writes the probe. SPNL_KSTR_IS_PTR asks
 * the C type system which shape the field has: for an array `typeof(f)` is
 * `char[N]` while `typeof(&f[0])` is `char *` (different types); for a pointer
 * the two are the same type. __builtin_choose_expr then picks the branch at
 * compile time. Both branches are type-checked by clang even though only one is
 * emitted (measured), so a field that is neither shape cannot slip through: the
 * _Static_assert at each call site requires a 1-byte element.
 */
#define SPNL_KSTR_IS_PTR(chain) \
    __builtin_types_compatible_p(__typeof__(chain), __typeof__(&(chain)[0]))

/* The call-site shape check, in two questions so that each wrong answer names the
 * call the author wrote instead of a diagnostic from inside the expansion:
 *   is it indexable at all? (an array decays for __builtin_classify_type, so both
 *     shapes land in the pointer class; an int or a struct value does not)
 *   are the things it indexes single BYTES? (this is what refuses a chain that
 *     stopped one hop short, on `struct dentry *` -- which is still "a pointer") */
#define SPNL_KSTR_CHECK(chain, msg)                                              \
    _Static_assert(__builtin_classify_type(chain) == __builtin_classify_type((char *)0), msg); \
    _Static_assert(sizeof((chain)[0]) == 1, msg)

/* Reads the string at <src>-><accessors...> into dst (sizeof(dst) bounded, always
 * NUL-terminated); evaluates to the helper's return = bytes written incl. NUL,
 * or negative on fault. `chain` is the same field path written against a null
 * base, which is what carries the type to SPNL_KSTR_IS_PTR. */
#define SPNL_KFIELD_STR(dst, chain, src, ...)                                    \
    __builtin_choose_expr(SPNL_KSTR_IS_PTR(chain),                               \
        bpf_probe_read_kernel_str((dst), sizeof(dst),                            \
            (const void *)(unsigned long)BPF_CORE_READ(src, __VA_ARGS__)),       \
        BPF_CORE_READ_STR_INTO(&(dst), src, __VA_ARGS__))
