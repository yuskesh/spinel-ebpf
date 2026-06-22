/* bpf_list/bpf_obj/kptr helper machinery for BPF qdiscs. */
#ifndef __contains
#define __contains(name, node) __attribute__((btf_decl_tag("contains:" #name ":" #node)))
#endif
#ifndef __kptr
#define __kptr __attribute__((btf_type_tag("kptr")))
#endif
#ifndef private
#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
#endif
#ifndef bpf_obj_new
#define bpf_obj_new(type)              ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#endif
#ifndef bpf_obj_drop
#define bpf_obj_drop(kptr)             bpf_obj_drop_impl(kptr, NULL)
#endif
#ifndef bpf_list_push_back
#define bpf_list_push_back(head, node) bpf_list_push_back_impl(head, node, NULL, 0)
#endif
#ifndef container_of
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - __builtin_offsetof(type, member)))
#endif

/* Wrapper struct holding one skb in a bpf_list. The __kptr tag
 * tells the verifier that this field owns a kernel sk_buff that
 * must be released via bpf_kptr_xchg before the wrapper is freed. */
struct spnl_qdisc_skb_node {
    struct bpf_list_node node;
    struct sk_buff __kptr *skb;
};

/* Per-unit single queue (spin_lock + list_head pair). The
 * __contains tag wires the list head to skb_node.node so the
 * verifier knows which container type the list holds. */
private(A) struct bpf_spin_lock spnl_qdisc_q_lock;
private(A) struct bpf_list_head spnl_qdisc_q_head __contains(spnl_qdisc_skb_node, node);
