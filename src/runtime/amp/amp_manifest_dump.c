/* SPDX-License-Identifier: Apache-2.0
 *
 * amp_manifest_dump.c -- dump the manifest fields the code generator derives.
 *
 * The CLI (`spinel-ebpf compile --target amp-m7 --build`) compiles this for the
 * HOST with -DAMP_BPF_C="<path>" so it #includes the emitted amp .bpf.c (whose
 * #ifdef SPNL_AMP_MANIFEST block holds the authoritative amp_triggers[] /
 * amp_abi_version / amp_ivars_size). Running it prints key=value lines the CLI
 * packs into <base>.manifest — the codegen values are read, not re-derived.
 */
#ifndef SPNL_AMP_MANIFEST
#define SPNL_AMP_MANIFEST 1
#endif
#ifndef AMP_BPF_C
#error "compile with -DAMP_BPF_C=\"<path to the amp .bpf.c>\""
#endif
#include AMP_BPF_C
#include <stdio.h>

int main(void)
{
	printf("abi_version=%u\n", amp_abi_version);
	printf("ivars_size=%u\n", amp_ivars_size);
	for (unsigned i = 0; i < amp_triggers_n; i++) {
		printf("trigger=%s kind=%d param=%u\n",
		       amp_triggers[i].fn, amp_triggers[i].kind, amp_triggers[i].param);
	}
	return 0;
}
