// SPDX-License-Identifier: GPL-2.0
//
// spnl_load_check -- load-only eBPF verifier probe for `spinel-ebpf check`.
//
// Opens + loads a .bpf.o exactly the way the real spinel-emitted binary does
// (spnl_runtime_init = bpf_object__open_file + bpf_object__load), but
// stops before attach / any workload run. This surfaces the *kernel verifier's*
// verdict cleanly. The compiler is the first harness that keeps generated
// programs correct by construction; the verifier is the second, kernel-side one,
// and this tool reports its answer without running anything:
//
//   exit 0  -> the verifier accepted every program (LOAD_OK on stderr)
//   exit 1  -> the verifier (or CO-RE relocation) rejected it; the full libbpf
//              load log (incl. the verifier trace) is on stderr for the caller
//              to summarise (LOAD_FAIL err=-N)
//   exit 2  -> usage
//   exit 3  -> open failed (malformed object)
//
// Build (Linux, needs libbpf-dev): cc -O2 tools/spnl_load_check.c -lbpf -lelf -lz
// Load-only means no bpffs mount / pin cleanup (unlike `bpftool prog loadall`)
// and it handles struct_ops / map-in-map / CO-RE the same way libbpf does.

#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>

static int print_cb(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    // Drop DEBUG spam; keep INFO/WARN which carry the "-- BEGIN/END PROG LOAD
    // LOG --" verifier trace and the "prog '<name>': failed to load: -N" line.
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <program.bpf.o>\n", argv[0]);
        return 2;
    }
    libbpf_set_print(print_cb);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "OPEN_FAIL %s\n", argv[1]);
        return 3;
    }

    int err = bpf_object__load(obj);
    bpf_object__close(obj);

    if (err) {
        fprintf(stderr, "LOAD_FAIL err=%d\n", err);
        return 1;
    }
    fprintf(stderr, "LOAD_OK\n");
    return 0;
}
