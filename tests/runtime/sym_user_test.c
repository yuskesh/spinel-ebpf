/* User-space symbolizer smoke test. Resolves the address of functions in
 * this very process via spnl_sym_user (/proc/self/maps + ELF .symtab) and
 * checks the symbol name comes back.
 *
 * Build + run (inside the debian:trixie build container):
 *   cc -O2 -Isrc/runtime -Iinclude tests/runtime/sym_user_test.c \
 *      src/runtime/spnl_runtime.c -lbpf -lelf -lz -o /tmp/sym_user_test
 *   /tmp/sym_user_test
 * Expected:
 *   my_marker_func -> [my_marker_func+0x0 [sym_user_test]] (rc=0)
 *   main           -> [main+0x... [sym_user_test]] (rc=0)
 */
#include "spnl_runtime.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int my_marker_func(int x) { return x * 3; }

int main(void)
{
    char buf[320];
    int fails = 0;

    int r1 = spnl_sym_user(getpid(), (unsigned long)(void *)&my_marker_func, buf, sizeof(buf));
    printf("my_marker_func -> [%s] (rc=%d)\n", buf, r1);
    if (r1 != 0 || strstr(buf, "my_marker_func") == NULL) fails++;

    int r2 = spnl_sym_user(getpid(), (unsigned long)(void *)&main, buf, sizeof(buf));
    printf("main           -> [%s] (rc=%d)\n", buf, r2);
    if (r2 != 0 || strstr(buf, "main") == NULL) fails++;

    if (fails) { printf("FAIL: %d symbol(s) not resolved\n", fails); return 1; }
    printf("OK: user symbolization resolved both symbols\n");
    return 0;
}
