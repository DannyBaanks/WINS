#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int helper_add(int a, int b);

int main(int argc, char **argv) {
    const char *msg = "Hello from Mach-O on Linux via WINS-MachO!\n";
    write(1, msg, 43);
    int res = helper_add(10, argc);
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    const char *env = getenv("WINS_MACHO_ENV");
    printf("helper_add=%d env=%s arg0=%s\n", res, env ? env : "(null)", argc > 0 ? argv[0] : "(none)");
    free(buf);
    return res;
}
