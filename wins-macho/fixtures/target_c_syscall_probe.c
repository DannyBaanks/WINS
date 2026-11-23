#include <stdint.h>

static inline long darwin_syscall3(long num, long a1, long a2, long a3) {
    long ret;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

int main(void) {
    const char msg[] = "Direct Darwin BSD syscall 0x2000004 (SYS_write) worked!\n";
    darwin_syscall3(0x2000004, 1, (long)msg, sizeof(msg) - 1);
    // Now hit a real Mach trap: mach_reply_port (0x100001a)
    darwin_syscall3(0x100001a, 0, 0, 0);
    return 0;
}
