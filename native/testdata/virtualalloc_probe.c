/* Differential i386 probe: recommitting a committed page preserves its data.
 * Compile to an object with zig cc -target x86-windows-gnu -O1
 * -ffreestanding -fno-builtin -c, then link with -nostdlib
 * -Wl,--entry=probe_main -Wl,--gc-sections -lkernel32. Run inside the WINS
 * cleanroom and compare stdout and exit status with Wine in a fresh prefix.
 * Expected output is "AB\n", exit 0. The former MAP_FIXED path prints A\0\n
 * and exits 1, making it a negative control for this specific regression.
 */
#include <windows.h>
void probe_main(void) {
    DWORD written;
    char *p = VirtualAlloc(0, 8192, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!p) ExitProcess(10);
    p[0] = 'A'; p[4096] = 'B';
    char *q = VirtualAlloc(p + 4096, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (!q) ExitProcess(11);
    char out[] = {p[0], p[4096], '\n'};
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), out, sizeof(out), &written, 0);
    ExitProcess(q != p + 4096 || out[0] != 'A' || out[1] != 'B');
}
