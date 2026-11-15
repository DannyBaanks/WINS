/* decommit_probe: VirtualFree(MEM_DECOMMIT / MEM_RELEASE) range semantics (i386, no CRT).
 *
 * Built like find_probe.c:
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main decommit_probe.c -lkernel32 -o decommit_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the
 * exit code byte for byte (tools/diff_wine.sh).
 *
 * Why: FalloutNV's heap puts guard pages between blocks by decommitting a
 * single page inside a larger reservation: VirtualFree(0x71e1000, 4096,
 * MEM_DECOMMIT) inside an 8 MB reservation at 0x7000000 (measured, WINS run
 * 2026-11-14). The loader decommitted from that address for the size of the
 * WHOLE reservation, so the next page (0x71e2000, still the game's live heap)
 * faulted in the game's main loop.
 *
 * Win32 decommits exactly the pages that contain a byte of [addr, addr+size);
 * size 0 at the reservation base means the whole reservation; a recommitted
 * page reads back as zeros; MEM_RELEASE wants the base address and size 0.
 * A decommitted page itself is not touched here (that needs SEH): only its
 * neighbours, which must stay readable and intact.
 */
#include <windows.h>

static HANDLE g_out;

static void put(const char *s) {
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(g_out, s, n, &w, 0);
}
static void putu(unsigned v) {
    char b[16]; int i = 15; b[i] = 0;
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    put(b + i);
}

#define PG 4096
static char *g_p;

/* Prints the marker byte of each listed page (all must be committed). */
static void pages(const char *what, const int *list, int n) {
    int i;
    char c[2] = {0, 0};
    put(what); put(":");
    for (i = 0; i < n; i++) {
        c[0] = g_p[list[i] * PG];
        put(" "); putu((unsigned)list[i]); put("=");
        if (c[0]) put(c); else put("0");
    }
    put("\n");
}

static void ret(const char *what, BOOL r) {
    put(what); put("="); putu(r ? 1 : 0);
    if (!r) { put(" err="); putu(GetLastError()); }
    put("\n");
}

void probe_main(void) {
    int i;
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    g_p = VirtualAlloc(0, 16 * PG, MEM_RESERVE, PAGE_READWRITE);
    if (!g_p) ExitProcess(2);
    if (VirtualAlloc(g_p, 16 * PG, MEM_COMMIT, PAGE_READWRITE) != g_p) ExitProcess(3);
    for (i = 0; i < 16; i++) g_p[i * PG] = (char)('a' + i);

    /* one guard page in the middle, as the game does */
    ret("decommit page 3", VirtualFree(g_p + 3 * PG, PG, MEM_DECOMMIT));
    { static const int l[] = { 0, 1, 2, 4, 5, 15 }; pages("after page 3", l, 6); }

    /* recommitting it gives a zero-filled page */
    if (VirtualAlloc(g_p + 3 * PG, PG, MEM_COMMIT, PAGE_READWRITE) != g_p + 3 * PG) ExitProcess(4);
    { static const int l[] = { 2, 3, 4 }; pages("recommit page 3", l, 3); }

    /* an unaligned range touches two pages: 6 and 7 */
    ret("decommit 6+100..7+99", VirtualFree(g_p + 6 * PG + 100, PG, MEM_DECOMMIT));
    { static const int l[] = { 5, 8, 9, 15 }; pages("after 6..7", l, 4); }
    if (VirtualAlloc(g_p + 6 * PG, 2 * PG, MEM_COMMIT, PAGE_READWRITE) != g_p + 6 * PG) ExitProcess(5);
    { static const int l[] = { 5, 6, 7, 8 }; pages("recommit 6..7", l, 4); }

    /* the last page of the reservation; nothing past it is ours */
    ret("decommit page 15", VirtualFree(g_p + 15 * PG, PG, MEM_DECOMMIT));
    { static const int l[] = { 0, 14 }; pages("after page 15", l, 2); }

    /* MEM_RELEASE wants the base and size 0 */
    ret("release interior", VirtualFree(g_p + PG, 0, MEM_RELEASE));
    ret("release base with size", VirtualFree(g_p, PG, MEM_RELEASE));
    { static const int l[] = { 0, 1, 14 }; pages("after refused releases", l, 3); }

    /* size 0 at the base decommits the whole reservation; recommit reads zeros */
    ret("decommit all", VirtualFree(g_p, 0, MEM_DECOMMIT));
    if (VirtualAlloc(g_p, 16 * PG, MEM_COMMIT, PAGE_READWRITE) != g_p) ExitProcess(6);
    { static const int l[] = { 0, 7, 15 }; pages("recommit all", l, 3); }

    ret("release", VirtualFree(g_p, 0, MEM_RELEASE));
    ret("release again", VirtualFree(g_p, 0, MEM_RELEASE));
    ExitProcess(0);
}
