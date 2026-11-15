/* str_probe: deterministic Win32 string-API probe (i386, no CRT).
 *
 * Built like filecase_probe.c:
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main str_probe.c -lkernel32 -o str_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the
 * exit code byte for byte (tools/diff_wine.sh).
 *
 * Why: FalloutNV builds its plugin mask with lstrcpyA(buf, "DATA\\") then
 * lstrcatA(buf, "*.esm") (call site 0x4625c4..0x46262c, read from the
 * decrypted runtime image). winrun32's lstrcatA measured the destination
 * length as 0 and overwrote it, so the game asked FindFirstFileA("*.esm")
 * in the game root instead of "DATA\\*.esm" and found no master file.
 * MultiByteToWideChar and LCMapStringA had the same length bug for a -1
 * (NUL-terminated) count and handled one character only.
 */
#include <windows.h>

static HANDLE g_out;

static void put(const char *s) {
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(g_out, s, n, &w, 0);
}
static void puti(int v) {
    char b[16]; int i = 15; unsigned u = v < 0 ? (unsigned)-v : (unsigned)v;
    b[i] = 0;
    if (u == 0) b[--i] = '0';
    while (u) { b[--i] = (char)('0' + u % 10); u /= 10; }
    if (v < 0) b[--i] = '-';
    put(b + i);
}
static void putw(const WCHAR *w, int n) {
    char b[64]; int i;
    for (i = 0; i < n && i < 63; i++) b[i] = (w[i] == 0) ? '0' : (w[i] < 128 ? (char)w[i] : '?');
    b[i] = 0;
    put(b);
}

void probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    char buf[64];
    int i;

    /* lstrcpyA / lstrcatA / lstrlenA: the FalloutNV plugin mask. */
    for (i = 0; i < 64; i++) buf[i] = 'Z';
    lstrcpyA(buf, "DATA\\");
    lstrcatA(buf, "*.esm");
    put("S|cat|"); put(buf); put("|"); puti(lstrlenA(buf)); put("\n");
    lstrcatA(buf, "");
    put("S|catempty|"); put(buf); put("\n");
    buf[0] = 0;
    lstrcatA(buf, "x");
    put("S|catonempty|"); put(buf); put("\n");
    put("S|len|"); puti(lstrlenA("FalloutNV.esm")); put("|"); puti(lstrlenA("")); put("\n");

    /* MultiByteToWideChar with a NUL-terminated (-1) source. */
    WCHAR w[32];
    for (i = 0; i < 32; i++) w[i] = 'Z';
    SetLastError(0);
    int need = MultiByteToWideChar(CP_ACP, 0, "DATA\\a.esm", -1, 0, 0);
    put("M|need|"); puti(need); put("|"); puti((int)GetLastError()); put("\n");
    int got = MultiByteToWideChar(CP_ACP, 0, "DATA\\a.esm", -1, w, 32);
    put("M|conv|"); puti(got); put("|"); putw(w, got); put("\n");
    got = MultiByteToWideChar(CP_ACP, 0, "abcdef", 3, w, 32);
    put("M|counted|"); puti(got); put("|"); putw(w, got); put("\n");
    SetLastError(0);
    got = MultiByteToWideChar(CP_ACP, 0, "abcdef", -1, w, 3);
    put("M|small|"); puti(got); put("|"); puti((int)GetLastError()); put("\n");

    /* LCMapStringA with a -1 source: plain copy and case mapping. */
    char d[32];
    for (i = 0; i < 32; i++) d[i] = 'Z';
    need = LCMapStringA(LOCALE_USER_DEFAULT, 0, "Data\\Update.bsa", -1, 0, 0);
    put("L|need|"); puti(need); put("\n");
    got = LCMapStringA(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE, "Data\\Update.bsa", -1, d, 32);
    put("L|upper|"); puti(got); put("|"); put(d); put("\n");
    got = LCMapStringA(LOCALE_USER_DEFAULT, LCMAP_LOWERCASE, "Data\\Update.bsa", -1, d, 32);
    put("L|lower|"); puti(got); put("|"); put(d); put("\n");

    ExitProcess(0);
}
