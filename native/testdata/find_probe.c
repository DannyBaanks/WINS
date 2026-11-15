/* find_probe: deterministic Win32 directory-enumeration probe (i386, no CRT).
 *
 * Built like filecase_probe.c:
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main find_probe.c -lkernel32 -o find_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the
 * exit code byte for byte (tools/diff_wine.sh).
 *
 * Why: FalloutNV lists its plugins with FindFirstFileA("DATA\\*.esm") and
 * FindFirstFileA("DATA\\*.esp"), then calls FindFirstFileA on every archive
 * and master ("DATA\\FalloutNV.esm", "DATA\\Update.bsa") before opening it,
 * and on "Data\\Music\\explore\\\\*" for its music folders (measured in the
 * Proton relay log: 494 calls). A FindFirstFileA that ignores its pattern and
 * always answers "FalloutNV.exe" hides every master file; the game never
 * opens FalloutNV.esm and sits on the loading screen.
 *
 * The probe builds its own fixture next to the exe and enumerates it with
 * wildcard, literal, wrong-case and negative patterns. Directory order is
 * host-defined, so the names of each query are sorted before printing. File
 * times differ per run, so only their plausibility is printed. Every line is
 * deterministic: no addresses, no timings, no locale-dependent formatting.
 */
#include <windows.h>

static HANDLE g_out;
static char g_base[300]; /* exe directory, with trailing separator */
static char g_path[400];

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
static void putx(unsigned v) {
    char b[16]; int i = 15; b[i] = 0;
    const char *h = "0123456789abcdef";
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = h[v & 15]; v >>= 4; }
    put("0x"); put(b + i);
}
static void join(const char *rel) {
    unsigned i = 0, j = 0;
    while (g_base[i]) { g_path[i] = g_base[i]; i++; }
    while (rel[j]) { g_path[i++] = rel[j++]; }
    g_path[i] = 0;
}
static int cmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
static void copy(char *d, const char *s, unsigned cap) {
    unsigned i = 0;
    while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; }
    d[i] = 0;
}

static void make_file(const char *rel, const char *content, unsigned len) {
    join(rel);
    HANDLE f = CreateFileA(g_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) ExitProcess(3);
    DWORD w;
    WriteFile(f, content, len, &w, 0);
    CloseHandle(f);
}

/* FILETIME of a file written this decade: high dword in [0x01d00000, 0x02000000). */
static const char *plausible(FILETIME t) {
    return (t.dwHighDateTime >= 0x01d00000u && t.dwHighDateTime < 0x02000000u) ? "ok" : "bad";
}

#define MAXE 32
static char g_names[MAXE][64];
static char g_lines[MAXE][160];

/* Q|<tag>|<handle valid>|<first error>|<count>|<end error>
 * E|<tag>|<name>|<attrs>|<size>|<write time>   (sorted by name) */
static void find_case(const char *tag, const char *rel) {
    WIN32_FIND_DATAA d;
    unsigned n = 0, i, j;
    join(rel);
    SetLastError(0);
    HANDLE h = FindFirstFileA(g_path, &d);
    DWORD e1 = GetLastError();
    DWORD e2 = 0;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (n < MAXE) {
                char *l = g_lines[n];
                unsigned k = 0;
                copy(g_names[n], d.cFileName, sizeof(g_names[n]));
                l[0] = 0;
                {
                    char tmp[16]; int t = 15; unsigned v = d.dwFileAttributes;
                    const char *hx = "0123456789abcdef";
                    tmp[t] = 0;
                    if (v == 0) tmp[--t] = '0';
                    while (v) { tmp[--t] = hx[v & 15]; v >>= 4; }
                    l[k++] = '0'; l[k++] = 'x';
                    while (tmp[t]) l[k++] = tmp[t++];
                }
                l[k++] = '|';
                {
                    char tmp[16]; int t = 15; unsigned v = d.nFileSizeLow;
                    tmp[t] = 0;
                    if (v == 0) tmp[--t] = '0';
                    while (v) { tmp[--t] = (char)('0' + v % 10); v /= 10; }
                    while (tmp[t]) l[k++] = tmp[t++];
                }
                l[k++] = '|';
                {
                    const char *p = (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                        ? "dir" : plausible(d.ftLastWriteTime);
                    while (*p) l[k++] = *p++;
                }
                l[k] = 0;
            }
            n++;
            SetLastError(0);
        } while (FindNextFileA(h, &d));
        e2 = GetLastError();
        SetLastError(0);
        BOOL c = FindClose(h);
        if (!c) { put("C|"); put(tag); put("|fail\n"); }
    }
    /* insertion sort by name (with its line) */
    unsigned m = n < MAXE ? n : MAXE;
    for (i = 1; i < m; i++) {
        for (j = i; j > 0 && cmp(g_names[j - 1], g_names[j]) > 0; j--) {
            char tn[64], tl[160];
            copy(tn, g_names[j], 64); copy(tl, g_lines[j], 160);
            copy(g_names[j], g_names[j - 1], 64); copy(g_lines[j], g_lines[j - 1], 160);
            copy(g_names[j - 1], tn, 64); copy(g_lines[j - 1], tl, 160);
        }
    }
    put("Q|"); put(tag); put("|"); put(h != INVALID_HANDLE_VALUE ? "1" : "0");
    put("|"); putu(e1); put("|"); putu(n); put("|"); putu(e2); put("\n");
    for (i = 0; i < m; i++) {
        put("E|"); put(tag); put("|"); put(g_names[i]); put("|"); put(g_lines[i]); put("\n");
    }
}

void probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    /* Absolute fixture paths from the command line (see filecase_probe.c). */
    const char *cmd = GetCommandLineA();
    int start = (cmd[0] == '"') ? 1 : 0;
    int end = start;
    if (cmd[0] == '"') { while (cmd[end] && cmd[end] != '"') end++; }
    else { while (cmd[end] && cmd[end] != ' ') end++; }
    int cut = -1, i;
    for (i = start; i < end; i++)
        if (cmd[i] == '\\' || cmd[i] == '/') cut = i;
    if (cut < 0) ExitProcess(2);
    int n = cut - start + 1;
    for (i = 0; i < n; i++) g_base[i] = cmd[start + i];
    g_base[n] = 0;

    join("FindFix");
    CreateDirectoryA(g_path, 0);
    join("FindFix\\Sub");
    CreateDirectoryA(g_path, 0);
    make_file("FindFix\\FalloutNV.esm", "TES4X", 5);
    make_file("FindFix\\DeadMoney.esm", "TES", 3);
    make_file("FindFix\\Update.bsa", "BSA\0abc", 7);
    make_file("FindFix\\plugins.ESP", "P", 1);
    make_file("FindFix\\readme.txt", "", 0);
    make_file("FindFix\\Sub\\a.kf", "KF", 2);

    /* What FalloutNV asks, in the case it asks it. */
    find_case("esm", "FINDFIX\\*.esm");
    find_case("esmup", "FindFix\\*.ESM");
    find_case("esp", "FindFix\\*.esp");
    find_case("literal", "FINDFIX\\FalloutNV.esm");
    find_case("literalci", "findfix\\update.BSA");
    find_case("qmark", "FindFix\\Fallout?V.esm");
    find_case("star", "FindFix\\*");
    find_case("starstar", "FindFix\\*.*");
    find_case("dblsep", "FindFix\\Sub\\\\*");
    find_case("fwdsep", "FindFix/Sub/*.kf");
    find_case("dirself", "FindFix\\Sub");
    /* Negative controls. */
    find_case("nomatch", "FindFix\\*.nope");
    find_case("missdir", "NoSuchDir\\*.esm");
    find_case("missfile", "FindFix\\nosuch.esm");

    /* FindClose / GetFileType on handles that are not what they claim. */
    SetLastError(0);
    BOOL bc = FindClose((HANDLE)0x12345678);
    put("X|findclose-bogus|"); putu(bc ? 1 : 0); put("|"); putu(GetLastError()); put("\n");

    join("FindFix\\Update.bsa");
    HANDLE f = CreateFileA(g_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    SetLastError(0);
    put("X|filetype-file|"); putu(GetFileType(f)); put("|"); putu(GetLastError()); put("\n");
    CloseHandle(f);
    SetLastError(0);
    DWORD bt = GetFileType((HANDLE)0x12345678);
    put("X|filetype-bogus|"); putu(bt); put("|"); putu(GetLastError()); put("\n");

    ExitProcess(0);
}
