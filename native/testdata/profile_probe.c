/* profile_probe: deterministic Win32 INI semantics probe (i386, no CRT).
 *
 * Built with (zig 0.16 needs the explicit mingw include/lib paths and
 * -fno-builtin so the freestanding code emits no memset/strlen calls):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main profile_probe.c -lkernel32 -o profile_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the
 * exit code byte for byte (tools/diff_wine.sh). It pins down the value semantics
 * of GetPrivateProfileStringA / GetPrivateProfileIntA that FalloutNV depends on:
 * the game stores sD3DDevice="AMD Radeon 760M Graphics (RADV PHOENIX)" WITH the
 * quotes in FalloutPrefs.ini and compares the returned string against the D3D9
 * adapter identifier. Windows strips the surrounding quotes; a shim that returns
 * them makes every comparison fail and sends the game to FalloutNVLauncher.exe.
 *
 * Every line is deterministic: no addresses, no timings, no locale-dependent
 * formatting. The INI is written by the probe itself into the working directory.
 */
#include <windows.h>

static HANDLE g_out;
static char g_ini[300];

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
static void puti(int v) {
    if (v < 0) { put("-"); putu((unsigned)(-(long long)v)); }
    else putu((unsigned)v);
}

/* S|<tag>|<rc>|<value>\n : one GetPrivateProfileStringA answer. */
static void str_case(const char *tag, const char *section, const char *key,
                     const char *def, unsigned size) {
    char buf[300];
    unsigned i;
    for (i = 0; i < sizeof(buf); i++) buf[i] = '#';
    DWORD rc = GetPrivateProfileStringA(section, key, def, buf, size, g_ini);
    buf[299] = 0;
    put("S|"); put(tag); put("|"); putu(rc); put("|"); put(buf); put("\n");
}
/* I|<tag>|<value>\n : one GetPrivateProfileIntA answer. */
static void int_case(const char *tag, const char *section, const char *key, int def) {
    int v = GetPrivateProfileIntA(section, key, def, g_ini);
    put("I|"); put(tag); put("|"); puti(v); put("\n");
}

static const char ini[] =
    "[Display]\r\n"
    "sD3DDevice=\"AMD Radeon 760M Graphics (RADV PHOENIX)\"\r\n"
    "double=\"quoted value\"\r\n"
    "single='single quoted'\r\n"
    "mismatch=\"mixed'\r\n"
    "mismatch2='mixed\"\r\n"
    "inner=\"a \"b\" c\"\r\n"
    "plain=noquotes\r\n"
    "spaces=   padded   \r\n"
    "qspaces=\"  padded  \"\r\n"
    "empty=\r\n"
    "onlyquote=\"\r\n"
    "trailq=\"value\" trailing\r\n"
    "leadq=prefix \"value\"\r\n"
    "tabbed=\t\"tabbed\"\t\r\n"
    "num=\"42\"\r\n"
    "numplain=42\r\n"
    "neg=\"-7\"\r\n"
    "hex=0x10\r\n"
    "junk=12abc\r\n"
    "[Other]\r\n"
    "x=1\r\n";

void probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    /* Profile functions resolve a bare relative name against the Windows
     * directory, not the cwd. Use the full path next to the exe (taken from
     * the command line, which both hosts fill with the exe path) so both
     * sides read the same file. */
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
    for (i = 0; i < n; i++) g_ini[i] = cmd[start + i];
    const char *name = "probe.ini";
    for (i = 0; name[i]; i++) g_ini[n + i] = name[i];
    g_ini[n + i] = 0;

    HANDLE f = CreateFileA(g_ini, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, 0);
    if (f == INVALID_HANDLE_VALUE) ExitProcess(3);
    DWORD w;
    WriteFile(f, ini, sizeof(ini) - 1, &w, 0);
    CloseHandle(f);

    /* The exact comparison FalloutNV makes at startup. */
    str_case("device", "Display", "sD3DDevice", "DEF", 256);
    /* Quote and whitespace semantics. */
    str_case("double", "Display", "double", "DEF", 256);
    str_case("single", "Display", "single", "DEF", 256);
    str_case("mismatch", "Display", "mismatch", "DEF", 256);
    str_case("mismatch2", "Display", "mismatch2", "DEF", 256);
    str_case("inner", "Display", "inner", "DEF", 256);
    str_case("plain", "Display", "plain", "DEF", 256);
    str_case("spaces", "Display", "spaces", "DEF", 256);
    str_case("qspaces", "Display", "qspaces", "DEF", 256);
    str_case("empty", "Display", "empty", "DEF", 256);
    str_case("onlyquote", "Display", "onlyquote", "DEF", 256);
    str_case("trailq", "Display", "trailq", "DEF", 256);
    str_case("leadq", "Display", "leadq", "DEF", 256);
    str_case("tabbed", "Display", "tabbed", "DEF", 256);
    /* Case insensitivity of section and key names. */
    str_case("casekey", "Display", "SD3DDEVICE", "DEF", 256);
    str_case("casesec", "display", "sD3DDevice", "DEF", 256);
    /* Missing key / section fall back to the default. */
    str_case("misskey", "Display", "nosuchkey", "DEF", 256);
    str_case("misssec", "NoSuchSection", "x", "DEF", 256);
    str_case("othersec", "Other", "x", "DEF", 256);
    /* Truncation: rc is the number of chars copied, buffer always NUL-ended. */
    str_case("trunc8", "Display", "sD3DDevice", "DEF", 8);
    str_case("trunc1", "Display", "sD3DDevice", "DEF", 1);
    str_case("trunc0", "Display", "sD3DDevice", "DEF", 0);
    /* Integer semantics: quotes, sign, hex prefix, trailing junk, default. */
    int_case("num", "Display", "num", 99);
    int_case("numplain", "Display", "numplain", 99);
    int_case("neg", "Display", "neg", 99);
    int_case("hex", "Display", "hex", 99);
    int_case("junk", "Display", "junk", 99);
    int_case("missint", "Display", "nosuchkey", 99);
    int_case("emptyint", "Display", "empty", 99);

    ExitProcess(0);
}
