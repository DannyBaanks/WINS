/* filecase_probe: deterministic Win32 file case-insensitivity probe (i386, no CRT).
 *
 * Built with (zig 0.16 needs the explicit mingw include/lib paths and
 * -fno-builtin so the freestanding code emits no memset/strlen calls):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main filecase_probe.c -lkernel32 -o filecase_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the
 * exit code byte for byte (tools/diff_wine.sh). It pins down the file-path
 * semantics FalloutNV depends on when it mounts its BSA archives: the game
 * reads sArchiveList ("Fallout - Textures.bsa, ...") and probes each archive
 * with GetFileAttributesA("DATA/Fallout - Textures.bsa") -- uppercase DATA,
 * while the on-disk directory is "Data". Win32 resolves every path component
 * case-insensitively; a case-sensitive shim answers "not found", the game
 * never opens a single archive, and it dies on a NULL dereference before the
 * first frame.
 *
 * The probe creates its own fixture (Data/Fallout - Textures.bsa,
 * Data/Shaders/pkg.sdp) next to the exe, then queries it with exact, upper,
 * lower and mixed case, with back- and forward slashes, plus missing-file and
 * missing-directory negative controls. Every line is deterministic: no
 * addresses, no timings, no locale-dependent formatting.
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

/* A|<tag>|<attrs>|<lasterror> : one GetFileAttributesA answer. */
static void attr_case(const char *tag, const char *rel) {
    join(rel);
    SetLastError(0);
    DWORD a = GetFileAttributesA(g_path);
    DWORD e = GetLastError();
    put("A|"); put(tag); put("|"); putx(a); put("|"); putu(e); put("\n");
}

/* F|<tag>|<opened>|<bytes read>|<content>|<lasterror> : CreateFileA+ReadFile. */
static void open_case(const char *tag, const char *rel) {
    join(rel);
    SetLastError(0);
    HANDLE f = CreateFileA(g_path, GENERIC_READ, FILE_SHARE_READ, 0,
                           OPEN_EXISTING, 0, 0);
    DWORD e = GetLastError();
    if (f == INVALID_HANDLE_VALUE) {
        put("F|"); put(tag); put("|0|0||"); putu(e); put("\n");
        return;
    }
    char buf[16]; DWORD n = 0; unsigned i;
    for (i = 0; i < sizeof(buf); i++) buf[i] = 0;
    ReadFile(f, buf, 8, &n, 0);
    CloseHandle(f);
    put("F|"); put(tag); put("|1|"); putu(n); put("|"); put(buf);
    put("|"); putu(e); put("\n");
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

void probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    /* Fixture paths are absolute, taken from the command line (both hosts
     * fill it with the exe path): the process cwd differs between Wine and
     * winrun32, so nothing may depend on it. */
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

    join("Data");
    CreateDirectoryA(g_path, 0); /* ERROR_ALREADY_EXISTS on reruns is fine */
    join("Data\\Shaders");
    CreateDirectoryA(g_path, 0);
    make_file("Data\\Fallout - Textures.bsa", "BSAPROBE", 8);
    make_file("Data\\Shaders\\pkg.sdp", "SDP", 3);

    /* The exact probe FalloutNV makes before mounting an archive. */
    attr_case("upperdir", "DATA\\Fallout - Textures.bsa");
    /* Case folds in every component, both separator styles. */
    attr_case("exact", "Data\\Fallout - Textures.bsa");
    attr_case("lowerall", "data\\fallout - textures.bsa");
    attr_case("mixed", "DaTa/FALLOUT - TEXTURES.BSA");
    attr_case("shader", "Data\\SHADERS\\pkg.sdp");
    attr_case("dir", "DATA");
    attr_case("dirslash", "data\\");
    /* Negative controls: missing file vs missing parent directory. */
    attr_case("missfile", "Data\\nosuch.bsa");
    attr_case("missdir", "Nope\\x.bsa");

    /* Opening with the wrong case must read the same bytes. */
    open_case("upperdir", "DATA\\Fallout - Textures.bsa");
    open_case("mixed", "data/FALLOUT - TEXTURES.BSA");
    open_case("shader", "DATA\\shaders\\PKG.SDP");
    open_case("missfile", "Data\\nosuch.bsa");
    open_case("missdir", "Nope\\x.bsa");

    ExitProcess(0);
}
