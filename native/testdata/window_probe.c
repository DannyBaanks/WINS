/* window_probe: deterministic USER32 window/message/activation probe (i386, no CRT).
 *
 * Built like find_probe.c, plus user32:
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main window_probe.c -lkernel32 -luser32 -o window_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the
 * exit code byte for byte (tools/diff_wine.sh). The oracle runs on a bare X
 * server (Xvfb, no window manager) so no WM focus traffic is mixed in.
 *
 * Why: FalloutNV's main loop (decrypted image, 0x86b301..0x86b669) pumps
 * PeekMessageA/TranslateMessage/DispatchMessageA and then does
 * `if (GetActiveWindow() != hwnd) Sleep(50)`. A USER32 that hands out a fixed
 * HWND from CreateWindowExA, a different fixed HWND from GetActiveWindow and
 * never calls the window procedure keeps the game asleep forever. The game
 * imports exactly: RegisterClassA, CreateWindowExA, DefWindowProcA,
 * ShowWindow, UpdateWindow, SetForegroundWindow, GetActiveWindow,
 * PeekMessageA, TranslateMessage, DispatchMessageA, SendMessageA,
 * GetWindowLongA, GetClassLongA, GetClientRect, AdjustWindowRect(Ex),
 * SetWindowPos, GetWindow, FindWindowA, EnumChildWindows, DestroyWindow,
 * Get/SetWindowTextA, GetClassNameA (plus input/cursor calls not probed here).
 * This probe exercises those, in the order the game uses them: a 320x240
 * window that is destroyed, then the game window, shown and activated.
 *
 * Every line is deterministic: HWNDs are printed only as relations (same /
 * zero / other), messages as numbers with the parameters that carry meaning.
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
static void puti(int v) {
    if (v < 0) { put("-"); putu((unsigned)(-v)); } else putu((unsigned)v);
}
static void putx(unsigned v) {
    char b[16]; int i = 15; b[i] = 0;
    const char *h = "0123456789abcdef";
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = h[v & 15]; v >>= 4; }
    put("0x"); put(b + i);
}

static HWND g_w1, g_w2, g_w3;

static void putwnd(HWND h) {
    if (h == 0) put("0");
    else if (h == g_w1 && g_w1) put("w1");
    else if (h == g_w2 && g_w2) put("w2");
    else if (h == g_w3 && g_w3) put("w3");
    else if (h == GetDesktopWindow()) put("desktop");
    else put("other");
}

/* Message log, filled by the window procedure and printed by the step. */
#define LOGN 128
static unsigned g_msg[LOGN], g_wp[LOGN], g_lp[LOGN], g_hw[LOGN];
static int g_n;
static int g_depth;

/* Messages a pointing device or an accessibility client produce: where the
 * pointer happens to sit decides them, not the API under test. */
static int input_dependent(UINT m) {
    return m == WM_GETOBJECT || m == WM_NCHITTEST || m == WM_SETCURSOR ||
           (m >= WM_MOUSEFIRST && m <= WM_MOUSELAST) || m == WM_MOUSEHOVER || m == WM_MOUSELEAVE ||
           m == WM_NCMOUSEMOVE || m == WM_NCMOUSEHOVER || m == WM_NCMOUSELEAVE;
}

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (g_n < LOGN && !input_dependent(m)) {
        unsigned w = 0, l = 0;
        g_hw[g_n] = (h == g_w1) ? 1 : (h == g_w2) ? 2 : (h == g_w3) ? 3 : 0;
        switch (m) {
        case WM_ACTIVATE: w = LOWORD(wp); break;
        case WM_ACTIVATEAPP: case WM_NCACTIVATE: case WM_SHOWWINDOW: w = (unsigned)wp; break;
        case WM_SIZE: w = (unsigned)wp; l = (unsigned)lp; break;
        case WM_WINDOWPOSCHANGING: case WM_WINDOWPOSCHANGED:
            /* flags carry the meaning; SWP_NOCLIENTSIZE/MOVE (0x800/0x1000) are internal */
            w = ((WINDOWPOS *)lp)->flags & 0x7ff; break;
        case WM_USER + 1: case WM_USER + 2: w = (unsigned)wp; l = (unsigned)lp; break;
        }
        g_msg[g_n] = m; g_wp[g_n] = w; g_lp[g_n] = l; g_n++;
    }
    if (m == WM_USER + 2) return 0x1234;
    if (m == WM_CREATE && g_depth == 0) {
        CREATESTRUCTA *cs = (CREATESTRUCTA *)lp;
        put("  WM_CREATE cs: "); puti(cs->cx); put("x"); puti(cs->cy);
        put(" style="); putx((unsigned)cs->style);
        put(" name="); put(cs->lpszName ? cs->lpszName : "(null)");
        put(" param="); putx((unsigned)(ULONG_PTR)cs->lpCreateParams); put("\n");
    }
    return DefWindowProcA(h, m, wp, lp);
}

static void flush(const char *what) {
    int i;
    put(what); put(":");
    for (i = 0; i < g_n; i++) {
        put(" ");
        if (g_hw[i] == 2) put("2:");
        if (g_hw[i] == 3) put("3:");
        putx(g_msg[i]);
        if (g_wp[i] || g_lp[i]) { put("("); putx(g_wp[i]); if (g_lp[i]) { put(","); putx(g_lp[i]); } put(")"); }
    }
    put("\n");
    g_n = 0;
}

static void state(const char *what) {
    put(what);
    put(": active="); putwnd(GetActiveWindow());
    put(" focus="); putwnd(GetFocus());
    /* Another process's window (the oracle's console) may hold the foreground
     * before ours is shown, so only "one of ours or not" is pinned. */
    {
        HWND fg = GetForegroundWindow();
        put(" fg=");
        if (fg && (fg == g_w1 || fg == g_w2 || fg == g_w3)) putwnd(fg); else put("notours");
    }
    put("\n");
}

static void rects(HWND h) {
    RECT r;
    GetClientRect(h, &r);
    put("  client "); puti(r.left); put(","); puti(r.top); put(" "); puti(r.right); put("x"); puti(r.bottom);
    GetWindowRect(h, &r);
    put("  window "); puti(r.right - r.left); put("x"); puti(r.bottom - r.top);
    put(" vis="); putu(IsWindowVisible(h) ? 1 : 0); put("\n");
}

static void pump(const char *what) {
    MSG m;
    int got = 0;
    while (PeekMessageA(&m, 0, 0, 0, PM_REMOVE)) {
        /* only our own posted messages are deterministic; the rest is counted */
        if (m.message >= WM_USER) { put("  peeked "); putx(m.message); put(" hwnd="); putwnd(m.hwnd); put("\n"); }
        else got++;
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
    flush(what);
}

static BOOL CALLBACK enum_cb(HWND h, LPARAM lp) { (void)h; (*(int *)lp)++; return TRUE; }

void probe_main(void) {
    WNDCLASSA wc;
    ATOM a, a2;
    HINSTANCE inst = GetModuleHandleA(0);
    RECT r;
    MSG m;
    char buf[64];
    int n;
    LRESULT lr;

    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    /* --- class registration --- */
    wc.style = CS_HREDRAW | CS_VREDRAW; wc.lpfnWndProc = wndproc; wc.cbClsExtra = 0; wc.cbWndExtra = 0;
    wc.hInstance = inst; wc.hIcon = LoadIconA(0, (LPCSTR)IDI_APPLICATION); wc.hCursor = LoadCursorA(0, (LPCSTR)IDC_ARROW);
    wc.hbrBackground = 0; wc.lpszMenuName = 0; wc.lpszClassName = "WinsProbeClass";
    SetLastError(0);
    a = RegisterClassA(&wc);
    put("RegisterClassA: "); put(a ? "atom" : "0"); put(" atom>=0xc000="); putu(a >= 0xC000); put("\n");
    SetLastError(0);
    a2 = RegisterClassA(&wc);
    put("RegisterClassA again: "); putu(a2); put(" err="); putu(GetLastError()); put("\n");

    /* --- AdjustWindowRect math (system metrics) --- */
    r.left = 0; r.top = 0; r.right = 1280; r.bottom = 720;
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    put("AdjustWindowRect overlapped: "); puti(r.left); put(","); puti(r.top); put(" "); puti(r.right); put(","); puti(r.bottom); put("\n");
    r.left = 0; r.top = 0; r.right = 1280; r.bottom = 720;
    AdjustWindowRectEx(&r, WS_POPUP, FALSE, 0);
    put("AdjustWindowRectEx popup: "); puti(r.left); put(","); puti(r.top); put(" "); puti(r.right); put(","); puti(r.bottom); put("\n");
    r.left = 0; r.top = 0; r.right = 1280; r.bottom = 720;
    AdjustWindowRect(&r, WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    put("AdjustWindowRect caption: "); puti(r.left); put(","); puti(r.top); put(" "); puti(r.right); put(","); puti(r.bottom); put("\n");

    {
        static const struct { const char *what; DWORD style; BOOL menu; DWORD ex; } adj[] = {
            { "caption+menu", WS_CAPTION | WS_SYSMENU, TRUE, 0 },
            { "overlapped+clientedge", WS_OVERLAPPEDWINDOW, FALSE, WS_EX_CLIENTEDGE },
            { "caption+toolwindow", WS_CAPTION, FALSE, WS_EX_TOOLWINDOW },
            { "border", WS_BORDER, FALSE, 0 },
            { "popup+thickframe", WS_POPUP | WS_THICKFRAME, FALSE, 0 },
            { "dlgframe", WS_DLGFRAME, FALSE, 0 },
            { "border+staticedge", WS_BORDER, FALSE, WS_EX_STATICEDGE },
            { "popup+dlgmodalframe", WS_POPUP, FALSE, WS_EX_DLGMODALFRAME },
        };
        unsigned i;
        for (i = 0; i < sizeof adj / sizeof adj[0]; i++) {
            r.left = 0; r.top = 0; r.right = 1280; r.bottom = 720;
            AdjustWindowRectEx(&r, adj[i].style, adj[i].menu, adj[i].ex);
            put("AdjustWindowRectEx "); put(adj[i].what); put(": ");
            puti(r.left); put(","); puti(r.top); put(" "); puti(r.right); put(","); puti(r.bottom); put("\n");
        }
    }

    state("before any window");

    /* --- the temporary 320x240 window (created hidden, destroyed) --- */
    g_n = 0;
    g_w1 = CreateWindowExA(0, "WinsProbeClass", "Probe One", WS_OVERLAPPEDWINDOW,
                           0, 0, 320, 240, 0, 0, inst, (LPVOID)0x5150);
    /* g_w1 is unknown inside the creation messages; they log as hwnd 0 */
    flush("create w1");
    put("w1 created: "); put(g_w1 ? "yes" : "no"); put("\n");
    rects(g_w1);
    state("after create w1");
    put("GetWindowLongA style="); putx((unsigned)GetWindowLongA(g_w1, GWL_STYLE));
    put(" exstyle="); putx((unsigned)GetWindowLongA(g_w1, GWL_EXSTYLE));
    put(" wndproc_is_ours="); putu(GetWindowLongA(g_w1, GWL_WNDPROC) == (LONG)(LONG_PTR)wndproc);
    put(" hinst_is_ours="); putu(GetWindowLongA(g_w1, GWL_HINSTANCE) == (LONG)(LONG_PTR)inst);
    put(" userdata="); putx((unsigned)GetWindowLongA(g_w1, GWL_USERDATA));
    put(" id="); putx((unsigned)GetWindowLongA(g_w1, GWL_ID)); put("\n");
    put("GetClassLongA style="); putx((unsigned)GetClassLongA(g_w1, GCL_STYLE));
    put(" wndproc_is_ours="); putu(GetClassLongA(g_w1, GCLP_WNDPROC) == (DWORD)(ULONG_PTR)wndproc);
    put(" hbr="); putx((unsigned)GetClassLongA(g_w1, GCLP_HBRBACKGROUND)); put("\n");
    n = GetClassNameA(g_w1, buf, sizeof buf); put("GetClassNameA="); puti(n); put(" "); put(buf); put("\n");
    n = GetWindowTextA(g_w1, buf, sizeof buf); put("GetWindowTextA="); puti(n); put(" "); put(buf); put("\n");
    n = GetWindowTextA(g_w1, buf, 5); put("GetWindowTextA(5)="); puti(n); put(" "); put(buf); put("\n");
    flush("text msgs");
    put("SetWindowTextA="); putu(SetWindowTextA(g_w1, "Renamed")); put("\n");
    flush("settext msgs");
    n = GetWindowTextA(g_w1, buf, sizeof buf); put("GetWindowTextA="); puti(n); put(" "); put(buf); put("\n");
    flush("gettext msgs");
    put("FindWindowA(class)="); putwnd(FindWindowA("WinsProbeClass", 0));
    put(" (title)="); putwnd(FindWindowA(0, "Renamed"));
    put(" (both)="); putwnd(FindWindowA("WinsProbeClass", "Renamed"));
    put(" (miss)="); putwnd(FindWindowA("NoSuchClassHere", 0)); put("\n");
    put("GetWindow owner="); putwnd(GetWindow(g_w1, GW_OWNER));
    put(" child="); putwnd(GetWindow(g_w1, GW_CHILD)); put("\n");
    n = 0; put("EnumChildWindows="); putu(EnumChildWindows(g_w1, enum_cb, (LPARAM)&n)); put(" n="); puti(n); put("\n");

    /* --- the queue: posted vs sent --- */
    pump("pump after create");
    put("PostMessageA="); putu(PostMessageA(g_w1, WM_USER + 1, 7, 9)); put("\n");
    flush("post (not yet delivered)");
    put("Peek NOREMOVE="); putu(PeekMessageA(&m, 0, WM_USER, WM_USER + 10, PM_NOREMOVE));
    put(" msg="); putx(m.message); put(" wp="); putu((unsigned)m.wParam); put(" lp="); putu((unsigned)m.lParam);
    put(" hwnd="); putwnd(m.hwnd); put("\n");
    put("Peek filter miss="); putu(PeekMessageA(&m, 0, WM_USER + 5, WM_USER + 10, PM_REMOVE)); put("\n");
    put("Peek REMOVE="); putu(PeekMessageA(&m, 0, WM_USER, WM_USER + 10, PM_REMOVE)); put("\n");
    flush("peek msgs");
    lr = DispatchMessageA(&m);
    put("DispatchMessageA="); putx((unsigned)lr); put("\n");
    flush("dispatch");
    put("Peek empty="); putu(PeekMessageA(&m, 0, WM_USER, WM_USER + 10, PM_REMOVE)); put("\n");
    lr = SendMessageA(g_w1, WM_USER + 2, 3, 4);
    put("SendMessageA="); putx((unsigned)lr); put("\n");
    flush("send");
    put("SendMessageA(bad hwnd)="); putx((unsigned)SendMessageA((HWND)0x1234ab, WM_USER + 2, 0, 0)); put("\n");

    /* --- destroy the temporary window --- */
    put("DestroyWindow="); putu(DestroyWindow(g_w1)); put("\n");
    flush("destroy w1");
    put("IsWindow(w1)="); putu(IsWindow(g_w1)); put("\n");
    state("after destroy w1");
    /* Wine answers ERROR_ACCESS_DENIED here, Windows ERROR_INVALID_WINDOW_HANDLE: only the result is pinned */
    put("DestroyWindow again="); putu(DestroyWindow(g_w1)); put("\n");
    pump("pump after destroy");

    /* --- the game window --- */
    g_w2 = CreateWindowExA(0, "WinsProbeClass", "Probe Game", WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                           CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720, 0, 0, inst, 0);
    flush("create w2");
    rects(g_w2);
    state("after create w2");
    put("ShowWindow(SHOW)="); putu(ShowWindow(g_w2, SW_SHOW)); put("\n");
    flush("show w2");
    state("after show w2");
    rects(g_w2);
    put("ShowWindow(SHOW) again="); putu(ShowWindow(g_w2, SW_SHOW)); put("\n");
    flush("show w2 again");
    put("UpdateWindow="); putu(UpdateWindow(g_w2)); put("\n");
    flush("update w2");
    put("SetForegroundWindow="); putu(SetForegroundWindow(g_w2)); put("\n");
    flush("setfg w2");
    state("after setfg w2");
    pump("pump after show");

    /* --- a second window created already visible (WS_VISIBLE): CreateWindowEx
     * shows it and activation moves inside the process (w2 -> w3 -> back) --- */
    g_w3 = CreateWindowExA(0, "WinsProbeClass", "Probe Visible", WS_POPUP | WS_VISIBLE,
                           0, 0, 640, 480, 0, 0, inst, 0);
    flush("create w3 visible");
    state("after create w3");
    rects(g_w3);
    pump("pump w3");
    put("DestroyWindow(w3)="); putu(DestroyWindow(g_w3)); put("\n");
    flush("destroy w3");
    state("after destroy w3");
    pump("pump after destroy w3");

    put("ShowWindow(HIDE)="); putu(ShowWindow(g_w2, SW_HIDE)); put("\n");
    flush("hide w2");
    state("after hide w2");
    put("ShowWindow(HIDE) again="); putu(ShowWindow(g_w2, SW_HIDE)); put("\n");
    flush("hide w2 again");
    /* Re-showing it is NOT probed: once hidden, the foreground passes to
     * another process's window (the oracle's console) and whether a later
     * ShowWindow may take it back depends on that window, not on this API. */
    put("ShowWindow(SHOWNOACTIVATE)="); putu(ShowWindow(g_w2, SW_SHOWNOACTIVATE)); put("\n");
    flush("shownoactivate w2");
    state("after shownoactivate w2");
    pump("pump after shownoactivate");

    put("SetWindowPos(size)="); putu(SetWindowPos(g_w2, 0, 0, 0, 800, 600, SWP_NOMOVE | SWP_NOZORDER)); put("\n");
    flush("setwindowpos");
    rects(g_w2);
    put("SetWindowPos(topmost)="); putu(SetWindowPos(g_w2, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)); put("\n");
    flush("setwindowpos topmost");
    put("exstyle="); putx((unsigned)GetWindowLongA(g_w2, GWL_EXSTYLE)); put("\n");

    put("DestroyWindow(w2)="); putu(DestroyWindow(g_w2)); put("\n");
    flush("destroy w2");
    state("after destroy w2");

    put("UnregisterClassA="); putu(UnregisterClassA("WinsProbeClass", inst)); put("\n");
    put("CreateWindowExA(unregistered)="); putwnd(CreateWindowExA(0, "WinsProbeClass", "x", WS_POPUP, 0, 0, 1, 1, 0, 0, inst, 0));
    put(" err="); putu(GetLastError()); put("\n");
    ExitProcess(0);
}
