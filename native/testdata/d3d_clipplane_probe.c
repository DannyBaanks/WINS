/* Wine oracle for IDirect3DDevice9::SetClipPlane / GetClipPlane / D3DRS_CLIPPLANEENABLE.
 *
 * Build (no CRT):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main d3d_clipplane_probe.c -ld3d9 -luser32 -lkernel32 -o d3d_clipplane_probe.exe
 */
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>

static HANDLE g_out;

static void put(const char *s) {
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(g_out, s, n, &w, 0);
}

static void putu(unsigned v) {
    char b[16];
    int i = 15;
    b[i] = 0;
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    put(b + i);
}

static void puthex(unsigned v) {
    char b[11];
    int i;
    b[0] = '0'; b[1] = 'x'; b[10] = 0;
    for (i = 0; i < 8; i++) {
        unsigned d = (v >> (28 - i * 4)) & 0xF;
        b[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    put(b);
}

static unsigned f2u(float f) {
    union { float f; unsigned u; } cv;
    cv.f = f;
    return cv.u;
}

static void row_mask(IDirect3DDevice9 *dev, IDirect3DSurface9 *rt, IDirect3DSurface9 *sys, unsigned row, char out[17]) {
    D3DLOCKED_RECT lr;
    HRESULT hr = IDirect3DDevice9_GetRenderTargetData(dev, rt, sys);
    if (FAILED(hr)) {
        for (int x = 0; x < 16; x++) out[x] = '?';
        out[16] = 0;
        return;
    }
    if (FAILED(IDirect3DSurface9_LockRect(sys, &lr, 0, D3DLOCK_READONLY))) {
        for (int x = 0; x < 16; x++) out[x] = '!';
        out[16] = 0;
        return;
    }
    unsigned *px = (unsigned *)((char *)lr.pBits + row * (unsigned)lr.Pitch);
    for (int x = 0; x < 16; x++) {
        unsigned rgb = px[x] & 0x00FFFFFFu;
        out[x] = (rgb == 0) ? '.' : ((rgb & 0xFF0000u) ? 'R' : 'O');
    }
    out[16] = 0;
    IDirect3DSurface9_UnlockRect(sys);
}

static void col_mask(IDirect3DDevice9 *dev, IDirect3DSurface9 *rt, IDirect3DSurface9 *sys, unsigned col, char out[17]) {
    D3DLOCKED_RECT lr;
    HRESULT hr = IDirect3DDevice9_GetRenderTargetData(dev, rt, sys);
    if (FAILED(hr)) {
        for (int y = 0; y < 16; y++) out[y] = '?';
        out[16] = 0;
        return;
    }
    if (FAILED(IDirect3DSurface9_LockRect(sys, &lr, 0, D3DLOCK_READONLY))) {
        for (int y = 0; y < 16; y++) out[y] = '!';
        out[16] = 0;
        return;
    }
    for (int y = 0; y < 16; y++) {
        unsigned *px = (unsigned *)((char *)lr.pBits + y * (unsigned)lr.Pitch);
        unsigned rgb = px[col] & 0x00FFFFFFu;
        out[y] = (rgb == 0) ? '.' : ((rgb & 0xFF0000u) ? 'R' : 'O');
    }
    out[16] = 0;
    IDirect3DSurface9_UnlockRect(sys);
}

typedef struct { float x, y, z, w; } VPos4;
typedef struct { float x, y, z; DWORD color; } VPos3Col;
typedef struct { float x, y, z, rhw; DWORD color; } VRhw;

static void ident_mat(D3DMATRIX *m) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            m->m[r][c] = (r == c) ? 1.0f : 0.0f;
}

void WINAPI probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(0);
    wc.lpszClassName = "wins_clip_probe";
    if (!RegisterClassA(&wc)) { put("FAIL RegisterClass\n"); ExitProcess(10); }
    HWND hwnd = CreateWindowA("wins_clip_probe", "clip", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
    if (!hwnd) { put("FAIL CreateWindow\n"); ExitProcess(11); }

    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) { put("FAIL Direct3DCreate9\n"); ExitProcess(12); }

    D3DCAPS9 caps;
    HRESULT hr = IDirect3D9_GetDeviceCaps(d3d, 0, D3DDEVTYPE_HAL, &caps);
    put("GetDeviceCaps="); puthex((unsigned)hr);
    put(" MaxUserClipPlanes>=6="); putu(caps.MaxUserClipPlanes >= 6 ? 1u : 0u); put("\n");

    D3DPRESENT_PARAMETERS pp = {0};
    pp.BackBufferWidth = 16;
    pp.BackBufferHeight = 16;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hwnd;
    pp.Windowed = TRUE;

    IDirect3DDevice9 *dev = 0;
    hr = IDirect3D9_CreateDevice(d3d, 0, D3DDEVTYPE_HAL, hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
    if (FAILED(hr) || !dev) { put("FAIL CreateDevice "); puthex((unsigned)hr); put("\n"); ExitProcess(13); }

    DWORD rs = 0xDEADBEEF;
    hr = IDirect3DDevice9_GetRenderState(dev, 152, &rs);
    put("Init RS152 hr="); puthex((unsigned)hr); put(" val="); puthex(rs); put("\n");

    float gp[4] = { 9.0f, 9.0f, 9.0f, 9.0f };
    hr = IDirect3DDevice9_GetClipPlane(dev, 0, gp);
    put("Init GetClipPlane(0) hr="); puthex((unsigned)hr);
    put(" bits="); puthex(f2u(gp[0])); put(","); puthex(f2u(gp[1]));
    put(","); puthex(f2u(gp[2])); put(","); puthex(f2u(gp[3])); put("\n");

    float sp[4] = { 1.5f, -2.25f, 0.5f, 3.0f };
    hr = IDirect3DDevice9_SetClipPlane(dev, 0, 0);
    put("SetClipPlane(0,NULL)="); puthex((unsigned)hr); put("\n");
    hr = IDirect3DDevice9_GetClipPlane(dev, 0, 0);
    put("GetClipPlane(0,NULL)="); puthex((unsigned)hr); put("\n");

    hr = IDirect3DDevice9_SetClipPlane(dev, 3, sp);
    put("SetClipPlane(3)="); puthex((unsigned)hr); put("\n");
    hr = IDirect3DDevice9_SetClipPlane(dev, 5, sp);
    put("SetClipPlane(5)="); puthex((unsigned)hr); put("\n");
    hr = IDirect3DDevice9_SetClipPlane(dev, 6, sp);
    gp[0] = 0; gp[1] = 0; gp[2] = 0; gp[3] = 0;
    HRESULT hr2 = IDirect3DDevice9_GetClipPlane(dev, 6, gp);
    put("SetClipPlane(6)="); puthex((unsigned)hr);
    put(" Get(6)="); puthex((unsigned)hr2); put(" "); puthex(f2u(gp[0])); put("\n");
    hr = IDirect3DDevice9_SetClipPlane(dev, 7, sp);
    gp[0] = 0; gp[1] = 0; gp[2] = 0; gp[3] = 0;
    hr2 = IDirect3DDevice9_GetClipPlane(dev, 7, gp);
    put("SetClipPlane(7)="); puthex((unsigned)hr);
    put(" Get(7)="); puthex((unsigned)hr2); put(" "); puthex(f2u(gp[0])); put("\n");

    hr = IDirect3DDevice9_SetClipPlane(dev, 0, sp);
    put("SetClipPlane(0)="); puthex((unsigned)hr);
    gp[0] = gp[1] = gp[2] = gp[3] = 0.0f;
    hr = IDirect3DDevice9_GetClipPlane(dev, 0, gp);
    put(" readback="); puthex((unsigned)hr);
    put(" "); puthex(f2u(gp[0])); put(","); puthex(f2u(gp[1]));
    put(","); puthex(f2u(gp[2])); put(","); puthex(f2u(gp[3])); put("\n");

    IDirect3DDevice9_SetRenderState(dev, 152, 0xF);
    IDirect3DDevice9_GetRenderState(dev, 152, &rs);
    put("SetRS(152,0xF) -> "); puthex(rs); put("\n");
    IDirect3DDevice9_SetRenderState(dev, 152, 0xFF);
    IDirect3DDevice9_GetRenderState(dev, 152, &rs);
    put("SetRS(152,0xFF) -> "); puthex(rs); put("\n");

    IDirect3DDevice9_Release(dev);
    IDirect3D9_Release(d3d);
    DestroyWindow(hwnd);
    ExitProcess(0);
}
