/* Host GL vs Wine pixel oracle for IDirect3DDevice9 clip planes (VS + FF + XYZRHW).
 *
 * Build (no CRT):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main d3d_clipplane_render_probe.c -ld3d9 -luser32 -lkernel32 -o d3d_clipplane_render_probe.exe
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
    wc.lpszClassName = "wins_clip_rprobe";
    if (!RegisterClassA(&wc)) { put("FAIL RegisterClass\n"); ExitProcess(10); }
    HWND hwnd = CreateWindowA("wins_clip_rprobe", "clipr", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
    if (!hwnd) { put("FAIL CreateWindow\n"); ExitProcess(11); }

    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) { put("FAIL Direct3DCreate9\n"); ExitProcess(12); }

    D3DPRESENT_PARAMETERS pp = {0};
    pp.BackBufferWidth = 16;
    pp.BackBufferHeight = 16;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hwnd;
    pp.Windowed = TRUE;

    IDirect3DDevice9 *dev = 0;
    HRESULT hr = IDirect3D9_CreateDevice(d3d, 0, D3DDEVTYPE_HAL, hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
    if (FAILED(hr) || !dev) { put("FAIL CreateDevice "); puthex((unsigned)hr); put("\n"); ExitProcess(13); }

    IDirect3DSurface9 *rt = 0, *sys = 0;
    if (FAILED(IDirect3DDevice9_CreateRenderTarget(dev, 16, 16, D3DFMT_A8R8G8B8, D3DMULTISAMPLE_NONE, 0, FALSE, &rt, 0))) {
        put("FAIL CreateRenderTarget\n"); ExitProcess(14);
    }
    if (FAILED(IDirect3DDevice9_CreateOffscreenPlainSurface(dev, 16, 16, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &sys, 0))) {
        put("FAIL CreateOffscreenPlainSurface\n"); ExitProcess(15);
    }
    IDirect3DDevice9_SetRenderTarget(dev, 0, rt);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZENABLE, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_CULLMODE, D3DCULL_NONE);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_LIGHTING, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_COLORVERTEX, 1);

    static const DWORD vs_tokens[] = {
        0xFFFE0200,
        0x0200001F, 0x80000000, 0x900F0000,
        0x02000001, 0xC00F0000, 0x90E40000,
        0x0000FFFF
    };
    static const DWORD ps_tokens[] = {
        0xFFFF0200,
        0x02000001, 0x800F0800, 0xA0E40000,
        0x0000FFFF
    };
    IDirect3DVertexShader9 *vs = 0;
    IDirect3DPixelShader9 *ps = 0;
    IDirect3DDevice9_CreateVertexShader(dev, vs_tokens, &vs);
    IDirect3DDevice9_CreatePixelShader(dev, ps_tokens, &ps);

    static const D3DVERTEXELEMENT9 decl_elems[] = {
        { 0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
        D3DDECL_END()
    };
    IDirect3DVertexDeclaration9 *vdecl = 0;
    IDirect3DDevice9_CreateVertexDeclaration(dev, decl_elems, &vdecl);

    float ps_red[4] = { 1.0f, 0.0f, 0.0f, 1.0f };
    IDirect3DDevice9_SetPixelShaderConstantF(dev, 0, ps_red, 1);

    static const VPos4 clip_quad[6] = {
        { -1.0f,  1.0f, 0.5f, 1.0f }, {  1.0f,  1.0f, 0.5f, 1.0f }, {  1.0f, -1.0f, 0.5f, 1.0f },
        { -1.0f,  1.0f, 0.5f, 1.0f }, {  1.0f, -1.0f, 0.5f, 1.0f }, { -1.0f, -1.0f, 0.5f, 1.0f },
    };
    char rbuf[17];

    /* Test 1: Programmable VS + clip plane 0 keeping x >= 0 */
    IDirect3DDevice9_SetVertexDeclaration(dev, vdecl);
    IDirect3DDevice9_SetVertexShader(dev, vs);
    IDirect3DDevice9_SetPixelShader(dev, ps);
    {
        D3DMATRIX w, v, p;
        ident_mat(&w); ident_mat(&v); ident_mat(&p);
        w.m[3][0] = 2.0f; v.m[3][0] = -2.0f; p.m[0][0] = 0.25f;
        IDirect3DDevice9_SetTransform(dev, D3DTS_WORLD, &w);
        IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &v);
        IDirect3DDevice9_SetTransform(dev, D3DTS_PROJECTION, &p);
    }
    {
        float p0[4] = { 1.0f, 0.0f, 0.0f, 0.0f };
        IDirect3DDevice9_SetClipPlane(dev, 0, p0);
        IDirect3DDevice9_SetRenderState(dev, 152, 1);
    }
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLELIST, 2, clip_quad, sizeof(VPos4));
    IDirect3DDevice9_EndScene(dev);
    row_mask(dev, rt, sys, 8, rbuf);
    put("VS plane0(x>=0) row8="); put(rbuf); put("\n");

    /* Test 2: Programmable VS + planes 0 and 2 together */
    {
        float p0[4] = { 1.0f, 0.0f, 0.0f, 0.25f };
        float p2[4] = { 0.0f, 1.0f, 0.0f, -0.25f };
        IDirect3DDevice9_SetClipPlane(dev, 0, p0);
        IDirect3DDevice9_SetClipPlane(dev, 2, p2);
        IDirect3DDevice9_SetRenderState(dev, 152, 1u | (1u << 2));
    }
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLELIST, 2, clip_quad, sizeof(VPos4));
    IDirect3DDevice9_EndScene(dev);
    row_mask(dev, rt, sys, 2, rbuf);
    put("VS p0+p2 row2="); put(rbuf); put("\n");
    row_mask(dev, rt, sys, 8, rbuf);
    put("VS p0+p2 row8="); put(rbuf); put("\n");

    /* Test 3: Disabled RS 152 = 0 */
    IDirect3DDevice9_SetRenderState(dev, 152, 0);
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLELIST, 2, clip_quad, sizeof(VPos4));
    IDirect3DDevice9_EndScene(dev);
    row_mask(dev, rt, sys, 8, rbuf);
    put("VS disabled row8="); put(rbuf); put("\n");

    /* Test 4: Pure Fixed-Function VS=NULL, PS=NULL with World/View/Proj */
    IDirect3DDevice9_SetVertexShader(dev, 0);
    IDirect3DDevice9_SetPixelShader(dev, 0);
    IDirect3DDevice9_SetFVF(dev, D3DFVF_XYZ | D3DFVF_DIFFUSE);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLORARG1, D3DTA_DIFFUSE);
    {
        D3DMATRIX w, v, p;
        ident_mat(&w); ident_mat(&v); ident_mat(&p);
        w.m[3][0] = 2.0f;
        v.m[3][0] = -2.0f;
        p.m[0][0] = 0.25f; p.m[1][1] = 0.25f;
        IDirect3DDevice9_SetTransform(dev, D3DTS_WORLD, &w);
        IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &v);
        IDirect3DDevice9_SetTransform(dev, D3DTS_PROJECTION, &p);
    }
    static const VPos3Col ff_quad[6] = {
        { -4.0f,  4.0f, 0.5f, 0xFFFF0000 }, {  4.0f,  4.0f, 0.5f, 0xFFFF0000 }, {  4.0f, -4.0f, 0.5f, 0xFFFF0000 },
        { -4.0f,  4.0f, 0.5f, 0xFFFF0000 }, {  4.0f, -4.0f, 0.5f, 0xFFFF0000 }, { -4.0f, -4.0f, 0.5f, 0xFFFF0000 },
    };
    {
        float p0[4] = { 1.0f, 0.0f, 0.0f, -1.0f };
        IDirect3DDevice9_SetClipPlane(dev, 0, p0);
        IDirect3DDevice9_SetRenderState(dev, 152, 1);
    }
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLELIST, 2, ff_quad, sizeof(VPos3Col));
    IDirect3DDevice9_EndScene(dev);
    row_mask(dev, rt, sys, 8, rbuf);
    put("FF w+2,v-2,p*0.25 plane(x-1>=0) row8="); put(rbuf); put("\n");

    /* Test 5: Pure Fixed-Function with perspective */
    {
        D3DMATRIX w, v, p;
        ident_mat(&w); ident_mat(&v); ident_mat(&p);
        v.m[3][2] = 2.0f;
        p.m[2][3] = 1.0f; p.m[3][3] = 0.0f;
        IDirect3DDevice9_SetTransform(dev, D3DTS_WORLD, &w);
        IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &v);
        IDirect3DDevice9_SetTransform(dev, D3DTS_PROJECTION, &p);
    }
    static const VPos3Col persp_quad[6] = {
        { -4.0f,  4.0f, 2.0f, 0xFFFF0000 }, {  4.0f,  4.0f, 2.0f, 0xFFFF0000 }, {  4.0f, -4.0f, 2.0f, 0xFFFF0000 },
        { -4.0f,  4.0f, 2.0f, 0xFFFF0000 }, {  4.0f, -4.0f, 2.0f, 0xFFFF0000 }, { -4.0f, -4.0f, 2.0f, 0xFFFF0000 },
    };
    {
        float p0[4] = { 1.0f, 0.0f, 0.0f, -1.0f };
        IDirect3DDevice9_SetClipPlane(dev, 0, p0);
        IDirect3DDevice9_SetRenderState(dev, 152, 1);
    }
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLELIST, 2, persp_quad, sizeof(VPos3Col));
    IDirect3DDevice9_EndScene(dev);
    row_mask(dev, rt, sys, 8, rbuf);
    put("FF persp plane(x-1>=0) row8="); put(rbuf); put("\n");

    /* Test 6: Pretransformed XYZRHW */
    IDirect3DDevice9_SetFVF(dev, D3DFVF_XYZRHW | D3DFVF_DIFFUSE);
    static const VRhw rhw_quad[6] = {
        { 0.0f,  0.0f, 0.5f, 1.0f, 0xFFFF0000 }, { 16.0f,  0.0f, 0.5f, 1.0f, 0xFFFF0000 }, { 16.0f, 16.0f, 0.5f, 1.0f, 0xFFFF0000 },
        { 0.0f,  0.0f, 0.5f, 1.0f, 0xFFFF0000 }, { 16.0f, 16.0f, 0.5f, 1.0f, 0xFFFF0000 }, {  0.0f, 16.0f, 0.5f, 1.0f, 0xFFFF0000 },
    };
    {
        float p0[4] = { 1.0f, 0.0f, 0.0f, -8.0f };
        IDirect3DDevice9_SetClipPlane(dev, 0, p0);
        IDirect3DDevice9_SetRenderState(dev, 152, 1);
    }
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLELIST, 2, rhw_quad, sizeof(VRhw));
    IDirect3DDevice9_EndScene(dev);
    row_mask(dev, rt, sys, 8, rbuf);
    put("XYZRHW plane(x-8>=0) row8="); put(rbuf); put("\n");

    IDirect3DVertexDeclaration9_Release(vdecl);
    IDirect3DPixelShader9_Release(ps);
    IDirect3DVertexShader9_Release(vs);
    IDirect3DSurface9_Release(sys);
    IDirect3DSurface9_Release(rt);
    IDirect3DDevice9_Release(dev);
    IDirect3D9_Release(d3d);
    DestroyWindow(hwnd);
    ExitProcess(0);
}
