/*
 * D3D9 StateBlock, UpdateSurface, UpdateTexture, and Device Reset differential probe.
 *
 * Build (no CRT):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main d3d_state_update_reset_probe.c -ld3d9 -luser32 -lkernel32 -o /tmp/d3d_state_update_reset_probe.exe
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
    char b[9];
    for (int i = 0; i < 8; i++) {
        unsigned d = (v >> (28 - i * 4)) & 0xFu;
        b[i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    b[8] = 0;
    put(b);
}

static void putu(unsigned v) {
    char b[16];
    int n = 0;
    if (v == 0) { put("0"); return; }
    while (v) { b[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    for (int i = 0; i < n / 2; i++) { char t = b[i]; b[i] = b[n - 1 - i]; b[n - 1 - i] = t; }
    b[n] = 0;
    put(b);
}

static void puti(int v) {
    if (v < 0) { put("-"); putu((unsigned)(-v)); }
    else putu((unsigned)v);
}

typedef struct {
    float x, y, z, rhw;
    float u, v;
} VTexRhw;

static void ident_mat(D3DMATRIX *m) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            m->m[r][c] = (r == c) ? 1.0f : 0.0f;
}

static void zero_mem(void *p, unsigned sz) {
    unsigned char *b = (unsigned char *)p;
    for (unsigned i = 0; i < sz; i++) b[i] = 0;
}

void WINAPI probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    WNDCLASSA wc;
    zero_mem(&wc, sizeof(wc));
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(0);
    wc.lpszClassName = "wins_d3d_state_reset_probe";
    if (!RegisterClassA(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) ExitProcess(10);
    HWND hwnd = CreateWindowA(wc.lpszClassName, "probe", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
    if (!hwnd) ExitProcess(11);

    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) ExitProcess(12);

    D3DPRESENT_PARAMETERS pp;
    zero_mem(&pp, sizeof(pp));
    pp.BackBufferWidth = 64;
    pp.BackBufferHeight = 48;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.BackBufferCount = 1;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hwnd;
    pp.Windowed = TRUE;
    pp.EnableAutoDepthStencil = TRUE;
    pp.AutoDepthStencilFormat = D3DFMT_D24S8;

    IDirect3DDevice9 *dev = 0;
    HRESULT hr = IDirect3D9_CreateDevice(d3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                                         D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
    put("create="); puthex((unsigned)hr); put("\n");
    if (FAILED(hr) || !dev) ExitProcess(13);

    /* 1. BeginStateBlock / EndStateBlock isolation + partial Apply */
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZENABLE, 1);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZWRITEENABLE, 0);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLOROP, D3DTOP_MODULATE);
    D3DMATRIX mv_live, mv_rec, mv_out;
    ident_mat(&mv_live); mv_live.m[3][0] = 10.0f;
    IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &mv_live);

    HRESULT hr_begin = IDirect3DDevice9_BeginStateBlock(dev);
    HRESULT hr_begin2 = IDirect3DDevice9_BeginStateBlock(dev);
    IDirect3DStateBlock9 *sb_fail = 0;
    HRESULT hr_csb_rec = IDirect3DDevice9_CreateStateBlock(dev, D3DSBT_ALL, &sb_fail);

    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZWRITEENABLE, 1);
    ident_mat(&mv_rec); mv_rec.m[3][0] = 42.0f;
    IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &mv_rec);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    D3DLIGHT9 light;
    zero_mem(&light, sizeof(light));
    light.Type = D3DLIGHT_DIRECTIONAL;
    light.Diffuse.r = 1.0f; light.Diffuse.g = 0.5f; light.Diffuse.b = 0.25f; light.Diffuse.a = 1.0f;
    light.Direction.z = 1.0f;
    IDirect3DDevice9_SetLight(dev, 1, &light);
    IDirect3DDevice9_LightEnable(dev, 1, TRUE);

    IDirect3DStateBlock9 *sb_rec = 0;
    HRESULT hr_end = IDirect3DDevice9_EndStateBlock(dev, &sb_rec);

    DWORD zw_during = 999, zen_after = 999, zw_after = 999, tss_after = 999;
    IDirect3DDevice9_GetRenderState(dev, D3DRS_ZWRITEENABLE, &zw_during);
    IDirect3DDevice9_GetTransform(dev, D3DTS_VIEW, &mv_out);
    int view_unchanged = (mv_out.m[3][0] == 10.0f);

    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZENABLE, 0);
    HRESULT hr_apply = IDirect3DStateBlock9_Apply(sb_rec);
    IDirect3DDevice9_GetRenderState(dev, D3DRS_ZENABLE, &zen_after);
    IDirect3DDevice9_GetRenderState(dev, D3DRS_ZWRITEENABLE, &zw_after);
    IDirect3DDevice9_GetTextureStageState(dev, 0, D3DTSS_COLOROP, &tss_after);
    IDirect3DDevice9_GetTransform(dev, D3DTS_VIEW, &mv_out);
    BOOL len1 = FALSE;
    IDirect3DDevice9_GetLightEnable(dev, 1, &len1);
    put("sb_rec=");
    puthex((unsigned)hr_begin); put(","); puthex((unsigned)hr_begin2); put(",");
    puthex((unsigned)hr_csb_rec); put(","); puthex((unsigned)hr_end); put(",");
    putu(zw_during); put(","); puti(view_unchanged); put(",");
    puthex((unsigned)hr_apply); put(",");
    putu(zen_after); put(","); putu(zw_after); put(","); putu(tss_after); put(",");
    puti((int)mv_out.m[3][0]); put(","); puti(len1 ? 1 : 0); put("\n");
    IDirect3DStateBlock9_Release(sb_rec);

    /* 2. CreateStateBlock PIXELSTATE vs ALL Capture & Apply */
    IDirect3DStateBlock9 *sb_pix = 0, *sb_all = 0;
    HRESULT hr_pix = IDirect3DDevice9_CreateStateBlock(dev, D3DSBT_PIXELSTATE, &sb_pix);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZWRITEENABLE, 0);
    HRESULT hr_cap = IDirect3DStateBlock9_Capture(sb_pix);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZWRITEENABLE, 1);
    mv_rec.m[3][0] = 99.0f;
    IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &mv_rec);
    IDirect3DStateBlock9_Apply(sb_pix);
    IDirect3DDevice9_GetRenderState(dev, D3DRS_ZWRITEENABLE, &zw_after);
    IDirect3DDevice9_GetTransform(dev, D3DTS_VIEW, &mv_out);

    HRESULT hr_all = IDirect3DDevice9_CreateStateBlock(dev, D3DSBT_ALL, &sb_all);
    mv_rec.m[3][0] = 5.0f;
    IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &mv_rec);
    IDirect3DDevice9_LightEnable(dev, 1, FALSE);
    IDirect3DStateBlock9_Apply(sb_all);
    D3DMATRIX mv_all_out;
    IDirect3DDevice9_GetTransform(dev, D3DTS_VIEW, &mv_all_out);
    IDirect3DDevice9_GetLightEnable(dev, 1, &len1);
    put("sb_cap=");
    puthex((unsigned)hr_pix); put(","); puthex((unsigned)hr_cap); put(",");
    putu(zw_after); put(","); puti((int)mv_out.m[3][0]); put(",");
    puthex((unsigned)hr_all); put(","); puti((int)mv_all_out.m[3][0]); put(",");
    puti(len1 ? 1 : 0); put("\n");
    IDirect3DStateBlock9_Release(sb_pix);
    IDirect3DStateBlock9_Release(sb_all);

    /* 3. UpdateSurface + UpdateTexture */
    IDirect3DSurface9 *sys_src = 0, *sys_rb = 0, *rt_def = 0;
    IDirect3DDevice9_CreateOffscreenPlainSurface(dev, 8, 8, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &sys_src, 0);
    IDirect3DDevice9_CreateOffscreenPlainSurface(dev, 8, 8, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &sys_rb, 0);
    IDirect3DDevice9_CreateRenderTarget(dev, 8, 8, D3DFMT_A8R8G8B8, D3DMULTISAMPLE_NONE, 0, FALSE, &rt_def, 0);

    D3DLOCKED_RECT lr;
    if (SUCCEEDED(IDirect3DSurface9_LockRect(sys_src, &lr, 0, 0))) {
        for (int y = 0; y < 8; y++) {
            DWORD *row = (DWORD *)((char *)lr.pBits + y * lr.Pitch);
            for (int x = 0; x < 8; x++) row[x] = 0xFF000000u | ((DWORD)y << 8) | (DWORD)x;
        }
        IDirect3DSurface9_UnlockRect(sys_src);
    }
    RECT srect = { 1, 2, 4, 5 };
    POINT dpt = { 3, 1 };
    HRESULT hr_us = IDirect3DDevice9_UpdateSurface(dev, sys_src, &srect, rt_def, &dpt);
    HRESULT hr_us_rev = IDirect3DDevice9_UpdateSurface(dev, rt_def, 0, sys_src, 0);
    IDirect3DDevice9_GetRenderTargetData(dev, rt_def, sys_rb);
    DWORD px_us_0 = 0, px_us_1 = 0;
    if (SUCCEEDED(IDirect3DSurface9_LockRect(sys_rb, &lr, 0, D3DLOCK_READONLY))) {
        px_us_0 = ((DWORD *)((char *)lr.pBits + 1 * lr.Pitch))[3];
        px_us_1 = ((DWORD *)((char *)lr.pBits + 3 * lr.Pitch))[5];
        IDirect3DSurface9_UnlockRect(sys_rb);
    }
    put("update_surf=");
    puthex((unsigned)hr_us); put(","); puthex((unsigned)hr_us_rev); put(",");
    puthex((unsigned)(px_us_0 & 0x00FFFFFFu)); put(",");
    puthex((unsigned)(px_us_1 & 0x00FFFFFFu)); put("\n");

    IDirect3DTexture9 *sys_tex = 0, *def_tex = 0;
    IDirect3DDevice9_CreateTexture(dev, 4, 4, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &sys_tex, 0);
    IDirect3DDevice9_CreateTexture(dev, 4, 4, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT, &def_tex, 0);
    if (SUCCEEDED(IDirect3DTexture9_LockRect(sys_tex, 0, &lr, 0, 0))) {
        for (int y = 0; y < 4; y++) {
            DWORD *row = (DWORD *)((char *)lr.pBits + y * lr.Pitch);
            for (int x = 0; x < 4; x++) row[x] = 0xFF112233u;
        }
        IDirect3DTexture9_UnlockRect(sys_tex, 0);
    }
    HRESULT hr_ut = IDirect3DDevice9_UpdateTexture(dev, (IDirect3DBaseTexture9 *)sys_tex, (IDirect3DBaseTexture9 *)def_tex);
    HRESULT hr_ut_rev = IDirect3DDevice9_UpdateTexture(dev, (IDirect3DBaseTexture9 *)def_tex, (IDirect3DBaseTexture9 *)sys_tex);

    IDirect3DDevice9_SetRenderTarget(dev, 0, rt_def);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZENABLE, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_LIGHTING, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_CULLMODE, D3DCULL_NONE);
    IDirect3DDevice9_SetTexture(dev, 0, (IDirect3DBaseTexture9 *)def_tex);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    IDirect3DDevice9_SetSamplerState(dev, 0, D3DSAMP_MAGFILTER, D3DTEXF_POINT);
    IDirect3DDevice9_SetSamplerState(dev, 0, D3DSAMP_MINFILTER, D3DTEXF_POINT);
    IDirect3DDevice9_SetFVF(dev, D3DFVF_XYZRHW | D3DFVF_TEX1);
    static const VTexRhw quad[4] = {
        { -0.5f, -0.5f, 0.5f, 1.0f, 0.0f, 0.0f },
        {  7.5f, -0.5f, 0.5f, 1.0f, 1.0f, 0.0f },
        { -0.5f,  7.5f, 0.5f, 1.0f, 0.0f, 1.0f },
        {  7.5f,  7.5f, 0.5f, 1.0f, 1.0f, 1.0f },
    };
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000u, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VTexRhw));
    IDirect3DDevice9_EndScene(dev);
    IDirect3DDevice9_SetTexture(dev, 0, 0);
    IDirect3DDevice9_GetRenderTargetData(dev, rt_def, sys_rb);
    DWORD px_ut = 0;
    if (SUCCEEDED(IDirect3DSurface9_LockRect(sys_rb, &lr, 0, D3DLOCK_READONLY))) {
        px_ut = ((DWORD *)((char *)lr.pBits + 4 * lr.Pitch))[4];
        IDirect3DSurface9_UnlockRect(sys_rb);
    }
    put("update_tex=");
    puthex((unsigned)hr_ut); put(","); puthex((unsigned)hr_ut_rev); put(",");
    puthex((unsigned)(px_ut & 0x00FFFFFFu)); put("\n");

    IDirect3DSurface9 *bb0 = 0;
    IDirect3DDevice9_GetBackBuffer(dev, 0, 0, D3DBACKBUFFER_TYPE_MONO, &bb0);
    IDirect3DDevice9_SetRenderTarget(dev, 0, bb0);
    IDirect3DSurface9_Release(bb0);
    IDirect3DTexture9_Release(def_tex);
    IDirect3DTexture9_Release(sys_tex);
    IDirect3DSurface9_Release(rt_def);
    IDirect3DSurface9_Release(sys_rb);
    IDirect3DSurface9_Release(sys_src);

    /* 4. Reset gates + reset & resize verification */
    D3DPRESENT_PARAMETERS pp2 = pp;
    pp2.BackBufferWidth = 128;
    pp2.BackBufferHeight = 96;

    IDirect3DVertexBuffer9 *def_vb = 0;
    IDirect3DDevice9_CreateVertexBuffer(dev, 64, 0, 0, D3DPOOL_DEFAULT, &def_vb, 0);
    HRESULT hr_rst_vb = IDirect3DDevice9_Reset(dev, &pp2);
    IDirect3DVertexBuffer9_Release(def_vb);

    IDirect3DSurface9 *extra_bb = 0;
    IDirect3DDevice9_GetBackBuffer(dev, 0, 0, D3DBACKBUFFER_TYPE_MONO, &extra_bb);
    HRESULT hr_rst_bb = IDirect3DDevice9_Reset(dev, &pp2);
    IDirect3DSurface9_Release(extra_bb);

    HRESULT hr_rst_ok = IDirect3DDevice9_Reset(dev, &pp2);
    IDirect3DSurface9 *new_bb = 0;
    D3DSURFACE_DESC bdesc;
    zero_mem(&bdesc, sizeof(bdesc));
    DWORD px_after_rst = 0;
    if (SUCCEEDED(hr_rst_ok) && SUCCEEDED(IDirect3DDevice9_GetBackBuffer(dev, 0, 0, D3DBACKBUFFER_TYPE_MONO, &new_bb)) && new_bb) {
        IDirect3DSurface9_GetDesc(new_bb, &bdesc);
        IDirect3DSurface9 *rb2 = 0;
        if (SUCCEEDED(IDirect3DDevice9_CreateOffscreenPlainSurface(dev, bdesc.Width, bdesc.Height, bdesc.Format, D3DPOOL_SYSTEMMEM, &rb2, 0)) && rb2) {
            IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF123456u, 1.0f, 0);
            if (SUCCEEDED(IDirect3DDevice9_GetRenderTargetData(dev, new_bb, rb2)) &&
                SUCCEEDED(IDirect3DSurface9_LockRect(rb2, &lr, 0, D3DLOCK_READONLY))) {
                px_after_rst = ((DWORD *)((char *)lr.pBits + 90 * lr.Pitch))[120] & 0x00FFFFFFu;
                IDirect3DSurface9_UnlockRect(rb2);
            }
            IDirect3DSurface9_Release(rb2);
        }
        IDirect3DSurface9_Release(new_bb);
    }

    DWORD lighting_rst = 999, scissor_rst = 999;
    IDirect3DDevice9_GetRenderState(dev, D3DRS_LIGHTING, &lighting_rst);
    IDirect3DDevice9_GetRenderState(dev, D3DRS_SCISSORTESTENABLE, &scissor_rst);
    IDirect3DDevice9_GetTransform(dev, D3DTS_VIEW, &mv_out);
    BOOL len1_after = TRUE;
    HRESULT hr_l1_after = IDirect3DDevice9_GetLightEnable(dev, 1, &len1_after);
    D3DVIEWPORT9 vp;
    zero_mem(&vp, sizeof(vp));
    IDirect3DDevice9_GetViewport(dev, &vp);
    put("reset=");
    puthex((unsigned)hr_rst_vb); put(","); puthex((unsigned)hr_rst_bb); put(",");
    puthex((unsigned)hr_rst_ok); put(",");
    putu(bdesc.Width); put("x"); putu(bdesc.Height); put(",");
    putu(vp.Width); put("x"); putu(vp.Height); put(",");
    putu(lighting_rst); put(","); putu(scissor_rst); put(",");
    puti((int)mv_out.m[3][0]); put(","); puthex((unsigned)hr_l1_after); put(",");
    puthex((unsigned)px_after_rst); put("\n");

    IDirect3DDevice9_Release(dev);
    IDirect3D9_Release(d3d);
    DestroyWindow(hwnd);
    ExitProcess(0);
}
