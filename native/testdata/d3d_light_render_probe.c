/*
 * Fixed-function vertex lighting pixel differential probe (Host GL vs Wine oracle).
 *
 * Build (no CRT):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main d3d_light_render_probe.c -ld3d9 -luser32 -lkernel32 -o /tmp/d3d_light_render_probe.exe
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

static void puthex6(unsigned v) {
    char b[7];
    for (int i = 0; i < 6; i++) {
        unsigned d = (v >> (20 - i * 4)) & 0xFu;
        b[i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    b[6] = 0;
    put(b);
}

static void zero_mem(void *p, unsigned sz) {
    unsigned char *b = (unsigned char *)p;
    for (unsigned i = 0; i < sz; i++) b[i] = 0;
}

typedef struct {
    float x, y, z;
    float nx, ny, nz;
    DWORD color;
} VLit;

static void ident_mat(D3DMATRIX *m) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            m->m[r][c] = (r == c) ? 1.0f : 0.0f;
}

static DWORD sample_center(IDirect3DDevice9 *dev, IDirect3DSurface9 *rt, IDirect3DSurface9 *sys) {
    D3DLOCKED_RECT lr;
    if (FAILED(IDirect3DDevice9_GetRenderTargetData(dev, rt, sys))) return 0xEEEEEEu;
    if (FAILED(IDirect3DSurface9_LockRect(sys, &lr, 0, D3DLOCK_READONLY))) return 0xDDDDDDu;
    DWORD px = ((DWORD *)((char *)lr.pBits + 8 * lr.Pitch))[8];
    IDirect3DSurface9_UnlockRect(sys);
    return px & 0x00FFFFFFu;
}

static void print_rgb(const char *tag, DWORD rgb) {
    put(tag); put("="); puthex6((unsigned)rgb); put("\n");
}

void WINAPI probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    WNDCLASSA wc;
    zero_mem(&wc, sizeof(wc));
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(0);
    wc.lpszClassName = "wins_d3d_light_render_probe";
    if (!RegisterClassA(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) ExitProcess(10);
    HWND hwnd = CreateWindowA(wc.lpszClassName, "light_rprobe", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
    if (!hwnd) ExitProcess(11);

    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) ExitProcess(12);

    D3DPRESENT_PARAMETERS pp;
    zero_mem(&pp, sizeof(pp));
    pp.BackBufferWidth = 16;
    pp.BackBufferHeight = 16;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.BackBufferCount = 1;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hwnd;
    pp.Windowed = TRUE;

    IDirect3DDevice9 *dev = 0;
    HRESULT hr = IDirect3D9_CreateDevice(d3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                                         D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
    if (FAILED(hr) || !dev) ExitProcess(13);

    IDirect3DSurface9 *rt = 0, *sys = 0;
    IDirect3DDevice9_CreateRenderTarget(dev, 16, 16, D3DFMT_A8R8G8B8, D3DMULTISAMPLE_NONE, 0, FALSE, &rt, 0);
    IDirect3DDevice9_CreateOffscreenPlainSurface(dev, 16, 16, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &sys, 0);
    IDirect3DDevice9_SetRenderTarget(dev, 0, rt);

    D3DMATRIX id;
    ident_mat(&id);
    IDirect3DDevice9_SetTransform(dev, D3DTS_WORLD, &id);
    IDirect3DDevice9_SetTransform(dev, D3DTS_VIEW, &id);
    IDirect3DDevice9_SetTransform(dev, D3DTS_PROJECTION, &id);

    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZENABLE, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_CULLMODE, D3DCULL_NONE);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_LIGHTING, 1);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_AMBIENT, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_SPECULARENABLE, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_COLORVERTEX, 0);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    IDirect3DDevice9_SetTextureStageState(dev, 0, D3DTSS_COLORARG1, D3DTA_DIFFUSE);
    IDirect3DDevice9_SetFVF(dev, D3DFVF_XYZ | D3DFVF_NORMAL | D3DFVF_DIFFUSE);

    static const VLit quad[4] = {
        { -1.0f,  1.0f, 0.0f,  0.0f, 0.0f, -1.0f, 0xFF00FF00u },
        {  1.0f,  1.0f, 0.0f,  0.0f, 0.0f, -1.0f, 0xFF00FF00u },
        { -1.0f, -1.0f, 0.0f,  0.0f, 0.0f, -1.0f, 0xFF00FF00u },
        {  1.0f, -1.0f, 0.0f,  0.0f, 0.0f, -1.0f, 0xFF00FF00u },
    };

    D3DMATERIAL9 mat;
    zero_mem(&mat, sizeof(mat));
    mat.Diffuse.r = 1.0f; mat.Diffuse.g = 0.5f; mat.Diffuse.b = 0.25f; mat.Diffuse.a = 1.0f;
    mat.Ambient.r = 1.0f; mat.Ambient.g = 1.0f; mat.Ambient.b = 1.0f; mat.Ambient.a = 1.0f;
    IDirect3DDevice9_SetMaterial(dev, &mat);

    /* Case 1: Directional light facing (0,0,1) -> dot(N,L)=1 -> (255, 128, 64) */
    D3DLIGHT9 dir;
    zero_mem(&dir, sizeof(dir));
    dir.Type = D3DLIGHT_DIRECTIONAL;
    dir.Diffuse.r = 1.0f; dir.Diffuse.g = 1.0f; dir.Diffuse.b = 1.0f; dir.Diffuse.a = 1.0f;
    dir.Direction.z = 1.0f;
    IDirect3DDevice9_SetLight(dev, 0, &dir);
    IDirect3DDevice9_LightEnable(dev, 0, TRUE);

    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VLit));
    IDirect3DDevice9_EndScene(dev);
    print_rgb("dir_full", sample_center(dev, rt, sys));

    /* Case 2: Angled directional light -> dot(N,L)=0.5 -> (128, 64, 32) */
    dir.Direction.x = 0.8660254f; dir.Direction.y = 0.0f; dir.Direction.z = 0.5f;
    IDirect3DDevice9_SetLight(dev, 0, &dir);
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VLit));
    IDirect3DDevice9_EndScene(dev);
    print_rgb("dir_half", sample_center(dev, rt, sys));

    /* Case 3: Ambient + Emissive only (light disabled) */
    IDirect3DDevice9_LightEnable(dev, 0, FALSE);
    D3DMATERIAL9 mat_amb;
    zero_mem(&mat_amb, sizeof(mat_amb));
    mat_amb.Ambient.r = 0.5f; mat_amb.Ambient.g = 0.0f; mat_amb.Ambient.b = 0.0f; mat_amb.Ambient.a = 1.0f;
    mat_amb.Emissive.r = 0.0f; mat_amb.Emissive.g = 0.25f; mat_amb.Emissive.b = 0.0f; mat_amb.Emissive.a = 1.0f;
    IDirect3DDevice9_SetMaterial(dev, &mat_amb);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_AMBIENT, 0x00808080u);
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VLit));
    IDirect3DDevice9_EndScene(dev);
    print_rgb("amb_emissive", sample_center(dev, rt, sys));

    /* Case 4: COLORVERTEX + DIFFUSEMATERIALSOURCE = COLOR1 */
    IDirect3DDevice9_SetRenderState(dev, D3DRS_AMBIENT, 0);
    IDirect3DDevice9_SetMaterial(dev, &mat);
    dir.Direction.x = 0.0f; dir.Direction.y = 0.0f; dir.Direction.z = 1.0f;
    IDirect3DDevice9_SetLight(dev, 0, &dir);
    IDirect3DDevice9_LightEnable(dev, 0, TRUE);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_COLORVERTEX, 1);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_DIFFUSEMATERIALSOURCE, D3DMCS_COLOR1);
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VLit));
    IDirect3DDevice9_EndScene(dev);
    print_rgb("colorvertex_diffuse", sample_center(dev, rt, sys));

    /* Case 5: Point light with 1/d attenuation at z=-2 (att = 0.5) */
    IDirect3DDevice9_SetRenderState(dev, D3DRS_COLORVERTEX, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_DIFFUSEMATERIALSOURCE, D3DMCS_MATERIAL);
    D3DLIGHT9 pt;
    zero_mem(&pt, sizeof(pt));
    pt.Type = D3DLIGHT_POINT;
    pt.Diffuse.r = 1.0f; pt.Diffuse.g = 1.0f; pt.Diffuse.b = 1.0f; pt.Diffuse.a = 1.0f;
    pt.Position.z = -2.0f;
    pt.Range = 10.0f;
    pt.Attenuation1 = 1.0f;
    IDirect3DDevice9_SetLight(dev, 0, &pt);
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VLit));
    IDirect3DDevice9_EndScene(dev);
    print_rgb("point_half", sample_center(dev, rt, sys));

    /* Case 6: Spot light inside vs outside cone */
    D3DLIGHT9 spot;
    zero_mem(&spot, sizeof(spot));
    spot.Type = D3DLIGHT_SPOT;
    spot.Diffuse.r = 1.0f; spot.Diffuse.g = 1.0f; spot.Diffuse.b = 1.0f; spot.Diffuse.a = 1.0f;
    spot.Position.z = -2.0f;
    spot.Direction.z = 1.0f;
    spot.Range = 10.0f;
    spot.Attenuation0 = 1.0f;
    spot.Falloff = 1.0f;
    spot.Theta = 1.0f;
    spot.Phi = 2.0f;
    IDirect3DDevice9_SetLight(dev, 0, &spot);
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VLit));
    IDirect3DDevice9_EndScene(dev);
    print_rgb("spot_inside", sample_center(dev, rt, sys));

    spot.Direction.x = 1.0f; spot.Direction.z = 0.0f;
    IDirect3DDevice9_SetLight(dev, 0, &spot);
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(VLit));
    IDirect3DDevice9_EndScene(dev);
    print_rgb("spot_outside", sample_center(dev, rt, sys));

    IDirect3DSurface9_Release(sys);
    IDirect3DSurface9_Release(rt);
    IDirect3DDevice9_Release(dev);
    IDirect3D9_Release(d3d);
    DestroyWindow(hwnd);
    ExitProcess(0);
}
