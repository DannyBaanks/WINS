/* Wine oracle for IDirect3DCubeTexture9, IDirect3DVolumeTexture9, IDirect3DVolume9,
 * CheckDeviceFormat for CUBE/VOLUME, cube/volume sampling, and D3DXCreate*FromFileInMemory.
 *
 * Build (no CRT):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main d3d_cube_vol_probe.c -ld3d9 -luser32 -lkernel32 -o d3d_cube_vol_probe.exe
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

typedef struct { float x, y, z, w; float u, v, s, q; } VPosTex;

static void draw_sample_and_print(
    IDirect3DDevice9 *dev,
    IDirect3DSurface9 *rt,
    IDirect3DSurface9 *sys,
    float tx, float ty, float tz,
    const char *label
) {
    VPosTex q[6] = {
        { -1,  1, 0.5f, 1, tx, ty, tz, 0 }, {  1,  1, 0.5f, 1, tx, ty, tz, 0 }, {  1, -1, 0.5f, 1, tx, ty, tz, 0 },
        { -1,  1, 0.5f, 1, tx, ty, tz, 0 }, {  1, -1, 0.5f, 1, tx, ty, tz, 0 }, { -1, -1, 0.5f, 1, tx, ty, tz, 0 },
    };
    IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF000000, 1.0f, 0);
    IDirect3DDevice9_BeginScene(dev);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLELIST, 2, q, sizeof(VPosTex));
    IDirect3DDevice9_EndScene(dev);
    D3DLOCKED_RECT lr;
    unsigned px = 0x11223344;
    if (SUCCEEDED(IDirect3DDevice9_GetRenderTargetData(dev, rt, sys)) &&
        SUCCEEDED(IDirect3DSurface9_LockRect(sys, &lr, 0, D3DLOCK_READONLY))) {
        unsigned *row = (unsigned *)((char *)lr.pBits + 4 * (unsigned)lr.Pitch);
        px = row[4];
        IDirect3DSurface9_UnlockRect(sys);
    }
    put(label); put("="); puthex(px & 0x00FFFFFFu); put("\n");
}

typedef struct {
    DWORD Width, Height, Depth, MipLevels, Format, ResourceType, ImageFileFormat;
} MY_D3DXIMAGE_INFO;

typedef HRESULT (WINAPI *PFN_D3DXGetImageInfo)(LPCVOID, UINT, MY_D3DXIMAGE_INFO *);
typedef HRESULT (WINAPI *PFN_D3DXCreateCube)(IDirect3DDevice9 *, LPCVOID, UINT, IDirect3DCubeTexture9 **);
typedef HRESULT (WINAPI *PFN_D3DXCreateVol)(IDirect3DDevice9 *, LPCVOID, UINT, IDirect3DVolumeTexture9 **);

static void write_u32(unsigned char *dst, unsigned v) {
    dst[0] = (unsigned char)(v & 0xFF);
    dst[1] = (unsigned char)((v >> 8) & 0xFF);
    dst[2] = (unsigned char)((v >> 16) & 0xFF);
    dst[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void init_argb_dds(unsigned char *hdr, unsigned w, unsigned h, unsigned d, unsigned mips, unsigned caps, unsigned caps2) {
    for (int i = 0; i < 128; i++) hdr[i] = 0;
    hdr[0] = 'D'; hdr[1] = 'D'; hdr[2] = 'S'; hdr[3] = ' ';
    write_u32(hdr + 4, 124);          /* dwSize */
    write_u32(hdr + 8, 0x1007 | (d > 1 ? 0x800000u : 0) | (mips > 1 ? 0x20000u : 0)); /* dwFlags */
    write_u32(hdr + 12, h);           /* dwHeight */
    write_u32(hdr + 16, w);           /* dwWidth */
    write_u32(hdr + 20, w * 4);       /* dwPitchOrLinearSize */
    write_u32(hdr + 24, d);           /* dwDepth */
    write_u32(hdr + 28, mips);        /* dwMipMapCount */
    write_u32(hdr + 76, 32);          /* ddspf.dwSize */
    write_u32(hdr + 80, 0x41);        /* DDPF_RGB | DDPF_ALPHAPIXELS */
    write_u32(hdr + 88, 32);          /* dwRGBBitCount */
    write_u32(hdr + 92, 0x00FF0000u); /* R mask */
    write_u32(hdr + 96, 0x0000FF00u); /* G mask */
    write_u32(hdr + 100, 0x000000FFu);/* B mask */
    write_u32(hdr + 104, 0xFF000000u);/* A mask */
    write_u32(hdr + 108, caps);       /* dwCaps */
    write_u32(hdr + 112, caps2);      /* dwCaps2 */
}

void WINAPI probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(0);
    wc.lpszClassName = "wins_cv_probe";
    if (!RegisterClassA(&wc)) ExitProcess(10);
    HWND hwnd = CreateWindowA("wins_cv_probe", "cv", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
    if (!hwnd) ExitProcess(11);

    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) ExitProcess(12);

    put("CDF cube A8R8G8B8="); puthex((unsigned)IDirect3D9_CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_CUBETEXTURE, D3DFMT_A8R8G8B8)); put("\n");
    put("CDF cube DXT1="); puthex((unsigned)IDirect3D9_CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_CUBETEXTURE, D3DFMT_DXT1)); put("\n");
    put("CDF cube RT="); puthex((unsigned)IDirect3D9_CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DUSAGE_RENDERTARGET, D3DRTYPE_CUBETEXTURE, D3DFMT_A8R8G8B8)); put("\n");
    put("CDF vol A8R8G8B8="); puthex((unsigned)IDirect3D9_CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_VOLUMETEXTURE, D3DFMT_A8R8G8B8)); put("\n");
    put("CDF vol DXT5="); puthex((unsigned)IDirect3D9_CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_VOLUMETEXTURE, D3DFMT_DXT5)); put("\n");
    put("CDF vol RT="); puthex((unsigned)IDirect3D9_CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, D3DUSAGE_RENDERTARGET, D3DRTYPE_VOLUMETEXTURE, D3DFMT_A8R8G8B8)); put("\n");

    D3DPRESENT_PARAMETERS pp = {0};
    pp.BackBufferWidth = 8;
    pp.BackBufferHeight = 8;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hwnd;
    pp.Windowed = TRUE;

    IDirect3DDevice9 *dev = 0;
    HRESULT hr = IDirect3D9_CreateDevice(d3d, 0, D3DDEVTYPE_HAL, hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);
    if (FAILED(hr) || !dev) ExitProcess(13);

    IDirect3DCubeTexture9 *ct = 0;
    hr = IDirect3DDevice9_CreateCubeTexture(dev, 0, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &ct, 0);
    put("CreateCube(0)="); puthex((unsigned)hr); put("\n");
    hr = IDirect3DDevice9_CreateCubeTexture(dev, 4, 0, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &ct, 0);
    put("CreateCube(4,0)="); puthex((unsigned)hr);
    put(" type="); putu(IDirect3DCubeTexture9_GetType(ct));
    put(" levels="); putu(IDirect3DCubeTexture9_GetLevelCount(ct)); put("\n");

    D3DSURFACE_DESC sdesc = {0};
    hr = IDirect3DCubeTexture9_GetLevelDesc(ct, 1, &sdesc);
    put("CubeGetLevelDesc(1)="); puthex((unsigned)hr);
    put(" type="); putu(sdesc.Type);
    put(" w="); putu(sdesc.Width); put(" h="); putu(sdesc.Height); put("\n");

    IDirect3DSurface9 *face_bad = 0, *face0 = 0;
    hr = IDirect3DCubeTexture9_GetCubeMapSurface(ct, 6, 0, &face_bad);
    put("GetCubeMapSurface(6)="); puthex((unsigned)hr); put("\n");
    hr = IDirect3DCubeTexture9_GetCubeMapSurface(ct, D3DCUBEMAP_FACE_POSITIVE_X, 0, &face0);
    put("GetCubeMapSurface(0)="); puthex((unsigned)hr);
    put(" surfType="); putu(IDirect3DSurface9_GetType(face0)); put("\n");
    IDirect3DSurface9_GetDesc(face0, &sdesc);
    put("FaceDesc type="); putu(sdesc.Type); put(" w="); putu(sdesc.Width); put("\n");
    IDirect3DSurface9_Release(face0);

    static const DWORD face_colors[6] = {
        0xFFFF0000u, /* +X red */
        0xFF00FF00u, /* -X green */
        0xFF0000FFu, /* +Y blue */
        0xFFFFFF00u, /* -Y yellow */
        0xFFFF00FFu, /* +Z magenta */
        0xFF00FFFFu, /* -Z cyan */
    };
    for (UINT f = 0; f < 6; f++) {
        D3DLOCKED_RECT lr;
        if (SUCCEEDED(IDirect3DCubeTexture9_LockRect(ct, (D3DCUBEMAP_FACES)f, 0, &lr, 0, 0))) {
            for (UINT y = 0; y < 4; y++) {
                DWORD *row = (DWORD *)((char *)lr.pBits + y * (unsigned)lr.Pitch);
                for (UINT x = 0; x < 4; x++) row[x] = face_colors[f];
            }
            IDirect3DCubeTexture9_UnlockRect(ct, (D3DCUBEMAP_FACES)f, 0);
        }
    }

    IDirect3DVolumeTexture9 *vt = 0;
    hr = IDirect3DDevice9_CreateVolumeTexture(dev, 0, 4, 4, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &vt, 0);
    put("CreateVol(0)="); puthex((unsigned)hr); put("\n");
    hr = IDirect3DDevice9_CreateVolumeTexture(dev, 4, 4, 4, 0, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &vt, 0);
    put("CreateVol(4,4,4,0)="); puthex((unsigned)hr);
    put(" type="); putu(IDirect3DVolumeTexture9_GetType(vt));
    put(" levels="); putu(IDirect3DVolumeTexture9_GetLevelCount(vt)); put("\n");

    D3DVOLUME_DESC vdesc = {0};
    hr = IDirect3DVolumeTexture9_GetLevelDesc(vt, 1, &vdesc);
    put("VolGetLevelDesc(1)="); puthex((unsigned)hr);
    put(" type="); putu(vdesc.Type);
    put(" w="); putu(vdesc.Width); put(" h="); putu(vdesc.Height); put(" d="); putu(vdesc.Depth); put("\n");

    IDirect3DVolume9 *vol0 = 0;
    hr = IDirect3DVolumeTexture9_GetVolumeLevel(vt, 0, &vol0);
    put("GetVolumeLevel(0)="); puthex((unsigned)hr);
    IDirect3DVolume9_GetDesc(vol0, &vdesc);
    put(" vtype="); putu(vdesc.Type); put(" vd="); putu(vdesc.Depth); put("\n");

    D3DLOCKED_BOX lb = {0};
    hr = IDirect3DVolume9_LockBox(vol0, &lb, 0, 0);
    put("VolLockBox="); puthex((unsigned)hr);
    put(" rp="); putu((unsigned)lb.RowPitch); put(" sp="); putu((unsigned)lb.SlicePitch); put("\n");
    if (SUCCEEDED(hr)) {
        static const DWORD slice_cols[4] = { 0xFFFF0000u, 0xFF00FF00u, 0xFF0000FFu, 0xFFFFFFFFu };
        for (UINT z = 0; z < 4; z++) {
            char *sl = (char *)lb.pBits + z * (unsigned)lb.SlicePitch;
            for (UINT y = 0; y < 4; y++) {
                DWORD *row = (DWORD *)(sl + y * (unsigned)lb.RowPitch);
                for (UINT x = 0; x < 4; x++) row[x] = slice_cols[z];
            }
        }
        IDirect3DVolume9_UnlockBox(vol0);
    }
    IDirect3DVolume9_Release(vol0);

    /* Render tests for Cube and Volume shaders */
    IDirect3DSurface9 *rt = 0, *sys = 0;
    IDirect3DDevice9_CreateRenderTarget(dev, 8, 8, D3DFMT_A8R8G8B8, D3DMULTISAMPLE_NONE, 0, FALSE, &rt, 0);
    IDirect3DDevice9_CreateOffscreenPlainSurface(dev, 8, 8, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &sys, 0);
    IDirect3DDevice9_SetRenderTarget(dev, 0, rt);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZENABLE, 0);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_CULLMODE, D3DCULL_NONE);

    /* vs_2_0: dcl_position v0; dcl_texcoord0 v1; mov oPos, v0; mov oT0, v1; end */
    static const DWORD vs_tokens[] = {
        0xFFFE0200,
        0x0200001F, 0x80000000, 0x900F0000,
        0x0200001F, 0x80000005, 0x900F0001,
        0x02000001, 0xC00F0000, 0x90E40000,
        0x02000001, 0xE00F0000, 0x90E40001,
        0x0000FFFF
    };
    /* ps_2_0 cube: dcl t0.xyz; dcl_cube s0; texld r0, t0, s0; mov oC0, r0; end */
    static const DWORD ps_cube_tokens[] = {
        0xFFFF0200,
        0x0200001F, 0x80000000, 0xB00F0000,
        0x0200001F, 0x98000000, 0xA00F0800,
        0x03000042, 0x800F0000, 0xB0E40000, 0xA0E40800,
        0x02000001, 0x800F0800, 0x80E40000,
        0x0000FFFF
    };
    /* ps_2_0 vol: dcl t0.xyz; dcl_volume s0; texld r0, t0, s0; mov oC0, r0; end */
    static const DWORD ps_vol_tokens[] = {
        0xFFFF0200,
        0x0200001F, 0x80000000, 0xB00F0000,
        0x0200001F, 0xA0000000, 0xA00F0800,
        0x03000042, 0x800F0000, 0xB0E40000, 0xA0E40800,
        0x02000001, 0x800F0800, 0x80E40000,
        0x0000FFFF
    };
    IDirect3DVertexShader9 *vs = 0;
    IDirect3DPixelShader9 *ps_cube = 0, *ps_vol = 0;
    IDirect3DDevice9_CreateVertexShader(dev, vs_tokens, &vs);
    IDirect3DDevice9_CreatePixelShader(dev, ps_cube_tokens, &ps_cube);
    IDirect3DDevice9_CreatePixelShader(dev, ps_vol_tokens, &ps_vol);

    static const D3DVERTEXELEMENT9 decl_elems[] = {
        { 0,  0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 },
        { 0, 16, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0 },
        D3DDECL_END()
    };
    IDirect3DVertexDeclaration9 *vdecl = 0;
    IDirect3DDevice9_CreateVertexDeclaration(dev, decl_elems, &vdecl);
    IDirect3DDevice9_SetVertexDeclaration(dev, vdecl);
    IDirect3DDevice9_SetVertexShader(dev, vs);
    IDirect3DDevice9_SetSamplerState(dev, 0, D3DSAMP_MAGFILTER, D3DTEXF_POINT);
    IDirect3DDevice9_SetSamplerState(dev, 0, D3DSAMP_MINFILTER, D3DTEXF_POINT);
    IDirect3DDevice9_SetSamplerState(dev, 0, D3DSAMP_MIPFILTER, D3DTEXF_NONE);

    IDirect3DDevice9_SetPixelShader(dev, ps_cube);
    IDirect3DDevice9_SetTexture(dev, 0, (IDirect3DBaseTexture9 *)ct);
    draw_sample_and_print(dev, rt, sys,  1,  0,  0, "CUBE(+X)");
    draw_sample_and_print(dev, rt, sys, -1,  0,  0, "CUBE(-X)");
    draw_sample_and_print(dev, rt, sys,  0,  1,  0, "CUBE(+Y)");
    draw_sample_and_print(dev, rt, sys,  0, -1,  0, "CUBE(-Y)");
    draw_sample_and_print(dev, rt, sys,  0,  0,  1, "CUBE(+Z)");
    draw_sample_and_print(dev, rt, sys,  0,  0, -1, "CUBE(-Z)");

    IDirect3DDevice9_SetPixelShader(dev, ps_vol);
    IDirect3DDevice9_SetTexture(dev, 0, (IDirect3DBaseTexture9 *)vt);
    draw_sample_and_print(dev, rt, sys, 0.5f, 0.5f, 0.125f, "VOL(z0)");
    draw_sample_and_print(dev, rt, sys, 0.5f, 0.5f, 0.375f, "VOL(z1)");
    draw_sample_and_print(dev, rt, sys, 0.5f, 0.5f, 0.625f, "VOL(z2)");
    draw_sample_and_print(dev, rt, sys, 0.5f, 0.5f, 0.875f, "VOL(z3)");

    /* Cube RenderTarget test */
    IDirect3DCubeTexture9 *ct_rt = 0;
    if (SUCCEEDED(IDirect3DDevice9_CreateCubeTexture(dev, 4, 1, D3DUSAGE_RENDERTARGET, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT, &ct_rt, 0))) {
        IDirect3DSurface9 *crt = 0;
        if (SUCCEEDED(IDirect3DCubeTexture9_GetCubeMapSurface(ct_rt, D3DCUBEMAP_FACE_NEGATIVE_X, 0, &crt))) {
            IDirect3DDevice9_SetRenderTarget(dev, 0, crt);
            IDirect3DDevice9_Clear(dev, 0, 0, D3DCLEAR_TARGET, 0xFF00AA55u, 1.0f, 0);
            IDirect3DDevice9_SetRenderTarget(dev, 0, rt);
            IDirect3DDevice9_SetPixelShader(dev, ps_cube);
            IDirect3DDevice9_SetTexture(dev, 0, (IDirect3DBaseTexture9 *)ct_rt);
            draw_sample_and_print(dev, rt, sys, -1, 0, 0, "CUBE_RT(-X)");
            IDirect3DSurface9_Release(crt);
        }
        IDirect3DCubeTexture9_Release(ct_rt);
    }

    /* D3DXCreateCubeTextureFromFileInMemory & Volume from DDS */
    HMODULE d3dx = LoadLibraryA("d3dx9_38.dll");
    if (!d3dx) d3dx = LoadLibraryA("d3dx9_43.dll");
    if (d3dx) {
        PFN_D3DXGetImageInfo pInfo = (PFN_D3DXGetImageInfo)GetProcAddress(d3dx, "D3DXGetImageInfoFromFileInMemory");
        PFN_D3DXCreateCube pCube = (PFN_D3DXCreateCube)GetProcAddress(d3dx, "D3DXCreateCubeTextureFromFileInMemory");
        PFN_D3DXCreateVol pVol = (PFN_D3DXCreateVol)GetProcAddress(d3dx, "D3DXCreateVolumeTextureFromFileInMemory");
        unsigned char dds_cube[128 + 24];
        init_argb_dds(dds_cube, 1, 1, 1, 1, 0x1008u, 0xFE00u); /* CAPS=COMPLEX|TEXTURE, CAPS2=CUBEMAP|ALLFACES */
        for (int i = 0; i < 6; i++) write_u32(dds_cube + 128 + i * 4, face_colors[i]);
        MY_D3DXIMAGE_INFO info = {0};
        if (pInfo) {
            hr = pInfo(dds_cube, sizeof(dds_cube), &info);
            put("D3DXInfoCube="); puthex((unsigned)hr); put(" rtype="); putu(info.ResourceType); put(" w="); putu(info.Width); put("\n");
        }
        if (pCube) {
            IDirect3DCubeTexture9 *dc = 0;
            hr = pCube(dev, dds_cube, sizeof(dds_cube), &dc);
            put("D3DXCreateCube="); puthex((unsigned)hr);
            if (SUCCEEDED(hr) && dc) {
                put(" type="); putu(IDirect3DCubeTexture9_GetType(dc)); put("\n");
                IDirect3DDevice9_SetPixelShader(dev, ps_cube);
                IDirect3DDevice9_SetTexture(dev, 0, (IDirect3DBaseTexture9 *)dc);
                draw_sample_and_print(dev, rt, sys, 0, 1, 0, "D3DX_CUBE(+Y)");
                IDirect3DCubeTexture9_Release(dc);
            } else put("\n");
        }
        unsigned char dds_vol[128 + 32];
        init_argb_dds(dds_vol, 2, 2, 2, 1, 0x1008u, 0x200000u); /* CAPS2=VOLUME */
        for (int i = 0; i < 4; i++) write_u32(dds_vol + 128 + i * 4, 0xFF112233u);
        for (int i = 4; i < 8; i++) write_u32(dds_vol + 128 + i * 4, 0xFF445566u);
        if (pInfo) {
            hr = pInfo(dds_vol, sizeof(dds_vol), &info);
            put("D3DXInfoVol="); puthex((unsigned)hr); put(" rtype="); putu(info.ResourceType); put(" d="); putu(info.Depth); put("\n");
        }
        if (pVol) {
            IDirect3DVolumeTexture9 *dv = 0;
            hr = pVol(dev, dds_vol, sizeof(dds_vol), &dv);
            put("D3DXCreateVol="); puthex((unsigned)hr);
            if (SUCCEEDED(hr) && dv) {
                put(" type="); putu(IDirect3DVolumeTexture9_GetType(dv)); put("\n");
                IDirect3DDevice9_SetPixelShader(dev, ps_vol);
                IDirect3DDevice9_SetTexture(dev, 0, (IDirect3DBaseTexture9 *)dv);
                draw_sample_and_print(dev, rt, sys, 0.5f, 0.5f, 0.25f, "D3DX_VOL(0)");
                draw_sample_and_print(dev, rt, sys, 0.5f, 0.5f, 0.75f, "D3DX_VOL(1)");
                IDirect3DVolumeTexture9_Release(dv);
            } else put("\n");
        }
    }

    IDirect3DDevice9_SetTexture(dev, 0, 0);
    IDirect3DVolumeTexture9_Release(vt);
    IDirect3DCubeTexture9_Release(ct);
    IDirect3DVertexDeclaration9_Release(vdecl);
    IDirect3DPixelShader9_Release(ps_vol);
    IDirect3DPixelShader9_Release(ps_cube);
    IDirect3DVertexShader9_Release(vs);
    IDirect3DSurface9_Release(sys);
    IDirect3DSurface9_Release(rt);
    IDirect3DDevice9_Release(dev);
    IDirect3D9_Release(d3d);
    DestroyWindow(hwnd);
    ExitProcess(0);
}
