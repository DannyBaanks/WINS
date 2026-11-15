/*
 * D3D9 light-state probe. Compare the HRESULTs and returned state under Wine
 * and WINS. The high light index mirrors the value observed at FalloutNV's
 * IDirect3DDevice9::SetLight call site; it is not assumed to be valid.
 *
 * Build with Zig's i686 Windows target and d3d9 import library. This fixture
 * never reads or writes the Fallout installation or its saves.
 */
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>
#include <stdio.h>
#include <string.h>

static HWND make_window(HINSTANCE instance) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = instance;
    wc.lpszClassName = "wins_d3d_light_probe";
    if (!RegisterClassA(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return 0;
    return CreateWindowA(wc.lpszClassName, "probe", WS_OVERLAPPEDWINDOW,
                         0, 0, 64, 64, 0, 0, instance, 0);
}

int main(void) {
    HINSTANCE instance = GetModuleHandleA(0);
    HWND window = make_window(instance);
    if (!window) return 10;

    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) return 11;

    D3DPRESENT_PARAMETERS pp = {0};
    pp.BackBufferWidth = 64;
    pp.BackBufferHeight = 32;
    pp.BackBufferFormat = D3DFMT_X8R8G8B8;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = window;
    pp.Windowed = TRUE;
    pp.EnableAutoDepthStencil = TRUE;
    pp.AutoDepthStencilFormat = D3DFMT_D24S8;

    IDirect3DDevice9 *device = 0;
    HRESULT create_hr = IDirect3D9_CreateDevice(
        d3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, window,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &device);
    printf("create=%08lx\n", (unsigned long)create_hr);
    if (FAILED(create_hr)) return 12;

    D3DLIGHT9 light = {0};
    light.Type = D3DLIGHT_POINT;
    light.Diffuse.r = 0.25f;
    light.Diffuse.g = 0.5f;
    light.Diffuse.b = 0.75f;
    light.Diffuse.a = 1.0f;
    light.Position.x = 1.0f;
    light.Range = 20.0f;
    light.Attenuation0 = 1.0f;

    D3DLIGHT9 readback = {0};
    HRESULT set_zero = IDirect3DDevice9_SetLight(device, 0, &light);
    HRESULT get_zero = IDirect3DDevice9_GetLight(device, 0, &readback);
    printf("zero=%08lx,%08lx,%u\n", (unsigned long)set_zero,
           (unsigned long)get_zero,
           (unsigned)(memcmp(&light, &readback, sizeof(light)) == 0));

    HRESULT enable_zero = IDirect3DDevice9_LightEnable(device, 0, TRUE);
    BOOL enabled_zero = FALSE;
    HRESULT get_enable_zero = IDirect3DDevice9_GetLightEnable(device, 0, &enabled_zero);
    printf("enable_zero=%08lx,%08lx,%u\n", (unsigned long)enable_zero,
           (unsigned long)get_enable_zero, (unsigned)enabled_zero);

    const DWORD observed_index = 0x0b002488;
    D3DLIGHT9 permissive_input = light;
    permissive_input.Type = 0xfedcba98;
    D3DLIGHT9 observed_readback = {0};
    HRESULT set_observed = IDirect3DDevice9_SetLight(device, observed_index, &permissive_input);
    HRESULT get_observed = IDirect3DDevice9_GetLight(device, observed_index, &observed_readback);
    HRESULT enable_observed = IDirect3DDevice9_LightEnable(device, observed_index, TRUE);
    printf("observed_index=%08lx,%08lx,%08lx,%u\n", (unsigned long)set_observed,
           (unsigned long)get_observed, (unsigned long)enable_observed,
           (unsigned)(memcmp(&permissive_input, &observed_readback, sizeof(permissive_input)) == 0));

    IDirect3DDevice9_Release(device);
    IDirect3D9_Release(d3d);
    DestroyWindow(window);
    return 0;
}
