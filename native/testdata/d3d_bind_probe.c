/* Wine oracle for rebinding the implicit render and depth surfaces.
 * zig cc -target x86-windows-gnu -O1 d3d_bind_probe.c -ld3d9 -lgdi32
 *   -luser32 -o d3d_bind_probe.exe
 * Exit 0 means the backbuffer rebind succeeded, reset the viewport, null RT0
 * failed, and rebinding the implicit depth surface succeeded. Run Wine in an
 * isolated prefix and display. WINS coverage is the corresponding Zig test;
 * this probe has not been run as a PE under WINS.
 */
#define COBJMACROS
#include <windows.h>
#include <d3d9.h>
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR s, int n) {
 (void)p; (void)s; (void)n;
 WNDCLASSA wc = {0}; wc.lpfnWndProc=DefWindowProcA; wc.hInstance=h; wc.lpszClassName="wins_probe";
 if(!RegisterClassA(&wc)) return 10;
 HWND w=CreateWindowA("wins_probe","x",WS_OVERLAPPEDWINDOW,0,0,64,64,0,0,h,0); if(!w) return 11;
 IDirect3D9 *d=Direct3DCreate9(D3D_SDK_VERSION); if(!d) return 12;
 D3DPRESENT_PARAMETERS pp={0}; pp.BackBufferWidth=64; pp.BackBufferHeight=32; pp.BackBufferFormat=D3DFMT_X8R8G8B8; pp.SwapEffect=D3DSWAPEFFECT_DISCARD; pp.hDeviceWindow=w; pp.Windowed=1; pp.EnableAutoDepthStencil=TRUE; pp.AutoDepthStencilFormat=D3DFMT_D24S8;
 IDirect3DDevice9 *dev=0; if(FAILED(IDirect3D9_CreateDevice(d,0,D3DDEVTYPE_HAL,w,D3DCREATE_SOFTWARE_VERTEXPROCESSING,&pp,&dev))) return 13;
 IDirect3DSurface9 *bb=0; if(FAILED(IDirect3DDevice9_GetBackBuffer(dev,0,0,D3DBACKBUFFER_TYPE_MONO,&bb))) return 14;
 D3DVIEWPORT9 vp={0,0,10,10,0,1}; if(FAILED(IDirect3DDevice9_SetViewport(dev,&vp))) return 15;
 if(FAILED(IDirect3DDevice9_SetRenderTarget(dev,0,bb))) return 16;
 if(FAILED(IDirect3DDevice9_GetViewport(dev,&vp))) return 17;
 if(vp.Width!=64 || vp.Height!=32) return 18;
 if(SUCCEEDED(IDirect3DDevice9_SetRenderTarget(dev,0,0))) return 19;
 IDirect3DSurface9 *ds=0; if(FAILED(IDirect3DDevice9_GetDepthStencilSurface(dev,&ds))) return 20;
 if(FAILED(IDirect3DDevice9_SetDepthStencilSurface(dev,ds))) return 21;
 IDirect3DSurface9_Release(ds);
 IDirect3DSurface9_Release(bb); IDirect3DDevice9_Release(dev); IDirect3D9_Release(d); DestroyWindow(w); return 0;
}
