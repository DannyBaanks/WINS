/*
 * XInput + DirectInput8 parity probe (Wine vs WINS).
 *
 * Build (no CRT):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main input_probe.c -ldinput8 -lkernel32 -o input_probe.exe
 */
#define COBJMACROS
#define DIRECTINPUT_VERSION 0x0800
#include <windows.h>
#include <dinput.h>
#include <xinput.h>

static const GUID MY_IID_IDirectInput8A = { 0xBF798030u, 0x483Au, 0x4DA2u, { 0xAA, 0x99, 0x5D, 0x64, 0xED, 0x36, 0x97, 0x00 } };
static const GUID MY_GUID_XAxis  = { 0xA36D02E0u, 0xC9F3u, 0x11CFu, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
static const GUID MY_GUID_YAxis  = { 0xA36D02E1u, 0xC9F3u, 0x11CFu, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
static const GUID MY_GUID_ZAxis  = { 0xA36D02E2u, 0xC9F3u, 0x11CFu, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
static const DIOBJECTDATAFORMAT my_mouse2_objs[11] = {
    { &MY_GUID_XAxis,  0, DIDFT_AXIS   | DIDFT_ANYINSTANCE, 0 },
    { &MY_GUID_YAxis,  4, DIDFT_AXIS   | DIDFT_ANYINSTANCE, 0 },
    { &MY_GUID_ZAxis,  8, DIDFT_AXIS   | DIDFT_ANYINSTANCE | DIDFT_OPTIONAL, 0 },
    { 0,              12, DIDFT_BUTTON | DIDFT_ANYINSTANCE, 0 },
    { 0,              13, DIDFT_BUTTON | DIDFT_ANYINSTANCE, 0 },
    { 0,              14, DIDFT_BUTTON | DIDFT_ANYINSTANCE | DIDFT_OPTIONAL, 0 },
    { 0,              15, DIDFT_BUTTON | DIDFT_ANYINSTANCE | DIDFT_OPTIONAL, 0 },
    { 0,              16, DIDFT_BUTTON | DIDFT_ANYINSTANCE | DIDFT_OPTIONAL, 0 },
    { 0,              17, DIDFT_BUTTON | DIDFT_ANYINSTANCE | DIDFT_OPTIONAL, 0 },
    { 0,              18, DIDFT_BUTTON | DIDFT_ANYINSTANCE | DIDFT_OPTIONAL, 0 },
    { 0,              19, DIDFT_BUTTON | DIDFT_ANYINSTANCE | DIDFT_OPTIONAL, 0 },
};
static const DIDATAFORMAT my_dfDIMouse2 = {
    sizeof(DIDATAFORMAT), sizeof(DIOBJECTDATAFORMAT), DIDF_RELAXIS, 20, 11, (LPDIOBJECTDATAFORMAT)my_mouse2_objs
};

static HANDLE g_out;

static void put(const char *s) {
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(g_out, s, n, &w, 0);
}

static void puthex(unsigned v) {
    char b[11];
    int i;
    b[0] = '0';
    b[1] = 'x';
    b[10] = 0;
    for (i = 0; i < 8; i++) {
        unsigned d = (v >> (28 - i * 4)) & 0xF;
        b[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    put(b);
}

static void putu(unsigned v) {
    char b[16];
    int i = 15;
    b[i--] = 0;
    if (v == 0) {
        b[i--] = '0';
    } else {
        while (v > 0) {
            b[i--] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    put(&b[i + 1]);
}

static void zmem(void *dst, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)dst;
    while (n--) *p++ = 0;
}

typedef struct {
    unsigned saw_mouse;
    unsigned saw_kb;
    unsigned other;
} EnumDevCtx;

static BOOL CALLBACK enum_dev_cb(LPCDIDEVICEINSTANCEA inst, LPVOID ref) {
    EnumDevCtx *c = (EnumDevCtx *)ref;
    unsigned base = inst->dwDevType & 0xFFu;
    if (inst->guidInstance.Data1 == 0x6F1D2B60u && base == DI8DEVTYPE_MOUSE)
        c->saw_mouse = 1;
    else if (inst->guidInstance.Data1 == 0x6F1D2B61u && base == DI8DEVTYPE_KEYBOARD)
        c->saw_kb = 1;
    else
        c->other++;
    return DIENUM_CONTINUE;
}

typedef struct {
    unsigned count;
    unsigned saw_esc;
    unsigned saw_enter;
} EnumObjCtx;

static BOOL CALLBACK mouse_obj_cb(LPCDIDEVICEOBJECTINSTANCEA obj, LPVOID ref) {
    EnumObjCtx *c = (EnumObjCtx *)ref;
    (void)obj;
    c->count++;
    return DIENUM_CONTINUE;
}

static BOOL CALLBACK kb_obj_cb(LPCDIDEVICEOBJECTINSTANCEA obj, LPVOID ref) {
    EnumObjCtx *c = (EnumObjCtx *)ref;
    c->count++;
    if (obj->dwOfs == DIK_ESCAPE) c->saw_esc = 1;
    if (obj->dwOfs == DIK_RETURN) c->saw_enter = 1;
    return DIENUM_CONTINUE;
}

void WINAPI probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    /* XInput via ordinal resolution on xinput1_3.dll */
    HMODULE xmod = LoadLibraryA("xinput1_3.dll");
    put("xmod="); putu(xmod != 0 ? 1 : 0); put("\n");
    if (xmod) {
        typedef DWORD (WINAPI *FnGetState)(DWORD, XINPUT_STATE *);
        typedef DWORD (WINAPI *FnSetState)(DWORD, XINPUT_VIBRATION *);
        typedef DWORD (WINAPI *FnGetCaps)(DWORD, DWORD, XINPUT_CAPABILITIES *);
        typedef void (WINAPI *FnEnable)(BOOL);
        FnGetState fn_get = (FnGetState)(void *)GetProcAddress(xmod, (LPCSTR)2);
        FnSetState fn_set = (FnSetState)(void *)GetProcAddress(xmod, (LPCSTR)3);
        FnGetCaps fn_caps = (FnGetCaps)(void *)GetProcAddress(xmod, (LPCSTR)4);
        FnEnable fn_en = (FnEnable)(void *)GetProcAddress(xmod, (LPCSTR)5);
        put("xptrs="); putu((fn_get && fn_set && fn_caps && fn_en) ? 1 : 0); put("\n");
        if (fn_en) fn_en(TRUE);
        XINPUT_STATE xs;
        zmem(&xs, sizeof(xs));
        XINPUT_VIBRATION xv;
        zmem(&xv, sizeof(xv));
        XINPUT_CAPABILITIES xc;
        zmem(&xc, sizeof(xc));
        put("xget0="); puthex(fn_get ? fn_get(0, &xs) : 0xDEADu);
        put(" xget4="); puthex(fn_get ? fn_get(4, &xs) : 0xDEADu);
        put(" xgetnull="); puthex(fn_get ? fn_get(0, 0) : 0xDEADu);
        put("\n");
        put("xset0="); puthex(fn_set ? fn_set(0, &xv) : 0xDEADu);
        put(" xset4="); puthex(fn_set ? fn_set(4, &xv) : 0xDEADu);
        put(" xcaps0="); puthex(fn_caps ? fn_caps(0, 0, &xc) : 0xDEADu);
        put(" xcaps4="); puthex(fn_caps ? fn_caps(4, 0, &xc) : 0xDEADu);
        put("\n");
    }

    /* DirectInput8 */
    IDirectInput8A *di = 0;
    HRESULT hr = DirectInput8Create(GetModuleHandleA(0), DIRECTINPUT_VERSION, &MY_IID_IDirectInput8A, (void **)&di, 0);
    put("di_create="); puthex((unsigned)hr); put("\n");
    if (FAILED(hr) || !di) ExitProcess(1);

    put("enum_null="); puthex((unsigned)IDirectInput8_EnumDevices(di, 0, 0, 0, 0)); put("\n");

    EnumDevCtx c_all = {0, 0, 0}, c_ptr = {0, 0, 0}, c_kb = {0, 0, 0};
    IDirectInput8_EnumDevices(di, DI8DEVCLASS_ALL, enum_dev_cb, &c_all, 0);
    IDirectInput8_EnumDevices(di, DI8DEVCLASS_POINTER, enum_dev_cb, &c_ptr, 0);
    IDirectInput8_EnumDevices(di, DI8DEVCLASS_KEYBOARD, enum_dev_cb, &c_kb, 0);
    put("enum_all="); putu(c_all.saw_mouse); put(","); putu(c_all.saw_kb);
    put(" ptr="); putu(c_ptr.saw_mouse); put(","); putu(c_ptr.saw_kb);
    put(" kb="); putu(c_kb.saw_mouse); put(","); putu(c_kb.saw_kb); put("\n");

    GUID g_mouse = { 0x6F1D2B60u, 0xD5A0u, 0x11CFu, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
    GUID g_kb    = { 0x6F1D2B61u, 0xD5A0u, 0x11CFu, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
    GUID g_bad   = { 0x11223344u, 0x5566u, 0x7788u, { 0 } };
    put("stat=");
    puthex((unsigned)IDirectInput8_GetDeviceStatus(di, &g_mouse)); put(",");
    puthex((unsigned)IDirectInput8_GetDeviceStatus(di, &g_kb)); put(",");
    puthex((unsigned)IDirectInput8_GetDeviceStatus(di, &g_bad)); put("\n");

    IDirectInputDevice8A *mdev = 0;
    HRESULT hr_m = IDirectInput8_CreateDevice(di, &g_mouse, &mdev, 0);
    put("m_create="); puthex((unsigned)hr_m);
    if (SUCCEEDED(hr_m) && mdev) {
        DIDEVICEINSTANCEA inst;
        zmem(&inst, sizeof(inst));
        inst.dwSize = sizeof(inst);
        HRESULT hr_info = IDirectInputDevice8_GetDeviceInfo(mdev, &inst);
        EnumObjCtx mo = {0, 0, 0};
        HRESULT hr_eo = IDirectInputDevice8_EnumObjects(mdev, mouse_obj_cb, &mo, 0);
        HRESULT hr_df = IDirectInputDevice8_SetDataFormat(mdev, &my_dfDIMouse2);
        HRESULT hr_aq = IDirectInputDevice8_Acquire(mdev);
        HRESULT hr_pl = IDirectInputDevice8_Poll(mdev);
        HRESULT hr_uq = IDirectInputDevice8_Unacquire(mdev);
        put(" info="); puthex((unsigned)hr_info);
        put(" d1="); puthex((unsigned)inst.guidInstance.Data1);
        put(" eo="); puthex((unsigned)hr_eo); put("/"); putu(mo.count);
        put(" df="); puthex((unsigned)hr_df);
        put(" aq="); puthex((unsigned)hr_aq);
        put(" pl="); puthex((unsigned)hr_pl);
        put(" uq="); puthex((unsigned)hr_uq);
        IDirectInputDevice8_Release(mdev);
    }
    put("\n");

    IDirectInputDevice8A *kdev = 0;
    HRESULT hr_k = IDirectInput8_CreateDevice(di, &g_kb, &kdev, 0);
    put("k_create="); puthex((unsigned)hr_k);
    if (SUCCEEDED(hr_k) && kdev) {
        DIDEVCAPS caps;
        zmem(&caps, sizeof(caps));
        caps.dwSize = sizeof(caps);
        HRESULT hr_cap = IDirectInputDevice8_GetCapabilities(kdev, &caps);
        EnumObjCtx ko = {0, 0, 0};
        HRESULT hr_eo = IDirectInputDevice8_EnumObjects(kdev, kb_obj_cb, &ko, 0);
        put(" cap="); puthex((unsigned)hr_cap);
        put(" type="); puthex((unsigned)(caps.dwDevType & 0xFFu));
        put(" eo="); puthex((unsigned)hr_eo);
        put(" esc="); putu(ko.saw_esc);
        put(" ent="); putu(ko.saw_enter);
        IDirectInputDevice8_Release(kdev);
    }
    put("\n");

    IDirectInput8_Release(di);
    ExitProcess(0);
}
