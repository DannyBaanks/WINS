/*
 * DirectSound DuplicateSoundBuffer + IDirectSoundNotify + 3D cone/Doppler parity probe (Wine vs WINS).
 *
 * Build (no CRT):
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main dsound_notify_dup_probe.c -ldsound -luser32 -lkernel32 -o dsound_notify_dup_probe.exe
 */
#define COBJMACROS
#include <windows.h>
#include <dsound.h>

static const GUID MY_IID_IDirectSoundNotify = { 0xB0210783u, 0x89CDu, 0x11D0u, { 0xAF, 0x08, 0x00, 0xA0, 0xC9, 0x25, 0xCD, 0x16 } };
static const GUID MY_IID_IDirectSound3DListener = { 0x279AFA84u, 0x4981u, 0x11CEu, { 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60 } };
static const GUID MY_IID_IDirectSound3DBuffer = { 0x279AFA86u, 0x4981u, 0x11CEu, { 0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60 } };

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
    int i = 0;
    if (v == 0) { put("0"); return; }
    while (v) { b[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i--) {
        char c[2] = { b[i], 0 };
        put(c);
    }
}

static void puti(int v) {
    if (v < 0) {
        put("-");
        putu((unsigned)(-v));
    } else {
        putu((unsigned)v);
    }
}

void WINAPI probe_main(void) {
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    LPDIRECTSOUND8 ds = 0;
    HRESULT hr = DirectSoundCreate8(0, &ds, 0);
    put("ds8="); puthex((unsigned)hr); put("\n");
    if (hr != DS_OK || !ds) ExitProcess(1);

    hr = IDirectSound8_SetCooperativeLevel(ds, GetDesktopWindow(), DSSCL_PRIORITY);
    put("coop="); puthex((unsigned)hr); put("\n");

    DSBUFFERDESC pdesc;
    for (unsigned i = 0; i < sizeof(pdesc); i++) ((unsigned char *)&pdesc)[i] = 0;
    pdesc.dwSize = sizeof(DSBUFFERDESC);
    pdesc.dwFlags = DSBCAPS_PRIMARYBUFFER | DSBCAPS_CTRL3D | DSBCAPS_CTRLVOLUME;

    LPDIRECTSOUNDBUFFER pri = 0;
    hr = IDirectSound8_CreateSoundBuffer(ds, &pdesc, &pri, 0);
    put("pri="); puthex((unsigned)hr); put("\n");

    LPDIRECTSOUND3DLISTENER listener = 0;
    HRESULT hr_l = IDirectSoundBuffer_QueryInterface(pri, &MY_IID_IDirectSound3DListener, (void **)&listener);
    put("listener="); puthex((unsigned)hr_l); put("\n");

    LPDIRECTSOUNDBUFFER dup_pri = 0;
    HRESULT hr_dp = IDirectSound8_DuplicateSoundBuffer(ds, pri, &dup_pri);
    put("dup_pri="); puthex((unsigned)hr_dp); put("\n");

    WAVEFORMATEX wfx;
    for (unsigned i = 0; i < sizeof(wfx); i++) ((unsigned char *)&wfx)[i] = 0;
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = 2;
    wfx.nSamplesPerSec = 44100;
    wfx.wBitsPerSample = 16;
    wfx.nBlockAlign = 4;
    wfx.nAvgBytesPerSec = 44100 * 4;

    DSBUFFERDESC plain_desc;
    for (unsigned i = 0; i < sizeof(plain_desc); i++) ((unsigned char *)&plain_desc)[i] = 0;
    plain_desc.dwSize = sizeof(DSBUFFERDESC);
    plain_desc.dwFlags = DSBCAPS_CTRLVOLUME;
    plain_desc.dwBufferBytes = 17640;
    plain_desc.lpwfxFormat = &wfx;

    LPDIRECTSOUNDBUFFER plain = 0;
    IDirectSound8_CreateSoundBuffer(ds, &plain_desc, &plain, 0);
    LPDIRECTSOUNDNOTIFY plain_n = 0;
    HRESULT hr_pn = IDirectSoundBuffer_QueryInterface(plain, &MY_IID_IDirectSoundNotify, (void **)&plain_n);
    put("plain_notify="); puthex((unsigned)hr_pn); put("\n");
    IDirectSoundBuffer_Release(plain);

    DSBUFFERDESC sdesc = plain_desc;
    sdesc.dwFlags = DSBCAPS_CTRLVOLUME | DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRLPOSITIONNOTIFY | DSBCAPS_GLOBALFOCUS;
    sdesc.dwBufferBytes = 44100; // 250 ms at 44100 * 4 B/s

    LPDIRECTSOUNDBUFFER orig = 0;
    hr = IDirectSound8_CreateSoundBuffer(ds, &sdesc, &orig, 0);
    put("orig="); puthex((unsigned)hr); put("\n");

    IDirectSoundBuffer_SetVolume(orig, -500);
    IDirectSoundBuffer_SetFrequency(orig, 22050);

    void *lp1 = 0;
    DWORD ll1 = 0;
    IDirectSoundBuffer_Lock(orig, 0, 16, &lp1, &ll1, 0, 0, 0);
    ((unsigned char *)lp1)[0] = 0xAA;
    ((unsigned char *)lp1)[5] = 0x55;
    IDirectSoundBuffer_Unlock(orig, lp1, ll1, 0, 0);

    LPDIRECTSOUNDBUFFER dup = 0;
    HRESULT hr_d = IDirectSound8_DuplicateSoundBuffer(ds, orig, &dup);
    LONG vol_dup = 0;
    DWORD freq_dup = 0;
    IDirectSoundBuffer_GetVolume(dup, &vol_dup);
    IDirectSoundBuffer_GetFrequency(dup, &freq_dup);
    void *dp1 = 0;
    DWORD dl1 = 0;
    IDirectSoundBuffer_Lock(dup, 0, 16, &dp1, &dl1, 0, 0, 0);
    unsigned b0 = ((unsigned char *)dp1)[0], b5 = ((unsigned char *)dp1)[5];
    IDirectSoundBuffer_Unlock(dup, dp1, dl1, 0, 0);

    LPDIRECTSOUNDNOTIFY dup_n = 0;
    HRESULT hr_dn = IDirectSoundBuffer_QueryInterface(dup, &MY_IID_IDirectSoundNotify, (void **)&dup_n);
    put("dup="); puthex((unsigned)hr_d);
    put(" vol="); puti((int)vol_dup);
    put(" freq="); putu(freq_dup);
    put(" bytes="); puthex(b0); put(","); puthex(b5);
    put(" qi_notify="); puthex((unsigned)hr_dn); put("\n");
    if (dup_n) IDirectSoundNotify_Release(dup_n);

    LPDIRECTSOUNDNOTIFY notif = 0;
    HRESULT hr_n = IDirectSoundBuffer_QueryInterface(orig, &MY_IID_IDirectSoundNotify, (void **)&notif);
    HANDLE ev_pos = CreateEventA(0, FALSE, FALSE, 0);
    HANDLE ev_stop = CreateEventA(0, FALSE, FALSE, 0);
    DSBPOSITIONNOTIFY posns[2];
    posns[0].dwOffset = 4410; // 50 ms at 22050 Hz * 4 B
    posns[0].hEventNotify = ev_pos;
    posns[1].dwOffset = DSBPN_OFFSETSTOP;
    posns[1].hEventNotify = ev_stop;
    HRESULT hr_sn = IDirectSoundNotify_SetNotificationPositions(notif, 2, posns);
    DWORD w0 = WaitForSingleObject(ev_pos, 0);
    DWORD ws0 = WaitForSingleObject(ev_stop, 0);
    IDirectSoundBuffer_Play(orig, 0, 0, DSBPLAY_LOOPING);
    DWORD w1 = WaitForSingleObject(ev_pos, 2000);
    DWORD ws1 = WaitForSingleObject(ev_stop, 0);
    IDirectSoundBuffer_Stop(orig);
    DWORD ws2 = WaitForSingleObject(ev_stop, 1000);
    put("notify qi="); puthex((unsigned)hr_n);
    put(" set="); puthex((unsigned)hr_sn);
    put(" pre="); putu(w0); put(","); putu(ws0);
    put(" mid="); putu(w1); put(","); putu(ws1);
    put(" stop="); putu(ws2); put("\n");
    IDirectSoundNotify_Release(notif);

    // Original released; duplicate still holds shared backing cleanly.
    IDirectSoundBuffer_Release(orig);
    void *dp2 = 0;
    DWORD dl2 = 0;
    IDirectSoundBuffer_Lock(dup, 0, 16, &dp2, &dl2, 0, 0, 0);
    unsigned b0_after = ((unsigned char *)dp2)[0];
    IDirectSoundBuffer_Unlock(dup, dp2, dl2, 0, 0);
    put("dup_after_release="); puthex(b0_after); put("\n");
    IDirectSoundBuffer_Release(dup);

    // 3D cones + Doppler parameter accessors on listener and primary/3D buffer (mono for DSBCAPS_CTRL3D).
    WAVEFORMATEX wfx_mono = wfx;
    wfx_mono.nChannels = 1;
    wfx_mono.nBlockAlign = 2;
    wfx_mono.nAvgBytesPerSec = 44100 * 2;
    DSBUFFERDESC d3d_desc = plain_desc;
    d3d_desc.dwFlags = DSBCAPS_CTRL3D;
    d3d_desc.lpwfxFormat = &wfx_mono;
    LPDIRECTSOUNDBUFFER b3_buf = 0;
    IDirectSound8_CreateSoundBuffer(ds, &d3d_desc, &b3_buf, 0);
    LPDIRECTSOUND3DBUFFER b3 = 0;
    IDirectSoundBuffer_QueryInterface(b3_buf, &MY_IID_IDirectSound3DBuffer, (void **)&b3);
    DWORD cin = 0, cout_ = 0;
    LONG cvol = 0;
    D3DVALUE dop = 0;
    IDirectSound3DBuffer_SetConeAngles(b3, 45, 90, DS3D_IMMEDIATE);
    IDirectSound3DBuffer_GetConeAngles(b3, &cin, &cout_);
    IDirectSound3DBuffer_SetConeOutsideVolume(b3, -1500, DS3D_IMMEDIATE);
    IDirectSound3DBuffer_GetConeOutsideVolume(b3, &cvol);
    IDirectSound3DListener_SetDopplerFactor(listener, 1.5f, DS3D_IMMEDIATE);
    IDirectSound3DListener_GetDopplerFactor(listener, &dop);
    put("3d cone="); putu(cin); put(","); putu(cout_);
    put(" outvol="); puti((int)cvol);
    put(" dopx10="); putu((unsigned)(dop * 10.0f + 0.5f)); put("\n");

    IDirectSound3DBuffer_Release(b3);
    IDirectSoundBuffer_Release(b3_buf);
    IDirectSound3DListener_Release(listener);
    IDirectSoundBuffer_Release(pri);
    CloseHandle(ev_pos);
    CloseHandle(ev_stop);
    IDirectSound8_Release(ds);
    ExitProcess(0);
}
