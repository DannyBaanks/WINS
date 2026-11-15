/* dshow_probe: deterministic DirectShow filter-graph probe (i386, no CRT).
 *
 * Built like filecase_probe.c, plus ole32:
 *   ZIGLIB="$(dirname "$(readlink -f "$(command -v zig)")")/lib"
 *   zig cc -target x86-windows-gnu -nostdlib -O1 -fno-builtin \
 *       -isystem "$ZIGLIB/libc/include/any-windows-any" \
 *       -L"$ZIGLIB/libc/mingw/lib32" \
 *       -Wl,--entry=probe_main dshow_probe.c -lkernel32 -lole32 -o dshow_probe.exe
 *
 * Run it under Wine (the oracle) and under winrun32 and compare stdout and the
 * exit code byte for byte (tools/diff_wine.sh).
 *
 * Why: FalloutNV plays its music through DirectShow with ITS OWN source
 * filter (Proton +quartz trace, 2026-11-13): CoCreateInstance(CLSID_FilterGraph)
 * -> AddFilter(own filter, NULL) (the filter QIs the graph for
 * IMediaEventSink, as CBaseFilter::JoinFilterGraph does) -> Render(own output
 * pin, MEDIATYPE_Stream / MEDIASUBTYPE_MPEG1Audio, pulled through
 * IAsyncReader) -> QI IMediaControl / IMediaEvent / IMediaPosition /
 * IBasicAudio -> put_Volume fades, Pause, Run, then GetEvent(0) and
 * duration/position polls every frame. This probe is that client, with the
 * source filter written the way the DirectShow base classes write one
 * (CBaseFilter, CBasePin::Connect, CAsyncOutputPin), over an embedded MP3
 * fixture shaped like the game's (dshow_fixture_mp3.h).
 *
 * Output is deterministic: HRESULTs, booleans, and times in whole
 * milliseconds; no pointers, no wall-clock values.
 */
#include <windows.h>
#include <dshow.h>
#include "dshow_fixture_mp3.h"

static HANDLE g_out;
static void put(const char *s) {
    DWORD n = 0, w;
    while (s[n]) n++;
    WriteFile(g_out, s, n, &w, 0);
}
static void puti(long v) {
    char b[24]; int i = 23; unsigned long u = v < 0 ? (unsigned long)-v : (unsigned long)v;
    b[i] = 0;
    if (u == 0) b[--i] = '0';
    while (u) { b[--i] = (char)('0' + u % 10); u /= 10; }
    if (v < 0) b[--i] = '-';
    put(b + i);
}
static void putx(unsigned long v) {
    char b[16]; int i = 15; const char *h = "0123456789abcdef";
    b[i] = 0;
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = h[v & 15]; v >>= 4; }
    put("0x"); put(b + i);
}
static void line_hr(const char *tag, HRESULT hr) { put("H|"); put(tag); put("|"); putx((unsigned long)hr); put("\n"); }
static void line_i(const char *tag, long v) { put("I|"); put(tag); put("|"); puti(v); put("\n"); }

static int geq(const GUID *a, const GUID *b) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    int i;
    for (i = 0; i < 16; i++) if (x[i] != y[i]) return 0;
    return 1;
}
/* 64-bit division without the CRT helper (__divdi3): shift-subtract. */
static LONGLONG sdiv64(LONGLONG a, LONGLONG b) {
    int neg = (a < 0) != (b < 0);
    unsigned long long n = a < 0 ? (unsigned long long)-a : (unsigned long long)a;
    unsigned long long d = b < 0 ? (unsigned long long)-b : (unsigned long long)b;
    unsigned long long q = 0, r = 0;
    int i;
    for (i = 63; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1);
        if (r >= d) { r -= d; q |= 1ULL << i; }
    }
    return neg ? -(LONGLONG)q : (LONGLONG)q;
}
static const GUID G_GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
static void zero(void *p, unsigned n) { unsigned char *c = p; while (n--) *c++ = 0; }

static const GUID G_CLSID_FilterGraph = {0xe436ebb3, 0x524f, 0x11ce, {0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IUnknown = {0x00000000, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID G_IID_IPersist = {0x0000010c, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID G_IID_IFilterGraph = {0x56a8689f, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IGraphBuilder = {0x56a868a9, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IMediaEventSink = {0x56a868a2, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IMediaControl = {0x56a868b1, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IMediaPosition = {0x56a868b2, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IBasicAudio = {0x56a868b3, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IMediaEvent = {0x56a868b6, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IMediaEventEx = {0x56a868c0, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IMediaSeeking = {0x36b73880, 0xc2c8, 0x11cf, {0x8b, 0x46, 0x00, 0x80, 0x5f, 0x6c, 0xef, 0x60}};
static const GUID G_IID_IMediaFilter = {0x56a86899, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IBaseFilter = {0x56a86895, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IPin = {0x56a86891, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IEnumPins = {0x56a86892, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_IID_IEnumMediaTypes = {0x89c31040, 0x846b, 0x11ce, {0x97, 0xd3, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a}};
static const GUID G_IID_IAsyncReader = {0x56a868aa, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_MEDIATYPE_Stream = {0xe436eb83, 0x524f, 0x11ce, {0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_MEDIASUBTYPE_MPEG1Audio = {0xe436eb87, 0x524f, 0x11ce, {0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}};
static const GUID G_TIME_FORMAT_MEDIA_TIME = {0x7b785574, 0x8c82, 0x11cf, {0xbc, 0x0c, 0x00, 0xaa, 0x00, 0xac, 0x74, 0xf6}};
static const GUID G_CLSID_Probe = {0x1badf00d, 0x0001, 0x0002, {0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}};

/* ---- the source filter, CBaseFilter style -------------------------------- */
typedef struct Src Src;
typedef struct { IPin iface; Src *f; IPin *peer; AM_MEDIA_TYPE mt; } OutPin;
typedef struct { IAsyncReader iface; Src *f; } Reader;
typedef struct { IEnumPins iface; LONG refs; Src *f; int pos; } EnumP;
typedef struct { IEnumMediaTypes iface; LONG refs; int pos; } EnumMT;
struct Src {
    IBaseFilter iface;
    LONG refs;
    IFilterGraph *graph; /* weak, as CBaseFilter::JoinFilterGraph keeps it */
    int joined, sink_qi_ok, left_graph;
    FILTER_STATE state;
    IReferenceClock *clock;
    OutPin pin;
    Reader reader;
    int sync_reads, requests;
};
static Src g_src;
static WCHAR g_name[64];

static void fill_mt(AM_MEDIA_TYPE *mt) {
    zero(mt, sizeof(*mt));
    mt->majortype = G_MEDIATYPE_Stream;
    mt->subtype = G_MEDIASUBTYPE_MPEG1Audio;
    mt->bFixedSizeSamples = TRUE;
    mt->lSampleSize = 1;
}

/* IEnumMediaTypes over our one type */
static HRESULT STDMETHODCALLTYPE emt_qi(IEnumMediaTypes *t, REFIID r, void **o) {
    if (geq(r, &G_IID_IUnknown) || geq(r, &G_IID_IEnumMediaTypes)) { *o = t; t->lpVtbl->AddRef(t); return S_OK; }
    *o = 0; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE emt_addref(IEnumMediaTypes *t) { return ++((EnumMT *)t)->refs; }
static ULONG STDMETHODCALLTYPE emt_release(IEnumMediaTypes *t) {
    EnumMT *e = (EnumMT *)t; ULONG r = --e->refs;
    if (!r) CoTaskMemFree(e);
    return r;
}
static HRESULT STDMETHODCALLTYPE emt_next(IEnumMediaTypes *t, ULONG n, AM_MEDIA_TYPE **out, ULONG *got) {
    EnumMT *e = (EnumMT *)t; ULONG k = 0;
    while (k < n && e->pos < 1) {
        AM_MEDIA_TYPE *m = CoTaskMemAlloc(sizeof(*m));
        fill_mt(m);
        out[k++] = m; e->pos++;
    }
    if (got) *got = k;
    return k == n ? S_OK : S_FALSE;
}
static HRESULT STDMETHODCALLTYPE emt_skip(IEnumMediaTypes *t, ULONG n) { EnumMT *e = (EnumMT *)t; e->pos += n; return e->pos <= 1 ? S_OK : S_FALSE; }
static HRESULT STDMETHODCALLTYPE emt_reset(IEnumMediaTypes *t) { ((EnumMT *)t)->pos = 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE emt_clone(IEnumMediaTypes *t, IEnumMediaTypes **o);
static IEnumMediaTypesVtbl emt_vtbl = { emt_qi, emt_addref, emt_release, emt_next, emt_skip, emt_reset, emt_clone };
static IEnumMediaTypes *emt_new(int pos) {
    EnumMT *e = CoTaskMemAlloc(sizeof(*e));
    e->iface.lpVtbl = &emt_vtbl; e->refs = 1; e->pos = pos;
    return &e->iface;
}
static HRESULT STDMETHODCALLTYPE emt_clone(IEnumMediaTypes *t, IEnumMediaTypes **o) { *o = emt_new(((EnumMT *)t)->pos); return S_OK; }

/* IEnumPins over our one pin */
static HRESULT STDMETHODCALLTYPE ep_qi(IEnumPins *t, REFIID r, void **o) {
    if (geq(r, &G_IID_IUnknown) || geq(r, &G_IID_IEnumPins)) { *o = t; t->lpVtbl->AddRef(t); return S_OK; }
    *o = 0; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE ep_addref(IEnumPins *t) { return ++((EnumP *)t)->refs; }
static ULONG STDMETHODCALLTYPE ep_release(IEnumPins *t) {
    EnumP *e = (EnumP *)t; ULONG r = --e->refs;
    if (!r) { e->f->iface.lpVtbl->Release(&e->f->iface); CoTaskMemFree(e); }
    return r;
}
static HRESULT STDMETHODCALLTYPE ep_next(IEnumPins *t, ULONG n, IPin **out, ULONG *got) {
    EnumP *e = (EnumP *)t; ULONG k = 0;
    while (k < n && e->pos < 1) { out[k] = &e->f->pin.iface; out[k]->lpVtbl->AddRef(out[k]); k++; e->pos++; }
    if (got) *got = k;
    return k == n ? S_OK : S_FALSE;
}
static HRESULT STDMETHODCALLTYPE ep_skip(IEnumPins *t, ULONG n) { EnumP *e = (EnumP *)t; e->pos += n; return e->pos <= 1 ? S_OK : S_FALSE; }
static HRESULT STDMETHODCALLTYPE ep_reset(IEnumPins *t) { ((EnumP *)t)->pos = 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE ep_clone(IEnumPins *t, IEnumPins **o);
static IEnumPinsVtbl ep_vtbl = { ep_qi, ep_addref, ep_release, ep_next, ep_skip, ep_reset, ep_clone };
static IEnumPins *ep_new(Src *f, int pos) {
    EnumP *e = CoTaskMemAlloc(sizeof(*e));
    e->iface.lpVtbl = &ep_vtbl; e->refs = 1; e->f = f; e->pos = pos;
    f->iface.lpVtbl->AddRef(&f->iface);
    return &e->iface;
}
static HRESULT STDMETHODCALLTYPE ep_clone(IEnumPins *t, IEnumPins **o) { *o = ep_new(((EnumP *)t)->f, ((EnumP *)t)->pos); return S_OK; }

/* IBaseFilter */
static HRESULT STDMETHODCALLTYPE f_qi(IBaseFilter *t, REFIID r, void **o) {
    if (geq(r, &G_IID_IUnknown) || geq(r, &G_IID_IPersist) || geq(r, &G_IID_IMediaFilter) || geq(r, &G_IID_IBaseFilter)) {
        *o = t; t->lpVtbl->AddRef(t); return S_OK;
    }
    *o = 0; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE f_addref(IBaseFilter *t) { return InterlockedIncrement(&((Src *)t)->refs); }
static ULONG STDMETHODCALLTYPE f_release(IBaseFilter *t) { return InterlockedDecrement(&((Src *)t)->refs); }
static HRESULT STDMETHODCALLTYPE f_getclassid(IBaseFilter *t, CLSID *c) { (void)t; *c = G_CLSID_Probe; return S_OK; }
static HRESULT STDMETHODCALLTYPE f_stop(IBaseFilter *t) { ((Src *)t)->state = State_Stopped; return S_OK; }
static HRESULT STDMETHODCALLTYPE f_pause(IBaseFilter *t) { ((Src *)t)->state = State_Paused; return S_OK; }
static HRESULT STDMETHODCALLTYPE f_run(IBaseFilter *t, REFERENCE_TIME s) { (void)s; ((Src *)t)->state = State_Running; return S_OK; }
static HRESULT STDMETHODCALLTYPE f_getstate(IBaseFilter *t, DWORD ms, FILTER_STATE *s) { (void)ms; *s = ((Src *)t)->state; return S_OK; }
static HRESULT STDMETHODCALLTYPE f_setsync(IBaseFilter *t, IReferenceClock *c) {
    Src *f = (Src *)t;
    if (c) c->lpVtbl->AddRef(c);
    if (f->clock) f->clock->lpVtbl->Release(f->clock);
    f->clock = c; return S_OK;
}
static HRESULT STDMETHODCALLTYPE f_getsync(IBaseFilter *t, IReferenceClock **c) {
    Src *f = (Src *)t; *c = f->clock;
    if (f->clock) f->clock->lpVtbl->AddRef(f->clock);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE f_enumpins(IBaseFilter *t, IEnumPins **e) { *e = ep_new((Src *)t, 0); return S_OK; }
static HRESULT STDMETHODCALLTYPE f_findpin(IBaseFilter *t, LPCWSTR id, IPin **p) {
    if (id && id[0] == 'O' && id[1] == 'u') { *p = &((Src *)t)->pin.iface; (*p)->lpVtbl->AddRef(*p); return S_OK; }
    *p = 0; return VFW_E_NOT_FOUND;
}
static HRESULT STDMETHODCALLTYPE f_queryinfo(IBaseFilter *t, FILTER_INFO *fi) {
    Src *f = (Src *)t; int i = 0;
    while (g_name[i] && i < 127) { fi->achName[i] = g_name[i]; i++; }
    fi->achName[i] = 0;
    fi->pGraph = f->graph;
    if (f->graph) f->graph->lpVtbl->AddRef(f->graph);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE f_join(IBaseFilter *t, IFilterGraph *g, LPCWSTR name) {
    Src *f = (Src *)t; int i = 0;
    f->graph = g;
    if (g) {
        IMediaEventSink *sink = 0;
        f->joined = 1;
        /* CBaseFilter::JoinFilterGraph: keep the sink weak */
        if (SUCCEEDED(g->lpVtbl->QueryInterface(g, &G_IID_IMediaEventSink, (void **)&sink)) && sink) {
            f->sink_qi_ok = 1;
            sink->lpVtbl->Release(sink);
        }
    } else {
        f->left_graph = 1;
    }
    if (name) { while (name[i] && i < 63) { g_name[i] = name[i]; i++; } }
    g_name[i] = 0;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE f_vendor(IBaseFilter *t, LPWSTR *v) { (void)t; *v = 0; return E_NOTIMPL; }
static IBaseFilterVtbl f_vtbl = { f_qi, f_addref, f_release, f_getclassid, f_stop, f_pause, f_run, f_getstate,
                                  f_setsync, f_getsync, f_enumpins, f_findpin, f_queryinfo, f_join, f_vendor };

/* output pin, CBasePin / CAsyncOutputPin style */
#define PIN(t) ((OutPin *)(t))
static HRESULT STDMETHODCALLTYPE p_qi(IPin *t, REFIID r, void **o) {
    if (geq(r, &G_IID_IUnknown) || geq(r, &G_IID_IPin)) { *o = t; t->lpVtbl->AddRef(t); return S_OK; }
    if (geq(r, &G_IID_IAsyncReader)) { *o = &PIN(t)->f->reader.iface; t->lpVtbl->AddRef(t); return S_OK; }
    *o = 0; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE p_addref(IPin *t) { return f_addref(&PIN(t)->f->iface); }
static ULONG STDMETHODCALLTYPE p_release(IPin *t) { return f_release(&PIN(t)->f->iface); }
static int acceptable(const AM_MEDIA_TYPE *m) {
    return geq(&m->majortype, &G_MEDIATYPE_Stream) &&
           (geq(&m->subtype, &G_MEDIASUBTYPE_MPEG1Audio) || geq(&m->subtype, &G_GUID_NULL));
}
static HRESULT STDMETHODCALLTYPE p_connect(IPin *t, IPin *rx, const AM_MEDIA_TYPE *pmt) {
    OutPin *p = PIN(t);
    PIN_DIRECTION d;
    AM_MEDIA_TYPE mt;
    HRESULT hr;
    if (!rx) return E_POINTER;
    if (p->peer) return VFW_E_ALREADY_CONNECTED;
    if (p->f->state != State_Stopped) return VFW_E_NOT_STOPPED;
    /* CBasePin::CheckConnect */
    if (FAILED(rx->lpVtbl->QueryDirection(rx, &d)) || d != PINDIR_INPUT) return VFW_E_INVALID_DIRECTION;
    if (pmt && !acceptable(pmt)) return VFW_E_TYPE_NOT_ACCEPTED;
    /* AgreeMediaType: the receiver's types first, then ours */
    {
        IEnumMediaTypes *e = 0;
        if (SUCCEEDED(rx->lpVtbl->EnumMediaTypes(rx, &e)) && e) {
            AM_MEDIA_TYPE *m = 0; ULONG got = 0;
            while (e->lpVtbl->Next(e, 1, &m, &got) == S_OK && got == 1) {
                int ok = acceptable(m);
                if (m->pbFormat) CoTaskMemFree(m->pbFormat);
                if (m->pUnk) m->pUnk->lpVtbl->Release(m->pUnk);
                CoTaskMemFree(m);
                if (ok) {
                    fill_mt(&mt);
                    if (rx->lpVtbl->ReceiveConnection(rx, t, &mt) == S_OK) {
                        e->lpVtbl->Release(e);
                        goto connected;
                    }
                }
            }
            e->lpVtbl->Release(e);
        }
    }
    fill_mt(&mt);
    hr = rx->lpVtbl->ReceiveConnection(rx, t, &mt);
    if (hr != S_OK) return FAILED(hr) ? hr : VFW_E_NO_ACCEPTABLE_TYPES;
connected:
    p->peer = rx;
    rx->lpVtbl->AddRef(rx);
    p->mt = mt;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE p_receive(IPin *t, IPin *c, const AM_MEDIA_TYPE *m) { (void)t; (void)c; (void)m; return E_UNEXPECTED; }
static HRESULT STDMETHODCALLTYPE p_disconnect(IPin *t) {
    OutPin *p = PIN(t);
    if (!p->peer) return S_FALSE;
    p->peer->lpVtbl->Release(p->peer);
    p->peer = 0;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE p_connectedto(IPin *t, IPin **o) {
    OutPin *p = PIN(t);
    *o = p->peer;
    if (!p->peer) return VFW_E_NOT_CONNECTED;
    p->peer->lpVtbl->AddRef(p->peer);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE p_cmt(IPin *t, AM_MEDIA_TYPE *m) {
    OutPin *p = PIN(t);
    if (!p->peer) { zero(m, sizeof(*m)); return VFW_E_NOT_CONNECTED; }
    *m = p->mt; return S_OK;
}
static HRESULT STDMETHODCALLTYPE p_info(IPin *t, PIN_INFO *pi) {
    static const WCHAR n[] = {'O', 'u', 't', 'p', 'u', 't', 0};
    int i;
    pi->pFilter = &PIN(t)->f->iface;
    pi->pFilter->lpVtbl->AddRef(pi->pFilter);
    pi->dir = PINDIR_OUTPUT;
    for (i = 0; n[i]; i++) pi->achName[i] = n[i];
    pi->achName[i] = 0;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE p_dir(IPin *t, PIN_DIRECTION *d) { (void)t; *d = PINDIR_OUTPUT; return S_OK; }
static HRESULT STDMETHODCALLTYPE p_id(IPin *t, LPWSTR *id) {
    WCHAR *s = CoTaskMemAlloc(7 * sizeof(WCHAR));
    (void)t;
    s[0] = 'O'; s[1] = 'u'; s[2] = 't'; s[3] = 'p'; s[4] = 'u'; s[5] = 't'; s[6] = 0;
    *id = s; return S_OK;
}
static HRESULT STDMETHODCALLTYPE p_accept(IPin *t, const AM_MEDIA_TYPE *m) { (void)t; return acceptable(m) ? S_OK : S_FALSE; }
static HRESULT STDMETHODCALLTYPE p_enummt(IPin *t, IEnumMediaTypes **e) { (void)t; *e = emt_new(0); return S_OK; }
static HRESULT STDMETHODCALLTYPE p_internal(IPin *t, IPin **a, ULONG *n) { (void)t; (void)a; (void)n; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE p_eos(IPin *t) { (void)t; return E_UNEXPECTED; }
static HRESULT STDMETHODCALLTYPE p_bflush(IPin *t) { (void)t; return E_UNEXPECTED; }
static HRESULT STDMETHODCALLTYPE p_eflush(IPin *t) { (void)t; return E_UNEXPECTED; }
static HRESULT STDMETHODCALLTYPE p_newseg(IPin *t, REFERENCE_TIME a, REFERENCE_TIME b, double r) { (void)t; (void)a; (void)b; (void)r; return S_OK; }
static IPinVtbl p_vtbl = { p_qi, p_addref, p_release, p_connect, p_receive, p_disconnect, p_connectedto, p_cmt,
                           p_info, p_dir, p_id, p_accept, p_enummt, p_internal, p_eos, p_bflush, p_eflush, p_newseg };

/* IAsyncReader over the fixture */
#define RD(t) (((Reader *)(t))->f)
static HRESULT STDMETHODCALLTYPE r_qi(IAsyncReader *t, REFIID r, void **o) { return p_qi(&RD(t)->pin.iface, r, o); }
static ULONG STDMETHODCALLTYPE r_addref(IAsyncReader *t) { return f_addref(&RD(t)->iface); }
static ULONG STDMETHODCALLTYPE r_release(IAsyncReader *t) { return f_release(&RD(t)->iface); }
static HRESULT copy_out(LONGLONG pos, LONG len, BYTE *buf, LONG *done) {
    LONGLONG size = fixture_mp3_len;
    LONG n = 0;
    if (pos < size) n = (LONG)((pos + len <= size) ? len : size - pos);
    { LONG i; for (i = 0; i < n; i++) buf[i] = fixture_mp3[pos + i]; }
    if (done) *done = n;
    return n == len ? S_OK : S_FALSE;
}
static HRESULT STDMETHODCALLTYPE r_reqalloc(IAsyncReader *t, IMemAllocator *pref, ALLOCATOR_PROPERTIES *props, IMemAllocator **out) {
    ALLOCATOR_PROPERTIES actual;
    (void)t;
    if (!pref) { *out = 0; return VFW_E_NO_ALLOCATOR; }
    if (props->cbAlign == 0) props->cbAlign = 1;
    if (FAILED(pref->lpVtbl->SetProperties(pref, props, &actual))) { *out = 0; return E_FAIL; }
    pref->lpVtbl->AddRef(pref);
    *out = pref;
    return S_OK;
}
#define MAXREQ 64
static IMediaSample *g_req[MAXREQ];
static DWORD_PTR g_req_user[MAXREQ];
static int g_req_n, g_flushing;
static HRESULT STDMETHODCALLTYPE r_request(IAsyncReader *t, IMediaSample *s, DWORD_PTR user) {
    RD(t)->requests++;
    if (g_flushing) return VFW_E_WRONG_STATE;
    if (g_req_n >= MAXREQ) return E_OUTOFMEMORY;
    g_req[g_req_n] = s; g_req_user[g_req_n] = user; g_req_n++;
    return S_OK;
}
static HRESULT fill_sample(IMediaSample *s) {
    REFERENCE_TIME a = 0, b = 0;
    BYTE *buf = 0; LONG done = 0; HRESULT hr;
    s->lpVtbl->GetTime(s, &a, &b);
    s->lpVtbl->GetPointer(s, &buf);
    hr = copy_out(sdiv64(a, 10000000), (LONG)sdiv64(b - a, 10000000), buf, &done);
    s->lpVtbl->SetActualDataLength(s, done);
    return hr;
}
static HRESULT STDMETHODCALLTYPE r_wait(IAsyncReader *t, DWORD ms, IMediaSample **s, DWORD_PTR *user) {
    int i;
    (void)t; (void)ms;
    *s = 0; *user = 0;
    if (g_req_n == 0) return g_flushing ? VFW_E_WRONG_STATE : VFW_E_TIMEOUT;
    *s = g_req[0]; *user = g_req_user[0];
    for (i = 1; i < g_req_n; i++) { g_req[i - 1] = g_req[i]; g_req_user[i - 1] = g_req_user[i]; }
    g_req_n--;
    if (g_flushing) return VFW_E_WRONG_STATE;
    return fill_sample(*s);
}
static HRESULT STDMETHODCALLTYPE r_syncaligned(IAsyncReader *t, IMediaSample *s) { RD(t)->sync_reads++; return fill_sample(s); }
static HRESULT STDMETHODCALLTYPE r_sync(IAsyncReader *t, LONGLONG pos, LONG len, BYTE *buf) { RD(t)->sync_reads++; return copy_out(pos, len, buf, 0); }
static HRESULT STDMETHODCALLTYPE r_length(IAsyncReader *t, LONGLONG *total, LONGLONG *avail) {
    (void)t;
    if (total) *total = fixture_mp3_len;
    if (avail) *avail = fixture_mp3_len;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE r_bflush(IAsyncReader *t) { (void)t; g_flushing = 1; return S_OK; }
static HRESULT STDMETHODCALLTYPE r_eflush(IAsyncReader *t) { (void)t; g_flushing = 0; return S_OK; }
static IAsyncReaderVtbl r_vtbl = { r_qi, r_addref, r_release, r_reqalloc, r_request, r_wait, r_syncaligned, r_sync,
                                   r_length, r_bflush, r_eflush };

/* ---- the client, FalloutNV's sequence ------------------------------------ */
static long ms_of_reftime(double s) { return (long)(s * 1000.0 + 0.5); }

/* Pump GetEvent until EC_COMPLETE or ~6 s; print the distinct codes in order. */
static void wait_complete(const char *tag, IMediaEvent *ev) {
    long seen[16]; int nseen = 0, i, k, complete = 0;
    for (k = 0; k < 120 && !complete; k++) {
        long code = 0; LONG_PTR a = 0, b = 0;
        HRESULT hr = ev->lpVtbl->GetEvent(ev, &code, &a, &b, 50);
        if (hr == S_OK) {
            int dup = 0;
            for (i = 0; i < nseen; i++) if (seen[i] == code) dup = 1;
            if (!dup && nseen < 16) seen[nseen++] = code;
            ev->lpVtbl->FreeEventParams(ev, code, a, b);
            if (code == EC_COMPLETE) complete = 1;
        } else if (hr != E_ABORT) {
            line_hr("getevent-unexpected", hr);
            break;
        }
    }
    put("E|"); put(tag); put("|");
    for (i = 0; i < nseen; i++) { if (i) put(","); putx((unsigned long)seen[i]); }
    put("|complete="); puti(complete); put("\n");
}

void probe_main(void) {
    IGraphBuilder *gb = 0;
    IMediaControl *mc = 0;
    IMediaEvent *ev = 0;
    IMediaPosition *mp = 0;
    IMediaSeeking *ms = 0;
    IBasicAudio *ba = 0;
    IUnknown *tmp = 0;
    HRESULT hr;
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    g_src.iface.lpVtbl = &f_vtbl; g_src.refs = 1;
    g_src.pin.iface.lpVtbl = &p_vtbl; g_src.pin.f = &g_src;
    g_src.reader.iface.lpVtbl = &r_vtbl; g_src.reader.f = &g_src;
    g_src.state = State_Stopped;

    line_hr("coinit", CoInitialize(0));
    hr = CoCreateInstance(&G_CLSID_FilterGraph, 0, CLSCTX_INPROC_SERVER, &G_IID_IFilterGraph, (void **)&gb);
    line_hr("create", hr);
    if (FAILED(hr) || !gb) ExitProcess(2);

    /* What the graph answers to, besides what the game uses. */
    {
        static const struct { const char *n; const GUID *g; } q[] = {
            {"qi-graphbuilder", &G_IID_IGraphBuilder}, {"qi-mediacontrol", &G_IID_IMediaControl},
            {"qi-mediaevent", &G_IID_IMediaEvent}, {"qi-mediaeventex", &G_IID_IMediaEventEx},
            {"qi-mediaposition", &G_IID_IMediaPosition}, {"qi-mediaseeking", &G_IID_IMediaSeeking},
            {"qi-basicaudio", &G_IID_IBasicAudio}, {"qi-mediafilter", &G_IID_IMediaFilter},
            {"qi-eventsink", &G_IID_IMediaEventSink}, {"qi-ipin-refused", &G_IID_IPin},
        };
        unsigned i;
        for (i = 0; i < sizeof(q) / sizeof(q[0]); i++) {
            tmp = 0;
            hr = gb->lpVtbl->QueryInterface(gb, q[i].g, (void **)&tmp);
            line_hr(q[i].n, hr);
            if (tmp) tmp->lpVtbl->Release(tmp);
        }
    }

    hr = gb->lpVtbl->AddFilter(gb, &g_src.iface, 0);
    line_hr("addfilter", hr);
    line_i("joined", g_src.joined);
    line_i("sink-qi", g_src.sink_qi_ok);
    line_i("has-name", g_name[0] != 0);

    hr = gb->lpVtbl->Render(gb, &g_src.pin.iface);
    line_hr("render", hr);
    line_i("connected", g_src.pin.peer != 0);
    line_i("mt-stream-mpeg1", g_src.pin.peer && acceptable(&g_src.pin.mt));
    line_i("pulled-data", (g_src.sync_reads + g_src.requests) > 0);
    hr = gb->lpVtbl->Render(gb, &g_src.pin.iface);
    line_hr("render-again", hr);

    gb->lpVtbl->QueryInterface(gb, &G_IID_IMediaControl, (void **)&mc);
    gb->lpVtbl->QueryInterface(gb, &G_IID_IMediaEvent, (void **)&ev);
    gb->lpVtbl->QueryInterface(gb, &G_IID_IMediaPosition, (void **)&mp);
    gb->lpVtbl->QueryInterface(gb, &G_IID_IMediaSeeking, (void **)&ms);
    gb->lpVtbl->QueryInterface(gb, &G_IID_IBasicAudio, (void **)&ba);
    if (!mc || !ev || !mp || !ms || !ba) ExitProcess(3);

    {
        REFTIME d = 0; LONGLONG d2 = 0; GUID fmt;
        hr = mp->lpVtbl->get_Duration(mp, &d);
        line_hr("get_duration", hr); line_i("duration-ms", ms_of_reftime(d));
        hr = ms->lpVtbl->GetDuration(ms, &d2);
        line_hr("seek-duration", hr); line_i("seek-duration-ms", (long)sdiv64(d2, 10000));
        hr = ms->lpVtbl->GetTimeFormat(ms, &fmt);
        line_hr("timeformat", hr); line_i("timeformat-media", geq(&fmt, &G_TIME_FORMAT_MEDIA_TIME));
        d = -1; hr = mp->lpVtbl->get_StopTime(mp, &d);
        line_hr("get_stoptime", hr); line_i("stop-eq-duration", ms_of_reftime(d) == (long)sdiv64(d2, 10000));
        d = -1; hr = mp->lpVtbl->get_CurrentPosition(mp, &d);
        line_hr("get_pos-stopped", hr); line_i("pos-stopped-ms", ms_of_reftime(d));
    }
    {
        long v = 1;
        line_hr("put_volume", ba->lpVtbl->put_Volume(ba, -2602));
        line_hr("get_volume", ba->lpVtbl->get_Volume(ba, &v)); line_i("volume", v);
        line_hr("put_volume-high", ba->lpVtbl->put_Volume(ba, 1));
        line_hr("put_volume-low", ba->lpVtbl->put_Volume(ba, -10001));
        line_hr("put_balance", ba->lpVtbl->put_Balance(ba, 0));
    }
    {
        OAFilterState st = -1;
        long code = -1; LONG_PTR a = 0, b = 0;
        hr = mc->lpVtbl->Pause(mc);
        line_i("pause-ok", SUCCEEDED(hr));
        hr = mc->lpVtbl->GetState(mc, 2000, &st);
        line_hr("getstate-paused", hr); line_i("state-paused", st);
        line_i("src-paused", g_src.state == State_Paused);
        line_i("src-has-clock", g_src.clock != 0);
        hr = ev->lpVtbl->GetEvent(ev, &code, &a, &b, 0);
        if (hr == S_OK) ev->lpVtbl->FreeEventParams(ev, code, a, b);
        line_hr("getevent-after-pause", hr); line_i("event-after-pause", hr == S_OK ? code : -1);
        line_hr("getevent-empty", ev->lpVtbl->GetEvent(ev, &code, &a, &b, 0));

        hr = mc->lpVtbl->Run(mc);
        line_i("run-ok", SUCCEEDED(hr));
        hr = mc->lpVtbl->GetState(mc, 2000, &st);
        line_hr("getstate-running", hr); line_i("state-running", st);
        line_i("src-running", g_src.state == State_Running);
        wait_complete("first", ev);
    }
    {
        REFTIME p = -1, d = 0;
        mp->lpVtbl->get_Duration(mp, &d);
        hr = mp->lpVtbl->get_CurrentPosition(mp, &p);
        line_hr("get_pos-end", hr); line_i("pos-at-end", (ms_of_reftime(p) >= ms_of_reftime(d) - 60) && ms_of_reftime(p) <= ms_of_reftime(d));
        /* The game loops its music: rewind and run again. */
        line_hr("put_pos-zero", mp->lpVtbl->put_CurrentPosition(mp, 0.0));
        p = -1; mp->lpVtbl->get_CurrentPosition(mp, &p);
        line_i("pos-rewound", ms_of_reftime(p) < 60);
        hr = mc->lpVtbl->Run(mc);
        line_i("rerun-ok", SUCCEEDED(hr));
        wait_complete("second", ev);
        line_hr("stop", mc->lpVtbl->Stop(mc));
        line_i("src-stopped", g_src.state == State_Stopped);
        p = -1; mp->lpVtbl->get_CurrentPosition(mp, &p);
        line_i("pos-after-stop-ms", ms_of_reftime(p) < 60 ? 0 : 1);
    }

    ba->lpVtbl->Release(ba); ms->lpVtbl->Release(ms); mp->lpVtbl->Release(mp);
    ev->lpVtbl->Release(ev); mc->lpVtbl->Release(mc);
    line_i("graph-final-release", (long)gb->lpVtbl->Release(gb));
    line_i("src-left-graph", g_src.left_graph);
    line_i("src-disconnected", g_src.pin.peer == 0);
    line_i("src-refs-back", g_src.refs);
    CoUninitialize();
    ExitProcess(0);
}
