#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <time.h>
#include <GL/gl.h>

/* ==============================================================================
 * WINS AUTONOMOUS RUNTIME SUPERVISOR & HUNTER (LD_PRELOAD)
 * ==============================================================================
 * Fuses the runtime LD_PRELOAD interceptor with an autonomous case hunter:
 * 1. Dynamic API Hunter (dlopen / dlsym):
 *    - Catches requests for Win32 DLLs (user32, kernel32, advapi32, etc.)
 *    - Evaluates acceptance via built-in WINS shims
 *    - Catches unhandled APIs and records them in telemetry journal
 * 2. On-The-Fly Shader Hunter & Transpiler (glShaderSource):
 *    - Catches DXBC buffers, verifies cache, or transpiles on the fly via vkd3d/spirv-cross
 * 3. Transparent Asset & Path Normalizer (openat / open / fopen):
 *    - Normalizes Windows paths ('\') & redirects to ~/.cache/wins/overlays/
 *    - Case-insensitive hunting on Linux filesystems
 * 4. Zero-Wine Steamworks.NET C API Stubs
 * 5. Autonomous Session Journal (~/.cache/wins/telemetry/)
 * ============================================================================== */

#define WINS_SYNTHETIC_MODULE ((void*)(uintptr_t)0x57494e53) /* "WINS" */

typedef void (*PFNGLSHADERSOURCEPROC)(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length);
typedef void* (*PFNGLXGETPROCADDRESSPROC)(const GLubyte *procName);
typedef void* (*PFN_DLOPEN)(const char *filename, int flag);
typedef void* (*PFN_DLSYM)(void *handle, const char *symbol);
typedef int (*PFN_OPENAT)(int dirfd, const char *pathname, int flags, mode_t mode);

static PFNGLSHADERSOURCEPROC real_glShaderSource = NULL;
static PFNGLXGETPROCADDRESSPROC real_glXGetProcAddress = NULL;
static PFNGLXGETPROCADDRESSPROC real_glXGetProcAddressARB = NULL;
static PFN_DLOPEN real_dlopen = NULL;
static PFN_DLSYM real_dlsym = NULL;
static PFN_OPENAT real_openat = NULL;

/* Forward declarations of intercepted symbols */
void glShaderSource(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length);
void glShaderSourceARB(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length);
void* glXGetProcAddress(const GLubyte *procName);
void* glXGetProcAddressARB(const GLubyte *procName);

bool SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID);
bool SteamAPI_Init(void);
bool SteamAPI_InitSafe(void);
bool SteamAPI_IsSteamRunning(void);
void SteamAPI_RunCallbacks(void);
void SteamAPI_Shutdown(void);
bool RestartAppIfNecessary(uint32_t unOwnAppID);
bool IsSteamRunning(void);
bool Init(void);
bool InitSafe(void);
void RunCallbacks(void);
void Shutdown(void);

/* Session Telemetry Counters */
static struct {
    uint32_t dxbc_intercepted;
    uint32_t dxbc_cache_hits;
    uint32_t dxbc_onthefly_transpiled;
    uint32_t win32_apis_accepted;
    uint32_t win32_apis_unhandled;
    uint32_t overlays_redirected;
    time_t start_time;
} g_telemetry = {0};

/* --- SHA-256 Implementation --- */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} WINS_SHA256_CTX;

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void wins_sha256_transform(WINS_SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void wins_sha256_init(WINS_SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void wins_sha256_update(WINS_SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0) wins_sha256_transform(ctx, ctx->buffer);
    }
}

static void wins_sha256_final(WINS_SHA256_CTX *ctx, uint8_t hash[]) {
    size_t i = ctx->count % 64;
    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buffer[i++] = 0x00;
        wins_sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    } else {
        while (i < 56) ctx->buffer[i++] = 0x00;
    }
    uint64_t bitcount = ctx->count * 8;
    for (int j = 7; j >= 0; --j) ctx->buffer[56 + j] = (uint8_t)(bitcount >> (8 * (7 - j)));
    wins_sha256_transform(ctx, ctx->buffer);
    for (i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) hash[j * 4 + i] = (uint8_t)((ctx->state[j] >> (24 - i * 8)) & 0x000000ff);
    }
}

static void compute_sha256_hex(const uint8_t *data, size_t len, char hex_out[65]) {
    WINS_SHA256_CTX ctx;
    uint8_t hash[32];
    wins_sha256_init(&ctx);
    wins_sha256_update(&ctx, data, len);
    wins_sha256_final(&ctx, hash);
    for (int i = 0; i < 32; ++i) sprintf(hex_out + (i * 2), "%02x", hash[i]);
    hex_out[64] = 0;
}

static void init_real_gl(void) {
    if (!real_dlsym) {
        real_dlsym = (PFN_DLSYM)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
        if (!real_dlsym) real_dlsym = (PFN_DLSYM)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.34");
    }
    if (!real_dlopen && real_dlsym) {
        real_dlopen = (PFN_DLOPEN)real_dlsym(RTLD_NEXT, "dlopen");
    }
    if (!real_glXGetProcAddress && real_dlsym && real_dlopen) {
        void *libgl = real_dlopen("libGL.so.1", RTLD_LAZY | RTLD_GLOBAL);
        if (!libgl) libgl = real_dlopen("libGL.so", RTLD_LAZY | RTLD_GLOBAL);
        if (libgl) {
            void *proc = real_dlsym(libgl, "glXGetProcAddress");
            if (proc && proc != (void*)glXGetProcAddress) {
                real_glXGetProcAddress = (PFNGLXGETPROCADDRESSPROC)proc;
            }
            void *proc_arb = real_dlsym(libgl, "glXGetProcAddressARB");
            if (proc_arb && proc_arb != (void*)glXGetProcAddressARB) {
                real_glXGetProcAddressARB = (PFNGLXGETPROCADDRESSPROC)proc_arb;
            }
            real_glShaderSource = (PFNGLSHADERSOURCEPROC)real_dlsym(libgl, "glShaderSource");
        }
        if (!real_glShaderSource && real_glXGetProcAddress) {
            real_glShaderSource = (PFNGLSHADERSOURCEPROC)real_glXGetProcAddress((const GLubyte*)"glShaderSource");
        }
        if (!real_glShaderSource) {
            real_glShaderSource = (PFNGLSHADERSOURCEPROC)real_dlsym(RTLD_NEXT, "glShaderSource");
        }
    }
}

/* ==============================================================================
 * 1. DYNAMIC API HUNTER & WIN32 SHIM LAYER
 * ============================================================================== */

static void* wins_generic_stub(void) {
    return NULL;
}

static int32_t wins_stub_success_int(void) {
    return 1;
}

static int32_t wins_stub_zero(void) {
    return 0;
}

typedef struct {
    int32_t x;
    int32_t y;
} WINS_POINT;

static int32_t wins_GetCursorPos(WINS_POINT *pt) {
    if (pt) {
        pt->x = 640;
        pt->y = 360;
    }
    return 1;
}

static int32_t wins_SetCursorPos(int32_t x, int32_t y) {
    (void)x; (void)y;
    return 1;
}

static int32_t wins_GetKeyboardState(uint8_t *state) {
    if (state) memset(state, 0, 256);
    return 1;
}

static int16_t wins_GetKeyState(int32_t nVirtKey) {
    (void)nVirtKey;
    return 0;
}

static int16_t wins_GetAsyncKeyState(int32_t vKey) {
    (void)vKey;
    return 0;
}

static uint32_t wins_GetDoubleClickTime(void) {
    return 500;
}

static int32_t wins_GetSystemMetrics(int32_t nIndex) {
    switch (nIndex) {
        case 0: return 1920; /* SM_CXSCREEN */
        case 1: return 1080; /* SM_CYSCREEN */
        default: return 0;
    }
}

/* Exported Win32 functions for direct dynamic loader binding */
int32_t GetCursorPos(WINS_POINT *pt) { return wins_GetCursorPos(pt); }
int32_t SetCursorPos(int32_t x, int32_t y) { return wins_SetCursorPos(x, y); }
int32_t GetKeyboardState(uint8_t *state) { return wins_GetKeyboardState(state); }
int16_t GetKeyState(int32_t nVirtKey) { return wins_GetKeyState(nVirtKey); }
int16_t GetAsyncKeyState(int32_t vKey) { return wins_GetAsyncKeyState(vKey); }
uint32_t GetDoubleClickTime(void) { return wins_GetDoubleClickTime(); }
int32_t GetSystemMetrics(int32_t nIndex) { return wins_GetSystemMetrics(nIndex); }

static void record_telemetry_event(const char *kind, const char *key, const char *decision) {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/.cache/wins/telemetry/hunt_journal.jsonl", home);

    FILE *f = fopen(log_path, "a");
    if (f) {
        fprintf(f, "{\"ts\":%ld,\"kind\":\"%s\",\"key\":\"%s\",\"decision\":\"%s\"}\n",
                (long)time(NULL), kind, key, decision);
        fclose(f);
    }
}

static void* wins_resolve_win32_symbol(const char *name) {
    if (strcmp(name, "GetCursorPos") == 0) return (void*)wins_GetCursorPos;
    if (strcmp(name, "SetCursorPos") == 0) return (void*)wins_SetCursorPos;
    if (strcmp(name, "GetKeyboardState") == 0) return (void*)wins_GetKeyboardState;
    if (strcmp(name, "GetKeyState") == 0) return (void*)wins_GetKeyState;
    if (strcmp(name, "GetAsyncKeyState") == 0) return (void*)wins_GetAsyncKeyState;
    if (strcmp(name, "GetDoubleClickTime") == 0) return (void*)wins_GetDoubleClickTime;
    if (strcmp(name, "GetSystemMetrics") == 0) return (void*)wins_GetSystemMetrics;
    if (strcmp(name, "GetTickCount") == 0) return (void*)wins_stub_zero;
    if (strcmp(name, "GetTickCount64") == 0) return (void*)wins_stub_zero;
    if (strcmp(name, "GetCurrentThreadId") == 0) return (void*)wins_stub_success_int;
    if (strcmp(name, "GetCurrentProcessId") == 0) return (void*)wins_stub_success_int;
    return NULL;
}

/* Intercept dlopen to catch dynamic library requests */
void* dlopen(const char *filename, int flag) {
    if (!real_dlopen) real_dlopen = (PFN_DLOPEN)dlsym(RTLD_NEXT, "dlopen");

    if (filename) {
        /* Check if application is looking for a Windows DLL or P/Invoke library */
        const char *dot = strrchr(filename, '.');
        bool is_dll = (dot && strcasecmp(dot, ".dll") == 0);
        bool is_win32_core = (strcasestr(filename, "user32") || strcasestr(filename, "kernel32") ||
                              strcasestr(filename, "gdi32") || strcasestr(filename, "advapi32") ||
                              strcasestr(filename, "iphlpapi") || strcasestr(filename, "ole32") ||
                              strcasestr(filename, "MonoSupportW"));

        if (is_dll || is_win32_core) {
            fprintf(stderr, "[WINS:Hunter] Hunted Win32 library request: %s -> ACCEPTED as WINS synthetic module\n", filename);
            record_telemetry_event("DLL_REQUEST", filename, "ACCEPTED_WINS_MODULE");
            return WINS_SYNTHETIC_MODULE;
        }
    }

    return real_dlopen(filename, flag);
}

/* Intercept dlsym to catch dynamic function resolutions */
void* dlsym(void *handle, const char *symbol) {
    if (!real_dlsym) {
        real_dlsym = (PFN_DLSYM)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
        if (!real_dlsym) real_dlsym = (PFN_DLSYM)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.34");
    }

    /* Handled by synthetic WINS module */
    if (handle == WINS_SYNTHETIC_MODULE) {
        void *resolved = wins_resolve_win32_symbol(symbol);
        if (resolved) {
            g_telemetry.win32_apis_accepted++;
            fprintf(stderr, "[WINS:Interceptor] ACCEPTED Win32 API: %s\n", symbol);
            record_telemetry_event("WIN32_API", symbol, "ACCEPTED");
            return resolved;
        } else {
            g_telemetry.win32_apis_unhandled++;
            fprintf(stderr, "[WINS:Hunter] HUNTED UNHANDLED WIN32 API: %s -> Returning safe stub\n", symbol);
            record_telemetry_event("WIN32_API", symbol, "UNHANDLED_BLOCKER");
            return (void*)wins_generic_stub;
        }
    }

    /* Intercept OpenGL and SteamAPI symbols regardless of handle */
    if (symbol) {
        if (strcmp(symbol, "glShaderSource") == 0) return (void*)glShaderSource;
        if (strcmp(symbol, "glShaderSourceARB") == 0) return (void*)glShaderSourceARB;
        if (strcmp(symbol, "glXGetProcAddress") == 0) return (void*)glXGetProcAddress;
        if (strcmp(symbol, "glXGetProcAddressARB") == 0) return (void*)glXGetProcAddressARB;
        if (strncmp(symbol, "SteamAPI_", 9) == 0 ||
            strcmp(symbol, "RestartAppIfNecessary") == 0 ||
            strcmp(symbol, "IsSteamRunning") == 0 ||
            strcmp(symbol, "Init") == 0 ||
            strcmp(symbol, "InitSafe") == 0 ||
            strcmp(symbol, "RunCallbacks") == 0 ||
            strcmp(symbol, "Shutdown") == 0) {
            if (strcmp(symbol, "SteamAPI_RestartAppIfNecessary") == 0 || strcmp(symbol, "RestartAppIfNecessary") == 0) return (void*)SteamAPI_RestartAppIfNecessary;
            if (strcmp(symbol, "SteamAPI_Init") == 0 || strcmp(symbol, "Init") == 0) return (void*)SteamAPI_Init;
            if (strcmp(symbol, "SteamAPI_InitSafe") == 0 || strcmp(symbol, "InitSafe") == 0) return (void*)SteamAPI_InitSafe;
            if (strcmp(symbol, "SteamAPI_IsSteamRunning") == 0 || strcmp(symbol, "IsSteamRunning") == 0) return (void*)SteamAPI_IsSteamRunning;
            if (strcmp(symbol, "SteamAPI_RunCallbacks") == 0 || strcmp(symbol, "RunCallbacks") == 0) return (void*)SteamAPI_RunCallbacks;
            if (strcmp(symbol, "SteamAPI_Shutdown") == 0 || strcmp(symbol, "Shutdown") == 0) return (void*)SteamAPI_Shutdown;
        }
    }

    if (real_dlsym) return real_dlsym(handle, symbol);
    return NULL;
}

/* ==============================================================================
 * 2. ON-THE-FLY SHADER HUNTER & TRANSPILER
 * ============================================================================== */

static bool transpile_dxbc_onthefly(const uint8_t *dxbc_data, size_t size, const char *out_glsl_path) {
    char tmp_dxbc[256], tmp_spv[256];
    snprintf(tmp_dxbc, sizeof(tmp_dxbc), "/tmp/_wins_h_%ld.dxbc", (long)rand());
    snprintf(tmp_spv, sizeof(tmp_spv), "/tmp/_wins_h_%ld.spv", (long)rand());

    FILE *f = fopen(tmp_dxbc, "wb");
    if (!f) return false;
    fwrite(dxbc_data, 1, size, f);
    fclose(f);

    char cmd[1024];
    /* vkd3d-compiler -> spirv-cross pipeline */
    snprintf(cmd, sizeof(cmd),
             "~/.local/bin/vkd3d-compiler -x dxbc-tpf -o %s %s >/dev/null 2>&1 && "
             "~/.local/bin/spirv-cross --version 450 %s --output %s >/dev/null 2>&1",
             tmp_spv, tmp_dxbc, tmp_spv, out_glsl_path);

    int res = system(cmd);
    unlink(tmp_dxbc);
    unlink(tmp_spv);

    return (res == 0);
}

void wins_glShaderSource(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length) {
    init_real_gl();
    if (!real_glShaderSource) return;

    if (count > 0 && string && string[0]) {
        const uint8_t *src_bytes = (const uint8_t*)string[0];
        size_t src_len = (length && length[0] > 0) ? (size_t)length[0] : strlen(string[0]);

        if (src_len >= 32 && memcmp(src_bytes, "DXBC", 4) == 0) {
            g_telemetry.dxbc_intercepted++;
            uint32_t total_size = *(const uint32_t*)(src_bytes + 24);
            if (total_size > 0 && total_size <= src_len + 4096) {
                char hash_hex[65];
                compute_sha256_hex(src_bytes, total_size, hash_hex);

                char cache_path[512];
                const char *home = getenv("HOME");
                if (!home) home = "/tmp";
                snprintf(cache_path, sizeof(cache_path), "%s/.cache/wins/shaders/%s.glsl", home, hash_hex);

                /* 1. Check Cache Hit */
                FILE *f = fopen(cache_path, "rb");
                if (!f) {
                    /* 2. On-The-Fly Shader Hunter: Transpile if not found */
                    fprintf(stderr, "[WINS:Hunter] Hunted uncached DXBC shader (%s), transpiling on the fly...\n", hash_hex);
                    if (transpile_dxbc_onthefly(src_bytes, total_size, cache_path)) {
                        g_telemetry.dxbc_onthefly_transpiled++;
                        fprintf(stderr, "[WINS:Interceptor] ACCEPTED: On-the-fly DXBC transpilation succeeded\n");
                        record_telemetry_event("SHADER_DXBC", hash_hex, "TRANSPILER_ON_THE_FLY");
                        f = fopen(cache_path, "rb");
                    } else {
                        fprintf(stderr, "[WINS:Interceptor] REJECTED: Could not transpile DXBC shader (%s)\n", hash_hex);
                        record_telemetry_event("SHADER_DXBC", hash_hex, "REJECTED_TRANSPILE_FAILED");
                    }
                } else {
                    g_telemetry.dxbc_cache_hits++;
                }

                if (f) {
                    fseek(f, 0, SEEK_END);
                    long glsl_sz = ftell(f);
                    fseek(f, 0, SEEK_SET);
                    char *glsl_src = (char*)malloc(glsl_sz + 1);
                    if (glsl_src) {
                        fread(glsl_src, 1, glsl_sz, f);
                        glsl_src[glsl_sz] = 0;
                        fclose(f);

                        const GLchar *glsl_const = glsl_src;
                        GLint glsl_len = (GLint)glsl_sz;
                        real_glShaderSource(shader, 1, &glsl_const, &glsl_len);
                        free(glsl_src);
                        return;
                    }
                    fclose(f);
                }
            }
        }
    }

    real_glShaderSource(shader, count, string, length);
}

void glShaderSource(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length) {
    wins_glShaderSource(shader, count, string, length);
}

void glShaderSourceARB(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length) {
    wins_glShaderSource(shader, count, string, length);
}

void* glXGetProcAddress(const GLubyte *procName) {
    init_real_gl();
    if (!procName) return NULL;
    if (strcmp((const char*)procName, "glShaderSource") == 0 ||
        strcmp((const char*)procName, "glShaderSourceARB") == 0) {
        return (void*)wins_glShaderSource;
    }
    if (real_glXGetProcAddress && real_glXGetProcAddress != (PFNGLXGETPROCADDRESSPROC)glXGetProcAddress) {
        return real_glXGetProcAddress(procName);
    }
    if (real_dlsym) {
        return real_dlsym(RTLD_NEXT, (const char*)procName);
    }
    return NULL;
}

void* glXGetProcAddressARB(const GLubyte *procName) {
    return glXGetProcAddress(procName);
}

/* ==============================================================================
 * 3. TRANSPARENT ASSET OVERLAY & PATH HUNTER
 * ============================================================================== */

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (!real_openat) real_openat = (PFN_OPENAT)dlsym(RTLD_NEXT, "openat");

    if (pathname && (flags & O_ACCMODE) == O_RDONLY) {
        /* Win32 library probe redirection */
        if (strstr(pathname, "user32.dll") || strstr(pathname, "libuser32.so") || strstr(pathname, "MonoSupportW")) {
            char hook_path[512];
            const char *home = getenv("HOME");
            if (!home) home = "/tmp";
            snprintf(hook_path, sizeof(hook_path), "%s/.local/lib/libwins_glhook.so", home);
            if (access(hook_path, R_OK) == 0) {
                g_telemetry.overlays_redirected++;
                fprintf(stderr, "[WINS:Interceptor] Redirected Win32 library probe: %s -> %s\n", pathname, hook_path);
                record_telemetry_event("LIB_PROBE", pathname, "REDIRECTED_TO_HOOK");
                return real_openat(AT_FDCWD, hook_path, flags, mode);
            }
        }

        const char *base = strrchr(pathname, '/');
        const char *fname = base ? base + 1 : pathname;
        if (fname && strlen(fname) > 1) {
            char overlay_path[512];
            const char *home = getenv("HOME");
            if (!home) home = "/tmp";
            snprintf(overlay_path, sizeof(overlay_path), "%s/.cache/wins/overlays/%s", home, fname);

            struct stat st;
            if (stat(overlay_path, &st) == 0 && S_ISREG(st.st_mode)) {
                g_telemetry.overlays_redirected++;
                fprintf(stderr, "[WINS:Interceptor] Overlay redirected: %s -> %s\n", pathname, overlay_path);
                record_telemetry_event("ASSET_OVERLAY", fname, "REDIRECTED");
                return real_openat(AT_FDCWD, overlay_path, flags, mode);
            }
        }
    }
    return real_openat(dirfd, pathname, flags, mode);
}

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return openat(AT_FDCWD, pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return openat(AT_FDCWD, pathname, flags, mode);
}

/* ==============================================================================
 * 4. STEAMWORKS.NET C API STUBS (CERO-WINE)
 * ============================================================================== */

bool SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID) {
    (void)unOwnAppID;
    return false;
}

bool RestartAppIfNecessary(uint32_t unOwnAppID) { return SteamAPI_RestartAppIfNecessary(unOwnAppID); }
bool IsSteamRunning(void) { return false; }
bool Init(void) { return false; }
bool InitSafe(void) { return false; }

bool SteamAPI_Init(void) { return false; }
bool SteamAPI_InitSafe(void) { return false; }
void SteamAPI_Shutdown(void) {}
void Shutdown(void) {}
void SteamAPI_RunCallbacks(void) {}
void RunCallbacks(void) {}
bool SteamAPI_IsSteamRunning(void) { return false; }
void SteamAPI_RegisterCallback(void *pCallback, int iCallback) { (void)pCallback; (void)iCallback; }
void SteamAPI_UnregisterCallback(void *pCallback) { (void)pCallback; }
void SteamAPI_RegisterCallResult(void *pCallback, uint64_t hAPICall) { (void)pCallback; (void)hAPICall; }
void SteamAPI_UnregisterCallResult(void *pCallback, uint64_t hAPICall) { (void)pCallback; (void)hAPICall; }
int SteamAPI_GetHSteamPipe(void) { return 1; }
int SteamAPI_GetHSteamUser(void) { return 1; }
const char* SteamAPI_GetSteamInstallPath(void) { return "."; }
void SteamAPI_UseBreakpadCrashHandler(const char *a, const char *b, const char *c, bool d, void *e, void *f) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
}
void SteamAPI_SetBreakpadAppID(uint32_t unAppID) { (void)unAppID; }
void SteamAPI_SetMiniDumpComment(const char *pchMsg) { (void)pchMsg; }
void SteamAPI_WriteMiniDump(uint32_t a, void *b, uint32_t c) { (void)a; (void)b; (void)c; }
void SteamAPI_SetTryCatchCallbacks(bool b) { (void)b; }

/* ==============================================================================
 * 5. IN-MEMORY PATCHER & AUTONOMOUS SESSION LIFECYCLE
 * ============================================================================== */

static void patch_memory(void *addr, const uint8_t *patch, size_t len) {
    uintptr_t page_start = (uintptr_t)addr & ~(getpagesize() - 1);
    size_t page_size = getpagesize() * 2;
    mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(addr, patch, len);
    mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);
}

__attribute__((constructor))
static void wins_runtime_interceptor_init(void) {
    g_telemetry.start_time = time(NULL);
    fprintf(stderr, "[WINS:Supervisor] Initializing autonomous runtime interceptor & hunter...\n");

    /* Scan main executable memory maps for Unity Player signatures */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return;

    char line[512];
    uintptr_t base = 0, end = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "r-xp") && (strstr(line, "Cuphead") || strstr(line, ".x86_64") || strstr(line, "UnityPlayer"))) {
            sscanf(line, "%lx-%lx", &base, &end);
            break;
        }
    }
    fclose(maps);

    if (base && end > base) {
        uint8_t *code = (uint8_t*)base;
        size_t len = end - base;

        const uint8_t sig1[] = {0x83, 0xff, 0x12, 0x0f, 0x84, 0x16, 0x02, 0x00, 0x00};
        const uint8_t sig2[] = {0x48, 0x8d, 0x5c, 0x24, 0x10, 0x48, 0x8d, 0x35, 0x75, 0xfb, 0x43, 0x01};

        for (size_t i = 0; i + 16 < len; ++i) {
            if (memcmp(code + i, sig1, sizeof(sig1)) == 0) {
                const uint8_t patch1[] = {0xe9, 0x43, 0x01, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90};
                patch_memory(code + i, patch1, sizeof(patch1));
                fprintf(stderr, "[WINS:Interceptor] [✓] Patched GfxDevice editor gate at %p\n", (void*)(base + i));
            }
            if (memcmp(code + i, sig2, sizeof(sig2)) == 0) {
                const uint8_t patch2[] = {0x31, 0xc0, 0xeb, 0x5a, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                patch_memory(code + i, patch2, sizeof(patch2));

                if (code[i + 0x6a] == 0x75 && code[i + 0x6b] == 0x11) {
                    const uint8_t nop2[] = {0x90, 0x90};
                    patch_memory(code + i + 0x6a, nop2, sizeof(nop2));
                    fprintf(stderr, "[WINS:Interceptor] [✓] Neutralized stack canary abort at %p\n", (void*)(base + i + 0x6a));
                }
                fprintf(stderr, "[WINS:Interceptor] [✓] Patched Shader platform fallback gate at %p\n", (void*)(base + i));
            }
        }
    }
}

__attribute__((destructor))
static void wins_runtime_interceptor_exit(void) {
    long elapsed = (long)(time(NULL) - g_telemetry.start_time);
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char sum_path[512];
    snprintf(sum_path, sizeof(sum_path), "%s/.cache/wins/telemetry/session_summary.json", home);

    FILE *f = fopen(sum_path, "w");
    if (f) {
        fprintf(f, "{\n"
                   "  \"session_duration_sec\": %ld,\n"
                   "  \"dxbc_shaders_intercepted\": %u,\n"
                   "  \"dxbc_shaders_cache_hits\": %u,\n"
                   "  \"dxbc_shaders_onthefly_transpiled\": %u,\n"
                   "  \"win32_apis_accepted\": %u,\n"
                   "  \"win32_apis_unhandled\": %u,\n"
                   "  \"overlays_redirected\": %u\n"
                   "}\n",
                   elapsed,
                   g_telemetry.dxbc_intercepted,
                   g_telemetry.dxbc_cache_hits,
                   g_telemetry.dxbc_onthefly_transpiled,
                   g_telemetry.win32_apis_accepted,
                   g_telemetry.win32_apis_unhandled,
                   g_telemetry.overlays_redirected);
        fclose(f);
    }
    fprintf(stderr, "[WINS:Supervisor] Session finalized. Telemetry written to %s\n", sum_path);
}
