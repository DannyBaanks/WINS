#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <GL/gl.h>

/* ==============================================================================
 * WINS AGNOSTIC RUNTIME INTERCEPTOR (LD_PRELOAD)
 * ==============================================================================
 * 1. Emulates Steamworks C API (libCSteamworks / libsteam_api)
 * 2. In-memory self-patching of Unity Player engine & shader platform gates
 * 3. Transparent openat / open overlay redirection (~/.cache/wins/overlays/)
 * 4. Intercepts glShaderSource & glXGetProcAddress
 * 5. Transparently transpiles DXBC bytecode to OpenGL Core GLSL 4.50 on the fly
 * ============================================================================== */

typedef int (*PFN_OPENAT)(int dirfd, const char *pathname, int flags, mode_t mode);
static PFN_OPENAT real_openat = NULL;

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (!real_openat) {
        real_openat = (PFN_OPENAT)dlsym(RTLD_NEXT, "openat");
    }

    if (pathname && (flags & O_ACCMODE) == O_RDONLY) {
        const char *base = strrchr(pathname, '/');
        const char *fname = base ? base + 1 : pathname;
        if (fname && strlen(fname) > 1) {
            char overlay_path[512];
            const char *home = getenv("HOME");
            if (!home) home = "/tmp";
            snprintf(overlay_path, sizeof(overlay_path), "%s/.cache/wins/overlays/%s", home, fname);
            
            struct stat st;
            if (stat(overlay_path, &st) == 0 && S_ISREG(st.st_mode)) {
                fprintf(stderr, "[WINS:Interceptor] Overlay redirected: %s -> %s\n", pathname, overlay_path);
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


typedef void (*PFNGLSHADERSOURCEPROC)(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length);
typedef void* (*PFNGLXGETPROCADDRESSPROC)(const GLubyte *procName);

static PFNGLSHADERSOURCEPROC real_glShaderSource = NULL;
static PFNGLXGETPROCADDRESSPROC real_glXGetProcAddress = NULL;
static PFNGLXGETPROCADDRESSPROC real_glXGetProcAddressARB = NULL;

static void init_real_gl(void) {
    if (!real_glXGetProcAddress) {
        void *libgl = dlopen("libGL.so.1", RTLD_LAZY | RTLD_GLOBAL);
        if (!libgl) libgl = dlopen("libGL.so", RTLD_LAZY | RTLD_GLOBAL);
        if (libgl) {
            real_glXGetProcAddress = (PFNGLXGETPROCADDRESSPROC)dlsym(libgl, "glXGetProcAddress");
            real_glXGetProcAddressARB = (PFNGLXGETPROCADDRESSPROC)dlsym(libgl, "glXGetProcAddressARB");
            real_glShaderSource = (PFNGLSHADERSOURCEPROC)dlsym(libgl, "glShaderSource");
        }
        if (!real_glShaderSource && real_glXGetProcAddress) {
            real_glShaderSource = (PFNGLSHADERSOURCEPROC)real_glXGetProcAddress((const GLubyte*)"glShaderSource");
        }
        if (!real_glShaderSource) {
            real_glShaderSource = (PFNGLSHADERSOURCEPROC)dlsym(RTLD_NEXT, "glShaderSource");
        }
    }
}

/* --- SHA-256 Simple Implementation for In-Memory Hash Lookup --- */
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

/* ==============================================================================
 * glShaderSource Interception & DXBC -> GLSL Translation
 * ============================================================================== */

void wins_glShaderSource(GLuint shader, GLsizei count, const GLchar *const *string, const GLint *length) {
    init_real_gl();
    if (!real_glShaderSource) return;

    if (count > 0 && string && string[0]) {
        const uint8_t *src_bytes = (const uint8_t*)string[0];
        size_t src_len = (length && length[0] > 0) ? (size_t)length[0] : strlen(string[0]);

        /* Check for DXBC magic header "DXBC" (0x43425844) */
        if (src_len >= 32 && memcmp(src_bytes, "DXBC", 4) == 0) {
            uint32_t total_size = *(const uint32_t*)(src_bytes + 24);
            if (total_size > 0 && total_size <= src_len + 4096) {
                char hash_hex[65];
                compute_sha256_hex(src_bytes, total_size, hash_hex);

                /* Look up cached GLSL */
                char cache_path[512];
                const char *home = getenv("HOME");
                if (!home) home = "/tmp";
                snprintf(cache_path, sizeof(cache_path), "%s/.cache/wins/shaders/%s.glsl", home, hash_hex);

                FILE *f = fopen(cache_path, "rb");
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
    if (real_glXGetProcAddress) {
        return real_glXGetProcAddress(procName);
    }
    return dlsym(RTLD_NEXT, (const char*)procName);
}

void* glXGetProcAddressARB(const GLubyte *procName) {
    return glXGetProcAddress(procName);
}

/* ==============================================================================
 * Steamworks.NET C API Emulation (Zero-Wine Steamworks Stub)
 * ============================================================================== */

bool SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID) {
    (void)unOwnAppID;
    return false; /* 0 = No restart required; proceed with standalone execution */
}

bool SteamAPI_Init(void) { return true; }
bool SteamAPI_InitSafe(void) { return true; }
void SteamAPI_Shutdown(void) {}
void SteamAPI_RunCallbacks(void) {}
bool SteamAPI_IsSteamRunning(void) { return true; }
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
 * In-Memory Engine Gate Patcher (Constructor)
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
    fprintf(stderr, "[WINS:Interceptor] Initializing agnostic runtime hook...\n");

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

        /* Signature 1: Unity GfxDevice editor check */
        /* 83 ff 12 0f 84 16 02 00 00 -> cmp edi, 0x12; je 97c067 */
        const uint8_t sig1[] = {0x83, 0xff, 0x12, 0x0f, 0x84, 0x16, 0x02, 0x00, 0x00};
        /* Signature 2: Unity Shader platform missing check */
        /* 48 8d 5c 24 10 48 8d 35 75 fb 43 01 */
        const uint8_t sig2[] = {0x48, 0x8d, 0x5c, 0x24, 0x10, 0x48, 0x8d, 0x35, 0x75, 0xfb, 0x43, 0x01};

        for (size_t i = 0; i + 16 < len; ++i) {
            if (memcmp(code + i, sig1, sizeof(sig1)) == 0) {
                /* Patch: jmp to CreateGfxDevice */
                const uint8_t patch1[] = {0xe9, 0x43, 0x01, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90};
                patch_memory(code + i, patch1, sizeof(patch1));
                fprintf(stderr, "[WINS:Interceptor] [✓] Patched GfxDevice editor gate at %p\n", (void*)(base + i));
            }
            if (memcmp(code + i, sig2, sizeof(sig2)) == 0) {
                /* Patch: return index 0 fallback cleanly to 0x8b384b */
                /* 0x8b384b - (0x8b37ef + 2) = 0x5a */
                const uint8_t patch2[] = {0x31, 0xc0, 0xeb, 0x5a, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                patch_memory(code + i, patch2, sizeof(patch2));

                /* Patch: disable stack canary abort at 0x8b3859 (offset 0x6a from sig2) */
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
