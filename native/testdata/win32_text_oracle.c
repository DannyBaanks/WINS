/* Independent oracle for the CP_UTF8 text fuzzer.
 *
 * Deliberately a different construction than native/shims/win32_text_impl.zig:
 * table-driven (Unicode Table 3-7 rows) instead of a switch, and written in C.
 * It models the same documented MultiByteToWideChar / WideCharToMultiByte
 * contract; it is cross-checked against CPython's UTF-8 codec by
 * native/test_win32_text.py. It is NOT a Windows kernel: replacement
 * granularity and error precedence are NOT_DEMONSTRATED against real Windows.
 */
#include <stddef.h>
#include <stdint.h>

typedef struct { uint8_t first_lo, first_hi, tail, lo, hi, mask; } Row;
static const Row rows[] = {
    {0xC2, 0xDF, 1, 0x80, 0xBF, 0x1F}, {0xE0, 0xE0, 2, 0xA0, 0xBF, 0x0F},
    {0xE1, 0xEC, 2, 0x80, 0xBF, 0x0F}, {0xED, 0xED, 2, 0x80, 0x9F, 0x0F},
    {0xEE, 0xEF, 2, 0x80, 0xBF, 0x0F}, {0xF0, 0xF0, 3, 0x90, 0xBF, 0x07},
    {0xF1, 0xF3, 3, 0x80, 0xBF, 0x07}, {0xF4, 0xF4, 3, 0x80, 0x8F, 0x07},
};

/* Returns number of bytes consumed; *bad set for an ill-formed prefix. */
static size_t dec8(const uint8_t *s, size_t n, size_t i, uint32_t *cp, int *bad) {
    uint8_t b = s[i];
    *bad = 0;
    if (b < 0x80) { *cp = b; return 1; }
    for (size_t r = 0; r < sizeof rows / sizeof rows[0]; r++) {
        const Row *w = &rows[r];
        if (b < w->first_lo || b > w->first_hi) continue;
        uint32_t v = b & w->mask;
        size_t used = 1;
        for (size_t t = 0; t < w->tail; t++) {
            uint8_t lo = t == 0 ? w->lo : 0x80, hi = t == 0 ? w->hi : 0xBF;
            if (i + used >= n || s[i + used] < lo || s[i + used] > hi) { *bad = 1; *cp = 0xFFFD; return used; }
            v = (v << 6) | (s[i + used] & 0x3F);
            used++;
        }
        *cp = v;
        return used;
    }
    *bad = 1; *cp = 0xFFFD;
    return 1;
}

static size_t dec16(const uint16_t *s, size_t n, size_t i, uint32_t *cp, int *bad) {
    uint16_t u = s[i];
    *bad = 0;
    if (u >= 0xD800 && u < 0xDC00 && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
        *cp = 0x10000u + (((uint32_t)u & 0x3FFu) << 10) + ((uint32_t)s[i + 1] & 0x3FFu);
        return 2;
    }
    if (u >= 0xD800 && u < 0xE000) { *bad = 1; *cp = 0xFFFD; return 1; }
    *cp = u;
    return 1;
}

static int fail(uint32_t *err, uint32_t code) { *err = code; return 0; }

int32_t wins_mb2wc(uint32_t flags, const uint8_t *src, int32_t cb, uint16_t *dst, int32_t cch, uint32_t *err) {
    *err = 0;
    if (flags != 0 && flags != 8) return fail(err, 1004);
    if (!src || cb == 0 || cb < -1 || cch < 0 || (!dst && cch > 0)) return fail(err, 87);
    size_t n = 0;
    if (cb == -1) { while (src[n]) n++; n++; } else n = (size_t)cb;
    size_t need = 0;
    for (size_t i = 0, used; i < n; i += used) {
        uint32_t cp; int bad;
        used = dec8(src, n, i, &cp, &bad);
        if (bad && flags == 8) return fail(err, 1113);
        need += cp >= 0x10000 ? 2 : 1;
    }
    if (cch == 0) return (int32_t)need;
    if (need > (size_t)cch) return fail(err, 122);
    size_t o = 0;
    for (size_t i = 0, used; i < n; i += used) {
        uint32_t cp; int bad;
        used = dec8(src, n, i, &cp, &bad);
        if (cp >= 0x10000) { cp -= 0x10000; dst[o++] = (uint16_t)(0xD800 + (cp >> 10)); dst[o++] = (uint16_t)(0xDC00 + (cp & 0x3FF)); }
        else dst[o++] = (uint16_t)cp;
    }
    return (int32_t)need;
}

int32_t wins_wc2mb(uint32_t flags, const uint16_t *src, int32_t cch, uint8_t *dst, int32_t cb, uint32_t *err) {
    *err = 0;
    if (flags != 0 && flags != 0x80) return fail(err, 1004);
    if (!src || cch == 0 || cch < -1 || cb < 0 || (!dst && cb > 0)) return fail(err, 87);
    size_t n = 0;
    if (cch == -1) { while (src[n]) n++; n++; } else n = (size_t)cch;
    size_t need = 0;
    for (size_t i = 0, used; i < n; i += used) {
        uint32_t cp; int bad;
        used = dec16(src, n, i, &cp, &bad);
        if (bad && flags == 0x80) return fail(err, 1113);
        need += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    }
    if (cb == 0) return (int32_t)need;
    if (need > (size_t)cb) return fail(err, 122);
    size_t o = 0;
    for (size_t i = 0, used; i < n; i += used) {
        uint32_t cp; int bad;
        used = dec16(src, n, i, &cp, &bad);
        if (cp < 0x80) dst[o++] = (uint8_t)cp;
        else if (cp < 0x800) { dst[o++] = 0xC0 | (cp >> 6); dst[o++] = 0x80 | (cp & 0x3F); }
        else if (cp < 0x10000) { dst[o++] = 0xE0 | (cp >> 12); dst[o++] = 0x80 | ((cp >> 6) & 0x3F); dst[o++] = 0x80 | (cp & 0x3F); }
        else { dst[o++] = 0xF0 | (cp >> 18); dst[o++] = 0x80 | ((cp >> 12) & 0x3F); dst[o++] = 0x80 | ((cp >> 6) & 0x3F); dst[o++] = 0x80 | (cp & 0x3F); }
    }
    return (int32_t)need;
}
