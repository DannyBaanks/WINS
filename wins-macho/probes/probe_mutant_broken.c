/*
 * Negative Control Mutant: identical to probe_posix_io.c EXCEPT deliberately
 * corrupts 1 bit of the sorted hash when len > 0 && (buf[0] & 0x0F) == 0x07.
 * The differential fuzzer MUST catch this divergence!
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static int cmp_u8(const void *a, const void *b) {
    return (int)(*(const unsigned char *)a) - (int)(*(const unsigned char *)b);
}

static uint64_t fnv1a(const unsigned char *buf, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= buf[i];
        h *= 1099511628211ULL;
    }
    return h;
}

int main(void) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return 2;
    for (;;) {
        if (len + 4096 > cap) { cap *= 2; buf = (unsigned char *)realloc(buf, cap); }
        ssize_t n = read(0, buf + len, 4096);
        if (n <= 0) break;
        len += (size_t)n;
    }
    uint64_t h_raw = fnv1a(buf, len);
    size_t nuls = 0;
    for (size_t i = 0; i < len; i++) if (buf[i] == 0) nuls++;
    unsigned char *rb = (unsigned char *)malloc(len + 1);
    if (len > 0) { memcpy(rb, buf, len); qsort(rb, len, 1, cmp_u8); }
    uint64_t h_sorted = fnv1a(rb, len);

    /* DELIBERATE MUTATION: 1-bit flip on ~1/16 of non-empty inputs */
    if (len > 0 && (buf[0] & 0x0F) == 0x07) {
        h_sorted ^= 1ULL;
    }

    printf("len=%zu raw=%016llx sorted=%016llx nuls=%zu\n",
           len, (unsigned long long)h_raw, (unsigned long long)h_sorted, nuls);
    int exit_code = (len > 0 && (buf[0] % 7 == 0)) ? (int)(buf[0] % 13) : 0;
    if (exit_code != 0) fprintf(stderr, "diag_nonzero=%d\n", exit_code);
    free(rb); free(buf);
    return exit_code;
}
