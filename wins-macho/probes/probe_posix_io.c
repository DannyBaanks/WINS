/*
 * Dual-compiled Differential Probe #1: POSIX I/O, Memory, Fortify, Stat, Qsort
 * Compiled BOTH as macOS x86_64 Mach-O (tested under wins_macho)
 * AND as Linux x86_64 ELF (the independent native oracle).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int cmp_u8(const void *a, const void *b) {
    unsigned char x = *(const unsigned char *)a;
    unsigned char y = *(const unsigned char *)b;
    return (int)x - (int)y;
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
    size_t cap = 4096;
    size_t len = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return 2;

    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char *)realloc(buf, cap);
            if (!nb) { free(buf); return 3; }
            buf = nb;
        }
        ssize_t n = read(0, buf + len, 4096);
        if (n < 0) { free(buf); return 4; }
        if (n == 0) break;
        len += (size_t)n;
    }

    uint64_t h_raw = fnv1a(buf, len);

    /* Exercise open(O_CREAT|O_TRUNC|O_RDWR), write, fstat, lseek/read, stat, unlink */
    char tmp_path[128];
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/wm_probe_io_%d.bin", (int)getpid());
    int fd = open(tmp_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) { free(buf); return 10; }
    size_t written = 0;
    while (written < len) {
        ssize_t w = write(fd, buf + written, len - written);
        if (w <= 0) { close(fd); unlink(tmp_path); free(buf); return 11; }
        written += (size_t)w;
    }
    struct stat st_fd;
    if (fstat(fd, &st_fd) != 0) { close(fd); unlink(tmp_path); free(buf); return 12; }
    close(fd);

    struct stat st_path;
    if (stat(tmp_path, &st_path) != 0) { unlink(tmp_path); free(buf); return 13; }
    if ((size_t)st_fd.st_size != len || (size_t)st_path.st_size != len) {
        unlink(tmp_path); free(buf); return 14;
    }

    /* Read back via stdio fopen/fread/fseek/ftell */
    FILE *fp = fopen(tmp_path, "rb");
    if (!fp) { unlink(tmp_path); free(buf); return 15; }
    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *rb = (unsigned char *)calloc(len + 1, 1);
    if (!rb) { fclose(fp); unlink(tmp_path); free(buf); return 16; }
    size_t got = (len > 0) ? fread(rb, 1, len, fp) : 0;
    fclose(fp);
    unlink(tmp_path);

    if ((size_t)fsz != len || got != len || (len > 0 && memcmp(buf, rb, len) != 0)) {
        free(rb); free(buf); return 17;
    }

    /* Exercise qsort, memchr, sprintf fortify */
    size_t nuls = 0;
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;
    while (p < end) {
        const unsigned char *hit = (const unsigned char *)memchr(p, 0, (size_t)(end - p));
        if (!hit) break;
        nuls++;
        p = hit + 1;
    }

    if (len > 0) qsort(rb, len, 1, cmp_u8);
    uint64_t h_sorted = fnv1a(rb, len);

    char line[256];
    sprintf(line, "len=%zu raw=%016llx sorted=%016llx nuls=%zu\n",
            len, (unsigned long long)h_raw, (unsigned long long)h_sorted, nuls);
    fputs(line, stdout);

    int exit_code = (len > 0 && (buf[0] % 7 == 0)) ? (int)(buf[0] % 13) : 0;
    if (exit_code != 0) {
        fprintf(stderr, "diag_nonzero=%d\n", exit_code);
    }

    free(rb);
    free(buf);
    return exit_code;
}
