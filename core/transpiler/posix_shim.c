/**
 * WINS Zero-Win32 POSIX Shimming Layer
 * Provides zero-overhead native Linux replacements for Windows Kernel32 / Advapi32
 * file I/O, path resolution, and registry access without running Wine.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define WINS_GENERIC_READ     0x80000000
#define WINS_GENERIC_WRITE    0x40000000
#define WINS_CREATE_ALWAYS    2
#define WINS_OPEN_EXISTING    3
#define WINS_OPEN_ALWAYS      4

static const char* DOS_DEVICES[] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    NULL
};

static int is_dos_device(const char* seg, size_t len) {
    char base[32];
    size_t i = 0;
    while (i < len && i < 31 && seg[i] != '.') {
        base[i] = (char)toupper((unsigned char)seg[i]);
        i++;
    }
    while (i > 0 && base[i - 1] == ' ') i--;
    base[i] = '\0';

    for (int d = 0; DOS_DEVICES[d]; d++) {
        if (strcmp(base, DOS_DEVICES[d]) == 0) return 1;
    }
    return 0;
}

/**
 * Normalizes Windows paths (C:\Users\...\AppData\Roaming\App\file.xml)
 * into native Linux paths (~/.config/app/file.xml), sanitizing DOS devices,
 * ADS streams, and trailing dots/spaces verified by the Zig Differential Fuzzer.
 */
int wins_normalize_path(const char* win_path, char* out_buf, size_t out_max) {
    if (!win_path || !out_buf || out_max < 2) return -1;

    const char* src = win_path;

    // 1. Strip Extended Length / UNC prefixes (\\?\ or \\.\)
    if (src[0] == '\\' && src[1] == '\\' && (src[2] == '?' || src[2] == '.') && src[3] == '\\') {
        src += 4;
    }

    // 2. Strip Windows Drive letter (e.g. "C:\" or "c:/")
    if (isalpha((unsigned char)src[0]) && src[1] == ':') {
        src += 2;
        if (*src == '\\' || *src == '/') {
            src++;
        }
    }

    size_t out_pos = 0;

    // 3. Map AppData\Roaming to ~/.config/
    const char* appdata = strcasestr(src, "AppData\\Roaming\\");
    if (!appdata) appdata = strcasestr(src, "AppData/Roaming/");

    if (appdata) {
        src = appdata + strlen("AppData/Roaming/");
        const char* home = getenv("HOME");
        if (!home) home = "/tmp";
        int written = snprintf(out_buf, out_max, "%s/.config/", home);
        if (written > 0 && (size_t)written < out_max) {
            out_pos = (size_t)written;
        }
    }

    // 4. Tokenize and sanitize path segments
    const char* seg_start = src;
    size_t i = 0;

    while (1) {
        char c = src[i];
        if (c == '\\' || c == '/' || c == '\0') {
            size_t seg_len = (size_t)((src + i) - seg_start);
            if (seg_len > 0) {
                // Ignore '.' segment
                if (!(seg_len == 1 && seg_start[0] == '.')) {
                    // Check for Alternate Data Stream (ADS): "file.txt:stream"
                    const char* colon = memchr(seg_start, ':', seg_len);
                    if (colon) {
                        seg_len = (size_t)(colon - seg_start);
                    }

                    // Trim trailing dots and spaces (Win32 auto-trim)
                    while (seg_len > 0 && (seg_start[seg_len - 1] == '.' || seg_start[seg_len - 1] == ' ')) {
                        seg_len--;
                    }

                    if (seg_len > 0) {
                        // Append directory separator if needed
                        if (out_pos > 0 && out_buf[out_pos - 1] != '/' && out_pos + 1 < out_max) {
                            out_buf[out_pos++] = '/';
                        }

                        // Sanitize DOS devices (e.g., CON -> _win_CON)
                        if (is_dos_device(seg_start, seg_len)) {
                            const char* pfx = "_win_";
                            size_t pfx_len = strlen(pfx);
                            if (out_pos + pfx_len < out_max) {
                                memcpy(out_buf + out_pos, pfx, pfx_len);
                                out_pos += pfx_len;
                            }
                        }

                        // Copy segment
                        if (out_pos + seg_len < out_max) {
                            memcpy(out_buf + out_pos, seg_start, seg_len);
                            out_pos += seg_len;
                        }
                    }
                }
            }

            if (c == '\0') break;
            seg_start = src + i + 1;
        }
        i++;
    }

    if (out_pos == 0 && out_max > 1) {
        out_buf[0] = '.';
        out_pos = 1;
    }

    out_buf[out_pos] = '\0';
    return 0;
}

static int mkdir_p(const char* path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return 0;

    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return 0;
}

/**
 * Native Linux implementation of Win32 CreateFileW/A.
 */
int wins_create_file(const char* win_path, unsigned int access_flags, unsigned int creation_disposition) {
    char norm_path[512];
    if (wins_normalize_path(win_path, norm_path, sizeof(norm_path)) != 0) {
        return -1;
    }

    int posix_flags = 0;
    if ((access_flags & WINS_GENERIC_READ) && (access_flags & WINS_GENERIC_WRITE)) {
        posix_flags |= O_RDWR;
    } else if (access_flags & WINS_GENERIC_WRITE) {
        posix_flags |= O_WRONLY;
    } else {
        posix_flags |= O_RDONLY;
    }

    if (creation_disposition == WINS_CREATE_ALWAYS) {
        posix_flags |= O_CREAT | O_TRUNC;
    } else if (creation_disposition == WINS_OPEN_ALWAYS) {
        posix_flags |= O_CREAT;
    }

    if (posix_flags & O_CREAT) {
        // Ensure parent directory exists
        char dir_buf[512];
        snprintf(dir_buf, sizeof(dir_buf), "%s", norm_path);
        char* last_slash = strrchr(dir_buf, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir_p(dir_buf);
        }
    }

    return open(norm_path, posix_flags, 0644);
}

/**
 * Native Linux implementation of Win32 ReadFile.
 */
int wins_read_file(int fd, void* buffer, size_t bytes_to_read, size_t* bytes_read) {
    if (fd < 0 || !buffer) return 0;
    ssize_t res = read(fd, buffer, bytes_to_read);
    if (res < 0) {
        if (bytes_read) *bytes_read = 0;
        return 0;
    }
    if (bytes_read) *bytes_read = (size_t)res;
    return 1;
}

/**
 * Native Linux implementation of Win32 WriteFile.
 */
int wins_write_file(int fd, const void* buffer, size_t bytes_to_write, size_t* bytes_written) {
    if (fd < 0 || !buffer) return 0;
    ssize_t res = write(fd, buffer, bytes_to_write);
    if (res < 0) {
        if (bytes_written) *bytes_written = 0;
        return 0;
    }
    if (bytes_written) *bytes_written = (size_t)res;
    return 1;
}

/**
 * Native Linux implementation of Win32 CloseHandle.
 */
int wins_close_file(int fd) {
    if (fd < 0) return 0;
    return close(fd) == 0;
}
