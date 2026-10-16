#define _GNU_SOURCE

#include "util.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

void perror_exit(const char* message) {
    perror(message);
    exit(1);
}

void pmsg_exit(const char* fmt, ...) {
    fprintf(stderr, "error: ");

    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    va_end(va);
    fputc('\n', stderr);
    exit(1);
}

void mkdir_recursive(const char* path) {
    assert(path);

    char* path_working = strdup(path);
    if (!path_working) {
        perror_exit("mkdir strdup");
    }

    for (char* str = path_working + 1; *str; str++) {
        if (*str == '/') {
            *str = '\0';
            if (mkdir(path_working, 0777) != 0 && errno != EEXIST) {
                perror_exit("mkdir");
            }
            *str = '/';
        }
    }

    if (mkdir(path_working, 0777) != 0 && errno != EEXIST) {
        perror_exit("mkdir");
    }
    free(path_working);
}

int make_output_path(
    char* out, size_t out_size, const char* input, const char* out_dir, const char* new_ext
) {
    assert(out && input && out_dir && new_ext);

    const char* name = input;
    for (const char* ptr = input; *ptr; ptr++) {
        if (*ptr == '/' || *ptr == '\\') {
            name = ptr + 1;
        }
    }

    const char* dot = strrchr(name, '.');
    size_t stem_len = (dot && dot != name) ? (size_t)(dot - name) : strlen(name);

    int n;
    if (*out_dir) {
        n = snprintf(out, out_size, "%s/%.*s%s", out_dir, (int)stem_len, name, new_ext);
    } else {
        n = snprintf(out, out_size, "%.*s%s", (int)stem_len, name, new_ext);
    }
    return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
}

FILE* open_output_file(const char* input, const char* out_dir, const char* new_ext) {
    char path[512];
    if (make_output_path(path, sizeof(path), input, out_dir, new_ext) != 0) {
        pmsg_exit("path too long");
    }

    FILE* file = fopen(path, "w+");
    if (!file) {
        fprintf(stderr, "failed to open path %s\n", path);
        perror_exit("fopen");
    }

    return file;
}
