#pragma once

#include <stddef.h>
#include <stdio.h>

void perror_exit(const char* message) __attribute__((noreturn));
void pmsg_exit(const char* fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

/// Creates a new directory at `path` if it doesn't exist, recursively
void mkdir_recursive(const char* path);

/// Builds "<out_dir>/<stem><new_ext>" from input. Returns 0 on success, -1 if the result didn't fit
/// in out.
int make_output_path(
    char* out, size_t out_size, const char* input, const char* out_dir, const char* new_ext
);

FILE* open_output_file(const char* input, const char* out_dir, const char* new_ext);
