#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void perror_exit(const char* message) {
    perror(message);
    exit(1);
}

void pmsg_exit(const char* message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

size_t round_up_pow2(size_t value, size_t align_pow2) {
    return (value + align_pow2 - 1) & ~(align_pow2 - 1);
}

void* offset_ptr(const uint8_t* base, size_t offset) {
    assert(base);

    return (void*)(base + offset);
}

void* rva_offset(
    const uint8_t* base, size_t offset, size_t image_size, void const** image_end_out
) {
    assert(base);

    if (offset > image_size) {
        fprintf(stdout, "invalid RVA offset: %zu exceeds image size %zu\n", offset, image_size);
        exit(1);
    }

    if (image_end_out) {
        *image_end_out = offset_ptr(base, image_size);
    }

    return offset_ptr(base, offset);
}

void* rva_offset_ranged(const uint8_t* base, size_t offset, size_t len, size_t image_size) {
    assert(base);

    if (offset > image_size || len > image_size - offset) {
        fprintf(
            stdout, "invalid RVA offset or size: range %zu..%zu exceeds image size %zu\n", offset,
            offset + len, image_size
        );
        exit(1);
    }

    return offset_ptr(base, offset);
}

const char* rva_cstring(const uint8_t* base, size_t offset, size_t image_size) {
    assert(base);

    if (offset > image_size) {
        fprintf(
            stdout, "invalid RVA string offset: offset %zu exceeds image size %zu\n", offset,
            image_size
        );
        exit(1);
    }

    return (const char*)offset_ptr(base, offset);
}
