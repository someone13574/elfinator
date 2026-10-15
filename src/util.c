#include "util.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

void perror_exit(const char* message) {
    perror(message);
    exit(1);
}

void pmsg_exit(const char* message) {
    fprintf(stderr, "error: %s\n", message);
    exit(1);
}

uint8_t* map_file(const char* path, size_t* size_out) {
    assert(size_out);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror_exit("open");
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror_exit("fstat");
    }

    // mmap rejects zero-length mappings with a confusing EINVAL
    if (st.st_size == 0) {
        pmsg_exit("empty file");
    }

    uint8_t* file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        perror_exit("mmap file");
    }

    *size_out = st.st_size;
    return file;
}

size_t round_up_pow2(size_t value, size_t align_pow2) {
    return (value + align_pow2 - 1) & ~(align_pow2 - 1);
}

_Bool is_pow2(size_t value) {
    return (value & (value - 1)) == 0;
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

void check_rva_cstring(const uint8_t* base, size_t offset, size_t image_size) {
    assert(base);

    if (offset > image_size) {
        fprintf(
            stdout, "invalid RVA string offset: offset %zu exceeds image size %zu\n", offset,
            image_size
        );
        exit(1);
    }

    if (!memchr(offset_ptr(base, offset), '\0', image_size - offset)) {
        fprintf(
            stdout,
            "invalid RVA string: string at offset %zu not terminated within image size %zu\n",
            offset, image_size
        );
        exit(1);
    }
}

const char* rva_cstring(const uint8_t* base, size_t offset, size_t image_size) {
    assert(base);

    check_rva_cstring(base, offset, image_size);
    return (const char*)offset_ptr(base, offset);
}
