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

void* rva_offset(const uint8_t* base, size_t offset) {
    assert(base);

    return (void*)(base + offset);
}
