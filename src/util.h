#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint64_t u64_align1 __attribute__((aligned(1)));

void perror_exit(const char* message);
void pmsg_exit(const char* message);

size_t round_up_pow2(size_t value, size_t align_pow2);
void* offset_ptr(const uint8_t* base, size_t offset);
void* rva_offset(const uint8_t* base, size_t offset, size_t image_size, void const** image_end_out);
void* rva_offset_ranged(const uint8_t* base, size_t offset, size_t len, size_t image_size);
const char* rva_cstring(const uint8_t* base, size_t offset, size_t image_size);
