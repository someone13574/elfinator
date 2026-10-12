#pragma once

#include <stddef.h>
#include <stdint.h>

void perror_exit(const char* message);
void pmsg_exit(const char* message);

size_t round_up_pow2(size_t value, size_t align_pow2);
void* rva_offset(const uint8_t* base, size_t offset);
