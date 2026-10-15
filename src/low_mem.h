#pragma once

#ifdef ELFINATOR_COMPAT

#include <stddef.h>
#include <stdint.h>

#define LOW_MEM_TOP_GAP 0x10000ull

_Bool low_mem_is_reserved();
void low_mem_reserve(uint64_t limit);
void* low_mem_alloc(uint64_t preferred, size_t size, size_t align);

#endif
