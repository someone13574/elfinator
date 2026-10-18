#pragma once

#ifdef ELFINATOR_COMPAT

#include <stddef.h>
#include <stdint.h>

#define COMPAT_ARENA_TOP_GAP 0x10000ull

_Bool compat_arena_is_reserved();
void compat_arena_reserve(uint64_t limit);
void* compat_arena_alloc(uint64_t preferred, size_t size, size_t align);

#endif
