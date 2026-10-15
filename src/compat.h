#pragma once

#ifdef ELFINATOR_COMPAT

#include <stdint.h>

void compat_init(uint64_t limit);
// Allocates the calling thread's 32-bit stack
void compat_alloc_stack(uint32_t stack_reserve);
// Calls a 32-bit function on the calling thread's 32-bit stack
uint32_t compat_call32(uint32_t fn, const uint32_t* args, uint32_t nargs);

#endif
